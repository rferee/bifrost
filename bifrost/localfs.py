"""Local filesystem operations.

Two rules drive everything here:

* Never overwrite a file in place. The JVM holds mod jars open by inode, and
  rewriting one under a running server can take it down. Write a temp file in
  the destination directory, fsync, rename(2), fsync the directory.
* Never unlink anything the user might want back. Removals are renamed into a
  trash directory on the same filesystem, which is instant and reversible.

bifrost's working directories live inside the data volume (default
/data/.bifrost) precisely so that staging, snapshots and trash are all on the
same filesystem as the files they shadow. That makes applying a change a rename
rather than a copy, and makes a pre-apply snapshot a hardlink farm that costs
nothing.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import TMP_PREFIX

log = logging.getLogger(__name__)

_HASH_CHUNK = 1 << 20

# A hardlink snapshot is free, but it only protects against a file being
# *replaced* - which is the only way bifrost itself writes. It does not protect
# against a file being modified in place, and the Minecraft server does exactly
# that to its config files. So small files get a real copy and big ones (jars)
# get a link.
_SNAPSHOT_COPY_MAX = 1 << 20


@dataclass(frozen=True)
class LocalEntry:
    path: str  # posix-relative to the rule root
    size: int
    mtime: int
    real: Path


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_many(paths: list[Path], workers: int = 4) -> dict[Path, str]:
    if not paths:
        return {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(paths, pool.map(sha256_of, paths), strict=True))


def scan(root: Path, excluded: object = None) -> dict[str, LocalEntry]:
    """Index a rule's local folder.

    Symlinks are skipped outright, in both files and directories: a symlink is a
    way to make a sync tool write outside the tree it was pointed at.
    """
    entries: dict[str, LocalEntry] = {}
    if not root.is_dir():
        return entries

    is_excluded = excluded if callable(excluded) else (lambda _: False)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [
            name
            for name in dirnames
            if not (current / name).is_symlink() and not name.startswith(".bifrost")
        ]
        for name in filenames:
            full = current / name
            if full.is_symlink():
                log.debug("skipping symlink %s", full)
                continue
            relative = PurePosixPath(full.relative_to(root).as_posix()).as_posix()
            if name.startswith(TMP_PREFIX) or name.endswith(".part"):
                continue
            if is_excluded(relative):
                continue
            try:
                stat = full.stat()
            except OSError:
                continue
            entries[relative] = LocalEntry(
                path=relative, size=stat.st_size, mtime=int(stat.st_mtime), real=full
            )
    return entries


def _fsync_file(path: Path) -> None:
    """Flush a file's contents to disk.

    Opened read-write on purpose: Windows rejects fsync on a read-only handle.
    """
    fd = os.open(path, os.O_RDWR)
    try:
        os.fsync(fd)
    except OSError as exc:  # pragma: no cover - filesystem dependent
        log.debug("fsync %s failed: %s", path, exc)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):  # Windows; only relevant in tests
        return
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _apply_ownership(path: Path, uid: int | None, gid: int | None) -> None:
    try:
        os.chmod(path, 0o664)
    except OSError:
        pass
    if uid is None and gid is None:
        return
    if not hasattr(os, "chown"):
        return
    try:
        os.chown(path, uid if uid is not None else -1, gid if gid is not None else -1)
    except PermissionError:
        log.debug("cannot chown %s (not running as root); leaving ownership as-is", path)
    except OSError as exc:
        log.warning("chown %s failed: %s", path, exc)


def place(source: Path, destination: Path, mtime: int, uid: int | None, gid: int | None) -> None:
    """Move a staged file into its final location atomically."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.parent / f"{TMP_PREFIX}{os.getpid()}-{destination.name}"
    try:
        try:
            os.replace(source, temp)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            shutil.copyfile(source, temp)
            source.unlink(missing_ok=True)

        os.utime(temp, (mtime, mtime))
        _apply_ownership(temp, uid, gid)
        _fsync_file(temp)

        os.replace(temp, destination)
        _fsync_dir(destination.parent)
    finally:
        if temp.exists() and temp != destination:
            temp.unlink(missing_ok=True)


def _clone(source: Path, target: Path) -> None:
    """Reproduce source at target as cheaply as is still safe."""
    try:
        if source.stat().st_size <= _SNAPSHOT_COPY_MAX:
            shutil.copy2(source, target)
            return
        os.link(source, target)
    except OSError:
        try:
            shutil.copy2(source, target)
        except OSError as exc:
            log.warning("could not clone %s to %s: %s", source, target, exc)


def snapshot(root: Path, destination: Path) -> None:
    """Hardlink every file under root into destination.

    Near-zero time and space for jars, and it gives an exact pre-apply image to
    roll back to if the server refuses to come up afterwards.
    """
    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not name.startswith(".bifrost")]
        target_dir = destination / current.relative_to(root)
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in filenames:
            source = current / name
            if source.is_symlink():
                continue
            _clone(source, target_dir / name)


def restore(snapshot_dir: Path, root: Path, uid: int | None, gid: int | None) -> list[str]:
    """Make root match a snapshot again. Returns the paths it had to remove."""
    removed: list[str] = []
    if not snapshot_dir.is_dir():
        return removed

    wanted: set[str] = set()
    for dirpath, _, filenames in os.walk(snapshot_dir):
        current = Path(dirpath)
        for name in filenames:
            source = current / name
            relative = source.relative_to(snapshot_dir).as_posix()
            wanted.add(relative)
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            temp = destination.parent / f"{TMP_PREFIX}restore-{destination.name}"
            temp.unlink(missing_ok=True)
            _clone(source, temp)
            _apply_ownership(temp, uid, gid)
            os.replace(temp, destination)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not name.startswith(".bifrost")]
        for name in filenames:
            full = current / name
            relative = full.relative_to(root).as_posix()
            if relative not in wanted and not name.startswith(TMP_PREFIX):
                full.unlink(missing_ok=True)
                removed.append(relative)
    return removed


def move_to_trash(path: Path, trash_root: Path, relative: str, stamp: int) -> Path:
    target = trash_root / str(stamp) / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(path, target)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.move(str(path), str(target))
    return target


def prune_trash(trash_root: Path, retention_days: int) -> None:
    if retention_days <= 0 or not trash_root.is_dir():
        return
    cutoff = time.time() - retention_days * 86400
    for child in trash_root.iterdir():
        if not child.is_dir() or not child.name.isdigit():
            continue
        if int(child.name) < cutoff:
            shutil.rmtree(child, ignore_errors=True)
            log.info("pruned expired trash %s", child)


def tail(path: Path, lines: int = 40) -> str:
    if not path.is_file():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])
