from __future__ import annotations

import os
from pathlib import Path

from bifrost import localfs


def test_place_moves_and_sets_mtime(tmp_path: Path) -> None:
    source = tmp_path / "staged.jar"
    source.write_bytes(b"payload")
    destination = tmp_path / "mods" / "final.jar"

    localfs.place(source, destination, 1_700_000_000, None, None)

    assert destination.read_bytes() == b"payload"
    assert int(destination.stat().st_mtime) == 1_700_000_000
    assert not source.exists()
    assert not list(destination.parent.glob(".bifrost-tmp-*"))


def test_place_replaces_rather_than_rewrites(tmp_path: Path) -> None:
    """Overwriting a jar in place can take down a running JVM; renaming cannot."""
    destination = tmp_path / "mods" / "mod.jar"
    destination.parent.mkdir()
    destination.write_bytes(b"old")
    original_inode = destination.stat().st_ino

    source = tmp_path / "new.jar"
    source.write_bytes(b"new")
    localfs.place(source, destination, 1_700_000_000, None, None)

    assert destination.read_bytes() == b"new"
    if os.name != "nt":
        assert destination.stat().st_ino != original_inode


def test_snapshot_and_restore_round_trip(tmp_path: Path) -> None:
    root = tmp_path / "mods"
    (root / "sub").mkdir(parents=True)
    (root / "keep.jar").write_bytes(b"keep")
    (root / "sub" / "nested.jar").write_bytes(b"nested")

    snapshot = tmp_path / "snap"
    localfs.snapshot(root, snapshot)

    # Simulate a bad sync: one file replaced, one added, one removed.
    (root / "keep.jar").write_bytes(b"corrupted")
    (root / "added.jar").write_bytes(b"added")
    (root / "sub" / "nested.jar").unlink()

    removed = localfs.restore(snapshot, root, None, None)

    assert (root / "keep.jar").read_bytes() == b"keep"
    assert (root / "sub" / "nested.jar").read_bytes() == b"nested"
    assert not (root / "added.jar").exists()
    assert removed == ["added.jar"]


def test_snapshot_restores_a_large_file_replaced_the_way_bifrost_replaces_them(
    tmp_path: Path,
) -> None:
    """Big files are hardlinked into the snapshot rather than copied.

    That is only sound because bifrost replaces files by rename, never by
    writing over them - so this test pins the invariant the optimisation rests
    on.
    """
    root = tmp_path / "mods"
    root.mkdir()
    original = b"jar" * 500_000  # comfortably over the copy threshold
    (root / "big.jar").write_bytes(original)

    snapshot = tmp_path / "snap"
    localfs.snapshot(root, snapshot)

    replacement = tmp_path / "staged.jar"
    replacement.write_bytes(b"broken" * 500_000)
    localfs.place(replacement, root / "big.jar", 1_700_000_000, None, None)
    assert (root / "big.jar").read_bytes() != original

    localfs.restore(snapshot, root, None, None)
    assert (root / "big.jar").read_bytes() == original


def test_scan_skips_temporary_and_partial_files(tmp_path: Path) -> None:
    root = tmp_path / "mods"
    root.mkdir()
    (root / "real.jar").write_bytes(b"x")
    (root / ".bifrost-tmp-123-real.jar").write_bytes(b"x")
    (root / "half.jar.part").write_bytes(b"x")

    assert sorted(localfs.scan(root)) == ["real.jar"]


def test_scan_honours_an_exclude_callback(tmp_path: Path) -> None:
    root = tmp_path / "mods"
    root.mkdir()
    (root / "a.jar").write_bytes(b"x")
    (root / "b.txt").write_bytes(b"x")

    found = localfs.scan(root, lambda relative: relative.endswith(".txt"))
    assert sorted(found) == ["a.jar"]


def test_trash_keeps_the_bytes(tmp_path: Path) -> None:
    root = tmp_path / "mods"
    root.mkdir()
    victim = root / "old.jar"
    victim.write_bytes(b"still here")

    target = localfs.move_to_trash(victim, tmp_path / "trash", "old.jar", 1_700_000_000)

    assert not victim.exists()
    assert target.read_bytes() == b"still here"


def test_prune_trash_drops_expired_batches(tmp_path: Path) -> None:
    trash = tmp_path / "trash"
    old = trash / "1000000000"
    old.mkdir(parents=True)
    (old / "ancient.jar").write_bytes(b"x")

    localfs.prune_trash(trash, retention_days=1)
    assert not old.exists()


def test_sha256_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "f"
    path.write_bytes(b"some bytes")
    assert localfs.sha256_of(path) == hashlib.sha256(b"some bytes").hexdigest()
