"""Planning and application for one rule.

The order of operations is the safety property. Everything is listed, planned
and downloaded before a single byte of /data changes, so a failure anywhere in
the network phase leaves the server untouched.
"""

from __future__ import annotations

import logging
import math
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import localfs
from .config import SENTINEL, Config, Rule
from .state import State
from .webdav import NextcloudClient, NotFound, RemoteEntry

log = logging.getLogger(__name__)


class GuardTripped(Exception):
    """A safety guard refused the whole pass. Nothing was changed."""


@dataclass
class Outcome:
    rule: Rule
    downloaded: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    uploaded: list[str] = field(default_factory=list)
    remote_deleted: list[str] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)
    snapshot_dir: Path | None = None
    applied_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def local_changed(self) -> bool:
        return bool(self.downloaded or self.deleted)

    @property
    def any_change(self) -> bool:
        return bool(self.downloaded or self.deleted or self.uploaded or self.remote_deleted)

    def summary(self) -> str:
        parts = []
        if self.downloaded:
            parts.append(f"{len(self.downloaded)} down")
        if self.deleted:
            parts.append(f"{len(self.deleted)} removed")
        if self.uploaded:
            parts.append(f"{len(self.uploaded)} up")
        if self.remote_deleted:
            parts.append(f"{len(self.remote_deleted)} removed remotely")
        if self.quarantined:
            parts.append(f"{len(self.quarantined)} quarantined")
        return ", ".join(parts) or "no changes"


class Engine:
    def __init__(self, config: Config, client: NextcloudClient, state: State):
        self.config = config
        self.client = client
        self.state = state
        self._listing_cache: dict[str, dict[str, RemoteEntry]] = {}
        # Scopes whose snapshot represents a known-good server. Held across the
        # settle window so that several passes coalescing into one restart roll
        # back to the state before the *first* of them, not the last.
        self.pending_snapshots: set[str] = set()

    # -- paths --------------------------------------------------------------

    def stage_dir(self, rule: Rule) -> Path:
        return self.config.state_dir / "stage" / rule.scope

    def snapshot_dir(self, rule: Rule) -> Path:
        return self.config.state_dir / "snapshots" / rule.scope

    def trash_dir(self, rule: Rule) -> Path:
        return self.config.state_dir / "trash" / rule.scope

    def new_pass(self) -> None:
        self._listing_cache.clear()

    # -- remote helpers -----------------------------------------------------

    def _listing(self, remote_path: str) -> dict[str, RemoteEntry]:
        cached = self._listing_cache.get(remote_path)
        if cached is None:
            cached = self.client.walk(remote_path, workers=self.config.workers)
            self._listing_cache[remote_path] = cached
        return cached

    def _require_sentinel(self, rule: Rule, listing: dict[str, RemoteEntry], create: bool) -> None:
        """The sentinel is what distinguishes an empty folder from a broken one.

        A revoked share, a renamed folder, a maintenance-mode 503 and a typo all
        produce a listing that reads as "the user deleted everything". A file
        that must be present says otherwise.
        """
        if SENTINEL in listing:
            return
        remote_path = self.config.remote_path(rule)
        if create:
            log.info("creating sentinel %s/%s", remote_path, SENTINEL)
            self.client.put_text(
                f"{remote_path}/{SENTINEL}",
                "This file marks a folder as managed by bifrost. Do not delete it:\n"
                "bifrost refuses to mirror deletions from a folder that has lost its sentinel.\n",
                int(time.time()),
            )
            listing[SENTINEL] = RemoteEntry(SENTINEL, False, None, 0, int(time.time()))
            return
        raise GuardTripped(
            f"{rule.name}: {remote_path}/{SENTINEL} is missing. Either the remote folder is not "
            "the one you meant, or something removed it. Refusing to sync. "
            "Set BIFROST_INIT_REMOTE=1 for the first run to create it."
        )

    def ensure_remote_folder(self, rule: Rule) -> None:
        remote_path = self.config.remote_path(rule)
        if not self.client.exists(remote_path):
            log.info("creating remote folder %s", remote_path)
            self.client.mkcol_p(remote_path)

    # -- guards -------------------------------------------------------------

    def _check_deletions(self, rule: Rule, deletions: list[str], population: int, where: str) -> None:
        if not deletions:
            return
        allowance = max(self.config.max_delete, math.ceil(population * self.config.max_delete_pct / 100))
        if len(deletions) > allowance:
            raise GuardTripped(
                f"{rule.name}: refusing to delete {len(deletions)} of {population} files {where} "
                f"(limit is {allowance}: max({self.config.max_delete}, "
                f"{self.config.max_delete_pct}%)). Nothing was changed. If this is intentional, "
                "raise BIFROST_MAX_DELETE / BIFROST_MAX_DELETE_PCT for one pass."
            )

    # -- pull ---------------------------------------------------------------

    def run_pull(self, rule: Rule) -> Outcome:
        outcome = Outcome(rule=rule)
        remote_path = self.config.remote_path(rule)

        try:
            listing = self._listing(remote_path)
        except NotFound:
            if self.config.init_remote:
                self.ensure_remote_folder(rule)
                listing = {}
                self._listing_cache[remote_path] = listing
            else:
                raise GuardTripped(
                    f"{rule.name}: remote folder {remote_path} does not exist. Create it in "
                    "Nextcloud, or set BIFROST_INIT_REMOTE=1 to have bifrost create it."
                ) from None

        self._require_sentinel(rule, listing, create=self.config.init_remote)

        remote_files = {
            path: entry
            for path, entry in listing.items()
            if not entry.is_dir and not rule.excluded(path)
        }
        local = localfs.scan(rule.local, rule.excluded)
        rows = self.state.entries(rule.scope)

        # This guard exists to stop a broken listing from being read as a mass
        # deletion, so it only applies when deletions are actually possible.
        # It also needs prior state: on a first run an empty remote folder
        # beside a full /data is the seeding case, not a deletion.
        if rule.delete == "mirror" and not remote_files and local and rows:
            raise GuardTripped(
                f"{rule.name}: {remote_path} lists zero files while {rule.local} holds "
                f"{len(local)}. That is what a maintenance-mode error page, a revoked share or a "
                "wrong path looks like. Refusing to sync."
            )

        # Re-download when the remote changed, or when a file bifrost owns has
        # gone missing locally. Deliberately not when a *quarantined* row is
        # missing locally (pulled=0): that file was rolled back on purpose and
        # must not come straight back.
        downloads = [
            entry
            for path, entry in sorted(remote_files.items())
            if (row := rows.get(path)) is None
            or row.etag != entry.etag
            or (row.pulled and path not in local)
        ]

        deletions: list[str] = []
        if rule.delete == "mirror":
            deletions = sorted(
                path
                for path, row in rows.items()
                if row.pulled and path not in remote_files and path in local
            )
            self._check_deletions(rule, deletions, len(local), f"from {rule.local}")

        if not downloads and not deletions:
            return outcome

        log.info(
            "%s: %d to download, %d to remove (%d remote / %d local)",
            rule.name,
            len(downloads),
            len(deletions),
            len(remote_files),
            len(local),
        )
        if self.config.dry_run:
            outcome.downloaded = [entry.path for entry in downloads]
            outcome.deleted = deletions
            log.info("%s: dry run, nothing applied", rule.name)
            return outcome

        # --- network phase: nothing under /data is touched yet -------------
        stage = self.stage_dir(rule)
        staged = self._stage_downloads(rule, downloads, stage)

        quarantined_hashes = self.state.quarantined()
        applicable: list[tuple[RemoteEntry, Path, str]] = []
        for entry, path in staged:
            digest = localfs.sha256_of(path)
            if digest in quarantined_hashes:
                log.warning(
                    "%s: %s is quarantined (a previous version of this exact file kept the "
                    "server from starting); not applying it",
                    rule.name,
                    entry.path,
                )
                path.unlink(missing_ok=True)
                outcome.quarantined.append(entry.path)
                # Remember the etag so it is not re-downloaded every pass, but
                # leave pulled=0 so it is not treated as ours.
                self.state.record(
                    rule.scope,
                    entry.path,
                    etag=entry.etag,
                    remote_mtime=entry.mtime,
                    remote_size=entry.size,
                    local_mtime=None,
                    local_size=None,
                    sha256=digest,
                    pulled=False,
                )
                continue
            applicable.append((entry, path, digest))

        if not applicable and not deletions:
            return outcome

        # --- apply phase ---------------------------------------------------
        snapshot = self.snapshot_dir(rule)
        if rule.fires_behavior:
            if rule.scope not in self.pending_snapshots:
                localfs.snapshot(rule.local, snapshot)
                self.pending_snapshots.add(rule.scope)
            outcome.snapshot_dir = snapshot

        stamp = int(time.time())
        for entry, path, digest in applicable:
            destination = rule.local / entry.path
            localfs.place(
                path, destination, entry.mtime, self.config.chown_uid, self.config.chown_gid
            )
            stat = destination.stat()
            self.state.record(
                rule.scope,
                entry.path,
                etag=entry.etag,
                remote_mtime=entry.mtime,
                remote_size=entry.size,
                local_mtime=int(stat.st_mtime),
                local_size=stat.st_size,
                sha256=digest,
                pulled=True,
            )
            outcome.downloaded.append(entry.path)
            outcome.applied_hashes[entry.path] = digest

        trash = self.trash_dir(rule)
        for path in deletions:
            victim = rule.local / path
            if victim.exists():
                target = localfs.move_to_trash(victim, trash, path, stamp)
                log.info("%s: removed %s (kept at %s)", rule.name, path, target)
            self.state.forget(rule.scope, path)
            outcome.deleted.append(path)

        localfs.prune_trash(trash, self.config.trash_retention_days)
        return outcome

    def _stage_downloads(
        self, rule: Rule, downloads: list[RemoteEntry], stage: Path
    ) -> list[tuple[RemoteEntry, Path]]:
        remote_path = self.config.remote_path(rule)
        stage.mkdir(parents=True, exist_ok=True)

        def fetch(entry: RemoteEntry) -> tuple[RemoteEntry, Path]:
            target = stage / entry.path
            self.client.download(f"{remote_path}/{entry.path}", target, entry.size)
            return entry, target

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            return list(pool.map(fetch, downloads))

    # -- push ---------------------------------------------------------------

    def run_push(self, rule: Rule) -> Outcome:
        outcome = Outcome(rule=rule)
        remote_path = self.config.remote_path(rule)

        self.ensure_remote_folder(rule)
        try:
            listing = self._listing(remote_path)
        except NotFound:
            listing = {}
        self._require_sentinel(rule, listing, create=True)

        remote_files = {
            path: entry
            for path, entry in listing.items()
            if not entry.is_dir and not rule.excluded(path)
        }
        local = localfs.scan(rule.local, rule.excluded)
        rows = self.state.entries(rule.scope)

        candidates: list[localfs.LocalEntry] = []
        for path, entry in sorted(local.items()):
            row = rows.get(path)
            if path not in remote_files:
                candidates.append(entry)
            elif row is None:
                candidates.append(entry)
            elif row.local_size != entry.size or row.local_mtime != entry.mtime:
                candidates.append(entry)

        # Only hash the files that look changed, and only upload the ones whose
        # content really differs - a touched file is not a new file.
        digests = localfs.sha256_many([entry.real for entry in candidates], self.config.workers)
        uploads = [
            (entry, digests[entry.real])
            for entry in candidates
            if (row := rows.get(entry.path)) is None
            or row.sha256 != digests[entry.real]
            or entry.path not in remote_files
        ]

        deletions: list[str] = []
        if rule.delete == "mirror":
            deletions = sorted(
                path for path in remote_files if path not in local and path in rows
            )
            self._check_deletions(rule, deletions, len(remote_files), f"from {remote_path}")

        if not uploads and not deletions:
            # Nothing to send, but remember the fresh (size, mtime, hash) so the
            # next pass does not hash these files all over again.
            for entry in candidates:
                row = rows.get(entry.path)
                remote = remote_files.get(entry.path)
                self.state.record(
                    rule.scope,
                    entry.path,
                    etag=(row.etag if row else None) or (remote.etag if remote else None),
                    remote_mtime=row.remote_mtime if row else None,
                    remote_size=row.remote_size if row else None,
                    local_mtime=entry.mtime,
                    local_size=entry.size,
                    sha256=digests[entry.real],
                    pulled=True,
                )
            return outcome

        log.info("%s: %d to upload, %d to remove remotely", rule.name, len(uploads), len(deletions))
        if self.config.dry_run:
            outcome.uploaded = [entry.path for entry, _ in uploads]
            outcome.remote_deleted = deletions
            log.info("%s: dry run, nothing applied", rule.name)
            return outcome

        for directory in sorted({str(Path(entry.path).parent) for entry, _ in uploads}):
            if directory not in (".", ""):
                self.client.mkcol_p(f"{remote_path}/{directory}")

        def send(item: tuple[localfs.LocalEntry, str]) -> tuple[localfs.LocalEntry, str, str | None]:
            entry, digest = item
            etag = self.client.upload(entry.real, f"{remote_path}/{entry.path}", entry.mtime)
            return entry, digest, etag

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            for entry, digest, etag in pool.map(send, uploads):
                # A file bifrost uploaded is under its management for this
                # scope just as much as one it downloaded: if it later vanishes
                # from Nextcloud, that is a deletion worth mirroring.
                self.state.record(
                    rule.scope,
                    entry.path,
                    etag=etag,
                    remote_mtime=entry.mtime,
                    remote_size=entry.size,
                    local_mtime=entry.mtime,
                    local_size=entry.size,
                    sha256=digest,
                    pulled=True,
                )
                outcome.uploaded.append(entry.path)

        for path in deletions:
            self.client.delete(f"{remote_path}/{path}")
            self.state.forget(rule.scope, path)
            outcome.remote_deleted.append(path)
            log.info("%s: removed %s from Nextcloud (recoverable from its trash bin)", rule.name, path)

        return outcome

    def run(self, rule: Rule) -> Outcome:
        return self.run_pull(rule) if rule.direction == "pull" else self.run_push(rule)
