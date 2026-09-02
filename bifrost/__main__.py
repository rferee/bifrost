"""bifrost entrypoint: poll, apply, react, verify."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import localfs
from .behavior import NoRconConfigured, ServerController, latest_log_tail
from .config import Config, ConfigError, Rule, load
from .engine import Engine, GuardTripped
from .rcon import RconAuthError, RconError
from .state import State
from .webdav import AuthError, NextcloudClient, QuotaExceeded, WebDAVError

log = logging.getLogger("bifrost")

BREAKER = "restart"
RESTART_PENDING = "restart_pending"

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_AUTH = 3


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _describe(config: Config) -> None:
    log.info("nextcloud %s as %s", config.nextcloud_url, config.nextcloud_user)
    log.info("data %s | state %s | poll every %ss", config.data_dir, config.state_dir, config.poll_interval)
    for rule in config.rules:
        log.info(
            "  %s  %s %s %s  delete=%s  behavior=%s",
            rule.name,
            config.remote_path(rule),
            "->" if rule.direction == "pull" else "<-",
            rule.local,
            rule.delete,
            rule.behavior if rule.behavior != "rcon" else f"rcon:{';'.join(rule.rcon_commands)}",
        )


def _self_test(client: NextcloudClient, config: Config) -> None:
    """Prove connectivity, TLS trust and credentials once, loudly, at startup."""
    used, available = client.quota()
    log.info("connected to Nextcloud (quota used=%s available=%s)", used, available)
    if available is not None and 0 <= available < 512 * 1024 * 1024:
        log.warning(
            "only %.1f MiB of Nextcloud quota left. Deletions go to the trash bin and every "
            "overwrite keeps a version, both of which count against it.",
            available / 1048576,
        )


def _rcon_self_test(config: Config) -> None:
    """Report up front whether the server can be driven at all.

    Otherwise the first sign of a wrong hostname is a deferred restart after
    files have already moved.
    """
    if not config.rcon_host or not any(rule.fires_behavior for rule in config.rules):
        return
    try:
        with ServerController(config).connect() as client:
            client.command("list")
        log.info("RCON reachable at %s:%s", config.rcon_host, config.rcon_port)
    except RconAuthError:
        raise
    except (RconError, NoRconConfigured) as exc:
        log.warning(
            "RCON is not reachable: %s. Files will still sync, but restarts will be deferred "
            "until it answers. Check that BIFROST_RCON names the Minecraft compose service and "
            "that both containers are in the same compose project.",
            exc,
        )


class Pending:
    """Work accumulated across a settle window, waiting for its behavior."""

    def __init__(self) -> None:
        self.restart = False
        self.rcon: list[tuple[str, ...]] = []
        self.files: list[str] = []
        self.rollbacks: dict[str, tuple[Rule, Path]] = {}
        self.hashes: dict[str, tuple[str, str]] = {}  # path -> (scope, sha256)
        self.since: float | None = None

    def __bool__(self) -> bool:
        return self.restart or bool(self.rcon)

    def clear(self) -> None:
        self.__init__()  # type: ignore[misc]


def _rollback(config: Config, engine: Engine, state: State, pending: Pending) -> None:
    log.error("rolling back %d change(s) applied since the last known-good boot", len(pending.files))

    for scope, (rule, snapshot_dir) in pending.rollbacks.items():
        removed = localfs.restore(snapshot_dir, rule.local, config.chown_uid, config.chown_gid)
        log.error("restored %s from snapshot (%d newly-added file(s) removed)", rule.local, len(removed))
        for path in removed:
            state.forget(scope, path)

    for path, (scope, digest) in pending.hashes.items():
        state.quarantine_add(
            digest, scope, path, "the server did not come back after this file was applied"
        )
        state.forget(scope, path)
        log.error("quarantined %s (sha256 %s)", path, digest[:12])

    engine.pending_snapshots.clear()


def _fire(
    config: Config,
    engine: Engine,
    state: State,
    controller: ServerController,
    pending: Pending,
    stop_event: threading.Event,
) -> bool:
    """Run the pending behaviors. Returns False if they should be retried."""
    for commands in pending.rcon:
        try:
            controller.run_commands(commands)
        except (RconError, NoRconConfigured) as exc:
            log.error("rcon behavior failed: %s", exc)
    pending.rcon.clear()

    if not pending.restart:
        engine.pending_snapshots.clear()
        state.clear_flag(RESTART_PENDING)
        return True

    reason = f"{len(pending.files)} file change(s)"
    log.info("restarting the server: %s", reason)
    result = controller.restart(reason, stop_event)

    if result.ok:
        log.info("restart complete: %s", result.detail)
        engine.pending_snapshots.clear()
        state.clear_flag(RESTART_PENDING)
        return True

    if stop_event.is_set():
        return False

    if not result.stopped:
        # The server was never stopped, so nothing that was applied is
        # implicated. Rolling back here would undo good files and quarantine
        # them over what is usually a DNS or networking problem.
        log.error(
            "could not restart the server: %s. Synced files are left in place and the "
            "restart is deferred to the next pass. Nothing was rolled back.",
            result.detail,
        )
        return False

    log.error("restart failed: %s", result.detail)
    tail = latest_log_tail(config.data_dir)
    if tail:
        log.error("last lines of logs/latest.log:\n%s", tail)

    state.clear_flag(RESTART_PENDING)

    if not pending.rollbacks:
        state.trip_breaker(BREAKER, result.detail)
        log.error("nothing to roll back. Breaker tripped; set BIFROST_RESET_BREAKER=1 to resume.")
        return True

    _rollback(config, engine, state, pending)

    log.error("restarting once more on the rolled-back files")
    retry = controller.restart("rollback", stop_event)
    if retry.ok:
        log.error(
            "server recovered after rollback. The offending file(s) stay quarantined and will "
            "not be applied again until they change in Nextcloud."
        )
        return True

    state.trip_breaker(BREAKER, f"{result.detail} (rollback also failed: {retry.detail})")
    log.error(
        "server is still down after the rollback. Breaker tripped - bifrost will not touch it "
        "again. Fix it by hand, then restart bifrost with BIFROST_RESET_BREAKER=1."
    )
    return True


def _run_pass(config: Config, engine: Engine, pending: Pending) -> bool:
    """One sweep over every rule. Returns True if anything under /data changed."""
    changed_local = False
    engine.new_pass()

    for rule in config.rules:
        try:
            outcome = engine.run(rule)
        except GuardTripped as exc:
            log.error("GUARD %s", exc)
            continue
        except QuotaExceeded as exc:
            log.error("%s: %s", rule.name, exc)
            continue
        except WebDAVError as exc:
            log.error("%s: %s", rule.name, exc)
            continue

        if not outcome.any_change:
            continue

        log.info("%s: %s", rule.name, outcome.summary())

        if outcome.local_changed:
            changed_local = True
            pending.files.extend(outcome.downloaded + outcome.deleted)
            for path, digest in outcome.applied_hashes.items():
                pending.hashes[path] = (rule.scope, digest)
            if outcome.snapshot_dir is not None:
                pending.rollbacks.setdefault(rule.scope, (rule, outcome.snapshot_dir))

        if rule.fires_behavior:
            pending.since = pending.since or time.monotonic()
            if rule.behavior == "restart":
                pending.restart = True
                engine.state.set_flag(RESTART_PENDING, rule.name)
            elif rule.rcon_commands and rule.rcon_commands not in pending.rcon:
                pending.rcon.append(rule.rcon_commands)

    return changed_local


def _restore_pending(state: State, pending: Pending) -> None:
    """Pick up a restart that a previous process could not deliver."""
    if state.get_flag(RESTART_PENDING):
        log.info("a restart was still owed from a previous run; it will be delivered now")
        pending.restart = True


def run(config: Config, client: NextcloudClient, state: State, stop_event: threading.Event) -> int:
    engine = Engine(config, client, state)
    controller = ServerController(config)
    pending = Pending()
    _restore_pending(state, pending)

    while not stop_event.is_set():
        blocked = state.breaker_reason(BREAKER)
        if blocked:
            log.error(
                "breaker is open (%s). bifrost is doing nothing until you restart it with "
                "BIFROST_RESET_BREAKER=1.",
                blocked,
            )
            stop_event.wait(config.poll_interval)
            continue

        try:
            changed = _run_pass(config, engine, pending)
        except AuthError as exc:
            log.error("%s", exc)
            return EXIT_AUTH

        try:
            (config.state_dir / "heartbeat").write_text(str(int(time.time())), encoding="utf-8")
        except OSError as exc:
            log.debug("could not write heartbeat: %s", exc)

        if changed and pending.since is not None:
            waited = time.monotonic() - pending.since
            if waited < config.settle_max:
                log.info("applied changes; waiting %ss in case more are coming", config.settle)
                stop_event.wait(config.settle)
                continue
            log.info("settle window capped at %ss; acting now", config.settle_max)

        if pending and _fire(config, engine, state, controller, pending, stop_event):
            pending.clear()

        stop_event.wait(config.poll_interval)

    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    try:
        config = load()
    except ConfigError as exc:
        _configure_logging("INFO")
        log.error("configuration error: %s", exc)
        return EXIT_CONFIG

    _configure_logging(config.log_level)
    _describe(config)

    config.state_dir.mkdir(parents=True, exist_ok=True)
    state = State(config.state_dir / "state.db")

    if os.environ.get("BIFROST_RESET_BREAKER", "").lower() in ("1", "true", "yes"):
        if state.breaker_reason(BREAKER):
            log.warning("clearing the open breaker on request")
        state.reset_breaker(BREAKER)
    if os.environ.get("BIFROST_CLEAR_QUARANTINE", "").lower() in ("1", "true", "yes"):
        log.warning("clearing %d quarantined file hash(es) on request", state.quarantine_clear())

    client = NextcloudClient(
        config.nextcloud_url,
        config.nextcloud_user,
        config.nextcloud_password,
        timeout=config.http_timeout,
        verify=config.verify_tls,
    )

    try:
        _self_test(client, config)
    except AuthError as exc:
        log.error("%s", exc)
        return EXIT_AUTH
    except WebDAVError as exc:
        log.error("cannot reach Nextcloud: %s", exc)
        return EXIT_AUTH

    stop_event = threading.Event()

    def _shutdown(signum: int, _frame: object) -> None:
        log.info("signal %s received; finishing up", signum)
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown)

    try:
        _rcon_self_test(config)

        if "--once" in argv:
            blocked = state.breaker_reason(BREAKER)
            if blocked:
                log.error(
                    "breaker is open (%s); refusing to run. Clear it with "
                    "BIFROST_RESET_BREAKER=1 once the server is healthy.",
                    blocked,
                )
                return EXIT_OK
            engine = Engine(config, client, state)
            pending = Pending()
            _restore_pending(state, pending)
            _run_pass(config, engine, pending)
            if pending:
                _fire(config, engine, state, ServerController(config), pending, stop_event)
            return EXIT_OK

        return run(config, client, state, stop_event)
    except RconAuthError as exc:
        log.error("%s", exc)
        return EXIT_AUTH
    finally:
        state.close()


if __name__ == "__main__":
    raise SystemExit(main())
