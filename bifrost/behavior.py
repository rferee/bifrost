"""Driving the Minecraft server over RCON.

There is no Docker socket here and there never will be. `stop` over RCON exits
the JVM cleanly, and Docker's `unless-stopped` / `always` policy restarts the
container on any exit including a clean one. That gives a full restart with a
sidecar that holds no host privileges at all.

The catch, and the reason verification below is not optional: Docker only arms a
restart policy once a container has been up for about ten seconds. A mod that
kills the JVM inside that window leaves the stack down for good - so bifrost
confirms the server actually came back rather than assuming that dropping the
RCON connection meant success.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .rcon import RconAuthError, RconClient, RconError, discover_password, wait_until_alive

log = logging.getLogger(__name__)

_PLAYER_COUNT = re.compile(r"There are (\d+)")
_COUNTDOWN_MARKS = (300, 120, 60, 30, 10, 5)


@dataclass
class RestartResult:
    ok: bool
    detail: str


class NoRconConfigured(Exception):
    pass


class ServerController:
    def __init__(self, config: Config):
        self.config = config
        self._password: str | None = None
        # How long to let the container actually exit before probing for it.
        self.post_stop_delay: float = config.post_stop_delay

    def password(self) -> str:
        if self._password:
            return self._password
        if self.config.rcon_password:
            self._password = self.config.rcon_password
        else:
            found = discover_password(self.config.data_dir)
            if not found:
                raise NoRconConfigured(
                    "no RCON password. Set BIFROST_RCON_PASSWORD(_FILE), or pin RCON_PASSWORD on "
                    "the Minecraft service so bifrost can read it from /data/.rcon-cli.env."
                )
            log.info("using the RCON password itzg wrote to /data (pin RCON_PASSWORD to be safe)")
            self._password = found
        return self._password

    def connect(self) -> RconClient:
        if not self.config.rcon_host:
            raise NoRconConfigured("BIFROST_RCON is not set")
        client = RconClient(self.config.rcon_host, self.config.rcon_port, self.password())
        client.connect()
        return client

    def players_online(self, client: RconClient) -> int | None:
        """None means "could not tell", which callers must treat as "occupied"."""
        try:
            match = _PLAYER_COUNT.search(client.command("list"))
        except RconError:
            return None
        return int(match.group(1)) if match else None

    def run_commands(self, commands: tuple[str, ...] | list[str]) -> list[str]:
        results = []
        with self.connect() as client:
            for command in commands:
                log.info("rcon> %s", command)
                results.append(client.command(command))
        return results

    def restart(self, reason: str, stop_event: threading.Event) -> RestartResult:
        countdown = self.config.restart_countdown

        try:
            client = self.connect()
        except RconAuthError as exc:
            return RestartResult(False, str(exc))
        except (RconError, NoRconConfigured) as exc:
            return RestartResult(False, f"cannot reach the server to restart it: {exc}")

        try:
            players = self.players_online(client)
            if players == 0:
                log.info("nobody online; skipping the countdown")
                countdown = 0
            elif players is None:
                log.info("could not read the player list; assuming players are online")

            client.command("save-all flush")

            for remaining in self._countdown_steps(countdown):
                client.command(
                    f'say [bifrost] Restarting in {remaining}s to apply {reason}'
                )
                sleep_for = remaining - next(
                    (mark for mark in _COUNTDOWN_MARKS if mark < remaining), 0
                )
                if stop_event.wait(sleep_for):
                    log.warning("shutdown requested mid-countdown; aborting the restart")
                    return RestartResult(False, "interrupted")

            client.command("save-all flush")
            log.info("stopping the server (%s)", reason)
            client.command("stop")
        except RconError as exc:
            return RestartResult(False, f"RCON failed during the restart sequence: {exc}")
        finally:
            client.close()

        deadline = time.monotonic() + self.config.boot_timeout
        if stop_event.wait(self.post_stop_delay):
            return RestartResult(False, "interrupted")

        try:
            alive = wait_until_alive(
                self.config.rcon_host or "",
                self.config.rcon_port,
                self.password(),
                deadline,
            )
        except RconAuthError as exc:
            return RestartResult(False, str(exc))

        if alive:
            return RestartResult(True, "server is back up")

        return RestartResult(
            False,
            f"the server did not answer RCON within {self.config.boot_timeout}s. "
            "Either a synced file keeps it from starting, or the container's restart policy "
            "is not always/unless-stopped.",
        )

    @staticmethod
    def _countdown_steps(countdown: int) -> list[int]:
        if countdown <= 0:
            return []
        marks = [mark for mark in _COUNTDOWN_MARKS if mark < countdown]
        return [countdown, *marks]


def latest_log_tail(data_dir: Path, lines: int = 30) -> str:
    from . import localfs

    return localfs.tail(data_dir / "logs" / "latest.log", lines)
