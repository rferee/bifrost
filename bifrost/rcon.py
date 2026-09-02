"""Minimal Source RCON client.

The protocol is small enough that a dependency would cost more than it saves:
little-endian length-prefixed packets, authenticate then issue commands.

Multi-packet responses are handled with the standard sentinel trick - after the
command, send a junk packet with a different request id and read until it comes
back. Minecraft answers unknown packet types with "Unknown request", which is
what marks the end of the real response.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from pathlib import Path

log = logging.getLogger(__name__)

SERVERDATA_RESPONSE_VALUE = 0
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_AUTH = 3

_MAX_PACKET = 4096 + 16


class RconError(Exception):
    pass


class RconAuthError(RconError):
    """Wrong password. Never retry this on a timer."""


class RconClient:
    def __init__(self, host: str, port: int, password: str, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._next_id = 1

    def __enter__(self) -> RconClient:
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def connect(self) -> None:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise RconError(f"cannot reach RCON at {self.host}:{self.port}: {exc}") from exc
        self._sock.settimeout(self.timeout)

        request_id = self._send(SERVERDATA_AUTH, self.password)
        # Some servers emit an empty RESPONSE_VALUE before the auth result.
        for _ in range(2):
            packet_id, packet_type, _ = self._recv_packet()
            if packet_type == SERVERDATA_AUTH_RESPONSE:
                if packet_id == -1:
                    raise RconAuthError("RCON authentication failed (wrong password)")
                if packet_id != request_id:
                    raise RconError("RCON authentication returned a mismatched request id")
                return
        raise RconError("RCON server never answered the authentication packet")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def command(self, command: str) -> str:
        if self._sock is None:
            raise RconError("not connected")
        request_id = self._send(SERVERDATA_EXECCOMMAND, command)
        sentinel_id = self._send(SERVERDATA_RESPONSE_VALUE, "")

        chunks: list[str] = []
        while True:
            try:
                packet_id, _, body = self._recv_packet()
            except TimeoutError:
                # Server never echoed the sentinel; return whatever arrived.
                break
            if packet_id == sentinel_id:
                break
            if packet_id == request_id:
                chunks.append(body)
        return "".join(chunks)

    # -- wire ---------------------------------------------------------------

    def _send(self, packet_type: int, body: str) -> int:
        assert self._sock is not None
        request_id = self._next_id
        self._next_id += 1
        payload = struct.pack("<ii", request_id, packet_type) + body.encode("utf-8") + b"\x00\x00"
        try:
            self._sock.sendall(struct.pack("<i", len(payload)) + payload)
        except OSError as exc:
            raise RconError(f"RCON send failed: {exc}") from exc
        return request_id

    def _recv_exactly(self, count: int) -> bytes:
        assert self._sock is not None
        buffer = bytearray()
        while len(buffer) < count:
            try:
                chunk = self._sock.recv(count - len(buffer))
            except TimeoutError:
                raise
            except OSError as exc:
                # A reset mid-read is the normal shape of "the container went
                # away", so it has to arrive as RconError like every other
                # unreachable-server case.
                raise RconError(f"RCON connection lost: {exc}") from exc
            if not chunk:
                raise RconError("RCON connection closed by the server")
            buffer.extend(chunk)
        return bytes(buffer)

    def _recv_packet(self) -> tuple[int, int, str]:
        raw_length = self._recv_exactly(4)
        (length,) = struct.unpack("<i", raw_length)
        if not 10 <= length <= _MAX_PACKET:
            raise RconError(f"RCON packet length {length} out of range")
        payload = self._recv_exactly(length)
        packet_id, packet_type = struct.unpack("<ii", payload[:8])
        body = payload[8:-2].decode("utf-8", errors="replace")
        return packet_id, packet_type, body


def discover_password(data_dir: Path) -> str | None:
    """Read the RCON password itzg/minecraft-server left in /data.

    The image regenerates a random password on every container start unless
    RCON_PASSWORD is pinned, and writes the live value into these files. Pinning
    it in compose is still the better answer - this is the fallback so bifrost
    works with an unmodified server.
    """
    env_file = data_dir / ".rcon-cli.env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("RCON_PASSWORD", "password"):
                return value.strip().strip("'\"") or None

    yaml_file = data_dir / ".rcon-cli.yaml"
    if yaml_file.is_file():
        for line in yaml_file.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "password":
                return value.strip().strip("'\"") or None

    properties = data_dir / "server.properties"
    if properties.is_file():
        for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "rcon.password":
                return value.strip() or None

    return None


def wait_until_alive(
    host: str, port: int, password: str, deadline: float, probe_interval: float = 5.0
) -> bool:
    """Poll RCON until the server answers `list`, or the deadline passes."""
    last_error: str = "never attempted"
    while time.monotonic() < deadline:
        try:
            with RconClient(host, port, password, timeout=5.0) as client:
                client.command("list")
                return True
        except RconAuthError:
            raise
        except RconError as exc:
            last_error = str(exc)
        time.sleep(probe_interval)
    log.debug("server did not answer RCON before the deadline: %s", last_error)
    return False
