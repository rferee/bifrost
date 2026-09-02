"""A fake Source RCON server, so behaviors can be tested without a JVM."""

from __future__ import annotations

import socketserver
import struct
import threading
from collections.abc import Callable

SERVERDATA_RESPONSE_VALUE = 0
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_AUTH = 3


def _pack(request_id: int, packet_type: int, body: str) -> bytes:
    payload = struct.pack("<ii", request_id, packet_type) + body.encode("utf-8") + b"\x00\x00"
    return struct.pack("<i", len(payload)) + payload


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: FakeRcon = self.server.owner  # type: ignore[attr-defined]
        if server.offline:
            # What a container that never came back looks like from the client
            # side: the connection is accepted and then dropped.
            self.request.close()
            return
        authenticated = False
        while True:
            header = self._read(4)
            if not header:
                return
            (length,) = struct.unpack("<i", header)
            payload = self._read(length)
            if not payload:
                return
            request_id, packet_type = struct.unpack("<ii", payload[:8])
            body = payload[8:-2].decode("utf-8", errors="replace")

            if packet_type == SERVERDATA_AUTH:
                ok = body == server.password
                authenticated = ok
                self.request.sendall(_pack(0, SERVERDATA_RESPONSE_VALUE, ""))
                self.request.sendall(
                    _pack(request_id if ok else -1, SERVERDATA_AUTH_RESPONSE, "")
                )
                if not ok:
                    return
            elif packet_type == SERVERDATA_EXECCOMMAND and authenticated:
                server.commands.append(body)
                self.request.sendall(_pack(request_id, SERVERDATA_RESPONSE_VALUE, server.respond(body)))
            else:
                # Anything else is echoed back, which is what terminates a
                # multi-packet read on the client side.
                self.request.sendall(
                    _pack(request_id, SERVERDATA_RESPONSE_VALUE, "Unknown request")
                )

    def _read(self, count: int) -> bytes:
        buffer = bytearray()
        while len(buffer) < count:
            chunk = self.request.recv(count - len(buffer))
            if not chunk:
                return b""
            buffer.extend(chunk)
        return bytes(buffer)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeRcon:
    def __init__(self, password: str = "secret", responder: Callable[[str], str] | None = None):
        self.password = password
        self.offline = False
        self.commands: list[str] = []
        self._responder = responder or (lambda command: f"ran {command}")
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.owner = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def respond(self, command: str) -> str:
        return self._responder(command)

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[0], self._server.server_address[1]

    def __enter__(self) -> FakeRcon:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
