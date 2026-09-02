"""An in-process WebDAV server backed by a temp directory.

Enough of the Nextcloud dialect to exercise the real client: Basic auth,
PROPFIND Depth 0/1 (and the Depth: infinity downgrade, so the recursive walk is
actually tested), ETags that change with content, X-OC-Mtime on PUT, MKCOL,
DELETE and quota properties.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse
from xml.sax.saxutils import escape


def _etag(path: Path) -> str:
    stat = path.stat()
    if path.is_dir():
        digest = hashlib.sha1(str(sorted(p.name for p in path.iterdir())).encode())
    else:
        digest = hashlib.sha1(path.read_bytes())
    digest.update(str(int(stat.st_mtime)).encode())
    return digest.hexdigest()[:24]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # noqa: D102
        pass

    # -- helpers ------------------------------------------------------------

    @property
    def _root(self) -> Path:
        return self.server.root  # type: ignore[attr-defined]

    @property
    def _prefix(self) -> str:
        return f"/remote.php/dav/files/{self.server.user}"  # type: ignore[attr-defined]

    def _authorized(self) -> bool:
        credentials = f"{self.server.user}:{self.server.password}"  # type: ignore[attr-defined]
        expected = "Basic " + base64.b64encode(credentials.encode()).decode()
        return self.headers.get("Authorization") == expected

    def _target(self) -> Path | None:
        path = unquote(urlparse(self.path).path)
        if not path.startswith(self._prefix):
            return None
        relative = path[len(self._prefix) :].strip("/")
        target = self._root / relative if relative else self._root
        try:
            target.resolve().relative_to(self._root.resolve())
        except ValueError:
            return None
        return target

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _respond(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _guard(self) -> Path | None:
        if not self._authorized():
            self._respond(401, b"unauthorized")
            return None
        target = self._target()
        if target is None:
            self._respond(400, b"bad path")
            return None
        return target

    def _href(self, path: Path) -> str:
        relative = path.relative_to(self._root).as_posix()
        suffix = f"/{quote(relative)}" if relative != "." else ""
        trailing = "/" if path.is_dir() else ""
        return f"{self._prefix}{suffix}{trailing}"

    def _propstat(self, path: Path) -> str:
        stat = path.stat()
        if path.is_dir():
            typ = "<d:resourcetype><d:collection/></d:resourcetype>"
            size = ""
        else:
            typ = "<d:resourcetype/>"
            size = f"<d:getcontentlength>{stat.st_size}</d:getcontentlength>"
        return (
            f"<d:response><d:href>{escape(self._href(path))}</d:href><d:propstat>"
            f"<d:prop>{typ}"
            f'<d:getetag>"{_etag(path)}"</d:getetag>'
            f"<d:getlastmodified>{formatdate(stat.st_mtime, usegmt=True)}</d:getlastmodified>"
            f"{size}</d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )

    # -- verbs --------------------------------------------------------------

    def do_PROPFIND(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        body = self._body()
        if not target.exists():
            self._respond(404, b"not found")
            return

        if b"quota-available-bytes" in body:
            payload = (
                '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
                f"<d:href>{self._prefix}/</d:href><d:propstat><d:prop>"
                "<d:quota-used-bytes>1024</d:quota-used-bytes>"
                "<d:quota-available-bytes>10737418240</d:quota-available-bytes>"
                "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
                "</d:response></d:multistatus>"
            ).encode()
            self._respond(207, payload, {"Content-Type": "application/xml; charset=utf-8"})
            return

        # Nextcloud silently downgrades Depth: infinity to 1. Doing the same
        # here is what makes the recursive walk worth testing.
        depth = self.headers.get("Depth", "1")
        responses = [self._propstat(target)]
        if depth != "0" and target.is_dir():
            for child in sorted(target.iterdir()):
                responses.append(self._propstat(child))

        payload = (
            '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">' + "".join(responses) + "</d:multistatus>"
        ).encode()
        self._respond(207, payload, {"Content-Type": "application/xml; charset=utf-8"})

    def do_GET(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        if not target.is_file():
            self._respond(404, b"not found")
            return
        self._respond(200, target.read_bytes(), {"Content-Type": "application/octet-stream"})

    def do_PUT(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        data = self._body()
        if not target.parent.is_dir():
            self._respond(409, b"conflict")
            return
        existed = target.exists()
        target.write_bytes(data)

        headers = {"ETag": f'"{_etag(target)}"'}
        mtime = self.headers.get("X-OC-Mtime")
        if mtime:
            import os

            os.utime(target, (int(mtime), int(mtime)))
            headers["X-OC-MTime"] = "accepted"
            headers["ETag"] = f'"{_etag(target)}"'
        self._respond(204 if existed else 201, b"", headers)

    def do_MKCOL(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        if target.exists():
            self._respond(405, b"exists")
            return
        if not target.parent.is_dir():
            self._respond(409, b"conflict")
            return
        target.mkdir()
        self._respond(201)

    def do_DELETE(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        if not target.exists():
            self._respond(404, b"not found")
            return
        if target.is_dir():
            import shutil

            shutil.rmtree(target)
        else:
            target.unlink()
        self._respond(204)

    def do_PROPPATCH(self) -> None:  # noqa: N802
        target = self._guard()
        if target is None:
            return
        payload = (
            '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
            f"<d:href>{escape(self._href(target))}</d:href>"
            "<d:propstat><d:prop><d:lastmodified/></d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
            "</d:response></d:multistatus>"
        ).encode()
        self._respond(207, payload, {"Content-Type": "application/xml; charset=utf-8"})


class FakeNextcloud:
    def __init__(self, root: Path, user: str = "bifrost", password: str = "app-password"):
        self.root = root
        self.user = user
        self.password = password
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.root = root  # type: ignore[attr-defined]
        self._server.user = user  # type: ignore[attr-defined]
        self._server.password = password  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> FakeNextcloud:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
