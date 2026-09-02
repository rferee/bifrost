"""Nextcloud WebDAV client.

Only the parts a sync client actually needs, but the Nextcloud dialect matters
more than the WebDAV spec here:

* `PROPFIND Depth: infinity` is silently downgraded to Depth: 1 by Sabre. You
  get a 207 with truncated results and no error, which a differ reads as
  "everything nested was deleted". So the tree is walked one level at a time.
* `oc:checksums` is client-supplied and unvalidated, and a PUT without the
  OC-Checksum header erases it. It is useless for change detection; the ETag is
  the remote change token and bifrost hashes content itself.
* Uploads must send `X-OC-Mtime`. Without it the remote mtime becomes the upload
  time, every uploaded file looks permanently newer than its local twin, and the
  two sides ping-pong forever.
* `getlastmodified` is RFC1123 at one-second resolution against ext4's
  nanoseconds, so mtimes are compared as whole seconds.
"""

from __future__ import annotations

import logging
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.utils import formatdate, parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import requests

log = logging.getLogger(__name__)

DAV = "{DAV:}"

_PROPFIND_BODY = b"""<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:resourcetype/>
    <d:getetag/>
    <d:getlastmodified/>
    <d:getcontentlength/>
  </d:prop>
</d:propfind>
"""

_QUOTA_BODY = b"""<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:quota-available-bytes/>
    <d:quota-used-bytes/>
  </d:prop>
</d:propfind>
"""


class WebDAVError(Exception):
    pass


class AuthError(WebDAVError):
    """Bad credentials.

    Always fatal, never retried on a timer: about ten failed authentications in
    thirty minutes trips Nextcloud's brute-force protection with a 429 that can
    persist for hours, from an IP the rest of the host shares.
    """


class NotFound(WebDAVError):
    pass


class QuotaExceeded(WebDAVError):
    pass


@dataclass(frozen=True)
class RemoteEntry:
    path: str  # relative to the PROPFIND root
    is_dir: bool
    etag: str | None
    size: int
    mtime: int


def _normalize(path: str) -> str:
    out = "/" + "/".join(part for part in path.split("/") if part)
    return out


def _parse_mtime(raw: str | None) -> int:
    if not raw:
        return 0
    try:
        return int(parsedate_to_datetime(raw).timestamp())
    except (TypeError, ValueError):
        return 0


class NextcloudClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        timeout: int = 120,
        verify: bool | str = True,
    ):
        self.base = f"{base_url.rstrip('/')}/remote.php/dav/files/{quote(username)}"
        self._auth = (username, password)
        self._timeout = timeout
        self._verify = verify
        self._local = threading.local()

    # -- plumbing -----------------------------------------------------------

    @property
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.auth = self._auth
            session.headers["User-Agent"] = "bifrost/0.1"
            self._local.session = session
        return session

    def _url(self, path: str) -> str:
        clean = "/".join(part for part in path.split("/") if part)
        return f"{self.base}/{quote(clean)}" if clean else self.base

    def _request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("verify", self._verify)
        try:
            response = self._session.request(method, url, **kwargs)  # type: ignore[arg-type]
        except requests.RequestException as exc:
            raise WebDAVError(f"{method} {url} failed: {exc}") from exc
        if response.status_code in (401, 403):
            raise AuthError(
                f"Nextcloud rejected the credentials ({response.status_code}). "
                "Check BIFROST_NEXTCLOUD_USER and the app password. "
                "bifrost will not retry - repeated failures trip brute-force protection."
            )
        if response.status_code == 429:
            raise AuthError(
                "Nextcloud returned 429 (brute-force throttle). This host's IP is rate-limited; "
                "fix the credentials and wait it out."
            )
        if response.status_code == 507:
            raise QuotaExceeded("Nextcloud is out of quota (507)")
        if response.status_code == 413:
            raise WebDAVError(
                "Nextcloud returned 413 (payload too large). The reverse proxy in front of it "
                "is capping upload size - raise client_max_body_size."
            )
        return response

    @staticmethod
    def _relative(root_path: str, href: str) -> str | None:
        target = _normalize(unquote(urlparse(href).path))
        root = _normalize(root_path)
        if target == root:
            return ""
        if not target.startswith(root.rstrip("/") + "/"):
            return None
        return target[len(root.rstrip("/")) + 1 :]

    # -- reads --------------------------------------------------------------

    def propfind(self, path: str, depth: int = 1) -> list[RemoteEntry]:
        url = self._url(path)
        response = self._request(
            "PROPFIND",
            url,
            headers={"Depth": str(depth), "Content-Type": "application/xml; charset=utf-8"},
            data=_PROPFIND_BODY,
        )
        if response.status_code == 404:
            raise NotFound(path)
        if response.status_code != 207:
            raise WebDAVError(f"PROPFIND {path} returned {response.status_code}")

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            # Maintenance mode and proxy errors return HTML. Parsing that as an
            # empty collection would look exactly like "the user deleted
            # everything", so it has to be an error.
            raise WebDAVError(
                f"PROPFIND {path} returned a non-XML body ({len(response.content)} bytes); "
                "Nextcloud may be in maintenance mode"
            ) from exc

        base_path = urlparse(url).path
        entries: list[RemoteEntry] = []
        for node in root.findall(f"{DAV}response"):
            href = node.findtext(f"{DAV}href") or ""
            relative = self._relative(base_path, href)
            if relative is None or relative == "":
                continue

            props: dict[str, ET.Element] = {}
            for propstat in node.findall(f"{DAV}propstat"):
                status = propstat.findtext(f"{DAV}status") or ""
                if " 200 " not in status:
                    continue
                prop = propstat.find(f"{DAV}prop")
                if prop is None:
                    continue
                for child in prop:
                    props[child.tag] = child

            resourcetype = props.get(f"{DAV}resourcetype")
            is_dir = resourcetype is not None and resourcetype.find(f"{DAV}collection") is not None

            etag = (props[f"{DAV}getetag"].text or "") if f"{DAV}getetag" in props else ""
            etag = etag.strip().lstrip("W/").strip('"') or None

            size_text = props[f"{DAV}getcontentlength"].text if f"{DAV}getcontentlength" in props else None
            mtime_text = props[f"{DAV}getlastmodified"].text if f"{DAV}getlastmodified" in props else None

            entries.append(
                RemoteEntry(
                    path=relative.rstrip("/"),
                    is_dir=is_dir,
                    etag=etag,
                    size=int(size_text) if size_text and size_text.isdigit() else 0,
                    mtime=_parse_mtime(mtime_text),
                )
            )
        return entries

    def walk(self, root: str, workers: int = 4) -> dict[str, RemoteEntry]:
        """Recursive listing, one Depth: 1 level at a time.

        Directories at the same depth are listed concurrently; a mods folder is
        flat, but config trees are not.
        """
        found: dict[str, RemoteEntry] = {}
        level = [""]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while level:
                prefixes = level
                level = []
                listings = pool.map(
                    lambda prefix: (prefix, self.propfind(f"{root}/{prefix}" if prefix else root)),
                    prefixes,
                )
                for prefix, entries in listings:
                    for entry in entries:
                        full = f"{prefix}/{entry.path}" if prefix else entry.path
                        found[full] = RemoteEntry(
                            path=full,
                            is_dir=entry.is_dir,
                            etag=entry.etag,
                            size=entry.size,
                            mtime=entry.mtime,
                        )
                        if entry.is_dir:
                            level.append(full)
        return found

    def exists(self, path: str) -> bool:
        try:
            self.propfind(path, depth=0)
            return True
        except NotFound:
            return False

    def quota(self) -> tuple[int | None, int | None]:
        """(used, available) in bytes. Available may be negative for unlimited."""
        response = self._request(
            "PROPFIND",
            self.base,
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
            data=_QUOTA_BODY,
        )
        if response.status_code != 207:
            return None, None
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            return None, None
        used = root.findtext(f".//{DAV}quota-used-bytes")
        available = root.findtext(f".//{DAV}quota-available-bytes")

        def _as_int(value: str | None) -> int | None:
            try:
                return int(value) if value is not None else None
            except ValueError:
                return None

        return _as_int(used), _as_int(available)

    def download(self, path: str, destination: Path, expected_size: int | None = None) -> int:
        response = self._request("GET", self._url(path), stream=True)
        if response.status_code == 404:
            raise NotFound(path)
        if response.status_code != 200:
            raise WebDAVError(f"GET {path} returned {response.status_code}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        partial = destination.with_name(destination.name + ".part")
        with partial.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1 << 20):
                handle.write(chunk)
                written += len(chunk)
        if expected_size is not None and expected_size > 0 and written != expected_size:
            partial.unlink(missing_ok=True)
            raise WebDAVError(
                f"GET {path} truncated: expected {expected_size} bytes, received {written}"
            )
        partial.replace(destination)
        return written

    # -- writes -------------------------------------------------------------

    def mkcol_p(self, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        for index in range(len(parts)):
            prefix = "/".join(parts[: index + 1])
            response = self._request("MKCOL", self._url(prefix))
            if response.status_code in (201, 405):  # created, or already there
                continue
            if response.status_code == 409:
                raise WebDAVError(f"MKCOL {prefix}: parent collection is missing")
            raise WebDAVError(f"MKCOL {prefix} returned {response.status_code}")

    def upload(self, source: Path, path: str, mtime: int) -> str | None:
        with source.open("rb") as handle:
            response = self._request(
                "PUT",
                self._url(path),
                data=handle,
                headers={
                    "X-OC-Mtime": str(int(mtime)),
                    "Content-Length": str(source.stat().st_size),
                },
            )
        if response.status_code not in (200, 201, 204):
            raise WebDAVError(f"PUT {path} returned {response.status_code}")

        if response.headers.get("X-OC-MTime") != "accepted":
            self._set_mtime(path, mtime)

        etag = (response.headers.get("ETag") or "").strip().lstrip("W/").strip('"')
        return etag or None

    def _set_mtime(self, path: str, mtime: int) -> None:
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop>'
            f"<d:lastmodified>{formatdate(mtime, usegmt=True)}</d:lastmodified>"
            "</d:prop></d:set></d:propertyupdate>"
        ).encode()
        response = self._request(
            "PROPPATCH",
            self._url(path),
            headers={"Content-Type": "application/xml; charset=utf-8"},
            data=body,
        )
        if response.status_code != 207:
            log.warning(
                "could not set remote mtime on %s (PROPPATCH %s); this file may re-sync repeatedly",
                path,
                response.status_code,
            )

    def delete(self, path: str) -> None:
        response = self._request("DELETE", self._url(path))
        if response.status_code not in (200, 204, 404):
            raise WebDAVError(f"DELETE {path} returned {response.status_code}")

    def put_text(self, path: str, text: str, mtime: int) -> None:
        response = self._request(
            "PUT",
            self._url(path),
            data=text.encode("utf-8"),
            headers={"X-OC-Mtime": str(int(mtime))},
        )
        if response.status_code not in (200, 201, 204):
            raise WebDAVError(f"PUT {path} returned {response.status_code}")
