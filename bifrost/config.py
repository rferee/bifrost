"""Environment-driven configuration.

Everything bifrost needs comes from environment variables, so a whole deployment
is one block inside a docker-compose service definition. Every problem found
here is fatal at startup: a sync sidecar that guesses at its own configuration
is a sidecar that eventually deletes the wrong directory.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

SENTINEL = ".bifrost-root"
TMP_PREFIX = ".bifrost-tmp-"


class ConfigError(Exception):
    """Anything wrong in the environment. Always fatal."""


# --------------------------------------------------------------------------
# Never-sync list
#
# These are refused regardless of what the rules say. server.properties carries
# rcon.password in plaintext and is rewritten from env on every boot; world/ and
# logs/ are server-owned, churny, and would burn a Nextcloud quota through file
# versions. A rule may not target these directories, and files matching these
# globs are skipped inside any rule.
# --------------------------------------------------------------------------
FORBIDDEN_DIRS = frozenset(
    {
        "world",
        "world_nether",
        "world_the_end",
        "logs",
        "crash-reports",
        "libraries",
        "versions",
        "cache",
        "backups",
        ".bifrost",
    }
)

FORBIDDEN_FILE_GLOBS = (
    "server.properties",
    "ops.json",
    "whitelist.json",
    "banned-*.json",
    "usercache.json",
    "eula.txt",
    ".rcon-cli*",
    "session.lock",
    "*.lock",
    TMP_PREFIX + "*",
    SENTINEL,
)

DIRECTIONS = ("pull", "push")
DELETE_MODES = ("off", "mirror")

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_DURATION_MULTIPLIER = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(raw: str, name: str) -> int:
    """Parse "30", "30s", "5m", "2h" into whole seconds."""
    match = _DURATION_RE.match(raw)
    if not match:
        raise ConfigError(f"{name}: {raw!r} is not a duration (try 30s, 5m, 2h)")
    return int(match.group(1)) * _DURATION_MULTIPLIER[match.group(2).lower()]


def is_denied(relpath: str) -> bool:
    """True if this path inside a rule must never be transferred."""
    parts = PurePosixPath(relpath).parts
    if not parts:
        return True
    if any(part in FORBIDDEN_DIRS for part in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(parts[-1], glob) for glob in FORBIDDEN_FILE_GLOBS)


@dataclass(frozen=True)
class Rule:
    """One watched folder moving in one direction.

    Direction is deliberately single-valued. The original concept had a separate
    "trigger" axis, but with one direction per rule a trigger is just "does this
    rule have a behavior", so the two collapsed into one and the nonsensical
    combinations stopped being representable.
    """

    index: int
    remote: str  # subpath under remote_root, e.g. "mods"
    local: Path  # absolute path under data_dir
    direction: str  # pull | push
    delete: str  # off | mirror
    behavior: str  # none | restart | rcon
    rcon_commands: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return f"rule{self.index}:{self.remote}:{self.direction}"

    @property
    def scope(self) -> str:
        """State key.

        Keyed on the remote folder, not the rule, so a pull rule and a push rule
        pointed at the same folder share one view of what has been synced. That
        is what stops the push rule from re-uploading whatever the pull rule
        just wrote.
        """
        return self.remote

    @property
    def fires_behavior(self) -> bool:
        return self.behavior != "none"

    def excluded(self, relpath: str) -> bool:
        if is_denied(relpath):
            return True
        name = PurePosixPath(relpath).name
        return any(
            fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(name, pattern)
            for pattern in self.excludes
        )


@dataclass(frozen=True)
class Config:
    nextcloud_url: str
    nextcloud_user: str
    nextcloud_password: str
    remote_root: str
    data_dir: Path
    state_dir: Path
    poll_interval: int
    settle: int
    settle_max: int
    rcon_host: str | None
    rcon_port: int
    rcon_password: str | None
    restart_countdown: int
    post_stop_delay: int
    boot_timeout: int
    max_delete: int
    max_delete_pct: int
    workers: int
    http_timeout: int
    trash_retention_days: int
    dry_run: bool
    init_remote: bool
    verify_tls: bool | str
    chown_uid: int | None
    chown_gid: int | None
    log_level: str
    rules: tuple[Rule, ...] = field(default_factory=tuple)

    def remote_path(self, rule: Rule) -> str:
        root = self.remote_root.strip("/")
        return f"{root}/{rule.remote}" if root else rule.remote


def _get(env: dict[str, str], name: str, default: str | None = None) -> str | None:
    value = env.get(name)
    if value is None or value == "":
        return default
    return value


def _secret(env: dict[str, str], name: str) -> str | None:
    """Read NAME, or NAME_FILE pointing at a Docker secret.

    The _FILE form is the one to use: env vars show up in `docker inspect` and
    /proc/<pid>/environ, and Compose mangles a literal $ in a password.
    """
    path = _get(env, name + "_FILE")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"{name}_FILE: cannot read {path}: {exc}") from exc
    return _get(env, name)


def _int(env: dict[str, str], name: str, default: int, minimum: int | None = None) -> int:
    raw = _get(env, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: {raw!r} is not an integer") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name}: must be >= {minimum}, got {value}")
    return value


def _bool(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = _get(env, name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _duration(env: dict[str, str], name: str, default: str) -> int:
    return parse_duration(_get(env, name, default) or default, name)


def _split(raw: str | None, sep: str = ",") -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(sep) if part.strip())


def _load_rules(env: dict[str, str], data_dir: Path) -> tuple[Rule, ...]:
    indices = sorted(
        int(match.group(1))
        for key in env
        if (match := re.fullmatch(r"BIFROST_RULE_(\d+)", key)) and env[key].strip()
    )
    if not indices:
        raise ConfigError(
            "no rules configured. Define at least BIFROST_RULE_1=<folder> "
            "(see docker-compose.example.yml)"
        )

    rules: list[Rule] = []
    for index in indices:
        prefix = f"BIFROST_RULE_{index}"
        folder = (_get(env, prefix) or "").strip().strip("/")
        if not folder:
            raise ConfigError(f"{prefix}: empty folder name")
        if ".." in PurePosixPath(folder).parts or PurePosixPath(folder).is_absolute():
            raise ConfigError(f"{prefix}: {folder!r} must be a relative path under the data dir")
        if any(part in FORBIDDEN_DIRS for part in PurePosixPath(folder).parts):
            raise ConfigError(
                f"{prefix}: refusing to sync {folder!r} - it is on the never-sync list "
                f"({', '.join(sorted(FORBIDDEN_DIRS))})"
            )

        direction = (_get(env, f"{prefix}_DIRECTION", "pull") or "pull").strip().lower()
        if direction not in DIRECTIONS:
            raise ConfigError(
                f"{prefix}_DIRECTION: {direction!r} is not one of {', '.join(DIRECTIONS)}. "
                "Two-way sync is not in this version; use one pull rule and one push rule."
            )

        delete = (_get(env, f"{prefix}_DELETE", "off") or "off").strip().lower()
        # An unquoted `off` in docker-compose.yml is a YAML boolean, so it
        # arrives as "false". Accept the mangled spellings rather than failing
        # on a file that looks correct.
        delete = {"false": "off", "no": "off", "0": "off", "none": "off"}.get(delete, delete)
        if delete not in DELETE_MODES:
            raise ConfigError(
                f"{prefix}_DELETE: {delete!r} is not one of {', '.join(DELETE_MODES)}"
            )

        raw_behavior = (_get(env, f"{prefix}_BEHAVIOR", "none") or "none").strip()
        rcon_commands: tuple[str, ...] = ()
        if raw_behavior.lower() in ("none", ""):
            behavior = "none"
        elif raw_behavior.lower() == "restart":
            behavior = "restart"
        elif raw_behavior.lower().startswith("rcon:"):
            behavior = "rcon"
            rcon_commands = _split(raw_behavior[len("rcon:") :], sep=";")
            if not rcon_commands:
                raise ConfigError(f"{prefix}_BEHAVIOR: rcon: needs at least one command")
        else:
            raise ConfigError(
                f"{prefix}_BEHAVIOR: {raw_behavior!r} is not one of none, restart, rcon:<cmd>;<cmd>"
            )

        remote = (_get(env, f"{prefix}_REMOTE", folder) or folder).strip().strip("/")

        rules.append(
            Rule(
                index=index,
                remote=remote,
                local=data_dir / folder,
                direction=direction,
                delete=delete,
                behavior=behavior,
                rcon_commands=rcon_commands,
                excludes=_split(_get(env, f"{prefix}_EXCLUDE")),
            )
        )

    seen: dict[tuple[str, str], int] = {}
    for rule in rules:
        key = (rule.remote, rule.direction)
        if key in seen:
            raise ConfigError(
                f"BIFROST_RULE_{rule.index} duplicates BIFROST_RULE_{seen[key]}: "
                f"same remote folder {rule.remote!r} and direction {rule.direction!r}"
            )
        seen[key] = rule.index

    return tuple(rules)


def load(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)

    url = _get(env, "BIFROST_NEXTCLOUD_URL")
    if not url:
        raise ConfigError("BIFROST_NEXTCLOUD_URL is required (e.g. https://cloud.example.com)")
    if not url.startswith(("http://", "https://")):
        raise ConfigError(f"BIFROST_NEXTCLOUD_URL: {url!r} must start with http:// or https://")

    user = _get(env, "BIFROST_NEXTCLOUD_USER")
    if not user:
        raise ConfigError("BIFROST_NEXTCLOUD_USER is required")

    password = _secret(env, "BIFROST_NEXTCLOUD_PASSWORD")
    if not password:
        raise ConfigError(
            "BIFROST_NEXTCLOUD_PASSWORD or BIFROST_NEXTCLOUD_PASSWORD_FILE is required. "
            "Use a Nextcloud app password, not your account password."
        )

    data_dir = Path(_get(env, "BIFROST_DATA_DIR", "/data") or "/data")
    # Default the working directory *inside* the data volume. Staging, snapshots
    # and trash then share a filesystem with the files they shadow, which turns
    # applying a change into a rename and a pre-apply snapshot into a hardlink
    # farm. It also means the example compose needs no second volume.
    state_raw = _get(env, "BIFROST_STATE_DIR")
    state_dir = Path(state_raw) if state_raw else data_dir / ".bifrost"

    rcon_endpoint = _get(env, "BIFROST_RCON")
    rcon_host: str | None = None
    rcon_port = 25575
    if rcon_endpoint:
        host, _, port = rcon_endpoint.partition(":")
        rcon_host = host.strip()
        if port:
            try:
                rcon_port = int(port)
            except ValueError as exc:
                raise ConfigError(f"BIFROST_RCON: {port!r} is not a port number") from exc

    verify_raw = _get(env, "BIFROST_TLS_VERIFY", "1") or "1"
    verify: bool | str
    if verify_raw.lower() in ("0", "false", "no", "off"):
        verify = False
    elif verify_raw.lower() in ("1", "true", "yes", "on"):
        verify = True
    else:
        verify = verify_raw  # path to a CA bundle

    poll_interval = _duration(env, "BIFROST_POLL_INTERVAL", "5m")
    settle = _duration(env, "BIFROST_SETTLE", "30s")
    settle_max = _duration(env, "BIFROST_SETTLE_MAX", "5m")
    if settle > settle_max:
        raise ConfigError("BIFROST_SETTLE must not exceed BIFROST_SETTLE_MAX")

    config = Config(
        nextcloud_url=url.rstrip("/"),
        nextcloud_user=user,
        nextcloud_password=password,
        remote_root=(_get(env, "BIFROST_REMOTE_ROOT", "") or "").strip("/"),
        data_dir=data_dir,
        state_dir=state_dir,
        poll_interval=poll_interval,
        settle=settle,
        settle_max=settle_max,
        rcon_host=rcon_host,
        rcon_port=rcon_port,
        rcon_password=_secret(env, "BIFROST_RCON_PASSWORD"),
        restart_countdown=_duration(env, "BIFROST_RESTART_COUNTDOWN", "60s"),
        # How long to let the container actually exit before probing for it.
        post_stop_delay=_duration(env, "BIFROST_POST_STOP_DELAY", "5s"),
        boot_timeout=_duration(env, "BIFROST_BOOT_TIMEOUT", "5m"),
        max_delete=_int(env, "BIFROST_MAX_DELETE", 3, minimum=0),
        max_delete_pct=_int(env, "BIFROST_MAX_DELETE_PCT", 25, minimum=0),
        workers=_int(env, "BIFROST_WORKERS", 4, minimum=1),
        http_timeout=_int(env, "BIFROST_HTTP_TIMEOUT", 120, minimum=1),
        trash_retention_days=_int(env, "BIFROST_TRASH_RETENTION_DAYS", 14, minimum=0),
        dry_run=_bool(env, "BIFROST_DRY_RUN"),
        init_remote=_bool(env, "BIFROST_INIT_REMOTE"),
        verify_tls=verify,
        chown_uid=_int(env, "BIFROST_CHOWN_UID", -1) if _get(env, "BIFROST_CHOWN_UID") else None,
        chown_gid=_int(env, "BIFROST_CHOWN_GID", -1) if _get(env, "BIFROST_CHOWN_GID") else None,
        log_level=(_get(env, "BIFROST_LOG_LEVEL", "INFO") or "INFO").upper(),
        rules=_load_rules(env, data_dir),
    )

    needs_rcon = any(rule.fires_behavior for rule in config.rules)
    if needs_rcon and not config.rcon_host:
        offenders = ", ".join(f"BIFROST_RULE_{r.index}" for r in config.rules if r.fires_behavior)
        raise ConfigError(
            f"BIFROST_RCON is required because {offenders} has a behavior. "
            "Set it to <minecraft-service>:25575."
        )

    return config
