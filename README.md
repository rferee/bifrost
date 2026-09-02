# bifrost

A sidecar that syncs folders between Nextcloud and a Minecraft server's `/data`,
and restarts the server when they change.

Drop a mod jar into a Nextcloud folder from a laptop; a minute later it is on the
server, players get a countdown, and the server comes back with the mod loaded.
Remove the jar and it is uninstalled the same way.

No Docker socket. No FUSE mount. No privileged access of any kind — bifrost talks
HTTPS to Nextcloud and RCON to the server, and that is the whole attack surface.

## How a pass works

Every `BIFROST_POLL_INTERVAL`, for each rule:

1. **List** the remote folder with a recursive `PROPFIND Depth: 1` walk.
2. **Plan** against the sync journal: what is new, what changed, what a previous
   pass placed and has since disappeared.
3. **Guard.** Abort the whole pass if the folder's sentinel is missing, if the
   listing is empty when it should not be, or if too much would be deleted.
4. **Stage** every download into `.bifrost/stage`. `/data` is untouched until the
   last byte has arrived.
5. **Settle.** Wait `BIFROST_SETTLE` for more changes, so eight jars dropped over
   ninety seconds become one restart instead of eight.
6. **Apply.** Snapshot the folder, then move each file into place with a rename.
   Removals go to a trash directory, never to `unlink`.
7. **React.** `save-all flush`, a countdown over `say`, then `stop`. Docker's
   restart policy brings the server back.
8. **Verify.** Reconnect over RCON until the server answers. If it never does,
   restore the snapshot, quarantine the new files, and try once more.

## Quick start

```sh
cp .env.example .env                                  # RCON_PASSWORD
mkdir -p secrets
printf '%s' '<nextcloud app password>' > secrets/nextcloud_app_password
cp docker-compose.example.yml docker-compose.yml      # then edit the URL and paths
docker compose up -d
```

Set `BIFROST_INIT_REMOTE=1` for the first start — it creates the remote folders
and their sentinel files — then remove it, so a folder that later goes missing is
an error rather than something bifrost silently recreates.

Use a **Nextcloud app password**, and ideally a dedicated Nextcloud user that owns
the bifrost folders and shares them out to you. App passwords cannot be scoped to
a folder: whatever credential bifrost holds can reach the whole account.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `BIFROST_NEXTCLOUD_URL` | *required* | Base URL only, e.g. `https://cloud.example.com`. bifrost appends the DAV path itself; a pasted `/remote.php/...` suffix is trimmed |
| `BIFROST_NEXTCLOUD_USER` | *required* | Nextcloud username |
| `BIFROST_NEXTCLOUD_PASSWORD` / `_FILE` | *required* | App password. Prefer `_FILE` with a Docker secret |
| `BIFROST_REMOTE_ROOT` | *(account root)* | Path all rules hang off, e.g. `bifrost/bdgncraft` |
| `BIFROST_DATA_DIR` | `/data` | The server's data volume |
| `BIFROST_STATE_DIR` | `<data>/.bifrost` | Journal, staging, snapshots, trash |
| `BIFROST_POLL_INTERVAL` | `5m` | How often to look |
| `BIFROST_SETTLE` | `30s` | Quiet period before firing a behavior |
| `BIFROST_SETTLE_MAX` | `5m` | Ceiling on deferring a behavior |
| `BIFROST_RCON` | — | `<service>:25575`. Required if any rule has a behavior |
| `BIFROST_RCON_PASSWORD` / `_FILE` | *(read from `/data`)* | Falls back to itzg's generated password |
| `BIFROST_RESTART_COUNTDOWN` | `60s` | Warning time. Skipped when nobody is online |
| `BIFROST_BOOT_TIMEOUT` | `5m` | How long to wait for the server to come back |
| `BIFROST_MAX_DELETE` | `3` | Absolute deletion limit per pass |
| `BIFROST_MAX_DELETE_PCT` | `25` | Relative deletion limit per pass |
| `BIFROST_WORKERS` | `4` | Concurrent transfers |
| `BIFROST_TRASH_RETENTION_DAYS` | `14` | How long deleted files are kept |
| `BIFROST_DRY_RUN` | `0` | Log the plan, change nothing |
| `BIFROST_INIT_REMOTE` | `0` | Create missing remote folders and sentinels |
| `BIFROST_TLS_VERIFY` | `1` | `0`, or a path to a CA bundle |
| `BIFROST_LOG_LEVEL` | `INFO` | |

### Rules

Numbered, one folder each:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BIFROST_RULE_<n>` | — | Folder under `/data`, e.g. `mods` |
| `BIFROST_RULE_<n>_DIRECTION` | `pull` | `pull` (Nextcloud → server) or `push` |
| `BIFROST_RULE_<n>_DELETE` | `off` | `off`, or `mirror` to propagate deletions |
| `BIFROST_RULE_<n>_BEHAVIOR` | `none` | `none`, `restart`, or `rcon:<cmd>;<cmd>` |
| `BIFROST_RULE_<n>_REMOTE` | *(same as local)* | Remote folder name, if it differs |
| `BIFROST_RULE_<n>_EXCLUDE` | — | Comma-separated globs |

Two rules on one folder — a `pull` and a `push` — share a journal, so they do not
fight. That is the recommended `mods` setup: pull is authoritative, push seeds the
Nextcloud folder on the first run and backs up anything dropped in over SSH.

There is no `sync` direction. Real two-way sync needs conflict copies, tombstones
and a settle window against a server that rewrites its own config files on every
boot; until that is built, saying `sync` gets you a startup error rather than a
tool quietly doing something else.

## Safety

Every one of these exists because the failure it prevents is easy to trigger:

- **Sentinel file.** A `.bifrost-root` must be present in each managed remote
  folder. A revoked share, a renamed folder, a maintenance-mode error page and a
  typo'd path all produce a listing that reads as *the user deleted everything*.
- **Deletion caps.** More than `max(3 files, 25%)` disappearing aborts the whole
  pass rather than skipping individual files.
- **Empty-listing guard.** A folder that once had files and now lists none is an
  error, not an instruction — unless nothing has ever been synced, which is the
  seeding case.
- **Trash, not unlink.** Removals move into `.bifrost/trash/<timestamp>/`.
- **Rename, never overwrite.** The JVM holds mod jars open by inode; rewriting one
  under a running server can take it down.
- **Rollback and quarantine.** If the server does not come back, the pre-apply
  snapshot is restored and the new files are quarantined *by content hash*, so the
  same jar is not re-downloaded and re-applied on the next poll.
- **Breaker.** If the rollback also fails to boot, bifrost stops touching the
  server entirely until you restart it with `BIFROST_RESET_BREAKER=1`.
- **Never-sync list.** `server.properties` (it holds `rcon.password` in plaintext),
  `ops.json`, `whitelist.json`, `banned-*.json`, `usercache.json`, `world/`,
  `logs/`, `crash-reports/`, `libraries/` are refused whatever the config says.
- **401 is fatal.** Roughly ten failed logins in thirty minutes trips Nextcloud's
  brute-force protection with a 429 lasting hours, for every service sharing that
  IP. bifrost never retries bad credentials on a timer.

Losing `.bifrost/state.db` is safe: an empty journal degrades bifrost to
additive-only and re-downloads everything.

## Operations

```sh
docker compose logs -f bdgncraft-bifrost
docker compose run --rm bdgncraft-bifrost --once          # one pass, then exit
BIFROST_DRY_RUN=1 docker compose up bdgncraft-bifrost     # plan only
BIFROST_RESET_BREAKER=1 docker compose up -d bdgncraft-bifrost
BIFROST_CLEAR_QUARANTINE=1 docker compose up -d bdgncraft-bifrost
```

Deleted files live in `<data>/.bifrost/trash/<scope>/<unix-timestamp>/`.

## Notes on the Minecraft service

Two settings matter regardless of bifrost:

- `stop_grace_period: 120s`. The 10-second default is shorter than itzg's
  `STOP_DURATION` of 60s, so a plain `docker compose restart` can `SIGKILL` the JVM
  mid-save. With `SYNC_CHUNK_WRITES: false` that risks region-file corruption.
- Pin `RCON_PASSWORD`. Left unset, itzg generates a new random one on every boot.
  bifrost can read it out of `/data/.rcon-cli.env`, but pinning removes the race.

And turn off itzg's own mod management (`REMOVE_OLD_MODS`, `MODS`, `MODS_FILE`,
`GENERIC_PACKS`) for any folder bifrost manages. The entrypoint deletes files in
`mods/` and `config/` at boot, and two tools with different opinions about which
jars belong there will not converge.

## Development

```sh
pip install -e ".[dev]"
pytest
ruff check .
```

Tests run against an in-process WebDAV server and a fake RCON server, so there is
nothing to stand up. `tests/fake_webdav.py` reproduces the parts of the Nextcloud
dialect that matter, including the silent `Depth: infinity` downgrade.
