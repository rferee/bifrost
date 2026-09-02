from __future__ import annotations

import pytest

from bifrost.config import ConfigError, is_denied, load, parse_duration

BASE = {
    "BIFROST_NEXTCLOUD_URL": "https://cloud.example.com",
    "BIFROST_NEXTCLOUD_USER": "bifrost",
    "BIFROST_NEXTCLOUD_PASSWORD": "app-password",
    "BIFROST_RULE_1": "mods",
}


def env(**overrides: str) -> dict[str, str]:
    return {**BASE, **overrides}


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("30", 30), ("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)],
)
def test_parse_duration(raw: str, seconds: int) -> None:
    assert parse_duration(raw, "x") == seconds


def test_parse_duration_rejects_nonsense() -> None:
    with pytest.raises(ConfigError):
        parse_duration("soon", "x")


def test_defaults() -> None:
    config = load(env())
    assert config.poll_interval == 300
    assert config.rules[0].direction == "pull"
    assert config.rules[0].delete == "off"
    assert config.rules[0].behavior == "none"
    assert config.state_dir == config.data_dir / ".bifrost"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("https://cloud.example.com", "https://cloud.example.com"),
        ("https://cloud.example.com/", "https://cloud.example.com"),
        # The URL Nextcloud shows in its own settings pane.
        ("https://cloud.example.com/remote.php/dav/files/rferee", "https://cloud.example.com"),
        ("https://cloud.example.com/remote.php/webdav", "https://cloud.example.com"),
        # A subpath install must survive.
        ("https://host.example.com/nextcloud", "https://host.example.com/nextcloud"),
        (
            "https://host.example.com/nextcloud/remote.php/dav/files/rferee",
            "https://host.example.com/nextcloud",
        ),
    ],
)
def test_base_url_is_normalised(given: str, expected: str) -> None:
    assert load(env(BIFROST_NEXTCLOUD_URL=given)).nextcloud_url == expected


def test_missing_password_is_fatal() -> None:
    broken = env()
    del broken["BIFROST_NEXTCLOUD_PASSWORD"]
    with pytest.raises(ConfigError, match="app password"):
        load(broken)


def test_password_can_come_from_a_file(tmp_path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("from-a-file\n", encoding="utf-8")
    config = load(
        env(
            BIFROST_NEXTCLOUD_PASSWORD="",
            BIFROST_NEXTCLOUD_PASSWORD_FILE=str(secret),
        )
    )
    assert config.nextcloud_password == "from-a-file"


def test_no_rules_is_fatal() -> None:
    broken = env()
    del broken["BIFROST_RULE_1"]
    with pytest.raises(ConfigError, match="no rules"):
        load(broken)


def test_never_sync_directories_are_rejected() -> None:
    with pytest.raises(ConfigError, match="never-sync"):
        load(env(BIFROST_RULE_1="world"))


def test_escaping_the_data_dir_is_rejected() -> None:
    with pytest.raises(ConfigError, match="relative path"):
        load(env(BIFROST_RULE_1="../../etc"))


def test_two_way_is_not_a_direction() -> None:
    with pytest.raises(ConfigError, match="Two-way sync is not in this version"):
        load(env(BIFROST_RULE_1_DIRECTION="sync"))


def test_duplicate_rules_are_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicates"):
        load(env(BIFROST_RULE_2="mods", BIFROST_RULE_2_DIRECTION="pull"))


def test_pull_and_push_on_one_folder_is_allowed() -> None:
    config = load(env(BIFROST_RULE_2="mods", BIFROST_RULE_2_DIRECTION="push"))
    assert [rule.direction for rule in config.rules] == ["pull", "push"]
    assert config.rules[0].scope == config.rules[1].scope


@pytest.mark.parametrize("spelling", ["off", "OFF", "false", "no", "0", "none"])
def test_delete_off_survives_yaml_mangling(spelling: str) -> None:
    """An unquoted `off` in compose is a YAML boolean and arrives as "false"."""
    assert load(env(BIFROST_RULE_1_DELETE=spelling)).rules[0].delete == "off"


def test_delete_still_rejects_nonsense() -> None:
    with pytest.raises(ConfigError, match="not one of"):
        load(env(BIFROST_RULE_1_DELETE="sometimes"))


def test_a_behavior_requires_rcon() -> None:
    with pytest.raises(ConfigError, match="BIFROST_RCON is required"):
        load(env(BIFROST_RULE_1_BEHAVIOR="restart"))


def test_rcon_endpoint_is_parsed() -> None:
    config = load(env(BIFROST_RULE_1_BEHAVIOR="restart", BIFROST_RCON="mc:25999"))
    assert (config.rcon_host, config.rcon_port) == ("mc", 25999)


def test_rcon_commands_are_split() -> None:
    config = load(
        env(BIFROST_RULE_1_BEHAVIOR="rcon:say hi;reload", BIFROST_RCON="mc:25575")
    )
    assert config.rules[0].behavior == "rcon"
    assert config.rules[0].rcon_commands == ("say hi", "reload")


def test_unknown_behavior_is_fatal() -> None:
    with pytest.raises(ConfigError, match="not one of"):
        load(env(BIFROST_RULE_1_BEHAVIOR="reboot-the-host", BIFROST_RCON="mc:25575"))


def test_remote_can_differ_from_local() -> None:
    config = load(
        env(
            BIFROST_REMOTE_ROOT="/bifrost/bdgncraft/",
            BIFROST_RULE_1="config",
            BIFROST_RULE_1_REMOTE="config-snapshot",
        )
    )
    assert config.remote_path(config.rules[0]) == "bifrost/bdgncraft/config-snapshot"
    assert config.rules[0].local.name == "config"


@pytest.mark.parametrize(
    "path",
    ["server.properties", "ops.json", "banned-ips.json", "world/level.dat", ".rcon-cli.env"],
)
def test_denied_paths(path: str) -> None:
    assert is_denied(path)


@pytest.mark.parametrize("path", ["fabric-api.jar", "sodium/config.toml", "notes.txt"])
def test_allowed_paths(path: str) -> None:
    assert not is_denied(path)


def test_rule_excludes() -> None:
    config = load(env(BIFROST_RULE_1_EXCLUDE="*.txt,drafts/*"))
    rule = config.rules[0]
    assert rule.excluded("readme.txt")
    assert rule.excluded("drafts/wip.jar")
    assert not rule.excluded("keep.jar")
