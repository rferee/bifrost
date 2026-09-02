"""Sync semantics. The guard tests matter most - they are the ones that fire on
the day something is genuinely wrong.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from conftest import seed_folder, write_remote

from bifrost.engine import GuardTripped


def test_pull_downloads_and_preserves_mtime(make_config, make_engine, remote, data):
    folder = seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha bytes", mtime=1_700_000_000)
    assert folder.is_dir()

    config = make_config()
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.downloaded == ["alpha.jar"]
    landed = data / "mods" / "alpha.jar"
    assert landed.read_bytes() == b"alpha bytes"
    assert int(landed.stat().st_mtime) == 1_700_000_000


def test_pull_is_idempotent(make_config, make_engine, remote):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha bytes")

    config = make_config()
    engine = make_engine(config)
    assert engine.run(config.rules[0]).downloaded == ["alpha.jar"]

    engine.new_pass()
    assert engine.run(config.rules[0]).downloaded == []


def test_pull_refuses_a_folder_without_the_sentinel(make_config, make_engine, remote):
    (remote / "mods").mkdir()
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config()
    engine = make_engine(config)
    with pytest.raises(GuardTripped, match="sentinel|bifrost-root"):
        engine.run(config.rules[0])


def test_pull_creates_the_sentinel_when_initialising(make_config, make_engine, remote):
    (remote / "mods").mkdir()
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config(BIFROST_INIT_REMOTE="1")
    engine = make_engine(config)
    assert engine.run(config.rules[0]).downloaded == ["alpha.jar"]
    assert (remote / "mods" / ".bifrost-root").is_file()


def test_mirror_delete_moves_the_file_to_trash(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")
    write_remote(remote, "mods/beta.jar", b"beta")

    config = make_config(BIFROST_RULE_1_DELETE="mirror")
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)
    assert (data / "mods" / "beta.jar").is_file()

    (remote / "mods" / "beta.jar").unlink()
    engine.new_pass()
    outcome = engine.run(rule)

    assert outcome.deleted == ["beta.jar"]
    assert not (data / "mods" / "beta.jar").exists()
    trashed = list((config.state_dir / "trash" / "mods").rglob("beta.jar"))
    assert len(trashed) == 1
    assert trashed[0].read_bytes() == b"beta"


def test_delete_off_never_removes_anything(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config(BIFROST_RULE_1_DELETE="off")
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)

    (remote / "mods" / "alpha.jar").unlink()
    engine.new_pass()
    outcome = engine.run(rule)

    assert outcome.deleted == []
    assert (data / "mods" / "alpha.jar").is_file()


def test_mass_deletion_aborts_the_whole_pass(make_config, make_engine, remote, data):
    seed_folder(remote)
    for index in range(10):
        write_remote(remote, f"mods/mod{index}.jar", f"mod{index}".encode())

    config = make_config(BIFROST_RULE_1_DELETE="mirror")
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)
    assert len(list((data / "mods").glob("*.jar"))) == 10

    for index in range(9):
        (remote / "mods" / f"mod{index}.jar").unlink()

    engine.new_pass()
    with pytest.raises(GuardTripped, match="refusing to delete 9 of 10"):
        engine.run(rule)

    # Nothing was touched: an aborted pass leaves the server exactly as it was.
    assert len(list((data / "mods").glob("*.jar"))) == 10


def test_empty_listing_after_a_successful_sync_is_refused(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config(BIFROST_RULE_1_DELETE="mirror")
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)

    # A maintenance-mode error page, a revoked share and a wrong path all look
    # exactly like this.
    (remote / "mods" / "alpha.jar").unlink()
    engine.new_pass()
    with pytest.raises(GuardTripped, match="zero files"):
        engine.run(rule)
    assert (data / "mods" / "alpha.jar").is_file()


def test_empty_remote_on_a_first_run_is_the_seeding_case(make_config, make_engine, remote, data):
    seed_folder(remote)
    (data / "mods").mkdir()
    (data / "mods" / "local.jar").write_bytes(b"local")

    config = make_config(BIFROST_RULE_1_DELETE="mirror")
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.downloaded == []
    assert (data / "mods" / "local.jar").is_file()


def test_never_sync_list_is_enforced(make_config, make_engine, remote, data):
    seed_folder(remote, "config")
    write_remote(remote, "config/server.properties", b"rcon.password=hunter2")
    write_remote(remote, "config/ok.toml", b"setting = 1")

    config = make_config(BIFROST_RULE_1="config")
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.downloaded == ["ok.toml"]
    assert not (data / "config" / "server.properties").exists()


def test_quarantined_content_is_not_applied(make_config, make_engine, remote, data):
    seed_folder(remote)
    payload = b"a jar that kills the server"
    write_remote(remote, "mods/bad.jar", payload)

    config = make_config()
    engine = make_engine(config)
    engine.state.quarantine_add(
        hashlib.sha256(payload).hexdigest(), "mods", "bad.jar", "test"
    )

    outcome = engine.run(config.rules[0])
    assert outcome.downloaded == []
    assert outcome.quarantined == ["bad.jar"]
    assert not (data / "mods" / "bad.jar").exists()

    # And it is not re-downloaded on every subsequent pass.
    engine.new_pass()
    assert engine.run(config.rules[0]).quarantined == []


def test_nested_directories_are_walked(make_config, make_engine, remote, data):
    seed_folder(remote, "config")
    write_remote(remote, "config/deep/nested/value.toml", b"x = 1")

    config = make_config(BIFROST_RULE_1="config")
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.downloaded == ["deep/nested/value.toml"]
    assert (data / "config" / "deep" / "nested" / "value.toml").read_bytes() == b"x = 1"


def test_push_seeds_an_empty_remote_folder(make_config, make_engine, remote, data):
    (data / "mods").mkdir()
    (data / "mods" / "local.jar").write_bytes(b"local bytes")

    config = make_config(BIFROST_RULE_1_DIRECTION="push")
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.uploaded == ["local.jar"]
    assert (remote / "mods" / "local.jar").read_bytes() == b"local bytes"
    assert (remote / "mods" / ".bifrost-root").is_file()


def test_push_is_idempotent(make_config, make_engine, remote, data):
    (data / "mods").mkdir()
    (data / "mods" / "local.jar").write_bytes(b"local bytes")

    config = make_config(BIFROST_RULE_1_DIRECTION="push")
    engine = make_engine(config)
    rule = config.rules[0]
    assert engine.run(rule).uploaded == ["local.jar"]

    engine.new_pass()
    assert engine.run(rule).uploaded == []


def test_pull_then_push_does_not_ping_pong(make_config, make_engine, remote, data):
    """The loop this guards against is the whole reason X-OC-Mtime is sent."""
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha", mtime=1_700_000_000)
    (data / "mods").mkdir()
    (data / "mods" / "only-local.jar").write_bytes(b"local")

    config = make_config(
        BIFROST_RULE_1="mods",
        BIFROST_RULE_1_DIRECTION="pull",
        BIFROST_RULE_2="mods",
        BIFROST_RULE_2_DIRECTION="push",
    )
    engine = make_engine(config)
    pull_rule, push_rule = config.rules

    first_pull = engine.run(pull_rule)
    first_push = engine.run(push_rule)
    assert first_pull.downloaded == ["alpha.jar"]
    assert first_push.uploaded == ["only-local.jar"]

    for _ in range(3):
        engine.new_pass()
        assert not engine.run(pull_rule).any_change
        assert not engine.run(push_rule).any_change


def test_dry_run_changes_nothing(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config(BIFROST_DRY_RUN="1")
    engine = make_engine(config)
    outcome = engine.run(config.rules[0])

    assert outcome.downloaded == ["alpha.jar"]
    assert not (data / "mods" / "alpha.jar").exists()


def test_a_locally_deleted_managed_file_comes_back(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config()
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)

    (data / "mods" / "alpha.jar").unlink()
    engine.new_pass()
    assert engine.run(rule).downloaded == ["alpha.jar"]


def test_changed_remote_content_is_re_downloaded(make_config, make_engine, remote, data):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"v1", mtime=1_700_000_000)

    config = make_config()
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)

    write_remote(remote, "mods/alpha.jar", b"v2 is longer", mtime=1_700_000_500)
    engine.new_pass()
    assert engine.run(rule).downloaded == ["alpha.jar"]
    assert (data / "mods" / "alpha.jar").read_bytes() == b"v2 is longer"


def test_snapshot_is_only_taken_for_rules_with_a_behavior(make_config, make_engine, remote):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config()
    engine = make_engine(config)
    assert engine.run(config.rules[0]).snapshot_dir is None
    assert engine.pending_snapshots == set()


def test_snapshot_holds_the_last_known_good_state(make_config, make_engine, remote, data: Path):
    seed_folder(remote)
    write_remote(remote, "mods/alpha.jar", b"alpha")

    config = make_config(
        BIFROST_RULE_1_BEHAVIOR="restart", BIFROST_RCON="localhost:25575"
    )
    engine = make_engine(config)
    rule = config.rules[0]
    engine.run(rule)

    snapshot = engine.snapshot_dir(rule)
    assert not (snapshot / "alpha.jar").exists()  # taken before alpha landed

    # A second pass inside the same settle window must not overwrite it.
    write_remote(remote, "mods/beta.jar", b"beta")
    engine.new_pass()
    engine.run(rule)
    assert not (snapshot / "alpha.jar").exists()
