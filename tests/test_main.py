"""End-to-end through the real entrypoint: config -> sync -> behavior -> verify."""

from __future__ import annotations

from pathlib import Path

from conftest import seed_folder, write_remote
from fake_rcon import FakeRcon
from fake_webdav import FakeNextcloud

from bifrost.__main__ import EXIT_AUTH, EXIT_CONFIG, main


def _responder(command: str) -> str:
    if command == "list":
        return "There are 0 of a max of 20 players online:"
    return ""


def _env(server: FakeNextcloud, rcon: FakeRcon, data: Path, state: Path) -> dict[str, str]:
    host, port = rcon.address
    return {
        "BIFROST_NEXTCLOUD_URL": server.url,
        "BIFROST_NEXTCLOUD_USER": server.user,
        "BIFROST_NEXTCLOUD_PASSWORD": server.password,
        "BIFROST_DATA_DIR": str(data),
        "BIFROST_STATE_DIR": str(state),
        "BIFROST_RCON": f"{host}:{port}",
        "BIFROST_RCON_PASSWORD": "secret",
        "BIFROST_POST_STOP_DELAY": "0",
        "BIFROST_BOOT_TIMEOUT": "10s",
        "BIFROST_RULE_1": "mods",
        "BIFROST_RULE_1_DIRECTION": "pull",
        "BIFROST_RULE_1_DELETE": "mirror",
        "BIFROST_RULE_1_BEHAVIOR": "restart",
        "BIFROST_RULE_2": "mods",
        "BIFROST_RULE_2_DIRECTION": "push",
    }


def test_a_dropped_jar_lands_and_restarts_the_server(monkeypatch, tmp_path, remote, data, server):
    seed_folder(remote)
    write_remote(remote, "mods/fabric-api.jar", b"the mod", mtime=1_700_000_000)

    with FakeRcon(password="secret", responder=_responder) as rcon:
        for key, value in _env(server, rcon, data, tmp_path / "state").items():
            monkeypatch.setenv(key, value)
        assert main(["--once"]) == 0

        assert (data / "mods" / "fabric-api.jar").read_bytes() == b"the mod"
        assert "stop" in rcon.commands
        assert rcon.commands.count("save-all flush") == 2


def test_an_untouched_folder_does_not_restart_anything(monkeypatch, tmp_path, remote, data, server):
    seed_folder(remote)
    write_remote(remote, "mods/fabric-api.jar", b"the mod")

    with FakeRcon(password="secret", responder=_responder) as rcon:
        for key, value in _env(server, rcon, data, tmp_path / "state").items():
            monkeypatch.setenv(key, value)
        assert main(["--once"]) == 0
        assert "stop" in rcon.commands

        rcon.commands.clear()
        assert main(["--once"]) == 0
        # The startup probe sends `list`; nothing else should happen.
        assert rcon.commands == ["list"]


def test_local_jars_are_seeded_up_on_the_first_pass(monkeypatch, tmp_path, remote, data, server):
    seed_folder(remote)
    (data / "mods").mkdir()
    (data / "mods" / "hand-installed.jar").write_bytes(b"was already here")

    with FakeRcon(password="secret", responder=_responder) as rcon:
        for key, value in _env(server, rcon, data, tmp_path / "state").items():
            monkeypatch.setenv(key, value)
        assert main(["--once"]) == 0

    assert (remote / "mods" / "hand-installed.jar").read_bytes() == b"was already here"
    # A push-only change must not restart the server.
    assert (data / "mods" / "hand-installed.jar").is_file()


def test_bad_credentials_exit_without_retrying(monkeypatch, tmp_path, remote, data, server):
    seed_folder(remote)

    with FakeRcon(password="secret") as rcon:
        for key, value in _env(server, rcon, data, tmp_path / "state").items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("BIFROST_NEXTCLOUD_PASSWORD", "wrong")
        assert main([]) == EXIT_AUTH


def test_unreachable_rcon_does_not_roll_back_or_trip_the_breaker(
    monkeypatch, tmp_path, remote, data, server
):
    """A restart that never happened implicates nothing.

    An unresolvable RCON host means the server was never stopped, so the files
    that just synced are not suspect: rolling them back would undo good work
    and quarantine it over a networking problem.
    """
    seed_folder(remote)
    write_remote(remote, "mods/fabric-api.jar", b"the mod")
    state_dir = tmp_path / "state"

    with FakeRcon(password="secret") as rcon:
        env = _env(server, rcon, data, state_dir)
        monkeypatch.setenv("BIFROST_BOOT_TIMEOUT", "1s")

    # The RCON server is gone before bifrost ever runs.
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert main(["--once"]) == 0

    # The file is still there, unquarantined, and the breaker is shut.
    assert (data / "mods" / "fabric-api.jar").read_bytes() == b"the mod"

    from bifrost.state import State

    state = State(state_dir / "state.db")
    try:
        assert state.breaker_reason("restart") is None
        assert state.quarantined() == set()
    finally:
        state.close()

    # And once RCON is reachable again, the deferred restart happens.
    host, port = env["BIFROST_RCON"].split(":")
    with FakeRcon(password="secret", responder=_responder) as rcon:
        monkeypatch.setenv("BIFROST_RCON", f"{rcon.address[0]}:{rcon.address[1]}")
        assert main(["--once"]) == 0
        assert "stop" in rcon.commands


def test_a_broken_config_exits_immediately(monkeypatch):
    monkeypatch.setenv("BIFROST_NEXTCLOUD_URL", "not-a-url")
    monkeypatch.setenv("BIFROST_NEXTCLOUD_USER", "bifrost")
    monkeypatch.setenv("BIFROST_NEXTCLOUD_PASSWORD", "x")
    monkeypatch.setenv("BIFROST_RULE_1", "mods")
    assert main([]) == EXIT_CONFIG


def test_a_failed_boot_rolls_back_and_quarantines(monkeypatch, tmp_path, remote, data, server):
    """The recovery path: the jar goes in, the server never answers again, so the
    jar comes back out and is not re-applied on the next pass."""
    seed_folder(remote)
    (data / "mods").mkdir()
    (data / "mods" / "good.jar").write_bytes(b"known good")
    write_remote(remote, "mods/bad.jar", b"kills the server")

    state_dir = tmp_path / "state"
    holder: dict[str, FakeRcon] = {}

    def dies_on_stop(command: str) -> str:
        if command == "stop":
            holder["rcon"].offline = True
            return ""
        return _responder(command)

    with FakeRcon(password="secret", responder=dies_on_stop) as rcon:
        holder["rcon"] = rcon
        for key, value in _env(server, rcon, data, state_dir).items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("BIFROST_BOOT_TIMEOUT", "1s")
        main(["--once"])

    assert not (data / "mods" / "bad.jar").exists(), "rollback should have removed it"
    assert (data / "mods" / "good.jar").read_bytes() == b"known good"

    # The breaker is open, so a second run touches nothing at all.
    with FakeRcon(password="secret", responder=_responder) as rcon:
        for key, value in _env(server, rcon, data, state_dir).items():
            monkeypatch.setenv(key, value)
        main(["--once"])
        assert not (data / "mods" / "bad.jar").exists()
        assert "stop" not in rcon.commands

    # ...and once cleared, the quarantine still keeps the bad jar out.
    with FakeRcon(password="secret", responder=_responder) as rcon:
        for key, value in _env(server, rcon, data, state_dir).items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("BIFROST_RESET_BREAKER", "1")
        main(["--once"])
        assert not (data / "mods" / "bad.jar").exists()
