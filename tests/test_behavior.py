from __future__ import annotations

import threading

import pytest
from fake_rcon import FakeRcon

from bifrost.behavior import ServerController


@pytest.mark.parametrize(
    ("countdown", "expected"),
    [(0, []), (5, [5]), (30, [30, 10, 5]), (60, [60, 30, 10, 5]), (120, [120, 60, 30, 10, 5])],
)
def test_countdown_steps(countdown: int, expected: list[int]) -> None:
    assert ServerController._countdown_steps(countdown) == expected


def _responder(command: str) -> str:
    if command == "list":
        return "There are 0 of a max of 20 players online:"
    return ""


def test_restart_saves_then_stops_and_verifies(make_config) -> None:
    with FakeRcon(password="secret", responder=_responder) as server:
        host, port = server.address
        config = make_config(
            BIFROST_RULE_1_BEHAVIOR="restart",
            BIFROST_RCON=f"{host}:{port}",
            BIFROST_RCON_PASSWORD="secret",
            BIFROST_RESTART_COUNTDOWN="60s",
        )
        controller = ServerController(config)
        controller.post_stop_delay = 0.0

        result = controller.restart("2 file change(s)", threading.Event())

    assert result.ok, result.detail
    # Nobody online, so the countdown is skipped entirely - but the world is
    # still flushed before and after, and `stop` is the last thing sent.
    assert "save-all flush" in server.commands
    assert server.commands.count("save-all flush") == 2
    assert not [command for command in server.commands if command.startswith("say ")]
    assert server.commands[-2] == "stop"  # the trailing entry is the verification `list`


def test_restart_warns_when_players_are_online(make_config) -> None:
    def occupied(command: str) -> str:
        if command == "list":
            return "There are 3 of a max of 20 players online: a, b, c"
        return ""

    with FakeRcon(password="secret", responder=occupied) as server:
        host, port = server.address
        config = make_config(
            BIFROST_RULE_1_BEHAVIOR="restart",
            BIFROST_RCON=f"{host}:{port}",
            BIFROST_RCON_PASSWORD="secret",
            BIFROST_RESTART_COUNTDOWN="5s",
        )
        controller = ServerController(config)
        controller.post_stop_delay = 0.0

        result = controller.restart("a mod update", threading.Event())

    assert result.ok, result.detail
    warnings = [command for command in server.commands if command.startswith("say ")]
    assert len(warnings) == 1
    assert "Restarting in 5s" in warnings[0]


def test_restart_reports_failure_when_the_server_never_returns(make_config) -> None:
    with FakeRcon(password="secret", responder=_responder) as server:
        host, port = server.address
        config = make_config(
            BIFROST_RULE_1_BEHAVIOR="restart",
            BIFROST_RCON=f"{host}:{port}",
            BIFROST_RCON_PASSWORD="secret",
            BIFROST_BOOT_TIMEOUT="1s",
        )
        controller = ServerController(config)
        controller.post_stop_delay = 0.0
        controller.restart("warm up", threading.Event())

    # The fake is gone now, which is what "the container never came back" looks
    # like from bifrost's side.
    result = controller.restart("a bad mod", threading.Event())
    assert not result.ok
    assert "restart" in result.detail.lower() or "reach" in result.detail.lower()


def test_shutdown_during_the_countdown_aborts(make_config) -> None:
    def occupied(command: str) -> str:
        return "There are 3 of a max of 20 players online: a, b, c" if command == "list" else ""

    with FakeRcon(password="secret", responder=occupied) as server:
        host, port = server.address
        config = make_config(
            BIFROST_RULE_1_BEHAVIOR="restart",
            BIFROST_RCON=f"{host}:{port}",
            BIFROST_RCON_PASSWORD="secret",
            BIFROST_RESTART_COUNTDOWN="60s",
        )
        controller = ServerController(config)
        stop_event = threading.Event()
        stop_event.set()

        result = controller.restart("a mod update", stop_event)

    assert not result.ok
    assert result.detail == "interrupted"
    assert "stop" not in server.commands


def test_rcon_behavior_runs_every_command(make_config) -> None:
    with FakeRcon(password="secret") as server:
        host, port = server.address
        config = make_config(
            BIFROST_RULE_1_BEHAVIOR="rcon:say reloaded;reload",
            BIFROST_RCON=f"{host}:{port}",
            BIFROST_RCON_PASSWORD="secret",
        )
        controller = ServerController(config)
        controller.run_commands(config.rules[0].rcon_commands)

    assert server.commands == ["say reloaded", "reload"]
