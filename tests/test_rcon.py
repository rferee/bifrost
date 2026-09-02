from __future__ import annotations

import pytest
from fake_rcon import FakeRcon

from bifrost.rcon import RconAuthError, RconClient, discover_password


def test_command_round_trip() -> None:
    with FakeRcon(password="secret") as server:
        host, port = server.address
        with RconClient(host, port, "secret") as client:
            assert client.command("list") == "ran list"
        assert server.commands == ["list"]


def test_wrong_password_raises() -> None:
    with FakeRcon(password="secret") as server:
        host, port = server.address
        with pytest.raises(RconAuthError):
            RconClient(host, port, "wrong").connect()


def test_long_response_is_not_truncated() -> None:
    payload = "x" * 3000
    with FakeRcon(password="secret", responder=lambda _: payload) as server:
        host, port = server.address
        with RconClient(host, port, "secret") as client:
            assert client.command("list") == payload


def test_unreachable_server_is_an_error() -> None:
    from bifrost.rcon import RconError

    with pytest.raises(RconError, match="cannot reach RCON"):
        RconClient("127.0.0.1", 1, "secret").connect()


def test_discover_password_from_rcon_cli_env(tmp_path) -> None:
    (tmp_path / ".rcon-cli.env").write_text("RCON_PASSWORD=abc123\n", encoding="utf-8")
    assert discover_password(tmp_path) == "abc123"


def test_discover_password_from_server_properties(tmp_path) -> None:
    (tmp_path / "server.properties").write_text(
        "motd=hello\nrcon.password=fromprops\nrcon.port=25575\n", encoding="utf-8"
    )
    assert discover_password(tmp_path) == "fromprops"


def test_discover_password_returns_none_when_absent(tmp_path) -> None:
    assert discover_password(tmp_path) is None
