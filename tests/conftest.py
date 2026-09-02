from __future__ import annotations

import os
from pathlib import Path

import pytest
from fake_webdav import FakeNextcloud

from bifrost import config as config_module
from bifrost.engine import Engine
from bifrost.state import State
from bifrost.webdav import NextcloudClient


@pytest.fixture
def remote(tmp_path: Path) -> Path:
    root = tmp_path / "remote"
    root.mkdir()
    return root


@pytest.fixture
def data(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


@pytest.fixture
def server(remote: Path):
    with FakeNextcloud(remote) as running:
        yield running


@pytest.fixture
def make_config(tmp_path: Path, data: Path, server: FakeNextcloud):
    def _make(**overrides: str) -> config_module.Config:
        env = {
            "BIFROST_NEXTCLOUD_URL": server.url,
            "BIFROST_NEXTCLOUD_USER": server.user,
            "BIFROST_NEXTCLOUD_PASSWORD": server.password,
            "BIFROST_DATA_DIR": str(data),
            "BIFROST_STATE_DIR": str(tmp_path / "state"),
            "BIFROST_RULE_1": "mods",
            "BIFROST_RULE_1_DIRECTION": "pull",
        }
        env.update(overrides)
        return config_module.load(env)

    return _make


@pytest.fixture
def make_engine(tmp_path: Path):
    created: list[State] = []

    def _make(config: config_module.Config) -> Engine:
        config.state_dir.mkdir(parents=True, exist_ok=True)
        state = State(config.state_dir / "state.db")
        created.append(state)
        client = NextcloudClient(
            config.nextcloud_url, config.nextcloud_user, config.nextcloud_password
        )
        return Engine(config, client, state)

    yield _make
    for state in created:
        state.close()


def write_remote(remote: Path, relative: str, content: bytes, mtime: int | None = None) -> Path:
    path = remote / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def seed_folder(remote: Path, folder: str = "mods") -> Path:
    """Create a remote folder with the sentinel bifrost insists on."""
    path = remote / folder
    path.mkdir(parents=True, exist_ok=True)
    (path / config_module.SENTINEL).write_text("managed by bifrost\n", encoding="utf-8")
    return path
