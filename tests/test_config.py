"""Tests for the config model: defaults, round-trip, permissions and redaction."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from battery_charger.config import (
    Config,
    ConfigError,
    DeviceConfig,
    default_config_path,
    load_config,
    redact_secret,
    write_config,
)


def test_default_config_path_uses_xdg_config_home(tmp_path: Path) -> None:
    env = {"XDG_CONFIG_HOME": str(tmp_path / "xdg"), "HOME": str(tmp_path / "home")}

    assert default_config_path(env) == tmp_path / "xdg" / "battery-charger" / "config.toml"


def test_default_config_path_falls_back_to_home_dot_config(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path / "home")}

    assert (
        default_config_path(env)
        == tmp_path / "home" / ".config" / "battery-charger" / "config.toml"
    )


def test_load_missing_file_returns_documented_defaults(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.toml")

    assert config == Config()
    assert config.interface == ""
    assert config.low_threshold == 25
    assert config.high_threshold == 85
    assert config.poll_interval == 30
    assert config.device.id == ""
    assert config.device.ip == ""
    assert config.device.local_key == ""
    assert config.device.version == 3.5


def test_round_trip_preserves_every_field(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.toml"
    original = Config(
        interface="wlan0",
        low_threshold=25,
        high_threshold=90,
        poll_interval=15,
        device=DeviceConfig(
            id="0123456789abcdef012345",
            ip="192.168.1.100",
            local_key="0123456789abcdef",
            version=3.5,
        ),
    )

    assert write_config(original, path) == path
    assert load_config(path) == original


def test_write_creates_file_with_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"

    write_config(Config(device=DeviceConfig(local_key="sekret-value")), path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_creates_parent_directory_with_mode_0700(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.toml"

    write_config(Config(), path)

    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_write_is_atomic_when_the_rename_fails(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(local_key="first-key-value")), path)
    before = path.read_bytes()

    def failing_replace(_source: object, _target: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError, match="rename"):
        write_config(Config(device=DeviceConfig(local_key="second-key-value")), path)

    assert path.read_bytes() == before
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["config.toml"]


def test_write_keeps_the_previous_file_on_a_short_write(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(local_key="first-key-value")), path)
    before = path.read_bytes()
    real_write = os.write

    def short_write(descriptor: int, data: bytes) -> int:
        real_write(descriptor, data[:1])
        return 1

    monkeypatch.setattr(os, "write", short_write)

    with pytest.raises(OSError, match="short write"):
        write_config(Config(device=DeviceConfig(local_key="second-key-value")), path)

    assert path.read_bytes() == before
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["config.toml"]


def test_write_tightens_permissions_of_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("")
    path.chmod(0o644)

    write_config(Config(), path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_load_rejects_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("low_threshold = [unterminated")

    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)


def test_load_rejects_non_utf8_config(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b'[device]\nid = "\xff\xfe"\n')

    with pytest.raises(ConfigError, match="UTF-8"):
        load_config(path)


@pytest.mark.parametrize(
    "body",
    [
        'low_threshold = "high"',
        "high_threshold = true",
        'poll_interval = "later"',
        'incident_threshold_s = "five"',
        "interface = 42",
        'device = "192.168.1.100"',
        '[device]\nversion = "three"',
        "[device]\nid = 123",
        "[device]\nlocal_key = 456",
    ],
)
def test_load_rejects_wrong_field_types(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(body)

    with pytest.raises(ConfigError):
        load_config(path)


def test_round_trip_escapes_special_characters(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = Config(
        device=DeviceConfig(id='quote"and\\slash', local_key="line\nbreak\tend"),
    )

    write_config(original, path)

    assert load_config(path) == original


def test_local_key_is_absent_from_repr() -> None:
    config = Config(device=DeviceConfig(local_key="super-secret-key"))

    assert "super-secret-key" not in repr(config)
    assert "super-secret-key" not in repr(config.device)


def test_incident_threshold_defaults_to_300_and_round_trips(tmp_path: Path) -> None:
    assert Config().incident_threshold_s == 300
    path = tmp_path / "config.toml"
    original = Config(incident_threshold_s=120)

    write_config(original, path)

    assert load_config(path) == original
    assert "incident_threshold_s = 120" in path.read_text(encoding="utf-8")


def test_redact_secret() -> None:
    assert redact_secret("") == "(not set)"
    assert redact_secret("abc") == "***"
    # Below 12 characters the whole secret is masked, not just most of it.
    assert redact_secret("abcdefgh") == "********"
    assert redact_secret("abcdefghijk") == "***********"
    # At 12 characters the first-two/last-two form is safe enough to keep.
    assert redact_secret("abcdefghijkl") == "ab...kl"
    assert redact_secret("0123456789abcdef") == "01...ef"
