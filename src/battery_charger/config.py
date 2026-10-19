"""TOML configuration, written atomically at mode 0600.

The file holds the device ``local_key``; it is excluded from ``repr()`` and must
only be printed through :func:`redact_secret`.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_DIR_NAME = "battery-charger"
CONFIG_FILE_NAME = "config.toml"
DEFAULT_INCIDENT_THRESHOLD_S = 300

_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class ConfigError(Exception):
    """Raised when the config file cannot be parsed or contains invalid values."""


def default_config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return ``$XDG_CONFIG_HOME/battery-charger/config.toml`` or ``~/.config/...``."""
    environ = os.environ if env is None else env
    xdg_config_home = environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        base = Path(xdg_config_home)
    else:
        base = Path(environ.get("HOME", "~")).expanduser() / ".config"
    return base / APP_DIR_NAME / CONFIG_FILE_NAME


def redact_secret(value: str) -> str:
    """Printable form of a secret: masked entirely below 12 characters."""
    if not value:
        return "(not set)"
    if len(value) < 12:
        return "*" * len(value)
    return f"{value[:2]}...{value[-2:]}"


@dataclass
class DeviceConfig:
    id: str = ""
    ip: str = ""
    local_key: str = field(default="", repr=False)
    version: float = 3.5


@dataclass
class Config:
    interface: str = ""
    low_threshold: int = 25
    high_threshold: int = 85
    poll_interval: int = 30
    # How long the plug must stay unreachable before an incident is recorded.
    incident_threshold_s: int = DEFAULT_INCIDENT_THRESHOLD_S
    device: DeviceConfig = field(default_factory=DeviceConfig)


def load_config(path: Path | None = None, env: Mapping[str, str] | None = None) -> Config:
    """Load a config file, returning defaults when the file does not exist yet."""
    config_path = path if path is not None else default_config_path(env)
    try:
        with open(config_path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        return Config()
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"invalid UTF-8 in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc
    return _config_from_mapping(data, config_path)


def write_config(
    config: Config, path: Path | None = None, env: Mapping[str, str] | None = None
) -> Path:
    """Write the config atomically at mode 0600 and return the path.

    A short or failed write lands in a temporary file, so an existing config
    and its local key can never be truncated.
    """
    config_path = path if path is not None else default_config_path(env)
    directory_created = not config_path.parent.exists()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if directory_created:
        try:
            os.chmod(config_path.parent, 0o700)
        except OSError:
            pass
    payload = render_config(config).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=config_path.parent, prefix=f".{config_path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError(
                f"short write to {temporary_path}: wrote {written} of {len(payload)} bytes"
            )
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary_path.unlink()
        raise
    os.close(descriptor)
    try:
        os.replace(temporary_path, config_path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary_path.unlink()
        raise
    with contextlib.suppress(OSError):
        os.chmod(config_path, 0o600)
    return config_path


def render_config(config: Config) -> str:
    lines = [
        "# Automatic Battery Charger configuration.",
        "# This file holds the device local key and is written with mode 0600.",
        f"interface = {_toml_string(config.interface)}",
        "",
        f"low_threshold = {config.low_threshold}",
        f"high_threshold = {config.high_threshold}",
        f"poll_interval = {config.poll_interval}",
        "",
        "# Seconds the plug must stay unreachable before an incident is recorded",
        "# and noticed. A shorter reconnect (the plug flaps for about a minute at a",
        "# time) is not an incident.",
        f"incident_threshold_s = {config.incident_threshold_s}",
        "",
        "[device]",
        f"id = {_toml_string(config.device.id)}",
        f"ip = {_toml_string(config.device.ip)}",
        f"local_key = {_toml_string(config.device.local_key)}",
        f"version = {float(config.device.version)!r}",
        "",
    ]
    return "\n".join(lines)


def _config_from_mapping(data: dict[str, Any], path: Path) -> Config:
    device_data = data.get("device", {})
    if not isinstance(device_data, dict):
        raise ConfigError(f"'device' must be a table in {path}")
    return Config(
        interface=_read_str(data, "interface", "", path),
        low_threshold=_read_int(data, "low_threshold", 25, path),
        high_threshold=_read_int(data, "high_threshold", 85, path),
        poll_interval=_read_int(data, "poll_interval", 30, path),
        incident_threshold_s=_read_int(
            data, "incident_threshold_s", DEFAULT_INCIDENT_THRESHOLD_S, path
        ),
        device=DeviceConfig(
            id=_read_str(device_data, "id", "", path),
            ip=_read_str(device_data, "ip", "", path),
            local_key=_read_str(device_data, "local_key", "", path),
            version=_read_version(device_data, "version", 3.5, path),
        ),
    )


def _read_str(data: Mapping[str, Any], key: str, default: str, path: Path) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"'{key}' must be a string in {path}")
    return value


def _read_int(data: Mapping[str, Any], key: str, default: int, path: Path) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{key}' must be an integer in {path}")
    return value


def _read_version(data: Mapping[str, Any], key: str, default: float, path: Path) -> float:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"'{key}' must be a number in {path}")
    return float(value)


def _toml_string(value: str) -> str:
    escaped = []
    for character in value:
        if character in _TOML_ESCAPES:
            escaped.append(_TOML_ESCAPES[character])
        elif ord(character) < 0x20:
            escaped.append(f"\\u{ord(character):04x}")
        else:
            escaped.append(character)
    return '"' + "".join(escaped) + '"'
