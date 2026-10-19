"""Battery state behind a small replaceable interface.

The real source is Linux ``/sys/class/power_supply``. ``power_now`` is unsigned
microwatts, so direction comes from ``status``/``ac_online``. Right after a
relay change ``AC0/online`` flips before ``BAT0/status`` settles, which is what
:attr:`BatteryReading.signals_settled` names.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

SYSFS_POWER_SUPPLY = Path("/sys/class/power_supply")
DEFAULT_BATTERY_NAME = "BAT0"
DEFAULT_AC_NAME = "AC0"
BATTERY_TYPE = "Battery"
MAINS_TYPE = "Mains"

_CHARGING_STATUS = "Charging"
_DISCHARGING_STATUS = "Discharging"
# Statuses that can only occur with the mains adapter connected.
_ON_AC_STATUSES = frozenset({_CHARGING_STATUS, "Full", "Not charging"})


class BatteryError(Exception):
    """Raised when the battery state cannot be read (missing or unreadable sysfs file)."""


@dataclass(frozen=True)
class BatteryReading:
    """One snapshot of the battery and the mains adapter.

    ``power_now``, ``energy_now`` and ``energy_full`` are the raw sysfs values
    in microwatts/microwatt-hours. They are optional because not every battery
    exposes them; the fields the controller needs are mandatory.
    """

    capacity: int
    status: str
    ac_online: bool
    power_now: int | None = None
    energy_now: int | None = None
    energy_full: int | None = None

    @property
    def is_charging(self) -> bool:
        """Whether the battery itself reports that it is taking charge.

        Exact comparison only: ``"Charging"`` is a substring of
        ``"Discharging"``, so a substring test reports a discharging battery as
        charging. The magnitude of ``power_now`` is deliberately ignored.
        """
        return self.status == _CHARGING_STATUS

    @property
    def signals_settled(self) -> bool:
        """Whether ``status`` and ``ac_online`` tell the same story.

        A mismatch means the reading is half-settled (the measured transition
        window) or genuinely ambiguous, and no threshold decision may be made
        from it.
        """
        if self.status in _ON_AC_STATUSES:
            return self.ac_online
        if self.status == _DISCHARGING_STATUS:
            return not self.ac_online
        return False


@runtime_checkable
class BatterySource(Protocol):
    """Where a :class:`BatteryReading` comes from."""

    def read(self) -> BatteryReading:
        """Return the current battery reading, or raise :class:`BatteryError`."""


class SysfsBattery:
    """Read the battery and the mains adapter from ``/sys/class/power_supply``.

    Paths are autodetected by default (preferring ``BAT0``/``AC0``, then the
    first supply whose ``type`` file says ``Battery``/``Mains``) and can be
    overridden explicitly, which is what tests use.
    """

    def __init__(
        self,
        battery_path: str | Path | None = None,
        ac_path: str | Path | None = None,
        *,
        root: str | Path = SYSFS_POWER_SUPPLY,
    ) -> None:
        if battery_path is not None:
            self._battery_path = Path(battery_path)
        else:
            self._battery_path = _detect_supply(
                Path(root), default_name=DEFAULT_BATTERY_NAME, prefix="BAT", kind=BATTERY_TYPE
            )
        if ac_path is not None:
            self._ac_path = Path(ac_path)
        else:
            self._ac_path = _detect_supply(
                Path(root), default_name=DEFAULT_AC_NAME, prefix="AC", kind=MAINS_TYPE
            )

    @property
    def battery_path(self) -> Path:
        """The battery directory this source reads."""
        return self._battery_path

    @property
    def ac_path(self) -> Path:
        """The mains adapter directory this source reads."""
        return self._ac_path

    def read(self) -> BatteryReading:
        """Read one snapshot; missing or unreadable required files raise :class:`BatteryError`."""
        capacity = _read_int(self._battery_path / "capacity", "battery capacity")
        status = _read_text(self._battery_path / "status", "battery status")
        ac_online = _read_int(self._ac_path / "online", "AC online") != 0
        return BatteryReading(
            capacity=capacity,
            status=status,
            ac_online=ac_online,
            power_now=_read_optional_int(self._battery_path / "power_now", "battery power_now"),
            energy_now=_read_optional_int(self._battery_path / "energy_now", "battery energy_now"),
            energy_full=_read_optional_int(
                self._battery_path / "energy_full", "battery energy_full"
            ),
        )


class FakeBattery:
    """Scripted :class:`BatterySource` for tests.

    Readings are emitted in the order they were scripted. Once the script is
    exhausted the last reading repeats, so a controller can be driven through a
    transition and then held in the resulting state deterministically.
    """

    def __init__(self, readings: Iterable[BatteryReading] | None = None) -> None:
        self._readings: list[BatteryReading] = list(readings or [])
        self.index = 0
        self.read_count = 0

    def script(self, *readings: BatteryReading) -> None:
        """Append readings to the script."""
        self._readings.extend(readings)

    def read(self) -> BatteryReading:
        """Emit the next scripted reading (repeating the last one)."""
        if not self._readings:
            raise BatteryError("FakeBattery has no scripted readings")
        reading = self._readings[min(self.index, len(self._readings) - 1)]
        self.index += 1
        self.read_count += 1
        return reading


def _detect_supply(root: Path, *, default_name: str, prefix: str, kind: str) -> Path:
    """Find a power supply directory under ``root`` by conventional name or ``type``."""
    preferred = root / default_name
    if (preferred / "type").is_file():
        return preferred
    try:
        entries = sorted(root.iterdir())
    except OSError as exc:
        raise BatteryError(f"cannot scan {root} for a {kind} power supply: {exc}") from exc
    for entry in entries:
        if entry.name.startswith(prefix) and (entry / "type").is_file():
            return entry
    for entry in entries:
        if _read_optional_text(entry / "type") == kind:
            return entry
    raise BatteryError(f"no {kind} power supply found under {root}")


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError as exc:
        raise BatteryError(f"{label} is missing at {path}") from exc
    except OSError as exc:
        raise BatteryError(f"cannot read {label} at {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise BatteryError(f"{label} at {path} is not text: {exc}") from exc


def _read_optional_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None


def _read_int(path: Path, label: str) -> int:
    text = _read_text(path, label)
    try:
        return int(text)
    except ValueError as exc:
        raise BatteryError(f"{label} at {path} is not an integer: {text!r}") from exc


def _read_optional_int(path: Path, label: str) -> int | None:
    try:
        return _read_int(path, label)
    except BatteryError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise
