"""Tests for the battery source: sysfs parsing and the scripted fake."""

from __future__ import annotations

from pathlib import Path

import pytest

from battery_charger import battery
from battery_charger.battery import BatteryError, BatteryReading, FakeBattery, SysfsBattery


def make_supply(
    directory: Path,
    *,
    kind: str,
    extra: dict[str, str] | None = None,
) -> Path:
    """Create a sysfs power-supply directory with a ``type`` file."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "type").write_text(kind + "\n", encoding="ascii")
    for name, value in (extra or {}).items():
        (directory / name).write_text(value, encoding="ascii")
    return directory


def sysfs_tree(root: Path) -> tuple[Path, Path]:
    battery_dir = make_supply(
        root / "BAT0",
        kind="Battery",
        extra={
            "capacity": "76\n",
            "status": "Charging\n",
            "power_now": "13651000\n",
            "energy_now": "43000000\n",
            "energy_full": "57000000\n",
        },
    )
    ac_dir = make_supply(root / "AC0", kind="Mains", extra={"online": "1\n"})
    return battery_dir, ac_dir


# --- reading ---


def test_is_charging_uses_exact_status_comparison() -> None:
    discharging = BatteryReading(capacity=50, status="Discharging", ac_online=False)

    # "Charging" is a substring of "Discharging"; a substring test would lie.
    assert discharging.is_charging is False
    assert BatteryReading(capacity=50, status="Charging", ac_online=True).is_charging is True


def test_is_charging_ignores_power_now_magnitude() -> None:
    # power_now is unsigned; direction comes from status, not magnitude.
    reading = BatteryReading(
        capacity=50,
        status="Discharging",
        ac_online=False,
        power_now=21_898_000,
    )

    assert reading.is_charging is False


@pytest.mark.parametrize(
    ("status", "ac_online", "settled"),
    [
        ("Charging", True, True),
        ("Charging", False, False),
        ("Discharging", False, True),
        ("Discharging", True, False),
        ("Full", True, True),
        ("Full", False, False),
        ("Not charging", True, True),
        ("Not charging", False, False),
        ("Unknown", True, False),
        ("Unknown", False, False),
        ("", True, False),
    ],
)
def test_signals_settled_pairs_status_with_ac_online(
    status: str, ac_online: bool, settled: bool
) -> None:
    reading = BatteryReading(capacity=50, status=status, ac_online=ac_online)

    assert reading.signals_settled is settled


# --- sysfs ---


def test_sysfs_reads_a_full_reading(tmp_path: Path) -> None:
    sysfs_tree(tmp_path)

    reading = SysfsBattery(root=tmp_path).read()

    assert reading == BatteryReading(
        capacity=76,
        status="Charging",
        ac_online=True,
        power_now=13651000,
        energy_now=43000000,
        energy_full=57000000,
    )


def test_sysfs_reads_an_offline_reading(tmp_path: Path) -> None:
    battery_dir = make_supply(
        tmp_path / "BAT0",
        kind="Battery",
        extra={"capacity": "76", "status": "Discharging", "power_now": "21898000"},
    )
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "0"})

    supplies = SysfsBattery(root=tmp_path)
    reading = supplies.read()

    assert reading.ac_online is False
    assert reading.status == "Discharging"
    assert supplies.battery_path == battery_dir


def test_sysfs_autodetects_nonstandard_names(tmp_path: Path) -> None:
    battery_dir = make_supply(
        tmp_path / "BATX",
        kind="Battery\n",
        extra={"capacity": "42", "status": "Full"},
    )
    ac_dir = make_supply(tmp_path / "AC1", kind="Mains", extra={"online": "1"})

    supplies = SysfsBattery(root=tmp_path)

    assert supplies.battery_path == battery_dir
    assert supplies.ac_path == ac_dir
    assert supplies.read().capacity == 42


def test_sysfs_prefers_bat0_over_other_batteries(tmp_path: Path) -> None:
    preferred = make_supply(
        tmp_path / "BAT0", kind="Battery", extra={"capacity": "10", "status": "Charging"}
    )
    make_supply(tmp_path / "BAT1", kind="Battery", extra={"capacity": "20", "status": "Charging"})
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    assert SysfsBattery(root=tmp_path).battery_path == preferred


def test_sysfs_accepts_explicit_paths(tmp_path: Path) -> None:
    battery_dir = make_supply(
        tmp_path / "custom-battery",
        kind="Battery",
        extra={"capacity": "33", "status": "Discharging"},
    )
    ac_dir = make_supply(tmp_path / "custom-ac", kind="Mains", extra={"online": "0"})

    reading = SysfsBattery(battery_path=battery_dir, ac_path=ac_dir).read()

    assert reading.capacity == 33
    assert reading.ac_online is False


def test_sysfs_missing_battery_directory_raises_a_typed_error(tmp_path: Path) -> None:
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    with pytest.raises(BatteryError, match="Battery"):
        SysfsBattery(root=tmp_path)


def test_sysfs_missing_file_raises_a_typed_error(tmp_path: Path) -> None:
    make_supply(tmp_path / "BAT0", kind="Battery", extra={"status": "Charging"})
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    supplies = SysfsBattery(root=tmp_path)
    with pytest.raises(BatteryError, match="capacity"):
        supplies.read()


def test_sysfs_unreadable_file_raises_a_typed_error(tmp_path: Path) -> None:
    battery_dir = make_supply(tmp_path / "BAT0", kind="Battery", extra={"status": "Charging"})
    # A directory where a file is expected is an unreadable "file" without
    # relying on file permissions (tests should not need to be non-root).
    (battery_dir / "capacity").mkdir()
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    supplies = SysfsBattery(root=tmp_path)
    with pytest.raises(BatteryError, match="capacity"):
        supplies.read()


def test_sysfs_non_integer_value_raises_a_typed_error(tmp_path: Path) -> None:
    make_supply(
        tmp_path / "BAT0",
        kind="Battery",
        extra={"capacity": "not-a-number", "status": "Charging"},
    )
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    supplies = SysfsBattery(root=tmp_path)
    with pytest.raises(BatteryError, match="capacity"):
        supplies.read()


def test_sysfs_missing_optional_energy_files_give_none(tmp_path: Path) -> None:
    battery_dir = make_supply(
        tmp_path / "BAT0", kind="Battery", extra={"capacity": "50", "status": "Charging"}
    )
    assert not (battery_dir / "power_now").exists()
    make_supply(tmp_path / "AC0", kind="Mains", extra={"online": "1"})

    reading = SysfsBattery(root=tmp_path).read()

    assert reading.power_now is None
    assert reading.energy_now is None
    assert reading.energy_full is None


# --- fake ---


def test_fake_battery_emits_the_scripted_reading_sequence() -> None:
    first = BatteryReading(capacity=24, status="Discharging", ac_online=False)
    second = BatteryReading(capacity=25, status="Charging", ac_online=True)
    fake = FakeBattery([first, second])

    assert fake.read() == first
    assert fake.read() == second
    # The last reading repeats so a controller can be driven to a stable state.
    assert fake.read() == second
    assert fake.read_count == 3


def test_fake_battery_can_be_scripted_incrementally() -> None:
    fake = FakeBattery()
    fake.script(BatteryReading(capacity=50, status="Charging", ac_online=True))

    assert fake.read().capacity == 50


def test_fake_battery_without_a_script_raises_a_typed_error() -> None:
    with pytest.raises(BatteryError):
        FakeBattery().read()


def test_sysfs_battery_satisfies_the_battery_source_protocol(tmp_path: Path) -> None:
    sysfs_tree(tmp_path)

    assert isinstance(FakeBattery(), battery.BatterySource)
    assert isinstance(SysfsBattery(root=tmp_path), battery.BatterySource)
