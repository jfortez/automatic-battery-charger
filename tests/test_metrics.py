"""Metrics store: session lifecycle, energy direction and report rendering.

The store is the memory of the control loop. Two requirements drive these
tests: energy must never be integrated from the unsigned ``power_now`` (an
unknown value is stored as NULL, not zero), and an in-flight session must not
survive a daemon restart as an open row.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from battery_charger.battery import BatteryReading
from battery_charger.metrics import MetricsStore, default_metrics_path, render_report


def reading(
    capacity: int,
    *,
    status: str = "Charging",
    ac_online: bool = True,
    energy_now: int | None = None,
    power_now: int | None = None,
) -> BatteryReading:
    return BatteryReading(
        capacity=capacity,
        status=status,
        ac_online=ac_online,
        power_now=power_now,
        energy_now=energy_now,
        energy_full=60_000_000,
    )


def charging(capacity: int, *, energy_now: int | None = None) -> BatteryReading:
    return reading(capacity, energy_now=energy_now, power_now=14_000_000)


def discharging(capacity: int, *, energy_now: int | None = None) -> BatteryReading:
    return reading(
        capacity,
        status="Discharging",
        ac_online=False,
        energy_now=energy_now,
        power_now=21_000_000,
    )


@pytest.fixture
def store(tmp_path: Path):
    metrics = MetricsStore(tmp_path / "metrics.sqlite")
    yield metrics
    metrics.close()


# --- charge turns ---


def test_charge_turn_records_duration_capacity_and_energy(store: MetricsStore) -> None:
    store.observe(charging(40, energy_now=10_000_000), 1000.0)
    store.observe(charging(50, energy_now=12_500_000), 1600.0)
    store.observe(discharging(49, energy_now=12_400_000), 2200.0)

    turns = store.charge_turns()
    assert len(turns) == 1
    turn = turns[0]
    assert turn.started_at == 1000.0
    assert turn.ended_at == 2200.0
    assert turn.duration_s == 1200.0
    assert turn.start_capacity == 40
    assert turn.end_capacity == 49
    assert turn.energy_wh == pytest.approx(2.4)


def test_unknown_energy_is_null_not_zero(store: MetricsStore) -> None:
    # power_now is present but unsigned, so it must not be turned into energy.
    store.observe(charging(40, energy_now=None), 0.0)
    store.observe(charging(45, energy_now=None), 60.0)
    store.observe(discharging(44, energy_now=None), 120.0)

    turn = store.charge_turns()[0]
    assert turn.energy_wh is None


def test_energy_is_unknown_when_only_the_end_reading_has_it(store: MetricsStore) -> None:
    store.observe(charging(40, energy_now=None), 0.0)
    store.observe(discharging(41, energy_now=11_000_000), 60.0)

    assert store.charge_turns()[0].energy_wh is None


def test_a_full_battery_does_not_open_a_charge_turn(store: MetricsStore) -> None:
    store.observe(reading(100, status="Full"), 0.0)
    store.observe(reading(100, status="Full"), 60.0)

    assert store.charge_turns() == []
    assert store.discharge_periods() == []


# --- discharge periods ---


def test_discharge_period_records_duration_and_capacity_delta(store: MetricsStore) -> None:
    store.observe(discharging(60, energy_now=20_000_000), 0.0)
    store.observe(discharging(55, energy_now=18_000_000), 200.0)
    store.observe(charging(54, energy_now=17_900_000), 350.0)

    periods = store.discharge_periods()
    assert len(periods) == 1
    period = periods[0]
    assert period.started_at == 0.0
    assert period.ended_at == 350.0
    assert period.duration_s == 350.0
    assert period.start_capacity == 60
    assert period.end_capacity == 54
    assert period.capacity_delta == 6


# --- settling ---


def test_half_settled_readings_do_not_split_sessions(store: MetricsStore) -> None:
    store.observe(charging(40, energy_now=10_000_000), 0.0)
    # AC has flipped off but BAT0/status has not settled yet: not a real change.
    store.observe(reading(41, status="Charging", ac_online=False), 60.0)

    assert len(store.charge_turns()) == 1
    assert store.discharge_periods() == []

    store.observe(discharging(41, energy_now=10_100_000), 120.0)
    turn = store.charge_turns()[0]
    assert turn.ended_at == 120.0
    assert turn.duration_s == 120.0
    assert len(store.discharge_periods()) == 1


# --- restart survival ---


def test_close_open_sessions_closes_an_in_flight_charge_turn(tmp_path: Path) -> None:
    path = tmp_path / "metrics.sqlite"
    store = MetricsStore(path)
    store.observe(charging(40, energy_now=10_000_000), 0.0)
    store.close_open_sessions(500.0, reason="daemon restart")
    store.close()

    reopened = MetricsStore(path)
    try:
        turns = reopened.charge_turns()
        assert len(turns) == 1
        turn = turns[0]
        assert turn.ended_at == 500.0
        assert turn.duration_s == 500.0
        assert turn.end_capacity is None
        assert turn.energy_wh is None
        assert turn.close_reason == "daemon restart"
    finally:
        reopened.close()


def test_close_open_sessions_closes_an_in_flight_discharge_period(tmp_path: Path) -> None:
    path = tmp_path / "metrics.sqlite"
    store = MetricsStore(path)
    store.observe(discharging(60), 0.0)
    store.close_open_sessions(300.0, reason="daemon restart")
    store.close()

    reopened = MetricsStore(path)
    try:
        period = reopened.discharge_periods()[0]
        assert period.ended_at == 300.0
        assert period.end_capacity is None
    finally:
        reopened.close()


# --- plug transitions ---


def test_plug_transitions_are_recorded_with_the_controller_reason(store: MetricsStore) -> None:
    store.record_plug_transition(
        0.0, on=True, reason="capacity 20% is at or below the low threshold"
    )
    store.record_plug_transition(
        60.0, on=False, reason="capacity 90% is at or above the high threshold"
    )

    transitions = store.plug_transitions()
    assert [(item.at, item.on) for item in transitions] == [(0.0, True), (60.0, False)]
    assert "low threshold" in transitions[0].reason
    assert "high threshold" in transitions[1].reason


# --- report ---


def test_report_renders_daily_totals_and_per_turn_rows(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        now = datetime(2026, 10, 11, 12, 0, 0).timestamp()
        start = now - 7200
        store.record_plug_transition(start, on=True, reason="capacity 50% inside the band")
        store.observe(charging(50, energy_now=10_000_000), start)
        store.observe(charging(80, energy_now=15_000_000), start + 1800)
        store.observe(discharging(80, energy_now=15_000_000), start + 1800)
        store.observe(discharging(60, energy_now=12_000_000), start + 3600)
        store.record_plug_transition(start + 3600, on=False, reason="capacity 85%")

        text = render_report(store, days=1, now=now)
    finally:
        store.close()

    assert "2026-10-11" in text
    assert "Plugged" in text
    assert "1.0h" in text  # one hour with the plug on
    assert "0.5h" in text  # half an hour charging
    assert "0:30" in text  # the single, thus average and longest, turn
    assert "50-80%" in text
    assert "5.0Wh" in text
    assert "Charge turns" in text
    assert "50->80%" in text


def test_report_renders_the_note_column_for_a_turn_closed_with_a_reason(
    tmp_path: Path,
) -> None:
    # Only taken when some turn carries a close_reason, so it needs its own
    # coverage: it appends an extra cell to every row.
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        now = datetime(2026, 10, 11, 12, 0, 0).timestamp()
        start = now - 7200
        store.observe(charging(50, energy_now=10_000_000), start)
        store.close_open_sessions(start + 1800, reason="daemon restart")

        text = render_report(store, days=1, now=now)
    finally:
        store.close()

    assert "note" in text
    assert "daemon restart" in text


def test_report_says_when_there_is_no_data(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        text = render_report(store, days=7, now=datetime(2026, 10, 11, 12, 0, 0).timestamp())
    finally:
        store.close()

    assert "No activity recorded" in text


def test_report_shows_unknown_energy_as_a_dash(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        now = datetime(2026, 10, 11, 12, 0, 0).timestamp()
        store.observe(charging(40), now - 300)
        store.observe(discharging(39), now - 120)
        text = render_report(store, days=1, now=now)
    finally:
        store.close()

    assert "Charge turns" in text
    assert "-" in text
    assert "0.0Wh" not in text


# --- incidents ---


def test_store_opens_an_incident_and_reports_it_open(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        incident_id = store.record_incident_start(1000.0, 55, "device returned error 905")

        current = store.open_incident()
    finally:
        store.close()

    assert current is not None
    assert current.id == incident_id
    assert current.started_at == 1000.0
    assert current.start_capacity == 55
    assert current.start_error == "device returned error 905"
    assert current.ended_at is None
    assert current.duration_s is None
    assert current.end_capacity is None
    assert current.end_reason is None
    assert current.suspended_s == 0.0


def test_store_closes_an_incident_with_end_values_and_the_suspension(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        incident_id = store.record_incident_start(1000.0, 55, "device returned error 905")
        store.record_incident_end(
            incident_id,
            10_600.0,
            3,
            reason="connectivity restored",
            suspended_s=7200.0,
        )

        current = store.open_incident()
        incidents = store.incidents()
    finally:
        store.close()

    assert current is None
    (incident,) = incidents
    assert incident.ended_at == 10_600.0
    assert incident.duration_s == 9_600.0
    assert incident.end_capacity == 3
    assert incident.end_reason == "connectivity restored"
    assert incident.suspended_s == 7200.0


def test_store_lists_incidents_that_overlap_the_window(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        before = store.record_incident_start(0.0, 80, "first")
        store.record_incident_end(
            before, 100.0, 40, reason="connectivity restored", suspended_s=0.0
        )
        inside = store.record_incident_start(1_000.0, 40, "second")
        store.record_incident_end(
            inside, 2_000.0, 30, reason="connectivity restored", suspended_s=0.0
        )
        ongoing = store.record_incident_start(3_000.0, 30, "third")

        overlapping = store.incidents(since=500.0)
        everything = store.incidents()
    finally:
        store.close()

    assert [incident.id for incident in overlapping] == [inside, ongoing]
    assert [incident.id for incident in everything] == [before, inside, ongoing]


def test_report_renders_plug_unreachable_incidents(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        now = datetime(2026, 10, 14, 12, 0, 0).timestamp()
        start = now - 4 * 3600
        incident_id = store.record_incident_start(start, 55, "device returned error 905")
        store.record_incident_end(
            incident_id,
            start + 3 * 3600,
            1,
            reason="connectivity restored",
            suspended_s=2 * 3600,
        )

        text = render_report(store, days=1, now=now)
    finally:
        store.close()

    assert "Plug unreachable incidents" in text
    assert "2026-10-14 08:00:00" in text
    assert "3:00" in text
    assert "55->1%" in text
    assert "connectivity restored; machine suspended 2:00" in text


def test_report_shows_an_ongoing_incident_as_ongoing(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        now = datetime(2026, 10, 14, 12, 0, 0).timestamp()
        store.record_incident_start(now - 3600, 42, "device returned error 901")

        text = render_report(store, days=1, now=now)
    finally:
        store.close()

    assert "Plug unreachable incidents" in text
    assert "ongoing" in text
    assert "No activity recorded" not in text


# --- paths ---


def test_default_metrics_path_follows_xdg_state_home() -> None:
    assert default_metrics_path({"XDG_STATE_HOME": "/tmp/state"}) == Path(
        "/tmp/state/battery-charger/metrics.sqlite"
    )


def test_default_metrics_path_falls_back_to_home() -> None:
    path = default_metrics_path({"HOME": "/home/tester"})

    assert path == Path("/home/tester/.local/state/battery-charger/metrics.sqlite")
