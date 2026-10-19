"""Daemon loop: battery-aware failure policy, backoff and safe shutdown.

The failure policy is the point of T8. It is a function of battery state, not a
flat retry count: below the low threshold an unreachable plug is dangerous and
must be retried persistently; above the high threshold it is merely annoying and
bounded; inside the band nothing needs doing, so the loop keeps observing. An
indeterminate result alone must never terminate the loop.
"""

from __future__ import annotations

import threading
from pathlib import Path

from battery_charger.battery import BatteryReading, FakeBattery
from battery_charger.config import Config, DeviceConfig
from battery_charger.controller import Action
from battery_charger.daemon import (
    EXIT_PLUG_UNREACHABLE,
    SHUTDOWN_EXIT_CODE,
    Daemon,
    StepResult,
)
from battery_charger.metrics import MetricsStore
from battery_charger.plug import FakePlug, PlugError

LOW = 25
HIGH = 85


def reading(
    capacity: int,
    *,
    charging: bool = True,
    settled: bool = True,
    energy_now: int | None = None,
) -> BatteryReading:
    status = "Charging" if charging else "Discharging"
    ac_online = charging if settled else not charging
    return BatteryReading(
        capacity=capacity,
        status=status,
        ac_online=ac_online,
        power_now=14_000_000 if charging else 21_000_000,
        energy_now=energy_now,
        energy_full=60_000_000,
    )


def charging(capacity: int) -> BatteryReading:
    return reading(capacity)


def discharging(capacity: int) -> BatteryReading:
    return reading(capacity, charging=False)


class ExplodingBattery:
    """A battery source that fails in a way no code intended."""

    def read(self) -> BatteryReading:
        raise RuntimeError("boom")


class HangingPlug(FakePlug):
    """A plug whose turn_off never returns until the test releases it."""

    def __init__(self) -> None:
        super().__init__(initial_on=True)
        self.release = threading.Event()

    def turn_off(self) -> None:
        self.calls.append("turn_off")
        self.release.wait(5)


class Clock:
    """A clock the test moves by hand, so a poll and its write differ in time."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class SlowAckingPlug(FakePlug):
    """A plug whose successful write is acknowledged ``delay_s`` later."""

    def __init__(self, clock: Clock, *, delay_s: float) -> None:
        super().__init__(initial_on=False)
        self._clock = clock
        self._delay_s = delay_s

    def turn_on(self) -> None:
        super().turn_on()
        self._clock.now += self._delay_s


class SlowFailingPlug(FakePlug):
    """A plug whose failed Tuya round trips consume wall-clock time."""

    def __init__(self, clock: Clock, *, per_failure_s: float) -> None:
        super().__init__()
        self._clock = clock
        self._per_failure_s = per_failure_s

    def is_on(self) -> bool:
        try:
            return super().is_on()
        except PlugError:
            self._clock.now += self._per_failure_s
            raise

    def turn_off(self) -> None:
        try:
            super().turn_off()
        except PlugError:
            self._clock.now += self._per_failure_s
            raise


def make_daemon(
    *,
    readings: list[BatteryReading] | None = None,
    battery: object | None = None,
    plug: FakePlug | None = None,
    store: MetricsStore | None = None,
    device_ip: str = "",
    **kwargs: object,
) -> Daemon:
    config = Config(
        low_threshold=LOW,
        high_threshold=HIGH,
        poll_interval=30,
        device=DeviceConfig(ip=device_ip),
    )
    return Daemon(
        battery if battery is not None else FakeBattery(readings or [charging(50)]),
        plug if plug is not None else FakePlug(),
        store,
        config,
        **kwargs,
    )


def line_collector() -> tuple[list[str], object]:
    lines: list[str] = []
    return lines, lines.append


# --- normal actions ---


def test_low_battery_turns_the_plug_on_and_logs_the_controller_reason() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=False)
    daemon = make_daemon(readings=[discharging(20)], plug=plug, emit=emit)

    outcome = daemon.step()

    assert outcome.action is Action.TURN_ON
    assert outcome.result is StepResult.OK
    assert plug.is_on() is True
    assert any("low threshold" in line for line in lines)


def test_high_battery_turns_the_plug_off_and_logs_the_controller_reason() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    daemon = make_daemon(readings=[charging(90)], plug=plug, emit=emit)

    outcome = daemon.step()

    assert outcome.action is Action.TURN_OFF
    assert plug.is_on() is False
    assert any("high threshold" in line for line in lines)


def test_inside_the_band_does_nothing() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    daemon = make_daemon(readings=[charging(50)], plug=plug, emit=emit)

    outcome = daemon.step()

    assert outcome.action is None
    assert plug.calls == ["is_on"]
    assert any("inside the band" in line for line in lines)


def test_half_settled_reading_never_acts() -> None:
    plug = FakePlug(initial_on=False)
    daemon = make_daemon(readings=[reading(20, settled=False)], plug=plug)

    outcome = daemon.step()

    assert outcome.action is None
    assert plug.calls == ["is_on"]


def test_debounce_state_is_carried_between_steps() -> None:
    plug = FakePlug(initial_on=False)
    daemon = make_daemon(
        readings=[charging(50), charging(20), charging(20)],
        plug=plug,
    )

    daemon.step()  # inside the band
    waiting = daemon.step()  # first settled reading below the low threshold

    assert waiting.action is None
    assert "waiting for 1/2" in waiting.reason
    assert plug.calls == ["is_on", "is_on"]

    confirmed = daemon.step()

    assert confirmed.action is Action.TURN_ON
    assert plug.is_on() is True


# --- dangerous: low battery ---


def test_low_battery_with_unreachable_plug_retries_persistently_and_logs_every_attempt() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=False)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_on", times=50)
    daemon = make_daemon(readings=[discharging(20)], plug=plug, emit=emit)

    outcomes = [daemon.step() for _ in range(4)]

    assert not any(outcome.result is StepResult.TERMINATED for outcome in outcomes)
    assert all(outcome.result is StepResult.PLUG_UNREACHABLE for outcome in outcomes)
    attempts = [line for line in lines if "attempt" in line]
    assert len(attempts) == 4
    assert all("DANGEROUS" in line for line in attempts)
    assert all("low threshold" in line for line in attempts)


def test_low_battery_terminates_only_after_the_explicit_generous_budget() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=False)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_on", times=50)
    daemon = make_daemon(
        readings=[discharging(20)],
        plug=plug,
        emit=emit,
        low_battery_retry_budget=2,
    )

    first = daemon.step()
    final = daemon.step()

    assert first.result is StepResult.PLUG_UNREACHABLE
    assert final.result is StepResult.TERMINATED
    assert final.exit_code == EXIT_PLUG_UNREACHABLE
    assert "power could not be restored" in final.reason
    assert any("power could not be restored" in line for line in lines)


def test_a_smaller_high_battery_budget_does_not_bound_the_dangerous_case() -> None:
    plug = FakePlug(initial_on=False)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_on", times=50)
    daemon = make_daemon(
        readings=[discharging(20)],
        plug=plug,
        high_battery_retry_budget=1,
    )

    outcomes = [daemon.step() for _ in range(5)]

    assert not any(outcome.result is StepResult.TERMINATED for outcome in outcomes)


# --- annoying: high battery ---


def test_high_battery_with_unreachable_plug_terminates_after_bounded_retries() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_off", times=50)
    daemon = make_daemon(
        readings=[charging(90)],
        plug=plug,
        emit=emit,
        high_battery_retry_budget=3,
    )

    outcomes = [daemon.step() for _ in range(3)]

    assert outcomes[-1].result is StepResult.TERMINATED
    assert outcomes[-1].exit_code == EXIT_PLUG_UNREACHABLE
    assert "high threshold" in outcomes[-1].reason
    assert any("giving up" in line for line in lines)
    attempts = [line for line in lines if "attempt" in line]
    assert len(attempts) == 3


def test_high_battery_retry_budget_is_configurable() -> None:
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_off", times=50)
    daemon = make_daemon(
        readings=[charging(90)],
        plug=plug,
        high_battery_retry_budget=5,
    )

    outcomes = [daemon.step() for _ in range(5)]

    assert outcomes[-1].result is StepResult.TERMINATED


# --- inside the band ---


def test_inside_band_with_unreachable_plug_keeps_observing_without_terminating() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=3)
    daemon = make_daemon(readings=[charging(50)], plug=plug, emit=emit)

    outcomes = [daemon.step() for _ in range(3)]

    assert all(outcome.result is StepResult.PLUG_UNREACHABLE for outcome in outcomes)
    assert not any(outcome.result is StepResult.TERMINATED for outcome in outcomes)
    assert any("observing" in line.lower() for line in lines)
    assert any("plug" in line.lower() for line in lines)


def test_indeterminate_plug_reads_alone_never_terminate() -> None:
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=20)
    daemon = make_daemon(readings=[charging(50)], plug=plug)

    outcomes = [daemon.step() for _ in range(20)]

    assert not any(outcome.result is StepResult.TERMINATED for outcome in outcomes)


# --- observation failures ---


def test_battery_read_failure_is_visible_and_never_terminates() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    daemon = make_daemon(battery=FakeBattery(), plug=plug, emit=emit)

    outcomes = [daemon.step() for _ in range(3)]

    assert all(outcome.result is StepResult.BATTERY_READ_FAILED for outcome in outcomes)
    assert any("battery read failed" in line for line in lines)
    assert plug.calls == []  # nothing is actuated while the battery is unknown


def test_unexpected_exception_is_logged_and_does_not_escape() -> None:
    lines, emit = line_collector()
    daemon = make_daemon(battery=ExplodingBattery(), emit=emit)

    outcome = daemon.step()

    assert outcome.result is StepResult.UNEXPECTED
    assert any("RuntimeError" in line and "boom" in line for line in lines)


# --- backoff ---


def test_dangerous_retry_cadence_stays_flat_instead_of_backing_off() -> None:
    # Racing the battery: a growing wait spends the remaining budget.
    plug = FakePlug(initial_on=False)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_on", times=50)
    daemon = make_daemon(readings=[discharging(20)], plug=plug, max_backoff_s=240)

    delays = [daemon.step().delay_s for _ in range(6)]

    assert delays == [30, 30, 30, 30, 30, 30]


def test_annoying_retry_cadence_still_backs_off_and_is_capped() -> None:
    # Above the high threshold nothing is urgent, so the wait still grows to
    # spare a plug that may be rejoining the network.
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_off", times=50)
    daemon = make_daemon(readings=[charging(90)], plug=plug, max_backoff_s=240)

    delays = [daemon.step().delay_s for _ in range(6)]

    assert delays == [30, 60, 120, 240, 240, 240]


def test_successful_control_resets_the_backoff() -> None:
    plug = FakePlug(initial_on=False)
    plug.fail_next("turn_on", times=1)
    daemon = make_daemon(readings=[discharging(20)], plug=plug)

    failed = daemon.step()
    recovered = daemon.step()

    assert failed.delay_s == 30
    assert recovered.result is StepResult.OK
    assert recovered.delay_s == 30
    assert plug.is_on() is True


# --- dry run ---


def test_dry_run_never_writes_the_relay_or_the_store(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        plug = FakePlug(initial_on=False)
        daemon = make_daemon(readings=[discharging(20)], plug=plug, store=store)

        outcome = daemon.step(dry_run=True)

        assert outcome.result is StepResult.DRY_RUN
        assert outcome.action is Action.TURN_ON
        assert plug.calls == ["is_on"]
        assert store.charge_turns() == []
        assert store.discharge_periods() == []
        assert store.plug_transitions() == []
        assert store.incidents() == []
    finally:
        store.close()


def test_dry_run_says_so_even_when_no_action_is_needed() -> None:
    lines, emit = line_collector()
    daemon = make_daemon(readings=[charging(50)], plug=FakePlug(initial_on=True), emit=emit)

    outcome = daemon.step(dry_run=True)

    assert outcome.result is StepResult.OK
    assert any("dry run" in line for line in lines)


# --- shutdown ---


def test_shutdown_turns_the_plug_off() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=True)
    daemon = make_daemon(plug=plug, emit=emit)

    assert daemon.shutdown() is True

    assert plug.is_on() is False
    assert any("OFF" in line for line in lines)


def test_shutdown_does_not_trust_a_stale_off_after_a_failed_write() -> None:
    plug = FakePlug(initial_on=False)
    plug.fail_next("turn_on", times=1)
    daemon = make_daemon(readings=[discharging(20)], plug=plug)
    daemon.step()  # the read said OFF, but the turn_on write failed: position unknown

    daemon.shutdown()

    assert "turn_off" in plug.calls


def test_shutdown_is_not_hung_by_a_stuck_plug() -> None:
    lines, emit = line_collector()
    plug = HangingPlug()
    daemon = make_daemon(plug=plug, emit=emit, shutdown_timeout=0.05)

    try:
        assert daemon.shutdown() is False
        assert any("timed out" in line for line in lines)
    finally:
        plug.release.set()


# --- run_forever ---


def test_run_forever_returns_the_termination_exit_code() -> None:
    plug = FakePlug(initial_on=True)
    plug.fail_next("is_on", times=50)
    plug.fail_next("turn_off", times=50)
    daemon = make_daemon(
        readings=[charging(90)],
        plug=plug,
        high_battery_retry_budget=2,
    )
    sleeps: list[float] = []

    code = daemon.run_forever(sleep=sleeps.append, install_signals=False)

    assert code == EXIT_PLUG_UNREACHABLE
    assert sleeps == [30]


def test_run_forever_on_interrupt_returns_the_plug_to_off() -> None:
    lines, emit = line_collector()
    plug = FakePlug(initial_on=False)
    daemon = make_daemon(readings=[discharging(20)], plug=plug, emit=emit)

    def interrupt(_seconds: float) -> None:
        raise KeyboardInterrupt

    code = daemon.run_forever(sleep=interrupt, install_signals=False)

    assert code == SHUTDOWN_EXIT_CODE
    assert plug.is_on() is False
    assert any("interrupted" in line.lower() for line in lines)


def test_run_forever_closes_in_flight_sessions_from_a_previous_run(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        store.observe(charging(40), 0.0)
        store.close()

        store = MetricsStore(tmp_path / "metrics.sqlite")
        plug = FakePlug(initial_on=True)
        daemon = make_daemon(readings=[charging(50)], plug=plug, store=store)

        def interrupt(_seconds: float) -> None:
            raise KeyboardInterrupt

        code = daemon.run_forever(sleep=interrupt, install_signals=False)

        turns = store.charge_turns()
        assert code == SHUTDOWN_EXIT_CODE
        assert turns[0].close_reason == "daemon restart"
        assert turns[-1].close_reason == "daemon shutdown"
    finally:
        store.close()


# --- store wiring ---


def test_successful_action_is_recorded_with_the_controller_reason(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        plug = FakePlug(initial_on=False)
        daemon = make_daemon(readings=[discharging(20)], plug=plug, store=store)

        daemon.step()

        transitions = store.plug_transitions()
        assert [item.on for item in transitions] == [False, True]
        assert "startup" in transitions[0].reason
        assert "low threshold" in transitions[1].reason
        periods = store.discharge_periods()
        assert len(periods) == 1
    finally:
        store.close()


# --- connectivity incidents ---


def test_brief_plug_flap_below_the_threshold_records_no_incident(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=2)
    try:
        daemon = make_daemon(
            readings=[charging(50)],
            plug=plug,
            store=store,
            wall_clock=clock,
            incident_threshold_s=300,
        )

        daemon.step()  # the plug stops answering at 1000
        clock.now += 30
        daemon.step()  # still silent, only 30 s
        clock.now += 30
        daemon.step()  # answers again before the 300 s threshold

        assert store.incidents() == []
    finally:
        store.close()


def test_unreachable_past_the_threshold_records_the_incident_from_the_first_failure(
    tmp_path: Path,
) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=4)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
        )

        daemon.step()  # the first failed read at 1000
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()  # 60 s unreachable: the threshold is crossed
        clock.now += 30
        daemon.step()  # already inside the incident: no second row, no second notice

        current = store.open_incident()
        incidents = store.incidents()
    finally:
        store.close()

    assert current is not None
    assert current.started_at == 1000.0, "the first failure, not the detection moment"
    assert current.start_capacity == 55
    assert "injected failure" in current.start_error
    assert len(incidents) == 1
    notices = [line for line in lines if "CONNECTIVITY INCIDENT" in line]
    assert len(notices) == 1
    assert "NOTICE" in notices[0]
    assert "1m00s" in notices[0]


def test_returning_connectivity_closes_the_incident_and_emits_one_notice(tmp_path: Path) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=3)
    try:
        daemon = make_daemon(
            readings=[charging(55), charging(55), charging(55), charging(3)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
        )

        daemon.step()
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()  # the incident opens at 1060
        clock.now += 90
        daemon.step()  # the plug answers again at 1150, battery at 3%

        assert store.open_incident() is None
        (incident,) = store.incidents()
    finally:
        store.close()

    assert incident.duration_s == 150.0
    assert incident.end_capacity == 3
    assert incident.end_reason == "connectivity restored"
    ended = [line for line in lines if "CONNECTIVITY INCIDENT ENDED" in line]
    assert len(ended) == 1
    assert "55% -> 3%" in ended[0]
    assert "2m30s" in ended[0]


def test_a_daemon_restart_adopts_and_closes_an_open_incident(tmp_path: Path) -> None:
    lines, emit = line_collector()
    path = tmp_path / "metrics.sqlite"
    store = MetricsStore(path)
    store.record_incident_start(1000.0, 55, "device returned error 905")
    store.close()

    store = MetricsStore(path)
    clock = Clock(4000.0)
    try:
        daemon = make_daemon(
            readings=[charging(30)],
            plug=FakePlug(initial_on=True),
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=300,
        )

        daemon.step()

        assert store.open_incident() is None
        (incident,) = store.incidents()
    finally:
        store.close()

    assert incident.ended_at == 4000.0
    assert incident.duration_s == 3000.0
    assert incident.end_reason == "connectivity restored"
    assert any("CONNECTIVITY INCIDENT ENDED" in line for line in lines)


def test_shutdown_leaves_an_open_incident_for_the_next_daemon(tmp_path: Path) -> None:
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=3)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            wall_clock=clock,
            incident_threshold_s=60,
        )
        daemon.step()
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()  # the incident is open

        daemon.shutdown()

        assert store.open_incident() is not None
        assert len(store.incidents()) == 1
    finally:
        store.close()


def test_dry_run_records_no_incident_even_with_a_silent_plug(tmp_path: Path) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    plug = FakePlug()
    plug.fail_next("is_on", times=10)
    try:
        daemon = make_daemon(
            readings=[charging(50)],
            plug=plug,
            store=store,
            emit=emit,
            incident_threshold_s=0,
        )

        daemon.step(dry_run=True)

        assert store.incidents() == []
        assert store.open_incident() is None
    finally:
        store.close()

    assert not any("CONNECTIVITY INCIDENT" in line for line in lines)


def test_unreachable_plug_off_the_local_networks_opens_no_incident(tmp_path: Path) -> None:
    # A network move is a topology fact, not an outage.
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=10)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
            device_ip="192.168.50.10",
            local_network_check=lambda address: False,
        )
        for _ in range(4):
            daemon.step()
            clock.now += 30
        assert store.incidents() == []
    finally:
        store.close()

    assert not any("CONNECTIVITY INCIDENT" in line for line in lines)
    explained = [line for line in lines if "not on any local network" in line]
    assert len(explained) == 1, "one explanation per off-network streak"
    assert "192.168.50.10" in explained[0]


def test_the_topology_gate_uses_the_address_the_plug_client_resolved(tmp_path: Path) -> None:
    # The configured IP is only a cache: use the address the client resolved.
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug(address="192.168.1.100")
    plug.fail_next("is_on", times=4)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
            device_ip="192.168.50.10",
            local_network_check=lambda address: address == "192.168.1.100",
        )
        daemon.step()
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()
        assert store.open_incident() is not None
    finally:
        store.close()

    assert any("CONNECTIVITY INCIDENT:" in line for line in lines)


def test_unreachable_plug_on_a_local_network_still_records_the_incident(tmp_path: Path) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=4)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
            device_ip="192.168.50.10",
            local_network_check=lambda address: True,
        )
        daemon.step()
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()
        assert store.open_incident() is not None
    finally:
        store.close()

    assert any("CONNECTIVITY INCIDENT:" in line for line in lines)


def test_an_open_incident_is_closed_unobserved_when_the_laptop_leaves_the_plug_network(
    tmp_path: Path,
) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    store.record_incident_start(1000.0, 55, "device returned error 905")
    clock = Clock(2_000.0)
    plug = FakePlug()
    plug.fail_next("is_on", times=1)
    try:
        daemon = make_daemon(
            readings=[charging(50)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            device_ip="192.168.50.10",
            local_network_check=lambda address: False,
        )
        daemon.step()
        assert store.open_incident() is None
        (incident,) = store.incidents()
    finally:
        store.close()

    assert incident.ended_at == 2_000.0
    assert incident.duration_s == 1_000.0
    assert incident.end_capacity == 50
    assert incident.end_reason == "the laptop left the plug's network"
    closed = [line for line in lines if "CONNECTIVITY INCIDENT" in line]
    assert len(closed) == 1
    assert "CLOSED UNOBSERVED" in closed[0]
    assert "ENDED" not in closed[0]


def test_a_suspension_during_an_incident_is_measured_and_recorded(tmp_path: Path) -> None:
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = FakePlug()
    plug.fail_next("is_on", times=4)
    try:
        daemon = make_daemon(
            readings=[charging(55)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=60,
        )

        daemon.step()  # 1000, the first failed read
        clock.now += 30
        daemon.step()
        clock.now += 30
        daemon.step()  # 1060, the incident opens
        clock.now += 7200  # the machine suspends for two hours
        daemon.step()  # 8260, still unreachable
        clock.now += 30
        daemon.step()  # 8290, the plug answers again

        (incident,) = store.incidents()
    finally:
        store.close()

    assert incident.suspended_s == 7170.0, "two hours minus the sleep the loop asked for"
    assert incident.duration_s == 7290.0
    ended = [line for line in lines if "CONNECTIVITY INCIDENT ENDED" in line]
    assert len(ended) == 1
    assert "machine suspended 1h59m30s" in ended[0]


def test_a_slow_poll_after_a_long_backoff_is_not_counted_as_a_machine_suspension(
    tmp_path: Path,
) -> None:
    # The loop's own Tuya timeouts are not machine suspension.
    lines, emit = line_collector()
    store = MetricsStore(tmp_path / "metrics.sqlite")
    clock = Clock()
    plug = SlowFailingPlug(clock, per_failure_s=20.0)
    plug.fail_next("is_on", times=6)
    plug.fail_next("turn_off", times=6)
    try:
        daemon = make_daemon(
            readings=[charging(90)],
            plug=plug,
            store=store,
            emit=emit,
            wall_clock=clock,
            incident_threshold_s=0,
        )
        delays = []
        for _ in range(6):
            outcome = daemon.step()
            delays.append(outcome.delay_s)
            clock.now += outcome.delay_s  # exactly the sleep the loop asked for
        recovered = daemon.step()  # the plug answers again and closes the incident
        (incident,) = store.incidents()
    finally:
        store.close()

    assert delays == [30, 60, 120, 240, 240, 240]
    assert recovered.result is StepResult.OK
    assert incident.suspended_s == 0.0, "the loop's own Tuya timeouts are not a suspension"
    assert not any("suspended" in line for line in lines)


def test_transition_is_recorded_at_the_write_moment_with_the_confirming_reason(
    tmp_path: Path,
) -> None:
    # Record the write moment and the confirming reason, even if the ack was lost.
    store = MetricsStore(tmp_path / "metrics.sqlite")
    try:
        clock = Clock()
        plug = SlowAckingPlug(clock, delay_s=19.0)
        plug.fail_next("is_on", times=50)
        plug.fail_next("turn_on", times=1)
        daemon = make_daemon(readings=[discharging(20)], plug=plug, store=store, wall_clock=clock)

        first = daemon.step()
        clock.now += 240.0
        poll_start = clock.now
        second = daemon.step()

        assert first.result is StepResult.PLUG_UNREACHABLE
        assert second.result is StepResult.OK
        written = store.plug_transitions()[-1]
        assert written.on is True
        assert written.at == poll_start + 19.0, "the write moment, not the poll's start"
        assert "low threshold" in written.reason
        assert "waiting for" not in written.reason, "the reason that confirmed the write"
    finally:
        store.close()
