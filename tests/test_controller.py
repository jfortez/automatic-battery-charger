"""Tests for the pure hysteresis controller.

The controller is the highest-value piece of logic: it is pure, so the whole
decision table — thresholds, deadband, settling debounce and startup
reconciliation — is provable without any hardware.
"""

from __future__ import annotations

import pytest

from battery_charger.battery import BatteryReading
from battery_charger.controller import (
    Action,
    ControllerState,
    decide,
)

LOW = 25
HIGH = 85


def reading(
    capacity: int,
    *,
    status: str = "Charging",
    ac_online: bool = True,
    power_now: int | None = 14_000_000,
) -> BatteryReading:
    return BatteryReading(
        capacity=capacity,
        status=status,
        ac_online=ac_online,
        power_now=power_now,
        energy_now=50_000_000,
        energy_full=60_000_000,
    )


def on_reading(capacity: int) -> BatteryReading:
    return reading(capacity, status="Charging", ac_online=True)


def off_reading(capacity: int) -> BatteryReading:
    return reading(capacity, status="Discharging", ac_online=False)


# --- hysteresis ---


def test_startup_with_plug_on_above_the_high_threshold_turns_off() -> None:
    decision = decide(on_reading(86), True, LOW, HIGH, None)

    assert decision.action is Action.TURN_OFF
    assert "high threshold" in decision.reason
    assert "startup" in decision.reason


def test_startup_with_plug_on_exactly_at_the_high_threshold_turns_off() -> None:
    decision = decide(on_reading(HIGH), True, LOW, HIGH, None)

    assert decision.action is Action.TURN_OFF


def test_startup_with_plug_off_below_the_low_threshold_turns_on() -> None:
    decision = decide(off_reading(24), False, LOW, HIGH, None)

    assert decision.action is Action.TURN_ON
    assert "low threshold" in decision.reason
    assert "startup" in decision.reason


def test_startup_with_plug_off_exactly_at_the_low_threshold_turns_on() -> None:
    decision = decide(off_reading(LOW), False, LOW, HIGH, None)

    assert decision.action is Action.TURN_ON


def test_startup_inside_the_band_with_the_plug_on_does_nothing() -> None:
    decision = decide(on_reading(50), True, LOW, HIGH, None)

    assert decision.action is Action.NONE
    assert "inside the band" in decision.reason


def test_startup_inside_the_band_with_the_plug_off_does_nothing() -> None:
    decision = decide(off_reading(50), False, LOW, HIGH, None)

    assert decision.action is Action.NONE
    assert "inside the band" in decision.reason


def test_startup_below_low_with_the_plug_already_on_does_nothing() -> None:
    decision = decide(on_reading(20), True, LOW, HIGH, None)

    assert decision.action is Action.NONE
    assert "already ON" in decision.reason


def test_startup_above_high_with_the_plug_already_off_does_nothing() -> None:
    decision = decide(off_reading(90), False, LOW, HIGH, None)

    assert decision.action is Action.NONE
    assert "already OFF" in decision.reason


# --- unknown plug state ---


def test_startup_with_unknown_plug_state_below_low_turns_on() -> None:
    decision = decide(off_reading(20), None, LOW, HIGH, None)

    assert decision.action is Action.TURN_ON
    assert "unknown" in decision.reason


def test_startup_with_unknown_plug_state_above_high_turns_off() -> None:
    decision = decide(on_reading(90), None, LOW, HIGH, None)

    assert decision.action is Action.TURN_OFF
    assert "unknown" in decision.reason


def test_startup_with_unknown_plug_state_inside_the_band_does_nothing() -> None:
    decision = decide(off_reading(50), None, LOW, HIGH, None)

    assert decision.action is Action.NONE
    assert "inside the band" in decision.reason


# --- settling ---


def test_half_settled_reading_does_not_act_at_the_low_threshold() -> None:
    # Relay just closed: AC reports on but the battery status still says
    # Discharging. Acting on this single sample is the measured bug.
    half_settled = reading(20, status="Discharging", ac_online=True)

    decision = decide(half_settled, False, LOW, HIGH)

    assert decision.action is Action.NONE
    assert "half-settled" in decision.reason


def test_half_settled_reading_does_not_act_at_the_high_threshold() -> None:
    # Relay just opened: AC reports off but the battery status still says
    # Charging.
    half_settled = reading(90, status="Charging", ac_online=False)

    decision = decide(half_settled, True, LOW, HIGH)

    assert decision.action is Action.NONE
    assert "half-settled" in decision.reason


def test_a_half_settled_sample_resets_a_pending_crossing() -> None:
    pending = ControllerState(pending=Action.TURN_ON, pending_samples=1)
    half_settled = reading(20, status="Discharging", ac_online=True)

    decision = decide(half_settled, False, LOW, HIGH, pending)

    assert decision.action is Action.NONE
    assert decision.state.pending is None


def test_the_measured_half_settled_sequence_never_acts_on_its_own() -> None:
    # Measured on the real hardware: right after the relay opens, AC0/online
    # reads 0 while BAT0/status still reads "Charging" for about 1.2 s.
    startup = decide(on_reading(86), True, LOW, HIGH, None)
    assert startup.action is Action.TURN_OFF

    # The caller opens the relay; the very next sample is half-settled.
    half = decide(reading(86, status="Charging", ac_online=False), False, LOW, HIGH, startup.state)
    assert half.action is Action.NONE
    assert "half-settled" in half.reason

    # The status settles to Discharging; at 86% the plug must stay off.
    settled = decide(off_reading(86), False, LOW, HIGH, half.state)
    assert settled.action is Action.NONE

    # And once capacity falls back inside the band, still nothing.
    inside = decide(off_reading(80), False, LOW, HIGH, settled.state)
    assert inside.action is Action.NONE


def test_a_crossing_needs_consecutive_settled_readings_before_acting() -> None:
    first = decide(on_reading(86), True, LOW, HIGH, ControllerState())

    assert first.action is Action.NONE
    assert "waiting" in first.reason
    assert first.state.pending is Action.TURN_OFF
    assert first.state.pending_samples == 1

    second = decide(on_reading(86), True, LOW, HIGH, first.state)

    assert second.action is Action.TURN_OFF
    assert "confirmed" in second.reason


def test_settle_window_is_configurable() -> None:
    state = ControllerState()
    for expected_samples in (1, 2):
        decision = decide(on_reading(86), True, LOW, HIGH, state, settle_samples=3)
        assert decision.action is Action.NONE
        assert decision.state.pending_samples == expected_samples
        state = decision.state

    decision = decide(on_reading(86), True, LOW, HIGH, state, settle_samples=3)

    assert decision.action is Action.TURN_OFF


def test_returning_inside_the_band_resets_a_pending_crossing() -> None:
    first = decide(on_reading(86), True, LOW, HIGH, ControllerState())
    assert first.state.pending is Action.TURN_OFF

    inside = decide(on_reading(70), True, LOW, HIGH, first.state)

    assert inside.action is Action.NONE
    assert inside.state.pending is None

    again = decide(on_reading(86), True, LOW, HIGH, inside.state)

    assert again.action is Action.NONE
    assert again.state.pending_samples == 1


def test_startup_reconciliation_accepts_one_settled_reading() -> None:
    # Startup reconciles on one settled reading; the debounce guards later crossings.
    decision = decide(on_reading(90), True, LOW, HIGH, None)

    assert decision.action is Action.TURN_OFF
    # The returned state is not None, so the next crossing is debounced.
    assert decision.state.pending is None


# --- chatter ---


def test_no_relay_chatter_at_the_high_threshold() -> None:
    decision = decide(on_reading(86), True, LOW, HIGH, None)
    assert decision.action is Action.TURN_OFF
    state = decision.state

    # The plug is now off and the battery hovers around the threshold.
    for capacity in (84, 86, 85, 86, 84, 86):
        decision = decide(off_reading(capacity), False, LOW, HIGH, state)
        assert decision.action is Action.NONE, f"chattered at {capacity}%"
        state = decision.state


def test_no_relay_chatter_at_the_low_threshold() -> None:
    decision = decide(off_reading(24), False, LOW, HIGH, None)
    assert decision.action is Action.TURN_ON
    state = decision.state

    # The plug is now on and the battery hovers around the threshold.
    for capacity in (26, 24, 25, 24, 26, 24):
        decision = decide(on_reading(capacity), True, LOW, HIGH, state)
        assert decision.action is Action.NONE, f"chattered at {capacity}%"
        state = decision.state


def test_deadband_is_wide_so_a_single_threshold_never_toggles_both_ways() -> None:
    # One capacity value cannot produce both actions: 85% never turns the plug
    # on, 25% never turns it off.
    assert decide(on_reading(50), True, LOW, HIGH, None).action is Action.NONE
    assert decide(off_reading(50), False, LOW, HIGH, None).action is Action.NONE
    assert decide(on_reading(84), True, LOW, HIGH, None).action is Action.NONE
    assert decide(off_reading(26), False, LOW, HIGH, None).action is Action.NONE


# --- validation ---


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValueError):
        decide(on_reading(50), True, HIGH, LOW, None)
    with pytest.raises(ValueError):
        decide(on_reading(50), True, LOW, LOW, None)


def test_settle_samples_must_be_positive() -> None:
    with pytest.raises(ValueError):
        decide(on_reading(50), True, LOW, HIGH, None, settle_samples=0)
