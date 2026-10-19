"""Pure hysteresis controller: decides the relay position, never touches it.

At or below the low threshold the plug must be ON, at or above the high
threshold it must be OFF, and inside the band the state is kept. A crossing is
acted on only after ``settle_samples`` consecutive settled readings; at startup
one settled reading is enough, and an unknown plug state never blocks a
battery-safety action.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .battery import BatteryReading

DEFAULT_SETTLE_SAMPLES = 2


class Action(StrEnum):
    TURN_ON = "turn_on"
    TURN_OFF = "turn_off"
    NONE = "none"


@dataclass(frozen=True)
class ControllerState:
    """Debounce bookkeeping carried between polls."""

    pending: Action | None = None
    pending_samples: int = 0


@dataclass(frozen=True)
class Decision:
    """The action to take, why, and the state to pass to the next call."""

    action: Action
    reason: str
    state: ControllerState


def decide(
    reading: BatteryReading,
    plug_state: bool | None,
    low_threshold: int,
    high_threshold: int,
    previous_state: ControllerState | None = None,
    *,
    settle_samples: int = DEFAULT_SETTLE_SAMPLES,
) -> Decision:
    if low_threshold >= high_threshold:
        raise ValueError(
            f"low_threshold ({low_threshold}) must be smaller than "
            f"high_threshold ({high_threshold})"
        )
    if settle_samples < 1:
        raise ValueError(f"settle_samples must be at least 1, got {settle_samples}")

    state_text = _plug_state_text(plug_state)
    if not reading.signals_settled:
        return Decision(
            Action.NONE,
            f"ignored half-settled reading for plug state {state_text}: "
            f"status={reading.status!r} and ac_online={reading.ac_online} disagree",
            ControllerState(),
        )

    crossing, reason = _crossing(reading, plug_state, low_threshold, high_threshold, state_text)
    if crossing is None:
        return Decision(Action.NONE, reason, ControllerState())

    if previous_state is None:
        return Decision(
            crossing,
            f"{reason}; startup reconciliation accepted one settled reading",
            ControllerState(),
        )

    count = previous_state.pending_samples + 1 if previous_state.pending is crossing else 1
    if count >= settle_samples:
        return Decision(
            crossing,
            f"{reason}; confirmed by {count} consecutive settled readings",
            ControllerState(),
        )
    return Decision(
        Action.NONE,
        f"{reason}; waiting for {count}/{settle_samples} consecutive settled readings",
        ControllerState(pending=crossing, pending_samples=count),
    )


def _crossing(
    reading: BatteryReading,
    plug_state: bool | None,
    low_threshold: int,
    high_threshold: int,
    state_text: str,
) -> tuple[Action | None, str]:
    """Return the threshold crossing the settled reading implies, if any."""
    capacity = reading.capacity
    if capacity <= low_threshold:
        if plug_state is True:
            return None, (
                f"capacity {capacity}% is at or below the low threshold {low_threshold}%"
                f" and the plug is already ON; nothing to do"
            )
        return (
            Action.TURN_ON,
            f"capacity {capacity}% is at or below the low threshold {low_threshold}%"
            f" with plug state {state_text}",
        )
    if capacity >= high_threshold:
        if plug_state is False:
            return None, (
                f"capacity {capacity}% is at or above the high threshold {high_threshold}%"
                f" and the plug is already OFF; nothing to do"
            )
        return (
            Action.TURN_OFF,
            f"capacity {capacity}% is at or above the high threshold {high_threshold}%"
            f" with plug state {state_text}",
        )
    return None, (
        f"capacity {capacity}% is inside the band ({low_threshold}-{high_threshold}%)"
        f" with plug state {state_text}; keeping the current plug state"
    )


def _plug_state_text(plug_state: bool | None) -> str:
    if plug_state is None:
        return "unknown"
    return "on" if plug_state else "off"
