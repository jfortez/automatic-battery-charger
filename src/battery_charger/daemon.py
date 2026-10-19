"""Poll loop joining battery, controller, plug and metrics store.

The control policy lives in :func:`battery_charger.controller.decide`; this
module owns the failure policy. Below the low threshold the relay is the only
thing that can save the machine, so retries stay at one per poll. Above the high
threshold they back off and are bounded, and inside the band the loop only
observes. A failed read never terminates the loop on its own.

Failed reads longer than ``incident_threshold_s`` open one reachability
incident, but only when the plug is on a local network: a network move is not an
outage. Machine suspension is measured from the end of the previous poll. No
exception escapes :meth:`Daemon.step` or :meth:`Daemon.run_forever`, and
shutdown returns the plug to OFF with a bounded wait.
"""

from __future__ import annotations

import contextlib
import ipaddress
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import FrameType

from .battery import BatteryError, BatteryReading, BatterySource
from .config import Config
from .controller import DEFAULT_SETTLE_SAMPLES, Action, ControllerState, decide
from .discovery import address_is_on_a_local_network
from .metrics import MetricsStore
from .plug import Plug, PlugError

# Distinct from the plug exit code 5: the daemon gave up controlling the plug.
EXIT_PLUG_UNREACHABLE = 6
SHUTDOWN_EXIT_CODE = 130
DEFAULT_HIGH_BATTERY_RETRY_BUDGET = 10
DEFAULT_SHUTDOWN_TIMEOUT = 20.0

# Jitter below this is not a suspension.
_SUSPENSION_TOLERANCE_S = 5.0


class StepResult(StrEnum):
    """How one poll iteration ended."""

    OK = "ok"
    DRY_RUN = "dry_run"
    BATTERY_READ_FAILED = "battery_read_failed"
    PLUG_UNREACHABLE = "plug_unreachable"
    TERMINATED = "terminated"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True)
class StepOutcome:
    """The observable result of one poll iteration."""

    result: StepResult
    reason: str
    action: Action | None = None
    delay_s: float = 0.0
    exit_code: int = 0


class Daemon:
    """One poll iteration at a time; :meth:`run_forever` joins them with backoff."""

    def __init__(
        self,
        battery: BatterySource,
        plug: Plug,
        store: MetricsStore | None,
        config: Config,
        *,
        poll_interval: float | None = None,
        low_battery_retry_budget: int | None = None,
        high_battery_retry_budget: int = DEFAULT_HIGH_BATTERY_RETRY_BUDGET,
        max_backoff_s: float | None = None,
        settle_samples: int = DEFAULT_SETTLE_SAMPLES,
        incident_threshold_s: int | None = None,
        local_network_check: Callable[[str], bool] | None = None,
        wall_clock: Callable[[], float] = time.time,
        emit: Callable[[str], None] = print,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT,
    ) -> None:
        interval = float(config.poll_interval if poll_interval is None else poll_interval)
        if interval <= 0:
            raise ValueError(f"poll_interval must be positive, got {interval}")
        if config.low_threshold >= config.high_threshold:
            raise ValueError(
                f"low_threshold ({config.low_threshold}) must be smaller than "
                f"high_threshold ({config.high_threshold})"
            )
        if low_battery_retry_budget is not None and low_battery_retry_budget < 1:
            raise ValueError("low_battery_retry_budget must be at least 1 or None")
        if high_battery_retry_budget < 1:
            raise ValueError("high_battery_retry_budget must be at least 1")
        if settle_samples < 1:
            raise ValueError(f"settle_samples must be at least 1, got {settle_samples}")
        incident_threshold = (
            config.incident_threshold_s if incident_threshold_s is None else incident_threshold_s
        )
        if incident_threshold < 0:
            raise ValueError(f"incident_threshold_s must not be negative, got {incident_threshold}")
        if shutdown_timeout <= 0:
            raise ValueError(f"shutdown_timeout must be positive, got {shutdown_timeout}")
        self._battery = battery
        self._plug = plug
        self._store = store
        self._low = config.low_threshold
        self._high = config.high_threshold
        self._poll_interval = interval
        self._low_battery_retry_budget = low_battery_retry_budget
        self._high_battery_retry_budget = high_battery_retry_budget
        self._max_backoff_s = float(max_backoff_s if max_backoff_s is not None else interval * 8)
        if self._max_backoff_s <= 0:
            raise ValueError(f"max_backoff_s must be positive, got {self._max_backoff_s}")
        self._settle_samples = settle_samples
        self._incident_threshold_s = int(incident_threshold)
        self._plug_address = config.device.ip.strip()
        self._local_network_check = local_network_check or address_is_on_a_local_network
        self._off_network_reported = False
        self._wall_clock = wall_clock
        self._emit = emit
        self._shutdown_timeout = shutdown_timeout
        self._controller_state: ControllerState | None = None
        self._pending_action: Action | None = None
        self._pending_reason = ""
        self._failure_streak = 0
        self._baseline_recorded = False
        self._last_plug_state: bool | None = None
        self._plug_error: str = ""
        self._unreachable_since: float | None = None
        self._unreachable_capacity: int | None = None
        self._unreachable_error = ""
        self._incident_id: int | None = None
        self._incident_started_at: float | None = None
        self._incident_start_capacity: int | None = None
        self._incident_suspended_s = 0.0
        self._incident_loaded = False
        self._last_step_end_at: float | None = None
        self._last_delay_s = 0.0
        self._previous_handlers: dict[signal.Signals, object] = {}

    # --- one poll ---

    def step(self, *, dry_run: bool = False) -> StepOutcome:
        """Perform exactly one poll iteration, never raising on an expected failure."""
        now = self._wall_clock()
        if not dry_run and not self._incident_loaded:
            self._incident_loaded = True
            self._load_open_incident()
        self._note_suspension(now)
        try:
            outcome = self._step(dry_run=dry_run)
        except Exception as exc:  # noqa: BLE001 - a crashed loop must stay visible, not fatal
            self._failure_streak += 1
            reason = f"unexpected failure in the control loop: {type(exc).__name__}: {exc}"
            self._log("ERROR", f"{reason}; continuing with the next poll")
            outcome = StepOutcome(StepResult.UNEXPECTED, reason, delay_s=self._retry_delay())
        self._last_step_end_at = self._wall_clock()
        self._last_delay_s = outcome.delay_s
        return outcome

    def _step(self, *, dry_run: bool) -> StepOutcome:
        now = self._wall_clock()
        try:
            reading = self._battery.read()
        except BatteryError as exc:
            self._failure_streak = 0
            self._log(
                "ERROR",
                f"battery read failed: {exc}; the plug is left as it is and the read is retried",
            )
            return StepOutcome(
                StepResult.BATTERY_READ_FAILED, str(exc), delay_s=self._poll_interval
            )

        self._observe(reading, now, dry_run=dry_run)
        plug_state = self._read_plug_state()
        self._track_plug_reachability(
            reading, now, reachable=plug_state is not None, dry_run=dry_run
        )
        if plug_state is not None and not self._baseline_recorded and not dry_run:
            self._record_transition(now, on=plug_state, reason="startup: observed the plug state")
            self._baseline_recorded = True

        decided = decide(
            reading,
            plug_state,
            self._low,
            self._high,
            self._controller_state,
            settle_samples=self._settle_samples,
        )
        self._controller_state = decided.state

        action = decided.action
        if (
            action is Action.NONE
            and decided.state.pending is not None
            and decided.state.pending is self._pending_action
        ):
            # Confirmed but not applied yet: keep trying until the plug answers.
            action = self._pending_action
        if decided.action is not Action.NONE:
            # Keep the confirming reason, not the pending text.
            self._pending_reason = decided.reason
        if action is not Action.NONE:
            self._pending_action = action
        elif decided.state.pending is None:
            self._pending_action = None
            self._pending_reason = ""

        if action is Action.NONE:
            self._failure_streak = 0
            suffix = "; dry run performs no relay write" if dry_run else ""
            if plug_state is None:
                self._log(
                    "WARNING",
                    f"plug unreachable: {self._plug_error}; decision: {decided.reason}; "
                    f"no action required, observing{suffix}",
                )
                return StepOutcome(
                    StepResult.PLUG_UNREACHABLE, decided.reason, delay_s=self._poll_interval
                )
            self._log("INFO", f"decision: {decided.reason}{suffix}")
            return StepOutcome(StepResult.OK, decided.reason, delay_s=self._poll_interval)

        if dry_run:
            target = "ON" if action is Action.TURN_ON else "OFF"
            reason = (
                f"dry run: would turn the plug {target} but writes no relay and records "
                f"nothing; decision: {decided.reason}"
            )
            self._log("INFO", reason)
            return StepOutcome(
                StepResult.DRY_RUN, reason, action=action, delay_s=self._poll_interval
            )

        if plug_state is not None and (plug_state == (action is Action.TURN_ON)):
            # The relay is already in the wanted position (e.g. a lost acknowledgement).
            self._pending_action = None
            self._pending_reason = ""
            self._failure_streak = 0
            self._log("INFO", f"decision: {decided.reason}; the relay was already in place")
            return StepOutcome(
                StepResult.OK, decided.reason, action=action, delay_s=self._poll_interval
            )

        try:
            if action is Action.TURN_ON:
                self._plug.turn_on()
            else:
                self._plug.turn_off()
        except PlugError as exc:
            return self._handle_plug_failure(action, reading, exc)
        except Exception as exc:  # noqa: BLE001 - an exotic plug failure is still a failure
            return self._handle_plug_failure(action, reading, exc)

        self._failure_streak = 0
        self._pending_action = None
        self._last_plug_state = action is Action.TURN_ON
        # A successful write proves reachability even when the read failed.
        self._track_plug_reachability(reading, self._wall_clock(), reachable=True, dry_run=dry_run)
        # Record the transition at the write moment, not at the poll's start.
        reason = self._pending_reason or decided.reason
        self._pending_reason = ""
        self._record_transition(self._wall_clock(), on=action is Action.TURN_ON, reason=reason)
        self._log(
            "INFO",
            f"plug turned {'ON' if action is Action.TURN_ON else 'OFF'}: {reason}",
        )
        return StepOutcome(
            StepResult.OK, decided.reason, action=action, delay_s=self._poll_interval
        )

    def _handle_plug_failure(
        self, action: Action, reading: BatteryReading, exc: Exception
    ) -> StepOutcome:
        self._failure_streak += 1
        # A failed write leaves the relay unknown; shutdown must try OFF.
        self._last_plug_state = None
        attempt = self._failure_streak
        delay = self._retry_delay(dangerous=action is Action.TURN_ON)
        if action is Action.TURN_ON:
            headline = (
                f"DANGEROUS: battery at {reading.capacity}% is at or below the low threshold "
                f"{self._low}% and the plug must be ON, but the attempt failed: {exc}"
            )
            budget = self._low_battery_retry_budget
            if budget is not None and attempt >= budget:
                reason = (
                    f"{headline}; gave up after {attempt} attempts; power could not be restored "
                    "(the battery will keep draining)"
                )
                self._log("ERROR", reason)
                return StepOutcome(
                    StepResult.TERMINATED,
                    reason,
                    action=action,
                    exit_code=EXIT_PLUG_UNREACHABLE,
                )
            suffix = f"attempt {attempt}" + (f"/{budget}" if budget is not None else "")
            self._log("ERROR", f"{headline}; {suffix}; retrying in {delay:.0f}s")
            return StepOutcome(StepResult.PLUG_UNREACHABLE, headline, action=action, delay_s=delay)

        headline = (
            f"battery at {reading.capacity}% is at or above the high threshold {self._high}% "
            f"and the plug must be OFF, but the attempt failed: {exc}"
        )
        if attempt >= self._high_battery_retry_budget:
            reason = (
                f"{headline}; giving up after {attempt} attempts; the laptop will keep charging"
            )
            self._log("ERROR", reason)
            return StepOutcome(
                StepResult.TERMINATED,
                reason,
                action=action,
                exit_code=EXIT_PLUG_UNREACHABLE,
            )
        self._log(
            "WARNING",
            f"{headline}; attempt {attempt}/{self._high_battery_retry_budget}; "
            f"retrying in {delay:.0f}s",
        )
        return StepOutcome(StepResult.PLUG_UNREACHABLE, headline, action=action, delay_s=delay)

    def _read_plug_state(self) -> bool | None:
        try:
            state = self._plug.is_on()
        except PlugError as exc:
            self._plug_error = str(exc)
            self._last_plug_state = None
            self._log("WARNING", f"plug read failed: {exc}")
            return None
        except Exception as exc:  # noqa: BLE001 - an exotic plug failure is still indeterminate
            self._plug_error = f"{type(exc).__name__}: {exc}"
            self._last_plug_state = None
            self._log("WARNING", f"plug read failed: {self._plug_error}")
            return None
        self._last_plug_state = state
        self._plug_error = ""
        return state

    # --- reachability incidents ---

    def _load_open_incident(self) -> None:
        """Adopt the incident a stopped daemon left open, if the store has one."""
        if self._store is None:
            return
        try:
            incident = self._store.open_incident()
        except Exception as exc:  # noqa: BLE001 - metrics must never stop battery control
            self._log("ERROR", f"metrics store could not read the open incident: {exc}")
            return
        if incident is None:
            return
        self._incident_id = incident.id
        self._incident_started_at = incident.started_at
        self._incident_start_capacity = incident.start_capacity
        self._incident_suspended_s = incident.suspended_s
        self._log(
            "INFO",
            f"adopted the open connectivity incident from "
            f"{self._format_time(incident.started_at)} (battery {incident.start_capacity}%)",
        )

    def _note_suspension(self, at: float) -> None:
        """Count wall-clock time beyond the sleep the loop last asked for.

        The machine suspending (on a drained battery, above all) freezes the
        process; the gap between polls is the only trace it leaves. The gap is
        measured from the **end** of the previous poll and the loop's own work
        is excluded, because two failed Tuya round trips can last longer than a
        poll interval and would otherwise be counted as a suspension.
        """
        if self._last_step_end_at is None or self._incident_id is None:
            return
        gap = at - self._last_step_end_at
        if gap <= self._last_delay_s + _SUSPENSION_TOLERANCE_S:
            return
        suspended = max(0.0, gap - self._last_delay_s)
        self._incident_suspended_s += suspended
        self._log(
            "INFO",
            f"{_human_seconds(suspended)} of unaccounted wall-clock time (the machine "
            "was suspended) is counted in the open connectivity incident",
        )

    def _track_plug_reachability(
        self, reading: BatteryReading, at: float, *, reachable: bool, dry_run: bool
    ) -> None:
        """Open or close the incident this poll's plug reachability implies."""
        if self._store is None or dry_run:
            return
        if reachable:
            self._close_incident_if_open(reading, at)
            return
        if not self._plug_is_expected_on_a_local_network():
            self._handle_off_network_unreachable(reading, at)
            return
        self._off_network_reported = False
        if self._unreachable_since is None:
            self._unreachable_since = at
            self._unreachable_capacity = reading.capacity
            self._unreachable_error = self._plug_error or "the plug did not answer"
            return
        if self._incident_id is not None:
            return
        elapsed = at - self._unreachable_since
        if elapsed < self._incident_threshold_s:
            return
        capacity = (
            self._unreachable_capacity
            if self._unreachable_capacity is not None
            else reading.capacity
        )
        try:
            self._incident_id = self._store.record_incident_start(
                self._unreachable_since, capacity, self._unreachable_error
            )
        except Exception as exc:  # noqa: BLE001 - metrics must never stop battery control
            self._log("ERROR", f"metrics store could not record the incident: {exc}")
            return
        self._incident_started_at = self._unreachable_since
        self._incident_start_capacity = capacity
        self._incident_suspended_s = 0.0
        self._log(
            "NOTICE",
            f"CONNECTIVITY INCIDENT: the plug has been unreachable for "
            f"{_human_seconds(elapsed)} (since {self._format_time(self._unreachable_since)}, "
            f"battery {capacity}%); first error: {self._unreachable_error}",
        )

    def _plug_topology_address(self) -> str:
        """The address that places the plug on a network: the one in use, if known.

        The configured IP is only a cache. Once the plug client has resolved the
        device (a stale address that stops answering is re-discovered by
        ``gwId``), that address is the truth, so the topology check follows the
        client instead of the config written days ago.
        """
        resolved = getattr(self._plug, "address", "")
        if isinstance(resolved, str) and resolved.strip():
            try:
                ipaddress.ip_address(resolved.strip())
            except ValueError:
                pass
            else:
                return resolved.strip()
        return self._plug_address

    def _plug_is_expected_on_a_local_network(self) -> bool:
        """Whether the plug address can be observed from here.

        An empty or unparseable address is unknown, never a reason to stop
        recording: only a valid address on no local subnet suppresses an
        incident, because then the laptop is provably on another network.
        """
        address = self._plug_topology_address()
        if not address:
            return True
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return True
        try:
            return bool(self._local_network_check(address))
        except Exception:  # noqa: BLE001 - topology knowledge must never stop control
            return True

    def _handle_off_network_unreachable(self, reading: BatteryReading, at: float) -> None:
        """Record nothing when the plug is simply not on this network.

        An incident already open is closed as unobserved: connectivity was not
        restored, the laptop left. A streak from the other network does not
        carry over, so returning to the plug's LAN starts a fresh threshold.
        """
        if self._incident_id is not None:
            self._close_incident_unobserved(reading, at)
            if self._incident_id is not None:
                return  # the store write failed; retry on the next poll
        self._unreachable_since = None
        self._unreachable_capacity = None
        self._unreachable_error = ""
        if not self._off_network_reported:
            self._log(
                "INFO",
                f"the plug address {self._plug_topology_address()} is not on any local "
                "network; its unreachability cannot be observed from here, so no "
                "connectivity incident is recorded",
            )
            self._off_network_reported = True

    def _close_incident_unobserved(self, reading: BatteryReading, at: float) -> None:
        """Close an open incident because the laptop left the plug's network."""
        if self._incident_id is None:
            return
        try:
            self._store.record_incident_end(
                self._incident_id,
                at,
                reading.capacity,
                reason="the laptop left the plug's network",
                suspended_s=self._incident_suspended_s,
            )
        except Exception as exc:  # noqa: BLE001 - the next poll retries the close
            self._log("ERROR", f"metrics store could not close the incident: {exc}")
            return
        started_at = self._incident_started_at
        duration = max(0.0, at - started_at) if started_at is not None else 0.0
        start_capacity = (
            self._incident_start_capacity
            if self._incident_start_capacity is not None
            else reading.capacity
        )
        notice = (
            f"CONNECTIVITY INCIDENT CLOSED UNOBSERVED: the plug address "
            f"{self._plug_topology_address()} is not on any local network, so the "
            f"incident cannot be observed to its end; recorded {_human_seconds(duration)}"
        )
        if started_at is not None:
            notice += f" (since {self._format_time(started_at)})"
        notice += f"; battery {start_capacity}% -> {reading.capacity}%"
        if self._incident_suspended_s > 0:
            notice += f"; machine suspended {_human_seconds(self._incident_suspended_s)}"
        self._reset_incident_tracking()
        self._log("NOTICE", notice)

    def _close_incident_if_open(self, reading: BatteryReading, at: float) -> None:
        if self._unreachable_since is not None and self._incident_id is None:
            self._reset_incident_tracking()
            return
        if self._incident_id is None:
            return
        try:
            self._store.record_incident_end(
                self._incident_id,
                at,
                reading.capacity,
                reason="connectivity restored",
                suspended_s=self._incident_suspended_s,
            )
        except Exception as exc:  # noqa: BLE001 - the next successful read retries
            self._log("ERROR", f"metrics store could not close the incident: {exc}")
            return
        started_at = self._incident_started_at
        duration = max(0.0, at - started_at) if started_at is not None else 0.0
        start_capacity = (
            self._incident_start_capacity
            if self._incident_start_capacity is not None
            else reading.capacity
        )
        notice = (
            f"CONNECTIVITY INCIDENT ENDED: the plug is reachable again after "
            f"{_human_seconds(duration)}"
        )
        if started_at is not None:
            notice += f" (since {self._format_time(started_at)})"
        notice += f"; battery {start_capacity}% -> {reading.capacity}%"
        if self._incident_suspended_s > 0:
            notice += f"; machine suspended {_human_seconds(self._incident_suspended_s)}"
        self._reset_incident_tracking()
        self._log("NOTICE", notice)

    def _reset_incident_tracking(self) -> None:
        self._unreachable_since = None
        self._unreachable_capacity = None
        self._unreachable_error = ""
        self._incident_id = None
        self._incident_started_at = None
        self._incident_start_capacity = None
        self._incident_suspended_s = 0.0
        self._off_network_reported = False

    # --- the loop ---

    def run_forever(
        self,
        *,
        dry_run: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        install_signals: bool = True,
    ) -> int:
        """Poll until terminated, interrupted or stopped; return a process exit code."""
        if install_signals:
            self._install_signal_handlers()
        self._close_sessions("daemon restart")
        try:
            while True:
                outcome = self.step(dry_run=dry_run)
                if outcome.result is StepResult.TERMINATED:
                    self._log("ERROR", f"terminating: {outcome.reason}")
                    self._close_sessions("daemon stopped")
                    return outcome.exit_code
                sleep(outcome.delay_s)
        except KeyboardInterrupt:
            self._log("WARNING", "interrupted; returning the plug to OFF")
            if dry_run:
                self._log("INFO", "dry run: no relay write on shutdown")
                self._close_sessions("daemon shutdown")
            else:
                self.shutdown()
            return SHUTDOWN_EXIT_CODE
        finally:
            if install_signals:
                self._restore_signal_handlers()

    def shutdown(self) -> bool:
        """Return the plug to OFF with a bounded wait; never hang forever.

        Returns whether the relay is known to be OFF. The call is bounded by
        ``shutdown_timeout`` because a stuck socket must not keep the process
        alive; if the wait expires the operator is told plainly that the plug
        may still be ON.
        """
        try:
            if self._last_plug_state is False and self._plug_error == "":
                self._log("INFO", "shutdown: the plug is already known OFF; nothing to do")
                return True
            if self._turned_off_within_timeout():
                self._last_plug_state = False
                self._log("INFO", "shutdown: the plug was turned OFF")
                return True
            return False
        finally:
            self._close_sessions("daemon shutdown")

    def _turned_off_within_timeout(self) -> bool:
        finished = threading.Event()
        outcome: dict[str, object] = {}

        def worker() -> None:
            try:
                self._plug.turn_off()
                outcome["ok"] = True
            except Exception as exc:  # noqa: BLE001 - reported below, never raised into the loop
                outcome["error"] = exc
            finally:
                finished.set()

        worker_thread = threading.Thread(target=worker, name="abc-shutdown", daemon=True)
        worker_thread.start()
        if not finished.wait(self._shutdown_timeout):
            self._log(
                "ERROR",
                f"shutdown: timed out after {self._shutdown_timeout:.0f}s waiting to turn the "
                "plug OFF; exiting anyway. The plug may still be ON - check it.",
            )
            return False
        if "error" in outcome:
            self._log(
                "ERROR",
                f"shutdown: could not turn the plug OFF ({outcome['error']}); "
                "the plug may still be ON - check it.",
            )
            return False
        return True

    # --- helpers ---

    def _retry_delay(self, *, dangerous: bool = False) -> float:
        if self._failure_streak == 0:
            return self._poll_interval
        if dangerous:
            # Racing the battery: a flat cadence wastes less of the remaining budget.
            return float(self._poll_interval)
        delay = self._poll_interval * (2 ** (self._failure_streak - 1))
        return float(min(delay, self._max_backoff_s))

    def _log(self, level: str, message: str) -> None:
        self._emit(f"{self._format_time(self._wall_clock())} {level} {message}")

    def _format_time(self, at: float) -> str:
        return datetime.fromtimestamp(at).strftime("%Y-%m-%d %H:%M:%S")

    def _observe(self, reading: BatteryReading, at: float, *, dry_run: bool) -> None:
        if self._store is None or dry_run:
            return
        try:
            self._store.observe(reading, at)
        except Exception as exc:  # noqa: BLE001 - metrics must never stop battery control
            self._log("ERROR", f"metrics store could not record the reading: {exc}")

    def _record_transition(self, at: float, *, on: bool, reason: str) -> None:
        if self._store is None:
            return
        try:
            self._store.record_plug_transition(at, on=on, reason=reason)
        except Exception as exc:  # noqa: BLE001 - metrics must never stop battery control
            self._log("ERROR", f"metrics store could not record the plug transition: {exc}")

    def _close_sessions(self, reason: str) -> None:
        if self._store is None:
            return
        try:
            self._store.close_open_sessions(self._wall_clock(), reason=reason)
        except Exception as exc:  # noqa: BLE001 - a failed close is reported, not fatal
            self._log("ERROR", f"metrics store could not close open sessions: {exc}")

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._previous_handlers[sig] = signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                # Not the main thread: Ctrl-C/SIGTERM still end the process,
                # just without this graceful path.
                continue

    def _restore_signal_handlers(self) -> None:
        for sig, handler in self._previous_handlers.items():
            with contextlib.suppress(ValueError, OSError, TypeError):
                signal.signal(sig, handler)  # type: ignore[arg-type]
        self._previous_handlers.clear()

    def _on_signal(self, _signum: int, _frame: FrameType | None) -> None:
        raise KeyboardInterrupt


def _human_seconds(seconds: float) -> str:
    """Format a duration for the notices: ``2h56m03s``, ``5m30s``, ``45s``."""
    total = max(0, int(round(seconds)))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"
