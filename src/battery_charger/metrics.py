"""SQLite metrics store and the plain-text report.

Four tables: charge turns, discharge periods, plug transitions and plug
reachability incidents. ``power_now`` is unsigned, so energy comes from
``energy_now`` differences and direction from the battery status. Sessions only
start or close on settled readings; a session left open by a stopped daemon is
closed at startup with NULL end values.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from datetime import time as clock_time
from pathlib import Path

from .battery import BatteryReading

APP_DIR_NAME = "battery-charger"
METRICS_FILE_NAME = "metrics.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS charge_turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    duration_s REAL,
    start_capacity INTEGER NOT NULL,
    end_capacity INTEGER,
    start_energy_wh REAL,
    energy_wh REAL,
    close_reason TEXT
);
CREATE TABLE IF NOT EXISTS discharge_periods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    duration_s REAL,
    start_capacity INTEGER NOT NULL,
    end_capacity INTEGER,
    capacity_delta INTEGER,
    close_reason TEXT
);
CREATE TABLE IF NOT EXISTS plug_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    is_on INTEGER NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plug_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    duration_s REAL,
    start_capacity INTEGER NOT NULL,
    end_capacity INTEGER,
    start_error TEXT NOT NULL,
    end_reason TEXT,
    suspended_s REAL NOT NULL DEFAULT 0
);
"""


def default_metrics_path(env: Mapping[str, str] | None = None) -> Path:
    """Return ``$XDG_STATE_HOME/battery-charger/metrics.sqlite`` or the home default."""
    environ = env if env is not None else os.environ
    xdg_state_home = environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        base = Path(xdg_state_home)
    else:
        base = Path(environ.get("HOME", "~")).expanduser() / ".local" / "state"
    return base / APP_DIR_NAME / METRICS_FILE_NAME


@dataclass(frozen=True)
class ChargeTurn:
    """One recorded charge turn."""

    id: int
    started_at: float
    ended_at: float | None
    duration_s: float | None
    start_capacity: int
    end_capacity: int | None
    energy_wh: float | None
    close_reason: str | None


@dataclass(frozen=True)
class DischargePeriod:
    """One recorded discharge period."""

    id: int
    started_at: float
    ended_at: float | None
    duration_s: float | None
    start_capacity: int
    end_capacity: int | None
    capacity_delta: int | None
    close_reason: str | None


@dataclass(frozen=True)
class PlugTransition:
    """One plug state event, with the controller's reason."""

    id: int
    at: float
    on: bool
    reason: str


@dataclass(frozen=True)
class PlugIncident:
    """One stretch during which the plug did not answer, with both battery ends."""

    id: int
    started_at: float
    ended_at: float | None
    duration_s: float | None
    start_capacity: int
    end_capacity: int | None
    start_error: str
    end_reason: str | None
    suspended_s: float


@dataclass(frozen=True)
class DailySummary:
    """Totals for one calendar day (local time) inside the report window."""

    day: date
    plugged_seconds: float
    charging_seconds: float
    discharging_seconds: float
    turns: int
    avg_turn_seconds: float | None
    longest_turn_seconds: float | None
    energy_wh: float | None
    band_min: int | None
    band_max: int | None


class MetricsStore:
    """Thin SQLite wrapper that turns battery observations into sessions.

    The session lifecycle lives in :meth:`observe`: a settled reading is enough
    to open a turn or period, and the transition out of one closes it and opens
    the other. Sessions are found in the database rather than in memory, so a
    restart cannot lose track of an in-flight row.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.executescript(_SCHEMA)

    def __enter__(self) -> MetricsStore:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Commit and close the database connection."""
        self._connection.close()

    # --- writes ---

    def observe(self, reading: BatteryReading, at: float) -> None:
        """Fold one battery reading into the recorded sessions.

        Half-settled readings are ignored: acting on them is what the
        controller's debounce exists to prevent, and recording them would split
        a turn at the relay transition.
        """
        if not reading.signals_settled:
            return
        open_turn = self._open_charge_turn()
        open_period = self._open_discharge_period()
        if reading.is_charging:
            if open_period is not None:
                self._close_discharge_period(open_period, reading, at)
            if open_turn is None:
                self._open_charge_turn_row(reading, at)
        elif reading.status == "Discharging":
            if open_turn is not None:
                self._close_charge_turn(open_turn, reading, at)
            if open_period is None:
                self._open_discharge_period_row(reading, at)
        else:
            if open_turn is not None:
                self._close_charge_turn(open_turn, reading, at)
            if open_period is not None:
                self._close_discharge_period(open_period, reading, at)

    def record_plug_transition(self, at: float, *, on: bool, reason: str) -> None:
        """Record a plug state event with the reason the controller gave."""
        with self._connection:
            self._connection.execute(
                "INSERT INTO plug_transitions (at, is_on, reason) VALUES (?, ?, ?)",
                (at, 1 if on else 0, reason),
            )

    def record_incident_start(self, at: float, capacity: int, error: str) -> int:
        """Open a plug-reachability incident and return its row id.

        ``at`` is the first failed read of the streak, not the moment the
        threshold was crossed; the row therefore measures the real outage.
        """
        with self._connection:
            cursor = self._connection.execute(
                "INSERT INTO plug_incidents (started_at, start_capacity, start_error) "
                "VALUES (?, ?, ?)",
                (at, capacity, error),
            )
        return int(cursor.lastrowid or 0)

    def record_incident_end(
        self,
        incident_id: int,
        at: float,
        capacity: int,
        *,
        reason: str,
        suspended_s: float = 0.0,
    ) -> None:
        """Close an incident at the poll that saw the plug answer again."""
        with self._connection:
            self._connection.execute(
                "UPDATE plug_incidents SET ended_at = ?, duration_s = MAX(0, ? - started_at), "
                "end_capacity = ?, end_reason = ?, suspended_s = ? WHERE id = ?",
                (at, at, capacity, reason, suspended_s, incident_id),
            )

    def close_open_sessions(self, at: float, *, reason: str = "daemon restart") -> int:
        """Close every open session, leaving unknown end values NULL.

        Returns the number of rows closed. Called at daemon startup so a kill
        cannot leave a row open forever, and at shutdown for an honest end time.
        """
        closed = 0
        with self._connection:
            for table in ("charge_turns", "discharge_periods"):
                rows = self._connection.execute(
                    f"SELECT * FROM {table} WHERE ended_at IS NULL"  # fixed table names
                ).fetchall()
                for row in rows:
                    duration = max(0.0, at - row["started_at"])
                    self._connection.execute(
                        f"UPDATE {table} SET ended_at = ?, duration_s = ?, "
                        "close_reason = ? WHERE id = ?",
                        (at, duration, reason, row["id"]),
                    )
                    closed += 1
        return closed

    # --- reads ---

    def charge_turns(self, *, since: float | None = None) -> list[ChargeTurn]:
        """Return recorded charge turns, oldest first."""
        query = "SELECT * FROM charge_turns"
        parameters: list[object] = []
        if since is not None:
            query += " WHERE started_at >= ?"
            parameters.append(since)
        query += " ORDER BY id"
        return [_charge_turn(row) for row in self._connection.execute(query, parameters)]

    def discharge_periods(self, *, since: float | None = None) -> list[DischargePeriod]:
        """Return recorded discharge periods, oldest first."""
        query = "SELECT * FROM discharge_periods"
        parameters: list[object] = []
        if since is not None:
            query += " WHERE started_at >= ?"
            parameters.append(since)
        query += " ORDER BY id"
        return [_discharge_period(row) for row in self._connection.execute(query, parameters)]

    def plug_transitions(self, *, since: float | None = None) -> list[PlugTransition]:
        """Return recorded plug state events, oldest first."""
        query = "SELECT * FROM plug_transitions"
        parameters: list[object] = []
        if since is not None:
            query += " WHERE at >= ?"
            parameters.append(since)
        query += " ORDER BY id"
        return [_plug_transition(row) for row in self._connection.execute(query, parameters)]

    def open_incident(self) -> PlugIncident | None:
        """Return the incident a stopped daemon left open, if any."""
        row = self._connection.execute(
            "SELECT * FROM plug_incidents WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return None if row is None else _plug_incident(row)

    def incidents(
        self, *, since: float | None = None, until: float | None = None
    ) -> list[PlugIncident]:
        """Return incidents overlapping the window, oldest first.

        An incident overlaps when it ended at or after ``since`` (an incident
        still open always does) and started at or before ``until``.
        """
        query = "SELECT * FROM plug_incidents"
        clauses: list[str] = []
        parameters: list[object] = []
        if since is not None:
            clauses.append("(ended_at IS NULL OR ended_at >= ?)")
            parameters.append(since)
        if until is not None:
            clauses.append("started_at <= ?")
            parameters.append(until)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        return [_plug_incident(row) for row in self._connection.execute(query, parameters)]

    def daily_summary(self, *, days: int = 7, now: float | None = None) -> list[DailySummary]:
        """Aggregate the recorded sessions by local calendar day."""
        if days < 1:
            raise ValueError(f"days must be at least 1, got {days}")
        window_end = time.time() if now is None else now
        today = datetime.fromtimestamp(window_end).date()
        first_day = today - timedelta(days=days - 1)
        window_start = _day_start(first_day)
        summaries: list[DailySummary] = []

        plugged: dict[date, float] = {}
        _add_plugged_seconds(plugged, self.plug_transitions(), window_start, window_end)

        turns = self.charge_turns()
        periods = self.discharge_periods()
        charging: dict[date, float] = {}
        discharging: dict[date, float] = {}
        for turn in turns:
            _add_interval(
                charging, turn.started_at, turn.ended_at or window_end, window_start, window_end
            )
        for period in periods:
            _add_interval(
                discharging,
                period.started_at,
                period.ended_at or window_end,
                window_start,
                window_end,
            )

        for offset in range(days):
            day = first_day + timedelta(days=offset)
            day_turns = [
                turn for turn in turns if datetime.fromtimestamp(turn.started_at).date() == day
            ]
            day_periods = [
                period
                for period in periods
                if datetime.fromtimestamp(period.started_at).date() == day
            ]
            durations = [turn.duration_s for turn in day_turns if turn.duration_s is not None]
            energies = [turn.energy_wh for turn in day_turns if turn.energy_wh is not None]
            capacities = [
                capacity
                for item in [*day_turns, *day_periods]
                for capacity in (item.start_capacity, item.end_capacity)
                if capacity is not None
            ]
            summaries.append(
                DailySummary(
                    day=day,
                    plugged_seconds=plugged.get(day, 0.0),
                    charging_seconds=charging.get(day, 0.0),
                    discharging_seconds=discharging.get(day, 0.0),
                    turns=len(day_turns),
                    avg_turn_seconds=(sum(durations) / len(durations)) if durations else None,
                    longest_turn_seconds=max(durations) if durations else None,
                    energy_wh=sum(energies) if energies else None,
                    band_min=min(capacities) if capacities else None,
                    band_max=max(capacities) if capacities else None,
                )
            )
        return summaries

    # --- internals ---

    def _open_charge_turn(self) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM charge_turns WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def _open_discharge_period(self) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM discharge_periods WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def _open_charge_turn_row(self, reading: BatteryReading, at: float) -> None:
        with self._connection:
            self._connection.execute(
                "INSERT INTO charge_turns "
                "(started_at, start_capacity, start_energy_wh) VALUES (?, ?, ?)",
                (at, reading.capacity, _wh(reading.energy_now)),
            )

    def _open_discharge_period_row(self, reading: BatteryReading, at: float) -> None:
        with self._connection:
            self._connection.execute(
                "INSERT INTO discharge_periods (started_at, start_capacity) VALUES (?, ?)",
                (at, reading.capacity),
            )

    def _close_charge_turn(self, row: sqlite3.Row, reading: BatteryReading, at: float) -> None:
        start_energy = row["start_energy_wh"]
        end_energy = _wh(reading.energy_now)
        energy = None if start_energy is None or end_energy is None else end_energy - start_energy
        with self._connection:
            self._connection.execute(
                "UPDATE charge_turns SET ended_at = ?, duration_s = ?, end_capacity = ?, "
                "energy_wh = ? WHERE id = ?",
                (at, max(0.0, at - row["started_at"]), reading.capacity, energy, row["id"]),
            )

    def _close_discharge_period(self, row: sqlite3.Row, reading: BatteryReading, at: float) -> None:
        with self._connection:
            self._connection.execute(
                "UPDATE discharge_periods SET ended_at = ?, duration_s = ?, end_capacity = ?, "
                "capacity_delta = ? WHERE id = ?",
                (
                    at,
                    max(0.0, at - row["started_at"]),
                    reading.capacity,
                    row["start_capacity"] - reading.capacity,
                    row["id"],
                ),
            )


def render_report(store: MetricsStore, *, days: int = 7, now: float | None = None) -> str:
    """Render the daily, incident and per-turn summary as short plain text."""
    window_end = time.time() if now is None else now
    summaries = store.daily_summary(days=days, now=window_end)
    window_start = _day_start(summaries[0].day)
    incidents = store.incidents(since=window_start, until=window_end)
    if not incidents and not any(
        summary.turns
        or summary.plugged_seconds
        or summary.charging_seconds
        or summary.discharging_seconds
        for summary in summaries
    ):
        return (
            f"Battery charger report - last {days} day(s), "
            f"through {datetime.fromtimestamp(window_end).date()}\n"
            "\n"
            "No activity recorded in this window. Run `abc run` first.\n"
        )

    turns = [
        turn for turn in store.charge_turns(since=window_start) if turn.started_at <= window_end
    ]
    lines = [
        f"Battery charger report - last {days} day(s), "
        f"through {datetime.fromtimestamp(window_end).date()}",
        "",
        _daily_table(summaries),
    ]
    if incidents:
        lines.append("")
        lines.append("Plug unreachable incidents")
        lines.extend(_incident_lines(incidents))
    lines.append("")
    if not turns:
        lines.append("No charge turns recorded in this window.")
    else:
        lines.append("Charge turns")
        lines.extend(_turn_lines(turns))
    lines.append("")
    return "\n".join(lines)


def format_duration(seconds: float | None) -> str:
    """Format seconds as ``h:mm`` (or ``-`` when unknown)."""
    if seconds is None:
        return "-"
    total_minutes = int(round(seconds / 60))
    return f"{total_minutes // 60}:{total_minutes % 60:02d}"


def _daily_table(summaries: list[DailySummary]) -> str:
    headers = (
        "Date",
        "Plugged",
        "Charging",
        "Discharging",
        "Turns",
        "Avg turn",
        "Longest",
        "Energy",
        "Band",
    )
    rows = [
        (
            summary.day.isoformat(),
            _hours(summary.plugged_seconds),
            _hours(summary.charging_seconds),
            _hours(summary.discharging_seconds),
            str(summary.turns),
            format_duration(summary.avg_turn_seconds),
            format_duration(summary.longest_turn_seconds),
            _energy(summary.energy_wh),
            _band(summary.band_min, summary.band_max),
        )
        for summary in summaries
    ]
    table = [headers, *rows]
    widths = [max(len(row[column]) for row in table) for column in range(len(headers))]
    return "\n".join(
        "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()
        for row in table
    )


def _turn_lines(turns: list[ChargeTurn]) -> list[str]:
    with_notes = any(turn.close_reason for turn in turns)
    headers = ["start", "duration", "capacity", "energy"] + (["note"] if with_notes else [])
    rows = [
        (
            datetime.fromtimestamp(turn.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            format_duration(turn.duration_s),
            _capacity_range(turn.start_capacity, turn.end_capacity),
            _energy(turn.energy_wh),
        )
        + ((turn.close_reason or "-",) if with_notes else ())
        for turn in turns
    ]
    table = [tuple(headers), *rows]
    widths = [max(len(row[column]) for row in table) for column in range(len(headers))]
    return [
        "  " + "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()
        for row in table
    ]


def _incident_lines(incidents: list[PlugIncident]) -> list[str]:
    headers = ("start", "duration", "battery", "detail")
    rows = [
        (
            datetime.fromtimestamp(incident.started_at).strftime("%Y-%m-%d %H:%M:%S"),
            format_duration(incident.duration_s),
            _capacity_range(incident.start_capacity, incident.end_capacity),
            _incident_detail(incident),
        )
        for incident in incidents
    ]
    table = [headers, *rows]
    widths = [max(len(row[column]) for row in table) for column in range(len(headers))]
    return [
        "  " + "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()
        for row in table
    ]


def _incident_detail(incident: PlugIncident) -> str:
    if incident.ended_at is None:
        return "ongoing"
    detail = incident.end_reason or "ended"
    if incident.suspended_s > 0:
        detail += f"; machine suspended {format_duration(incident.suspended_s)}"
    return detail


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:.1f}h"


def _energy(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}Wh"


def _band(low: int | None, high: int | None) -> str:
    if low is None or high is None:
        return "-"
    return f"{low}-{high}%"


def _capacity_range(start: int, end: int | None) -> str:
    return f"{start}->{end}%" if end is not None else f"{start}->?%"


def _wh(microwatt_hours: int | None) -> float | None:
    return None if microwatt_hours is None else microwatt_hours / 1_000_000


def _charge_turn(row: sqlite3.Row) -> ChargeTurn:
    return ChargeTurn(
        id=row["id"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        duration_s=row["duration_s"],
        start_capacity=row["start_capacity"],
        end_capacity=row["end_capacity"],
        energy_wh=row["energy_wh"],
        close_reason=row["close_reason"],
    )


def _discharge_period(row: sqlite3.Row) -> DischargePeriod:
    return DischargePeriod(
        id=row["id"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        duration_s=row["duration_s"],
        start_capacity=row["start_capacity"],
        end_capacity=row["end_capacity"],
        capacity_delta=row["capacity_delta"],
        close_reason=row["close_reason"],
    )


def _plug_transition(row: sqlite3.Row) -> PlugTransition:
    return PlugTransition(id=row["id"], at=row["at"], on=bool(row["is_on"]), reason=row["reason"])


def _plug_incident(row: sqlite3.Row) -> PlugIncident:
    return PlugIncident(
        id=row["id"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        duration_s=row["duration_s"],
        start_capacity=row["start_capacity"],
        end_capacity=row["end_capacity"],
        start_error=row["start_error"],
        end_reason=row["end_reason"],
        suspended_s=row["suspended_s"],
    )


def _day_start(day: date) -> float:
    return datetime.combine(day, clock_time.min).timestamp()


def _add_plugged_seconds(
    seconds_by_day: dict[date, float],
    transitions: list[PlugTransition],
    window_start: float,
    window_end: float,
) -> None:
    open_at: float | None = None
    for transition in transitions:
        if transition.on:
            if open_at is None:
                open_at = transition.at
        elif open_at is not None:
            _add_interval(seconds_by_day, open_at, transition.at, window_start, window_end)
            open_at = None
    if open_at is not None:
        _add_interval(seconds_by_day, open_at, window_end, window_start, window_end)


def _add_interval(
    seconds_by_day: dict[date, float],
    start: float,
    end: float,
    window_start: float,
    window_end: float,
) -> None:
    start = max(start, window_start)
    end = min(end, window_end)
    if end <= start:
        return
    day = datetime.fromtimestamp(start).date()
    while True:
        next_midnight = _day_start(day + timedelta(days=1))
        chunk_end = min(end, next_midnight)
        seconds_by_day[day] = seconds_by_day.get(day, 0.0) + (chunk_end - start)
        if chunk_end >= end:
            return
        day += timedelta(days=1)
        start = chunk_end
