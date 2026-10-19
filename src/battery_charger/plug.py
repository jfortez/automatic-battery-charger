"""Local plug control behind a replaceable seam.

:class:`TuyaPlug` wraps one ``tinytuya.Device`` (protocol 3.5) and uses the
switch datapoint discovered from the status payload. The ``gwId`` is stable and
the IP is only a cache: a failed read or write is retried once, at the
re-discovered address or at the last known one with a fresh socket and session
key. Liveness is an authenticated round trip, never a broadcast reply.

Every failure becomes :class:`PlugError`; the local key never appears in a
message, log line or traceback.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import tinytuya

from . import discovery
from .config import DeviceConfig

SWITCH_DATAPOINT = 1
DEFAULT_TIMEOUT = 4.0

_PLUG_OPERATIONS = frozenset({"is_on", "turn_on", "turn_off", "close"})
_MISSING = object()
_KEY_PLACEHOLDER = "[local key]"


class PlugError(Exception):
    """A plug operation failed. ``operation`` names it; ``reason`` is human-readable."""

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation
        self.reason = reason
        super().__init__(f"{operation}: {reason}")


@dataclass(frozen=True)
class AddressChange:
    """A successful re-resolution of the plug's cached IP address."""

    previous_ip: str
    current_ip: str


@runtime_checkable
class Plug(Protocol):
    """The actuator seam: read the switch, set it, release resources."""

    def is_on(self) -> bool:
        """Return whether the relay is closed (the appliance is energised)."""

    def turn_on(self) -> None:
        """Close the relay."""

    def turn_off(self) -> None:
        """Open the relay."""

    def close(self) -> None:
        """Release any network resources. Must not raise."""


class TuyaPlug:
    """A :class:`Plug` backed by one Tuya device over the local LAN.

    It depends only on :class:`~battery_charger.config.DeviceConfig`. The
    optional ``discovery_fn`` exists for tests; production code lets it default
    to :func:`discovery.discover` (looked up at call time so monkeypatching
    works).
    """

    def __init__(
        self,
        device: DeviceConfig,
        *,
        interface: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        discovery_fn: Callable[..., discovery.DiscoveryResult] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        self._config = device
        self._interface = interface
        self._timeout = timeout
        self._discovery_fn = discovery_fn
        self._address = device.ip.strip()
        self._device = self._build_device(self._address)
        self.last_address_change: AddressChange | None = None

    @property
    def address(self) -> str:
        """The address currently in use."""
        return self._address

    def __repr__(self) -> str:
        # Do not use tinytuya's repr: it prints the local key.
        return f"TuyaPlug(id={self._config.id!r}, address={self._address!r})"

    def is_on(self) -> bool:
        """Return datapoint 1 as a bool, with one retry on failure."""

        def read(device: object) -> bool:
            return _read_switch(device.status())  # type: ignore[attr-defined]

        return self._run("is_on", read)

    def turn_on(self) -> None:
        """Write ``True`` to datapoint 1, with one retry on failure."""

        def write(device: object) -> None:
            _check_write("turn_on", device.set_value(SWITCH_DATAPOINT, True), expected=True)  # type: ignore[attr-defined]

        self._run("turn_on", write)

    def turn_off(self) -> None:
        """Write ``False`` to datapoint 1, with one retry on failure."""

        def write(device: object) -> None:
            _check_write("turn_off", device.set_value(SWITCH_DATAPOINT, False), expected=False)  # type: ignore[attr-defined]

        self._run("turn_off", write)

    def close(self) -> None:
        """Close the underlying connection, ignoring any error."""
        with contextlib.suppress(Exception):
            self._device.close()

    def _run(self, operation: str, action: Callable[[object], object]) -> object:
        failure = "no configured address" if not self._address else ""
        if self._address:
            try:
                return action(self._device)
            except Exception as exc:  # noqa: BLE001 - every transport/protocol failure is classified here
                failure = _failure_text(exc, self._config.local_key)
        # One retry always: re-discovered address first; silence never cancels it.
        discovered = self._resolve_address()
        address = discovered or self._address
        if not address:
            raise PlugError(
                operation,
                f"{failure}; rediscovery found no device with gwId {self._config.id!r}",
            ) from None
        # A fresh socket and session key are the point of the retry.
        self._use_address(address)
        try:
            return action(self._device)
        except Exception as exc:  # noqa: BLE001 - the retry is the last attempt
            silent = (
                "" if discovered else f"; rediscovery found no device with gwId {self._config.id!r}"
            )
            raise PlugError(
                operation,
                f"{failure}; retry at {address} failed: "
                f"{_failure_text(exc, self._config.local_key)}{silent}",
            ) from None

    def _build_device(self, address: str) -> tinytuya.Device:
        return tinytuya.Device(
            self._config.id,
            address=address or None,
            local_key=self._config.local_key,
            version=float(self._config.version),
            port=discovery.TCP_PORT,
            connection_timeout=self._timeout,
            connection_retry_limit=1,
        )

    def _resolve_address(self) -> str:
        discover = self._discovery_fn if self._discovery_fn is not None else discovery.discover
        try:
            result = discover(
                interface=self._interface,
                timeout=self._timeout,
                scan_tcp=False,
            )
        except Exception:  # noqa: BLE001 - discovery failure at most cancels the retry
            return ""
        found = discovery.find_device(result.devices, self._config.id)
        if found is None:
            return ""
        return found.ip.strip()

    def _use_address(self, address: str) -> None:
        previous = self._address
        self._address = address
        old_device, self._device = self._device, self._build_device(address)
        with contextlib.suppress(Exception):
            old_device.close()
        if address != previous:
            self.last_address_change = AddressChange(previous_ip=previous, current_ip=address)


class FakePlug:
    """In-memory :class:`Plug` for tests.

    Records every operation in :attr:`calls` and can be configured with
    :meth:`fail_next` to raise :class:`PlugError` for a chosen operation a
    chosen number of times.
    """

    def __init__(self, *, initial_on: bool = False, address: str = "fake-plug") -> None:
        self._on = initial_on
        self.address = address
        self.calls: list[str] = []
        self.last_address_change: AddressChange | None = None
        self._failures: dict[str, int] = {}

    def fail_next(self, operation: str, *, times: int = 1) -> None:
        """Make the next ``times`` calls of ``operation`` raise :class:`PlugError`."""
        if operation not in _PLUG_OPERATIONS:
            raise ValueError(
                f"unknown plug operation {operation!r}; expected one of {sorted(_PLUG_OPERATIONS)}"
            )
        if times < 1:
            raise ValueError(f"times must be at least 1, got {times}")
        self._failures[operation] = self._failures.get(operation, 0) + times

    def is_on(self) -> bool:
        """Return the in-memory switch state."""
        self._call("is_on")
        return self._on

    def turn_on(self) -> None:
        """Set the in-memory switch state to on."""
        self._call("turn_on")
        self._on = True

    def turn_off(self) -> None:
        """Set the in-memory switch state to off."""
        self._call("turn_off")
        self._on = False

    def close(self) -> None:
        """Record the close call."""
        self._call("close")

    def _call(self, operation: str) -> None:
        self.calls.append(operation)
        remaining = self._failures.get(operation, 0)
        if remaining > 0:
            self._failures[operation] = remaining - 1
            raise PlugError(operation, f"injected failure for {operation}")


def _read_switch(status: object) -> bool:
    if not isinstance(status, dict):
        raise PlugError("is_on", "device returned no status payload")
    error = status.get("Err")
    if error:
        raise PlugError("is_on", f"device returned error {error}: {status.get('Error', '')}")
    dps = status.get("dps")
    if not isinstance(dps, dict):
        raise PlugError("is_on", "device status contains no datapoint map")
    value = _dp_value(dps, SWITCH_DATAPOINT)
    if value is _MISSING:
        raise PlugError("is_on", f"device status is missing datapoint {SWITCH_DATAPOINT}")
    return _switch_value(value)


def _switch_value(value: object, operation: str = "is_on") -> bool:
    # Exact matching only: a truthiness test would read the string "false" as on.
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise PlugError(
        operation,
        f"datapoint {SWITCH_DATAPOINT} has unexpected value {value!r} ({type(value).__name__})",
    )


def _check_write(operation: str, result: object, *, expected: bool) -> None:
    if result is None:
        raise PlugError(operation, "device did not acknowledge the write")
    if not isinstance(result, dict):
        raise PlugError(
            operation,
            f"device returned an unexpected write response ({type(result).__name__})",
        )
    error = result.get("Err")
    if error:
        raise PlugError(operation, f"device returned error {error}: {result.get('Error', '')}")
    dps = result.get("dps")
    if not isinstance(dps, dict):
        raise PlugError(operation, "device acknowledgement contains no datapoint map")
    value = _dp_value(dps, SWITCH_DATAPOINT)
    if value is _MISSING:
        raise PlugError(
            operation, f"device acknowledgement is missing datapoint {SWITCH_DATAPOINT}"
        )
    acknowledged = _switch_value(value, operation)
    if acknowledged is not expected:
        raise PlugError(
            operation,
            f"device acknowledged datapoint {SWITCH_DATAPOINT}={value!r}, expected {expected}",
        )


def _dp_value(dps: Mapping[object, object], index: int) -> object:
    for key in (index, str(index)):
        if key in dps:
            return dps[key]
    return _MISSING


def _failure_text(exc: Exception, local_key: str) -> str:
    """Render a failure without ever including the local key."""
    if isinstance(exc, PlugError):
        text = exc.reason
    else:
        text = f"{type(exc).__name__}: {exc}"
    return _scrub(text, local_key)


def _scrub(text: str, secret: str) -> str:
    if not secret:
        return text
    return text.replace(secret, _KEY_PLACEHOLDER)
