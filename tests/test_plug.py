"""Tests for the plug client: the FakePlug contract and TuyaPlug behaviour.

All hardware is stubbed. The plug is the actuator for a physical outcome, so
these tests pin the failure classification (one typed :class:`PlugError`), the
single retry after re-resolving the device by its stable ``gwId``, and the rule
that the local key never appears in a message, log line or traceback.
"""

from __future__ import annotations

import traceback
import types
from collections.abc import Callable

import pytest

from battery_charger import discovery, plug
from battery_charger.config import DeviceConfig

LOCAL_KEY = "fedcba9876543210"
TARGET_ID = "0123456789abcdef012345"
OTHER_ID = "00000000000000000000"
CACHED_IP = "192.168.1.100"
NEW_IP = "192.168.1.101"
INTERFACE = "wlan0"
TIMEOUT = 2.5


class StubTuyaDevice:
    """Stands in for ``tinytuya.Device`` with per-address canned results."""

    instances: list[StubTuyaDevice] = []
    status_results: dict[str, object] = {}
    status_errors: dict[str, Exception] = {}
    write_results: dict[str, object] = {}
    write_errors: dict[str, Exception] = {}
    close_errors: dict[str, Exception] = {}

    def __init__(
        self,
        dev_id: str,
        address: str | None = None,
        local_key: str = "",
        version: float = 3.1,
        port: int = 6668,
        connection_timeout: float = 5.0,
        connection_retry_limit: int = 5,
        **_kwargs: object,
    ) -> None:
        self.dev_id = dev_id
        self.address = address
        self.local_key = local_key
        self.version = version
        self.port = port
        self.connection_timeout = connection_timeout
        self.connection_retry_limit = connection_retry_limit
        self.writes: list[tuple[int, object]] = []
        self.closed = False
        type(self).instances.append(self)

    def status(self) -> object:
        error = type(self).status_errors.get(self.address or "")
        if error is not None:
            raise error
        if self.address in type(self).status_results:
            return type(self).status_results[self.address]
        return {"dps": {"1": True}}

    def set_value(self, index: int, value: object) -> object:
        self.writes.append((index, value))
        error = type(self).write_errors.get(self.address or "")
        if error is not None:
            raise error
        if self.address in type(self).write_results:
            return type(self).write_results[self.address]
        return {"dps": {str(index): value}}

    def close(self) -> None:
        self.closed = True
        error = type(self).close_errors.get(self.address or "")
        if error is not None:
            raise error


@pytest.fixture
def stub_tinytuya(monkeypatch: pytest.MonkeyPatch) -> type[StubTuyaDevice]:
    """Install a fresh device stub in the plug module for each test."""

    class Stub(StubTuyaDevice):
        instances = []
        status_results = {}
        status_errors = {}
        write_results = {}
        write_errors = {}
        close_errors = {}

    monkeypatch.setattr(plug, "tinytuya", types.SimpleNamespace(Device=Stub))
    return Stub


def device_config() -> DeviceConfig:
    return DeviceConfig(id=TARGET_ID, ip=CACHED_IP, local_key=LOCAL_KEY, version=3.5)


def make_plug(
    config: DeviceConfig | None = None,
    *,
    discovery_fn: Callable[..., discovery.DiscoveryResult] | None = None,
    interface: str | None = None,
    timeout: float = TIMEOUT,
) -> plug.TuyaPlug:
    return plug.TuyaPlug(
        config if config is not None else device_config(),
        interface=interface,
        timeout=timeout,
        discovery_fn=discovery_fn,
    )


def discovery_result(devices: list[discovery.DiscoveredDevice]) -> discovery.DiscoveryResult:
    return discovery.DiscoveryResult(
        interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
        devices=list(devices),
        tcp_scanned=False,
    )


def target_at(ip: str) -> discovery.DiscoveredDevice:
    return discovery.DiscoveredDevice(
        ip=ip, device_id=TARGET_ID, product_key="abcdefghijklmnop", version="3.5"
    )


def make_discovery(
    *devices: discovery.DiscoveredDevice,
) -> Callable[..., discovery.DiscoveryResult]:
    def _discover(**_kwargs: object) -> discovery.DiscoveryResult:
        return discovery_result(list(devices))

    return _discover


# --- FakePlug ---


def test_fake_plug_records_the_call_sequence_and_tracks_state() -> None:
    fake = plug.FakePlug()

    assert fake.is_on() is False
    fake.turn_on()
    assert fake.is_on() is True
    fake.turn_off()
    assert fake.is_on() is False
    fake.close()

    assert fake.calls == ["is_on", "turn_on", "is_on", "turn_off", "is_on", "close"]
    assert isinstance(fake, plug.Plug)


def test_fake_plug_can_fail_a_chosen_operation_a_chosen_number_of_times() -> None:
    fake = plug.FakePlug(address="192.168.1.100")
    fake.fail_next("turn_on", times=2)

    with pytest.raises(plug.PlugError) as first:
        fake.turn_on()
    with pytest.raises(plug.PlugError) as second:
        fake.turn_on()
    assert first.value.operation == "turn_on"
    assert second.value.operation == "turn_on"

    fake.turn_on()
    assert fake.is_on() is True


def test_fake_plug_failure_leaves_the_state_unchanged() -> None:
    fake = plug.FakePlug(initial_on=True)
    fake.fail_next("turn_off")

    with pytest.raises(plug.PlugError):
        fake.turn_off()

    assert fake.is_on() is True


def test_fake_plug_rejects_unknown_operations() -> None:
    with pytest.raises(ValueError):
        plug.FakePlug().fail_next("explode")


# --- reads ---


@pytest.mark.parametrize("value", [True, 1])
def test_tuya_plug_is_on_reads_datapoint_1(stub_tinytuya, value: object) -> None:
    stub_tinytuya.status_results[CACHED_IP] = {"dps": {"1": value}}

    assert make_plug().is_on() is True


@pytest.mark.parametrize("value", [False, 0])
def test_tuya_plug_is_off_reads_datapoint_1(stub_tinytuya, value: object) -> None:
    stub_tinytuya.status_results[CACHED_IP] = {"dps": {"1": value}}

    assert make_plug().is_on() is False


def test_tuya_plug_uses_datapoint_1_as_the_only_source_of_truth(stub_tinytuya) -> None:
    # Measured live: dp 14 (relay_status) said "on" while dp 1 was false.
    stub_tinytuya.status_results[CACHED_IP] = {"dps": {"1": False, "14": "on"}}

    assert make_plug().is_on() is False


def test_tuya_plug_raises_a_typed_error_on_a_device_error(stub_tinytuya) -> None:
    stub_tinytuya.status_results[CACHED_IP] = {"Err": "905", "Error": "Check device key or version"}

    with pytest.raises(plug.PlugError) as info:
        make_plug(discovery_fn=make_discovery()).is_on()

    assert info.value.operation == "is_on"
    assert "905" in info.value.reason


def test_tuya_plug_raises_a_typed_error_when_datapoint_1_is_missing(stub_tinytuya) -> None:
    stub_tinytuya.status_results[CACHED_IP] = {"dps": {"14": "on"}}

    with pytest.raises(plug.PlugError, match="datapoint 1"):
        make_plug(discovery_fn=make_discovery()).is_on()


def test_tuya_plug_raises_a_typed_error_on_an_unexpected_value(stub_tinytuya) -> None:
    stub_tinytuya.status_results[CACHED_IP] = {"dps": {"1": "true"}}

    with pytest.raises(plug.PlugError, match="unexpected value"):
        make_plug(discovery_fn=make_discovery()).is_on()


# --- writes ---


def test_tuya_plug_turn_on_writes_true_to_datapoint_1(stub_tinytuya) -> None:
    make_plug().turn_on()

    assert stub_tinytuya.instances[-1].writes == [(1, True)]


def test_tuya_plug_turn_off_writes_false_to_datapoint_1(stub_tinytuya) -> None:
    make_plug().turn_off()

    assert stub_tinytuya.instances[-1].writes == [(1, False)]


def test_tuya_plug_rejects_a_write_acknowledged_with_the_wrong_state(stub_tinytuya) -> None:
    stub_tinytuya.write_results[CACHED_IP] = {"dps": {"1": False}}

    with pytest.raises(plug.PlugError, match="expected True"):
        make_plug(discovery_fn=make_discovery()).turn_on()


def test_tuya_plug_rejects_a_write_without_an_acknowledgement(stub_tinytuya) -> None:
    stub_tinytuya.write_results[CACHED_IP] = None

    with pytest.raises(plug.PlugError, match="acknowledge"):
        make_plug(discovery_fn=make_discovery()).turn_on()


def test_tuya_plug_rejects_an_acknowledgement_without_the_datapoint(stub_tinytuya) -> None:
    stub_tinytuya.write_results[CACHED_IP] = {"ack": True}

    with pytest.raises(plug.PlugError, match="no datapoint map"):
        make_plug(discovery_fn=make_discovery()).turn_on()


def test_tuya_plug_uses_the_configured_protocol_and_bounded_timeout(stub_tinytuya) -> None:
    make_plug()

    created = stub_tinytuya.instances[-1]
    assert created.dev_id == TARGET_ID
    assert created.address == CACHED_IP
    assert created.local_key == LOCAL_KEY
    assert created.version == 3.5
    assert created.port == 6668
    assert created.connection_timeout == TIMEOUT
    assert created.connection_retry_limit == 1


# --- re-resolution ---


def test_tuya_plug_re_resolves_by_gwid_after_a_read_failure(stub_tinytuya) -> None:
    stub_tinytuya.status_errors[CACHED_IP] = OSError("no route to host")
    stub_tinytuya.status_results[NEW_IP] = {"dps": {"1": True}}
    calls: list[dict] = []

    def discover(**kwargs: object) -> discovery.DiscoveryResult:
        calls.append(dict(kwargs))
        return discovery_result([target_at(NEW_IP)])

    client = make_plug(discovery_fn=discover, interface=INTERFACE)

    assert client.is_on() is True
    assert client.address == NEW_IP
    assert [device.address for device in stub_tinytuya.instances] == [CACHED_IP, NEW_IP]
    assert calls == [{"interface": INTERFACE, "timeout": TIMEOUT, "scan_tcp": False}]
    change = client.last_address_change
    assert change is not None
    assert change.previous_ip == CACHED_IP
    assert change.current_ip == NEW_IP


def test_tuya_plug_re_resolves_by_gwid_after_a_write_failure(stub_tinytuya) -> None:
    stub_tinytuya.write_errors[CACHED_IP] = OSError("no route to host")
    discover_calls: list[int] = []

    def discover(**_kwargs: object) -> discovery.DiscoveryResult:
        discover_calls.append(1)
        return discovery_result([target_at(NEW_IP)])

    client = make_plug(discovery_fn=discover)
    client.turn_off()

    assert stub_tinytuya.instances[-1].address == NEW_IP
    assert stub_tinytuya.instances[-1].writes == [(1, False)]
    assert len(discover_calls) == 1


def test_tuya_plug_does_not_discover_when_the_first_call_succeeds(stub_tinytuya) -> None:
    discover_calls: list[int] = []

    def discover(**_kwargs: object) -> discovery.DiscoveryResult:
        discover_calls.append(1)
        return discovery_result([target_at(NEW_IP)])

    client = make_plug(discovery_fn=discover)

    assert client.is_on() is True
    assert discover_calls == []
    assert client.last_address_change is None


def test_tuya_plug_tries_again_at_the_same_address_when_discovery_confirms_it(
    stub_tinytuya,
) -> None:
    # First status call fails, the retry at the same address succeeds.
    fail_once = {"count": 0}

    def status_method(_self: object) -> object:
        fail_once["count"] += 1
        if fail_once["count"] == 1:
            raise OSError("transient")
        return {"dps": {"1": False}}

    stub_tinytuya.status = status_method  # type: ignore[method-assign]

    client = make_plug(discovery_fn=make_discovery(target_at(CACHED_IP)))

    assert client.is_on() is False
    assert client.address == CACHED_IP
    assert client.last_address_change is None


def test_tuya_plug_retries_at_the_known_address_when_the_broadcast_is_silent(
    stub_tinytuya,
) -> None:
    # Broadcast silence must not cancel the retry; liveness is authenticated.
    fail_once = {"count": 0}

    def status_method(_self: object) -> object:
        fail_once["count"] += 1
        if fail_once["count"] == 1:
            raise OSError("transient")
        return {"dps": {"1": False}}

    stub_tinytuya.status = status_method  # type: ignore[method-assign]

    client = make_plug(discovery_fn=make_discovery())

    assert client.is_on() is False
    assert client.address == CACHED_IP
    assert [device.address for device in stub_tinytuya.instances] == [CACHED_IP, CACHED_IP]
    assert stub_tinytuya.instances[0] is not stub_tinytuya.instances[1]
    assert client.last_address_change is None


def test_tuya_plug_raises_when_rediscovery_finds_no_matching_gwid(stub_tinytuya) -> None:
    stub_tinytuya.status_errors[CACHED_IP] = OSError("unreachable")
    other = discovery.DiscoveredDevice(ip=NEW_IP, device_id=OTHER_ID)

    client = make_plug(discovery_fn=make_discovery(other))

    with pytest.raises(plug.PlugError, match="rediscovery") as info:
        client.is_on()

    # The silent broadcast is reported, but it no longer cancels the retry.
    assert [device.address for device in stub_tinytuya.instances] == [CACHED_IP, CACHED_IP]
    assert f"retry at {CACHED_IP} failed" in info.value.reason


def test_tuya_plug_raises_after_exactly_one_retry(stub_tinytuya) -> None:
    stub_tinytuya.status_errors[CACHED_IP] = OSError("unreachable")
    stub_tinytuya.status_errors[NEW_IP] = OSError("still unreachable")

    client = make_plug(discovery_fn=make_discovery(target_at(NEW_IP)))

    with pytest.raises(plug.PlugError) as info:
        client.is_on()

    assert "still unreachable" in info.value.reason
    assert [device.address for device in stub_tinytuya.instances] == [CACHED_IP, NEW_IP]


# --- secrecy ---


def test_plug_error_never_leaks_the_local_key(stub_tinytuya) -> None:
    stub_tinytuya.status_errors[CACHED_IP] = RuntimeError(f"refused using key {LOCAL_KEY}")

    client = make_plug(discovery_fn=make_discovery())

    with pytest.raises(plug.PlugError) as info:
        client.is_on()

    rendered = "".join(traceback.format_exception(info.value))
    assert LOCAL_KEY not in rendered
    assert LOCAL_KEY not in str(info.value)
    assert LOCAL_KEY not in repr(client)
    assert "[local key]" in info.value.reason


def test_retry_failure_never_leaks_the_local_key(stub_tinytuya) -> None:
    stub_tinytuya.status_errors[CACHED_IP] = OSError("unreachable")
    stub_tinytuya.status_errors[NEW_IP] = RuntimeError(f"key is {LOCAL_KEY}")

    client = make_plug(discovery_fn=make_discovery(target_at(NEW_IP)))

    with pytest.raises(plug.PlugError) as info:
        client.is_on()

    rendered = "".join(traceback.format_exception(info.value))
    assert LOCAL_KEY not in rendered
    assert "[local key]" in info.value.reason


# --- lifecycle ---


def test_tuya_plug_close_is_best_effort(stub_tinytuya) -> None:
    stub_tinytuya.close_errors[CACHED_IP] = OSError("socket already gone")

    make_plug().close()


def test_tuya_plug_close_closes_the_underlying_device(stub_tinytuya) -> None:
    client = make_plug()

    client.close()

    assert stub_tinytuya.instances[-1].closed is True
