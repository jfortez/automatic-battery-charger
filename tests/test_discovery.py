"""Tests for Tuya LAN discovery: request bytes, reply decoding and target verdicts."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest
import tinytuya

from battery_charger import discovery
from battery_charger.discovery import (
    DiscoveredDevice,
    DiscoveryError,
    InterfaceInfo,
    build_discovery_request,
    candidate_hosts,
    decode_discovery_reply,
    device_from_payload,
    find_device,
    pick_interface,
    probe_tcp_hosts,
    tcp_port_open,
)

FIXTURES = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> bytes:
    return bytes.fromhex((FIXTURES / name).read_text(encoding="ascii").strip())


def test_build_discovery_request_is_a_6699_frame_with_json_body() -> None:
    payload = build_discovery_request("192.168.1.229")

    assert payload[:4] == b"\x00\x00\x66\x99"
    # The request is packed without a retcode field, hence no_retcode=True.
    message = tinytuya.unpack_message(payload, hmac_key=tinytuya.udpkey, no_retcode=True)
    assert message.payload == b'{"from": "app", "ip": "192.168.1.229"}'


def test_decode_v35_reply_fixture() -> None:
    # The fixture is an anonymized v3.5 frame: every device identifier is synthetic.
    payload = decode_discovery_reply(read_fixture("discovery_reply_v35.hex"))

    assert payload is not None
    assert payload["ip"] == "192.168.1.100"
    assert payload["gwId"] == "0123456789abcdef012345"
    assert payload["productKey"] == "abcdefghijklmnop"
    assert payload["version"] == "3.5"
    for field in ("uuid", "active", "encrypt", "token", "wf_cfg", "sl", "clientLink"):
        assert field in payload


def test_decode_returns_none_for_garbage() -> None:
    assert decode_discovery_reply(b"") is None
    assert decode_discovery_reply(b"\x00" * 64) is None
    assert decode_discovery_reply(b"not a tuya message") is None


def test_decode_rejects_a_truncated_reply() -> None:
    frame = read_fixture("discovery_reply_v35.hex")

    assert decode_discovery_reply(frame[:16]) is None
    assert decode_discovery_reply(frame[: len(frame) // 2]) is None


def test_decode_ignores_bytes_trailing_the_frame() -> None:
    frame = read_fixture("discovery_reply_v35.hex")

    payload = decode_discovery_reply(frame + b"\x00" * 8)

    assert payload is not None
    assert payload["gwId"] == "0123456789abcdef012345"


def test_decode_rejects_a_valid_frame_with_invalid_json() -> None:
    body = b"this is not json"
    message = tinytuya.TuyaMessage(
        0, tinytuya.REQ_DEVINFO, 0, body, 0, True, tinytuya.PREFIX_6699_VALUE, False
    )
    frame = tinytuya.pack_message(message, hmac_key=tinytuya.udpkey)

    assert decode_discovery_reply(frame) is None


def test_payload_without_gwid_cannot_become_a_device() -> None:
    body = json.dumps({"ip": "192.168.1.99"}).encode()
    message = tinytuya.TuyaMessage(
        0, tinytuya.REQ_DEVINFO, 0, body, 0, True, tinytuya.PREFIX_6699_VALUE, False
    )
    frame = tinytuya.pack_message(message, hmac_key=tinytuya.udpkey)

    payload = decode_discovery_reply(frame)

    assert payload == {"ip": "192.168.1.99"}
    assert device_from_payload(payload, "192.168.1.99") is None


def test_device_from_payload_maps_expected_fields() -> None:
    payload = {
        "ip": "192.168.1.100",
        "gwId": "0123456789abcdef012345",
        "productKey": "abcdefghijklmnop",
        "version": "3.5",
        "uuid": "uuid-1",
        "active": 1,
        "encrypt": True,
        "token": True,
    }

    device = device_from_payload(payload, "192.168.1.100")

    assert device is not None
    assert device.device_id == "0123456789abcdef012345"
    assert device.product_key == "abcdefghijklmnop"
    assert device.version == "3.5"
    assert device.ip == "192.168.1.100"
    assert device.uuid == "uuid-1"
    assert device.encrypt is True
    assert device.tcp_open is False
    assert device.discovered_via == "udp"


def test_device_from_payload_requires_a_gwid() -> None:
    assert device_from_payload({"ip": "192.168.1.181"}, "192.168.1.181") is None
    assert device_from_payload({}, "192.168.1.181") is None


def test_device_from_payload_falls_back_to_source_ip() -> None:
    device = device_from_payload({"gwId": "gw-1"}, "10.0.0.7")

    assert device is not None
    assert device.ip == "10.0.0.7"


def test_device_from_payload_rejects_a_claimed_ip_that_differs_from_the_source() -> None:
    payload = {"ip": "192.168.1.100", "gwId": "0123456789abcdef012345"}

    assert device_from_payload(payload, "127.0.0.1") is None
    assert device_from_payload(payload, "10.0.0.9") is None


def test_device_from_payload_takes_the_address_from_the_packet_source() -> None:
    payload = {"ip": "10.0.0.7", "gwId": "gw-1"}

    device = device_from_payload(payload, "10.0.0.7")

    assert device is not None
    assert device.ip == "10.0.0.7"


def test_find_device() -> None:
    devices = [
        DiscoveredDevice(ip="10.0.0.1", device_id="one"),
        DiscoveredDevice(ip="10.0.0.2", device_id="two"),
    ]

    assert find_device(devices, "two") == devices[1]
    assert find_device(devices, "three") is None
    assert find_device(devices, "") is None
    assert find_device([], "one") is None


def test_interface_broadcast_derivation() -> None:
    assert (
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24).broadcast
        == "192.168.1.255"
    )
    assert InterfaceInfo(name="eth0", address="10.1.2.3", prefixlen=16).broadcast == "10.1.255.255"
    assert (
        InterfaceInfo(name="eth0", address="172.20.0.1", prefixlen=12).broadcast == "172.31.255.255"
    )


def test_candidate_hosts_excludes_own_address_and_broadcast() -> None:
    interface = InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24)

    hosts = candidate_hosts(interface)

    assert len(hosts) == 253
    assert "192.168.1.1" in hosts
    assert "192.168.1.100" in hosts
    assert "192.168.1.229" not in hosts
    assert "192.168.1.255" not in hosts


def _recording_host_generator() -> tuple[list[int], object]:
    consumed: list[int] = []

    def generate(_interface: InterfaceInfo):
        for index in range(1_000_000):
            consumed.append(index)
            yield f"10.0.0.{index}"

    return consumed, generate


def test_candidate_hosts_caps_during_generation(monkeypatch) -> None:
    consumed, generate = _recording_host_generator()
    monkeypatch.setattr(discovery, "_iter_candidate_hosts", generate)
    interface = InterfaceInfo(name="eth9", address="10.9.9.9", prefixlen=8)

    hosts = discovery.candidate_hosts(interface, limit=8)

    assert hosts == [f"10.0.0.{index}" for index in range(8)]
    assert len(consumed) == 8


def test_bounded_candidates_never_materialises_the_whole_subnet(monkeypatch) -> None:
    consumed, generate = _recording_host_generator()
    monkeypatch.setattr(discovery, "_iter_candidate_hosts", generate)
    interface = InterfaceInfo(name="eth9", address="10.9.9.9", prefixlen=8)

    hosts = discovery._bounded_candidates(interface)

    assert len(hosts) == discovery.MAX_UNICAST_TARGETS
    assert len(consumed) == discovery.MAX_UNICAST_TARGETS


def test_pick_interface_auto_prefers_wifi_over_docker_and_tailscale(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "default_route_interface", lambda *args, **kwargs: None)
    interfaces = [
        InterfaceInfo(name="lo", address="127.0.0.1", prefixlen=8),
        InterfaceInfo(name="tailscale0", address="100.91.1.71", prefixlen=32),
        InterfaceInfo(name="docker0", address="10.0.0.1", prefixlen=24),
        InterfaceInfo(name="br-9b5998a0fa5a", address="172.18.0.1", prefixlen=16),
        InterfaceInfo(name="eth0", address="10.20.30.40", prefixlen=24),
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
    ]

    assert pick_interface(interfaces).name == "wlan0"


def test_default_route_interface_parses_proc_net_route(tmp_path: Path) -> None:
    route_file = tmp_path / "route"
    route_file.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0164A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "docker0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )

    assert discovery.default_route_interface(str(route_file)) == "wlan0"
    assert discovery.default_route_interface(str(tmp_path / "missing")) is None


def test_pick_interface_prefers_the_default_route_interface(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "default_route_interface", lambda *args, **kwargs: "eth0")
    interfaces = [
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
        InterfaceInfo(name="eth0", address="10.20.30.40", prefixlen=24),
    ]

    assert pick_interface(interfaces).name == "eth0"


def test_pick_interface_falls_back_when_the_default_route_is_unknown(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "default_route_interface", lambda *args, **kwargs: "wwan9")
    interfaces = [
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
        InterfaceInfo(name="eth0", address="10.20.30.40", prefixlen=24),
    ]

    assert pick_interface(interfaces).name == "wlan0"


def test_pick_interface_skips_a_default_route_on_the_skip_list(monkeypatch) -> None:
    """A full-tunnel VPN can own the default route; it must not be selected."""
    monkeypatch.setattr(discovery, "default_route_interface", lambda *args, **kwargs: "tailscale0")
    interfaces = [
        InterfaceInfo(name="tailscale0", address="100.91.1.71", prefixlen=32),
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
    ]

    assert pick_interface(interfaces).name == "wlan0"


def test_pick_interface_explicit_name_or_address() -> None:
    interfaces = [
        InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
        InterfaceInfo(name="eth0", address="10.20.30.40", prefixlen=24),
    ]

    assert pick_interface(interfaces, "eth0").name == "eth0"
    assert pick_interface(interfaces, "192.168.1.229").name == "wlan0"


def test_pick_interface_unknown_raises() -> None:
    interfaces = [InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24)]

    with pytest.raises(DiscoveryError, match="wlan1"):
        pick_interface(interfaces, "wlan1")


def test_pick_interface_without_candidates_raises() -> None:
    interfaces = [InterfaceInfo(name="lo", address="127.0.0.1", prefixlen=8)]

    with pytest.raises(DiscoveryError):
        pick_interface(interfaces)


def test_tcp_port_open_against_a_local_listener() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[socket.socket] = []

    def accept_once() -> None:
        try:
            conn, _ = server.accept()
            accepted.append(conn)
        except OSError:
            pass

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    try:
        assert tcp_port_open("127.0.0.1", port=port, timeout=1.0) is True
    finally:
        thread.join(timeout=2)
        for conn in accepted:
            conn.close()
        server.close()

    assert tcp_port_open("127.0.0.1", port=port, timeout=0.2) is False


def test_tcp_port_open_binds_the_requested_source_address(loopback_tcp_listener) -> None:
    # 127.0.0.2 is not the default source for a connection to 127.0.0.3 (which is
    # 127.0.0.1 here), so this fails if ``source_address`` is dropped.
    listener = loopback_tcp_listener(host="127.0.0.3")

    assert (
        tcp_port_open("127.0.0.3", port=listener.port, timeout=1.0, source_address="127.0.0.2")
        is True
    )

    assert listener.wait_for_peer()[0][0] == "127.0.0.2"


def test_probe_tcp_hosts_returns_only_open_hosts() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    thread = threading.Thread(target=lambda: server.accept(), daemon=True)
    thread.start()
    try:
        open_hosts = probe_tcp_hosts(["127.0.0.1", "127.0.0.2"], port=port, timeout=0.5)
    finally:
        server.close()
    thread.join(timeout=2)

    assert open_hosts == {"127.0.0.1"}


# --- authenticated probe ---


def test_probe_authenticated_requires_a_local_key() -> None:
    outcome = discovery.probe_authenticated("127.0.0.1", device_id="dev", timeout=0.2)

    assert outcome.authenticated is False
    assert outcome.connected is False


def test_probe_authenticated_never_raises_on_an_unconnectable_address() -> None:
    outcome = discovery.probe_authenticated(
        "999.999.999.999", device_id="dev", local_key="0123456789abcdef", timeout=0.2
    )

    assert outcome.authenticated is False
    assert outcome.connected is False


def test_probe_authenticated_reports_reachable_but_unauthenticated(
    loopback_tcp_listener,
) -> None:
    listener = loopback_tcp_listener(host="127.0.0.2")

    outcome = discovery.probe_authenticated(
        "127.0.0.2",
        device_id="dev",
        local_key="0123456789abcdef",
        version=3.5,
        port=listener.port,
        timeout=0.3,
    )

    assert outcome.authenticated is False
    assert outcome.connected is True
    assert outcome.detail
    assert listener.wait_for_peer()


# --- real loopback discovery sweeps ---


def test_discover_receives_decodes_and_merges_real_loopback_sockets(
    loopback_udp_responder, loopback_tcp_listener
) -> None:
    responder = loopback_udp_responder(expected_senders=1)
    listener = loopback_tcp_listener(host="127.0.0.2")

    result = discovery.discover(
        interface="127.0.0.1",
        timeout=1.5,
        interfaces=[InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
        discovery_port=responder.port,
        tcp_port=listener.port,
    )

    by_id = {device.device_id: device for device in result.devices}
    assert "0123456789abcdef012345" in by_id
    # The claimed IP is only trusted when it matches the packet source, so the
    # loopback responder's rewritten claim (127.0.0.1) is what is recorded.
    assert by_id["0123456789abcdef012345"].ip == "127.0.0.1"
    assert by_id["0123456789abcdef012345"].product_key == "abcdefghijklmnop"
    assert by_id["0123456789abcdef012345"].discovered_via == "udp"
    assert result.rejected_announcements == 0
    tcp_only = [device for device in result.devices if device.discovered_via == "tcp"]
    assert tcp_only == [DiscoveredDevice(ip="127.0.0.2", tcp_open=True, discovered_via="tcp")]
    assert listener.wait_for_peer() and listener.peers[0][0] == "127.0.0.1"


def test_discover_discards_an_announcement_whose_claimed_ip_is_not_the_source(
    loopback_udp_responder,
) -> None:
    """A frame forged with the public udpkey must not become a discovered device."""
    responder = loopback_udp_responder(rewrite_ip=False, expected_senders=2, settle=0.2)

    result = discovery.discover(
        interface="127.0.0.1",
        timeout=1.0,
        scan_tcp=False,
        interfaces=[InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
        discovery_port=responder.port,
        local_port=free_udp_port(),
    )

    assert result.devices == []
    assert result.rejected_announcements == 1


def test_discover_receives_replies_addressed_to_the_discovery_port(
    loopback_udp_responder, monkeypatch
) -> None:
    """The tested device addresses replies to the fixed discovery port.

    The request comes from a decoy socket whose source port differs from the
    fixed reply port, and the sweep's own sends are suppressed, so a responder
    (or a binding) that targets the request source instead cannot pass.
    """
    local_port = free_udp_port()
    responder = loopback_udp_responder(reply_to_port=local_port, expected_senders=2, settle=0.5)
    monkeypatch.setattr(discovery, "_send_discovery", lambda *args, **kwargs: None)
    decoy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        decoy.sendto(b"decoy", ("127.0.0.1", responder.port))
        result = discovery.discover(
            interface="127.0.0.1",
            timeout=1.0,
            scan_tcp=False,
            interfaces=[InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
            discovery_port=responder.port,
            local_port=local_port,
        )
    finally:
        decoy.close()

    assert any(device.device_id == "0123456789abcdef012345" for device in result.devices)


def test_sweep_bind_budget_covers_the_measured_sweep_hold() -> None:
    interface = InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24)

    budget = discovery._sweep_bind_budget(interface, timeout=3.0, unicast=True)

    # Live measurement: the 254-send unicast phase alone took 3.07 s, and the
    # port is then held for the receive timeout on top of that.
    assert budget >= 3.0 + 3.07
    # The old ``timeout + 1.0`` budget cannot survive a real sweep.
    assert budget > 3.0 + 1.0


def test_bind_budget_waits_out_a_sweep_that_holds_the_discovery_port(
    loopback_udp_responder,
) -> None:
    """A competitor holding the port past the old ``timeout + 1`` budget is waited out.

    Under the old budget this sweep gave up and bound an ephemeral port, which
    the tested device never answers, producing a false absence.
    """
    local_port = free_udp_port()
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", local_port))
    responder = loopback_udp_responder(reply_to_port=local_port, settle=0.05)

    def release_after(seconds: float) -> None:
        time.sleep(seconds)
        holder.close()

    releasing = threading.Thread(target=release_after, args=(1.5,), daemon=True)
    releasing.start()
    try:
        result = discovery.discover(
            interface="127.0.0.1",
            timeout=0.2,
            scan_tcp=False,
            interfaces=[InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
            discovery_port=responder.port,
            local_port=local_port,
        )
    finally:
        releasing.join(timeout=3)
        holder.close()

    assert result.degraded is False
    assert any(device.device_id == "0123456789abcdef012345" for device in result.devices)


def test_bind_timeout_degrades_loudly_instead_of_claiming_absence(
    loopback_udp_responder, monkeypatch
) -> None:
    local_port = free_udp_port()
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", local_port))
    responder = loopback_udp_responder(reply_to_port=local_port, settle=0.05)
    monkeypatch.setattr(discovery, "_sweep_bind_budget", lambda *args, **kwargs: 0.1)
    try:
        result = discovery.discover(
            interface="127.0.0.1",
            timeout=0.2,
            scan_tcp=False,
            interfaces=[InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
            discovery_port=responder.port,
            local_port=local_port,
        )
    finally:
        holder.close()

    assert result.degraded is True
    assert str(local_port) in result.degraded_reason
    assert "ephemeral" in result.degraded_reason
    assert all(device.device_id != "0123456789abcdef012345" for device in result.devices)


def test_discover_wraps_socket_bind_errors_as_discovery_error(monkeypatch) -> None:
    """An interface that disappears mid-bind must raise DiscoveryError, not OSError."""
    ghost = InterfaceInfo(name="ghost0", address="203.0.113.7", prefixlen=24)
    monkeypatch.setattr(discovery, "_sweep_bind_budget", lambda *args, **kwargs: 0.0)

    with pytest.raises(DiscoveryError):
        discovery.discover(
            interface="ghost0",
            timeout=0.1,
            scan_tcp=False,
            interfaces=[ghost],
        )


def free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --- authenticated probe deadline ---


def test_probe_authenticated_returns_within_its_overall_deadline(
    dribble_tcp_listener,
) -> None:
    """tinytuya resets its recv retry counter on every byte; the probe must not."""
    listener = dribble_tcp_listener(host="127.0.0.2", interval=0.2)

    started = time.monotonic()
    outcome = discovery.probe_authenticated(
        "127.0.0.2",
        device_id="dev",
        local_key="0123456789abcdef",
        version=3.5,
        port=listener.port,
        timeout=0.4,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert outcome.authenticated is False
    assert outcome.connected is True
    assert "deadline" in outcome.detail


def test_concurrent_discovery_sweeps_each_receive_their_own_reply(
    loopback_udp_responder,
) -> None:
    local_port = free_udp_port()
    responder = loopback_udp_responder(reply_to_port=local_port, settle=0.3)
    interfaces = [InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)]
    barrier = threading.Barrier(2)
    results: list[discovery.DiscoveryResult | None] = [None, None]
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            results[index] = discovery.discover(
                interface="127.0.0.1",
                timeout=1.0,
                scan_tcp=False,
                interfaces=interfaces,
                discovery_port=responder.port,
                local_port=local_port,
            )
        except BaseException as exc:  # noqa: BLE001 - reported through the assertions
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(index,), daemon=True) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    received = [
        any(device.device_id == "0123456789abcdef012345" for device in result.devices)
        for result in results
        if result is not None
    ]
    assert received == [True, True]


def test_two_concurrent_sweeps_both_answer_when_one_send_phase_is_slow(
    loopback_udp_responder, monkeypatch
) -> None:
    """The real /24 send phase takes ~3.1 s; the old ``timeout + 1`` budget lost that race.

    Two sweeps start together and each simulates the measured slow send phase.
    With the derived budget they serialise on the fixed reply port and both
    find the device; with ``timeout + 1`` the second binds an ephemeral port and
    finds nothing.
    """
    local_port = free_udp_port()
    responder = loopback_udp_responder(reply_to_port=local_port, settle=0.05)
    interfaces = [InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)]

    def slow_send(sock, request, interface, *, unicast, port=discovery.DISCOVERY_PORT):
        time.sleep(1.2)
        sock.sendto(request, (interface.broadcast, port))

    monkeypatch.setattr(discovery, "_send_discovery", slow_send)
    barrier = threading.Barrier(2)
    results: list[discovery.DiscoveryResult | None] = [None, None]
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            results[index] = discovery.discover(
                interface="127.0.0.1",
                timeout=0.4,
                scan_tcp=False,
                interfaces=interfaces,
                discovery_port=responder.port,
                local_port=local_port,
            )
        except BaseException as exc:  # noqa: BLE001 - reported through the assertions
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(index,), daemon=True) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert errors == []
    for result in results:
        assert result is not None
        assert result.degraded is False
        assert any(device.device_id == "0123456789abcdef012345" for device in result.devices)
