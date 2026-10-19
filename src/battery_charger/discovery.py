"""LAN discovery for Tuya v3.4/v3.5 devices.

Discovery uses the encrypted 6699 exchange on UDP/7000 (broadcast plus every
candidate host) and probes TCP/6668 as an independent liveness signal. No local
key is needed; :func:`probe_authenticated` is the one exception and performs a
read-only status round trip so ``abc doctor`` can prove identity.

A claimed announcement IP must equal the packet source, because the ``udpkey``
is public and frames can be forged. The tested plug replies to UDP/7000 on the
host regardless of the request's source port, so that port is bound exclusively
and concurrent sweeps serialise; a degraded sweep is never reported as absence.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import itertools
import json
import socket
import struct
import threading
import time
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import tinytuya

DISCOVERY_PORT = 7000
TCP_PORT = 6668
DEFAULT_DISCOVERY_TIMEOUT = 3.0
DEFAULT_TCP_TIMEOUT = 0.35
DEFAULT_AUTH_TIMEOUT = 2.0
TCP_SCAN_WORKERS = 64
MAX_UNICAST_TARGETS = 4096

# A sweep holds the reply port for the send phase plus the timeout.
# Budget 15 ms per target, measured on a /24.
MEASURED_UNICAST_SEND_SECONDS_PER_TARGET = 0.015
BIND_BUDGET_MARGIN = 2.0

_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B

_AUTO_SKIP_PREFIXES = (
    "lo",
    "tailscale",
    "docker",
    "br-",
    "virbr",
    "veth",
    "tun",
    "wg",
    "zt",
    "podman",
    "cni",
)
_AUTO_PREFERRED_PREFIXES = ("wl", "en", "et")


class DiscoveryError(Exception):
    """Raised when discovery cannot run, e.g. no usable network interface."""


@dataclass(frozen=True)
class AuthenticatedProbe:
    """Outcome of an authenticated TCP/6668 status round trip."""

    connected: bool
    authenticated: bool
    detail: str = ""


@dataclass(frozen=True)
class InterfaceInfo:
    """A local IPv4 interface with its prefix length."""

    name: str
    address: str
    prefixlen: int

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.address}/{self.prefixlen}", strict=False)

    @property
    def broadcast(self) -> str:
        return str(self.network.broadcast_address)

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefixlen}"


@dataclass
class DiscoveredDevice:
    """A Tuya device seen on the LAN."""

    ip: str
    device_id: str = ""
    product_key: str = ""
    version: str = ""
    uuid: str = ""
    active: int = 0
    encrypt: bool = False
    token: bool = False
    tcp_open: bool = False
    discovered_via: str = "udp"


@dataclass
class DiscoveryResult:
    """Everything one discovery sweep found, plus the interface it used.

    ``degraded`` means the sweep could not use the fixed reply port and ran on
    an ephemeral one; devices that answer to the discovery port may be missing,
    so a degraded result must never be read as proof of absence.
    ``rejected_announcements`` counts frames whose claimed IP did not match the
    packet source.
    """

    interface: InterfaceInfo
    devices: list[DiscoveredDevice]
    tcp_scanned: bool = True
    degraded: bool = False
    degraded_reason: str = ""
    rejected_announcements: int = 0


def build_discovery_request(host_ip: str) -> bytes:
    """Build the encrypted 6699 discovery request for this host's IPv4 address."""
    body = json.dumps({"from": "app", "ip": host_ip}).encode()
    message = tinytuya.TuyaMessage(
        0,
        tinytuya.REQ_DEVINFO,
        None,
        body,
        0,
        True,
        tinytuya.PREFIX_6699_VALUE,
        True,
    )
    return tinytuya.pack_message(message, hmac_key=tinytuya.udpkey)


def decode_discovery_reply(data: bytes) -> dict | None:
    """Decode a raw reply datagram into the JSON payload, or ``None``."""
    if not data:
        return None
    try:
        message = tinytuya.unpack_message(data, hmac_key=tinytuya.udpkey)
    except Exception:  # noqa: BLE001 - third-party unpack can raise struct/decoding errors
        return None
    if not message.payload:
        return None
    try:
        decoded = json.loads(message.payload)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def device_from_payload(payload: dict, source_ip: str) -> DiscoveredDevice | None:
    """Map a decoded discovery payload to a device; requires a ``gwId``.

    The ``ip`` the payload claims is only trusted when it equals the address the
    datagram was sent from. The ``udpkey`` is public, so a forged frame can claim
    any address; :func:`discover` counts and reports those frames instead of
    accepting them.
    """
    device_id = str(payload.get("gwId") or "").strip()
    if not device_id:
        return None
    claimed_ip = str(payload.get("ip") or "").strip()
    if claimed_ip and claimed_ip != source_ip:
        return None
    try:
        active = int(payload.get("active") or 0)
    except (TypeError, ValueError):
        active = 0
    return DiscoveredDevice(
        ip=source_ip or claimed_ip,
        device_id=device_id,
        product_key=str(payload.get("productKey") or ""),
        version=str(payload.get("version") or ""),
        uuid=str(payload.get("uuid") or ""),
        active=active,
        encrypt=bool(payload.get("encrypt")),
        token=bool(payload.get("token")),
    )


def find_device(devices: Iterable[DiscoveredDevice], device_id: str) -> DiscoveredDevice | None:
    """Return the device with this ``gwId``, or ``None`` when absent/unconfigured."""
    if not device_id:
        return None
    for device in devices:
        if device.device_id == device_id:
            return device
    return None


def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate local IPv4 interfaces and their prefix lengths."""
    interfaces: list[InterfaceInfo] = []
    for _index, name in socket.if_nameindex():
        address_and_mask = _interface_address(name)
        if address_and_mask is None:
            continue
        address, netmask = address_and_mask
        interfaces.append(InterfaceInfo(name=name, address=address, prefixlen=_prefixlen(netmask)))
    return interfaces


def address_is_on_a_local_network(address: str) -> bool:
    """Return whether ``address`` belongs to one of this host's IPv4 networks.

    Used to tell "the plug is down" from "the laptop is on another network":
    an unreachable plug whose address is on no local subnet cannot be observed
    for a power outage from here. Invalid or empty input returns ``False``;
    callers decide how to treat an address they cannot judge.
    """
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(target in interface.network for interface in list_interfaces())


def default_route_interface(route_path: str = "/proc/net/route") -> str | None:
    """Return the interface that carries the IPv4 default route, if known."""
    try:
        with open(route_path, encoding="ascii", errors="replace") as handle:
            return _parse_default_route(handle.read())
    except OSError:
        return None


def _parse_default_route(text: str) -> str | None:
    """Extract the default-route interface name from ``/proc/net/route`` text."""
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "00000000":
            return fields[0]
    return None


def pick_interface(interfaces: list[InterfaceInfo], explicit: str | None = None) -> InterfaceInfo:
    """Pick an interface by name/IP, the default route, or a name heuristic."""
    if explicit:
        for interface in interfaces:
            if interface.name == explicit or interface.address == explicit:
                return interface
        available = ", ".join(f"{item.name} ({item.address})" for item in interfaces)
        raise DiscoveryError(f"interface {explicit!r} not found; available: {available}")

    route_name = default_route_interface()
    if route_name:
        for interface in interfaces:
            if interface.name == route_name and not interface.name.startswith(_AUTO_SKIP_PREFIXES):
                return interface

    for prefix in _AUTO_PREFERRED_PREFIXES:
        preferred = [
            interface
            for interface in interfaces
            if interface.name.startswith(prefix)
            and not interface.name.startswith(_AUTO_SKIP_PREFIXES)
        ]
        if preferred:
            return preferred[0]

    fallback = [
        interface for interface in interfaces if not interface.name.startswith(_AUTO_SKIP_PREFIXES)
    ]
    if fallback:
        return fallback[0]

    raise DiscoveryError("no usable IPv4 network interface found; pass --interface explicitly")


def candidate_hosts(interface: InterfaceInfo, *, limit: int | None = None) -> list[str]:
    """All host addresses in the interface subnet, excluding our own address.

    ``limit`` caps the addresses while iterating, so a huge subnet is never
    materialised just to be sliced afterwards.
    """
    hosts = _iter_candidate_hosts(interface)
    if limit is None:
        return list(hosts)
    return list(itertools.islice(hosts, limit))


def _iter_candidate_hosts(interface: InterfaceInfo) -> Iterator[str]:
    for host in interface.network.hosts():
        address = str(host)
        if address != interface.address:
            yield address


def tcp_port_open(
    ip: str,
    *,
    port: int = TCP_PORT,
    timeout: float = DEFAULT_TCP_TIMEOUT,
    source_address: str | None = None,
) -> bool:
    """Return whether a TCP connection to ``ip:port`` succeeds."""
    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout,
            source_address=(source_address, 0) if source_address else None,
        ):
            return True
    except OSError:
        return False


def probe_tcp_hosts(
    hosts: Iterable[str],
    *,
    port: int = TCP_PORT,
    timeout: float = DEFAULT_TCP_TIMEOUT,
    workers: int = TCP_SCAN_WORKERS,
    source_address: str | None = None,
) -> set[str]:
    """Concurrently probe TCP/6668 on every host and return the open ones."""
    host_list = list(hosts)
    if not host_list:
        return set()
    with ThreadPoolExecutor(max_workers=min(workers, len(host_list))) as pool:
        results = pool.map(
            lambda host: tcp_port_open(
                host, port=port, timeout=timeout, source_address=source_address
            ),
            host_list,
        )
        return {host for host, is_open in zip(host_list, results, strict=True) if is_open}


def probe_authenticated(
    ip: str,
    *,
    device_id: str = "",
    local_key: str = "",
    version: float = 3.5,
    port: int = TCP_PORT,
    timeout: float = DEFAULT_AUTH_TIMEOUT,
) -> AuthenticatedProbe:
    """Query the device status with the local key to prove identity.

    This is a read-only DP_QUERY. ``connected`` means TCP answered even though
    the key did not authenticate; ``authenticated`` means a full status round
    trip succeeded. The probe never raises: doctor must be able to distinguish
    "not reachable" from "reachable but not proven".

    The whole round trip runs under a hard deadline. tinytuya's ``_recv_all``
    resets its retry counter on every received byte, so a peer dribbling bytes
    can otherwise keep the probe alive far past ``timeout``.
    """
    if not ip or not local_key:
        return AuthenticatedProbe(
            connected=False, authenticated=False, detail="no local key configured"
        )
    deadline = max(timeout, 0.0)
    outcome: dict[str, object] = {}
    holder: dict[str, tinytuya.Device] = {}

    def run_probe() -> None:
        device: tinytuya.Device | None = None
        try:
            device = tinytuya.Device(
                device_id,
                address=ip,
                local_key=local_key,
                version=float(version),
                port=port,
                connection_timeout=timeout,
                connection_retry_limit=1,
            )
            holder["device"] = device
            outcome["status"] = device.status()
        except Exception as exc:  # noqa: BLE001 - any transport/crypto failure means "not proven"
            outcome["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if device is not None:
                with contextlib.suppress(Exception):
                    device.close()

    worker = threading.Thread(target=run_probe, name="tuya-auth-probe", daemon=True)
    worker.start()
    worker.join(deadline)
    if worker.is_alive():
        # Unblock a worker stuck in recv so a dribbling peer cannot extend the probe.
        device = holder.get("device")
        if device is not None:
            with contextlib.suppress(Exception):
                connection = getattr(device, "socket", None)
                if connection is not None:
                    connection.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                device.close()
        connected = tcp_port_open(ip, port=port, timeout=min(timeout, 1.0))
        return AuthenticatedProbe(
            connected=connected,
            authenticated=False,
            detail=f"probe exceeded its {timeout:g}s overall deadline",
        )
    status = outcome.get("status")
    failure = str(outcome.get("error") or "")
    if isinstance(status, dict) and not status.get("Err"):
        return AuthenticatedProbe(
            connected=True, authenticated=True, detail="status query succeeded"
        )
    if isinstance(status, dict) and status.get("Err"):
        failure = f"device returned {status.get('Err')}: {status.get('Error', 'unknown error')}"
    connected = tcp_port_open(ip, port=port, timeout=min(timeout, 1.0))
    return AuthenticatedProbe(
        connected=connected, authenticated=False, detail=failure or "no response from device"
    )


def _sweep_bind_budget(interface: InterfaceInfo, timeout: float, *, unicast: bool) -> float:
    """Seconds a competing sweep may wait for the fixed reply port.

    Derived from the measured unicast send rate: a /24 sweep spends ~12 ms per
    ``sendto`` and the port is held for that whole send phase plus the receive
    timeout. ``timeout + 1`` cannot outlast a real sweep.
    """
    send_seconds = 0.0
    if unicast:
        send_seconds = (
            len(_bounded_candidates(interface)) * MEASURED_UNICAST_SEND_SECONDS_PER_TARGET
        )
    return max(timeout, 0.0) + send_seconds + BIND_BUDGET_MARGIN


def discover(
    *,
    interface: str | None = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    scan_tcp: bool = True,
    unicast: bool = True,
    interfaces: Iterable[InterfaceInfo] | None = None,
    discovery_port: int = DISCOVERY_PORT,
    local_port: int = DISCOVERY_PORT,
    tcp_port: int = TCP_PORT,
) -> DiscoveryResult:
    """Run one full discovery sweep: encrypted UDP/7000 plus optional TCP/6668.

    ``interfaces``, ``discovery_port``, ``local_port`` and ``tcp_port`` are
    injection seams so tests can drive the real send/receive loop against
    loopback sockets.
    """
    available = list(interfaces) if interfaces is not None else list_interfaces()
    selected = pick_interface(available, interface)
    devices: dict[str, DiscoveredDevice] = {}
    rejected_announcements = 0

    bind_budget = _sweep_bind_budget(selected, timeout, unicast=unicast)
    with _discovery_socket(selected.address, local_port=local_port, bind_timeout=bind_budget) as (
        sock,
        degraded_reason,
    ):
        request = build_discovery_request(selected.address)
        _send_discovery(sock, request, selected, unicast=unicast, port=discovery_port)
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, sender = sock.recvfrom(65535)
            except OSError:
                break
            payload = decode_discovery_reply(data)
            if payload is None:
                continue
            claimed_ip = str(payload.get("ip") or "").strip()
            if claimed_ip and claimed_ip != sender[0]:
                rejected_announcements += 1
                continue
            device = device_from_payload(payload, sender[0])
            if device is not None:
                devices[device.device_id] = device

    if scan_tcp:
        hosts = _bounded_candidates(selected)
        open_hosts = probe_tcp_hosts(hosts, port=tcp_port, source_address=selected.address)
        for device in devices.values():
            device.tcp_open = device.ip in open_hosts
        known_ips = {device.ip for device in devices.values()}
        for ip in sorted(open_hosts - known_ips, key=ipaddress.ip_address):
            devices[f"tcp:{ip}"] = DiscoveredDevice(ip=ip, tcp_open=True, discovered_via="tcp")

    ordered = sorted(devices.values(), key=lambda device: ipaddress.ip_address(device.ip))
    return DiscoveryResult(
        interface=selected,
        devices=ordered,
        tcp_scanned=scan_tcp,
        degraded=bool(degraded_reason),
        degraded_reason=degraded_reason,
        rejected_announcements=rejected_announcements,
    )


def _bounded_candidates(interface: InterfaceInfo) -> list[str]:
    return candidate_hosts(interface, limit=MAX_UNICAST_TARGETS)


def _send_discovery(
    sock: socket.socket,
    request: bytes,
    interface: InterfaceInfo,
    *,
    unicast: bool,
    port: int = DISCOVERY_PORT,
) -> None:
    targets = [interface.broadcast]
    if unicast:
        targets.extend(_bounded_candidates(interface))
    for target in targets:
        try:
            sock.sendto(request, (target, port))
        except OSError:
            continue


@contextlib.contextmanager
def _discovery_socket(
    address: str,
    *,
    local_port: int = DISCOVERY_PORT,
    bind_timeout: float = 0.0,
) -> Iterator[tuple[socket.socket, str]]:
    """Yield the UDP socket that receives discovery replies on ``address``.

    The tested Tuya v3.5 plug replies to UDP port 7000 on the host, not to the
    source port of the request (verified live: an ephemeral-bound sender gets
    zero replies while an unrelated :7000 listener receives them). The port is
    therefore required and must be exclusive: ``SO_REUSEPORT`` would let two
    concurrent sweeps share it while the kernel delivers every reply to only
    one of them, which is exactly how a live device looked absent. Binding
    without it serialises concurrent sweeps instead; a caller waits up to
    ``bind_timeout`` for the port and then degrades to an ephemeral port for
    devices that do reply to the request source port. The degraded reason is
    yielded so the caller can report it and refuse to treat the sweep as proof
    of absence.
    """
    deadline = time.monotonic() + max(bind_timeout, 0.0)
    degraded_reason = ""
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind((address, local_port))
            break
        except OSError:
            sock.close()
        if time.monotonic() >= deadline:
            degraded_reason = (
                f"UDP port {local_port} on {address} stayed busy for "
                f"{max(bind_timeout, 0.0):.1f}s; ran on an ephemeral port, so "
                "devices that reply to the discovery port may be missed"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind((address, 0))
            except OSError as exc:
                sock.close()
                raise DiscoveryError(
                    f"could not bind a discovery socket on {address}: {exc}"
                ) from exc
            break
        time.sleep(0.05)
    try:
        yield sock, degraded_reason
    finally:
        sock.close()


def _interface_address(name: str) -> tuple[str, str] | None:
    request = struct.pack("256s", name.encode()[:15])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            address_data = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, request)
            netmask_data = fcntl.ioctl(sock.fileno(), _SIOCGIFNETMASK, request)
        except OSError:
            return None
    return socket.inet_ntoa(address_data[20:24]), socket.inet_ntoa(netmask_data[20:24])


def _prefixlen(netmask: str) -> int:
    return bin(int(ipaddress.IPv4Address(netmask))).count("1")
