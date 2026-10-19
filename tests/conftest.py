"""Shared test support: loopback sockets shaped like a Tuya device.

The UDP responder replays a v3.5 discovery reply fixture (device identifiers
are synthetic), rewritten to claim the
address it is actually sent from (production discovery only trusts an
announcement whose claimed IP matches the packet source), and the TCP listener
records the peer address of every accepted connection, so the real discovery
send/receive loop and the TCP probe path can run without hardware.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest
import tinytuya

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY_FIXTURE = FIXTURES / "discovery_reply_v35.hex"


def load_discovery_reply() -> bytes:
    """Return the v3.5 discovery reply fixture as raw frame bytes."""
    return bytes.fromhex(DISCOVERY_FIXTURE.read_text(encoding="ascii").strip())


def rewrite_discovery_reply_ip(frame: bytes, ip: str) -> bytes:
    """Return the fixture reply with its claimed ``ip`` set to ``ip``.

    A loopback responder impersonates a device at the loopback address it
    answers from; without this the claimed fixture address would not match the
    packet source and production code would (correctly) reject the frame.
    """
    message = tinytuya.unpack_message(frame, hmac_key=tinytuya.udpkey)
    payload = json.loads(message.payload)
    payload["ip"] = ip
    rewritten = tinytuya.TuyaMessage(
        message.seqno,
        message.cmd,
        0,
        json.dumps(payload).encode(),
        0,
        True,
        tinytuya.PREFIX_6699_VALUE,
        False,
    )
    return tinytuya.pack_message(rewritten, hmac_key=tinytuya.udpkey)


class UdpDiscoveryResponder:
    """Reply to every discovery datagram with a Tuya reply frame fixture.

    Replies are held until ``expected_senders`` distinct source endpoints have
    been seen (or ``settle`` seconds pass with no new one), which is what makes
    two concurrent sweeps observable: each sweep must receive its own reply.
    """

    def __init__(
        self,
        reply: bytes | None = None,
        *,
        expected_senders: int = 1,
        settle: float = 0.4,
        reply_to_port: int | None = None,
        rewrite_ip: bool = True,
    ) -> None:
        self.reply = reply if reply is not None else load_discovery_reply()
        self.expected_senders = expected_senders
        self.settle = settle
        # Model the tested plug's fixed destination port.
        self.reply_to_port = reply_to_port
        # ``rewrite_ip=False`` models a forged frame: the claimed address does
        # not match the address the datagram is actually sent from.
        self.rewrite_ip = rewrite_ip
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 0))
        self.socket.settimeout(0.05)
        self.port = self.socket.getsockname()[1]
        self.senders: list[tuple[str, int]] = []
        self._rewritten: dict[str, bytes] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _reply_for(self, sender_ip: str) -> bytes:
        if not self.rewrite_ip:
            return self.reply
        cached = self._rewritten.get(sender_ip)
        if cached is None:
            cached = rewrite_discovery_reply_ip(self.reply, sender_ip)
            self._rewritten[sender_ip] = cached
        return cached

    def _serve(self) -> None:
        pending: set[tuple[str, int]] = set()
        last_seen: float | None = None
        while not self._stop.is_set():
            try:
                _data, sender = self.socket.recvfrom(65535)
            except TimeoutError:
                pass
            except OSError:
                break
            else:
                if sender not in pending:
                    pending.add(sender)
                    self.senders.append(sender)
                last_seen = time.monotonic()
            if pending and (
                len(pending) >= self.expected_senders
                or (last_seen is not None and time.monotonic() - last_seen >= self.settle)
            ):
                for sender in list(pending):
                    target = (
                        (sender[0], self.reply_to_port)
                        if self.reply_to_port is not None
                        else sender
                    )
                    try:
                        self.socket.sendto(self._reply_for(sender[0]), target)
                    except OSError:
                        pass
                pending.clear()
                last_seen = None

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.socket.close()


class TcpListener:
    """Accept TCP connections on a loopback address and record peer addresses."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, 0))
        self.socket.listen(8)
        self.host, self.port = self.socket.getsockname()
        self.peers: list[tuple[str, int]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.socket.settimeout(0.05)
        while not self._stop.is_set():
            try:
                connection, peer = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            self.peers.append(peer)
            connection.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.socket.close()

    def wait_for_peer(self, timeout: float = 2.0) -> list[tuple[str, int]]:
        """Wait briefly for at least one accepted connection and return peers."""
        deadline = time.monotonic() + timeout
        while not self.peers and time.monotonic() < deadline:
            time.sleep(0.01)
        return list(self.peers)


class DribbleTcpListener:
    """Accept TCP connections and dribble one byte at a time, forever.

    This models the peer that defeats tinytuya's per-``recv`` timeout: its
    ``_recv_all`` resets its retry counter on every received byte, so a slow
    drip can keep an authenticated probe running far past its timeout.
    """

    def __init__(
        self, host: str = "127.0.0.1", *, interval: float = 0.2, total: float = 30.0
    ) -> None:
        self.interval = interval
        self.total = total
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, 0))
        self.socket.listen(8)
        self.host, self.port = self.socket.getsockname()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.socket.settimeout(0.05)
        while not self._stop.is_set():
            try:
                connection, _peer = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._dribble, args=(connection,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _dribble(self, connection: socket.socket) -> None:
        deadline = time.monotonic() + self.total
        try:
            while not self._stop.is_set() and time.monotonic() < deadline:
                connection.sendall(b"\x00")
                time.sleep(self.interval)
        except OSError:
            pass
        finally:
            connection.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.socket.close()


@pytest.fixture
def loopback_udp_responder():
    """Factory for UDP discovery responders cleaned up after each test."""
    created: list[UdpDiscoveryResponder] = []

    def start(**kwargs: object) -> UdpDiscoveryResponder:
        responder = UdpDiscoveryResponder(**kwargs)
        created.append(responder)
        return responder

    yield start
    for responder in created:
        responder.close()


@pytest.fixture
def loopback_tcp_listener():
    """Factory for TCP listeners cleaned up after each test."""
    created: list[TcpListener] = []

    def start(host: str = "127.0.0.1") -> TcpListener:
        listener = TcpListener(host)
        created.append(listener)
        return listener

    yield start
    for listener in created:
        listener.close()


@pytest.fixture
def dribble_tcp_listener():
    """Factory for slow-drip TCP listeners cleaned up after each test."""
    created: list[DribbleTcpListener] = []

    def start(host: str = "127.0.0.1", **kwargs: float) -> DribbleTcpListener:
        listener = DribbleTcpListener(host, **kwargs)
        created.append(listener)
        return listener

    yield start
    for listener in created:
        listener.close()
