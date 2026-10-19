"""Tests for the Tuya sharing login seam, driven by stubbed LoginControl objects."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest
import requests

from battery_charger import auth


def make_session() -> auth.QrSession:
    return auth.QrSession(
        user_code="USER123", token="QRTOKEN", qr_data="tuyaSmart--qrLogin?token=QRTOKEN"
    )


class StubLoginControl:
    """Records calls and replays canned responses; never touches the network."""

    def __init__(self, qr_response: dict, poll_results: list[tuple[bool, dict]]) -> None:
        self.qr_response = qr_response
        self.poll_results = list(poll_results)
        self.qr_calls: list[tuple[str, str, str]] = []
        self.poll_calls: list[tuple[str, str, str]] = []

    def qr_code(self, client_id: str, schema: str, user_code: str) -> dict:
        self.qr_calls.append((client_id, schema, user_code))
        return self.qr_response

    def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
        self.poll_calls.append((token, client_id, user_code))
        if not self.poll_results:
            raise AssertionError("poll_login called login_result more often than expected")
        return self.poll_results.pop(0)


def test_request_qr_uses_home_assistant_public_client() -> None:
    login = StubLoginControl({"success": True, "result": {"qrcode": "QRTOKEN"}}, [])

    session = auth.request_qr(login, "USER123")

    assert login.qr_calls == [(auth.TUYA_CLIENT_ID, auth.TUYA_SCHEMA, "USER123")]
    assert session.token == "QRTOKEN"
    assert session.user_code == "USER123"
    assert session.qr_data == "tuyaSmart--qrLogin?token=QRTOKEN"


def test_request_qr_raises_helpful_error_when_user_code_is_rejected() -> None:
    login = StubLoginControl(
        {"success": False, "code": "USERCODE_INCORRECT", "msg": "User Code Incorrect"}, []
    )

    with pytest.raises(auth.UserCodeRejected) as excinfo:
        auth.request_qr(login, "BAD")

    assert excinfo.value.code == "USERCODE_INCORRECT"
    assert "User Code Incorrect" in str(excinfo.value)


def test_request_qr_raises_when_token_is_missing() -> None:
    login = StubLoginControl({"success": True, "result": {}}, [])

    with pytest.raises(auth.LoginError, match="token"):
        auth.request_qr(login, "USER123")


def test_request_qr_wraps_requests_failures() -> None:
    class BrokenLogin:
        def qr_code(self, client_id: str, schema: str, user_code: str) -> dict:
            raise requests.exceptions.ConnectionError("connection refused")

    with pytest.raises(auth.LoginError, match="connection refused"):
        auth.request_qr(BrokenLogin(), "USER123")


def test_request_qr_wraps_json_decode_failures() -> None:
    class BrokenLogin:
        def qr_code(self, client_id: str, schema: str, user_code: str) -> dict:
            raise json.JSONDecodeError("Expecting value", "<html>", 0)

    with pytest.raises(auth.LoginError, match="Expecting value"):
        auth.request_qr(BrokenLogin(), "USER123")


def test_request_qr_wraps_a_malformed_response() -> None:
    """A None/[]/null cloud response must not escape as AttributeError/TypeError."""

    class MalformedLogin:
        def __init__(self, response: object) -> None:
            self.response = response

        def qr_code(self, client_id: str, schema: str, user_code: str) -> object:
            return self.response

    for response in (None, [], "null", 0):
        with pytest.raises(auth.LoginError, match="malformed"):
            auth.request_qr(MalformedLogin(response), "USER123")  # type: ignore[arg-type]


def test_poll_login_retries_until_the_user_scans() -> None:
    login = StubLoginControl(
        {"success": True, "result": {"qrcode": "QRTOKEN"}},
        [
            (False, {"success": False, "code": "PENDING", "msg": "not scanned yet"}),
            (False, {"success": False, "code": "PENDING", "msg": "not scanned yet"}),
            (True, {"access_token": "at", "t": 123}),
        ],
    )
    session = auth.request_qr(login, "USER123")
    clock = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    info = auth.poll_login(
        login,
        session,
        timeout=30.0,
        interval=2.0,
        sleep=fake_sleep,
        monotonic=lambda: clock[0],
    )

    assert info == {"access_token": "at", "t": 123}
    assert sleeps == [2.0, 2.0]
    assert login.poll_calls == [
        ("QRTOKEN", auth.TUYA_CLIENT_ID, "USER123"),
        ("QRTOKEN", auth.TUYA_CLIENT_ID, "USER123"),
        ("QRTOKEN", auth.TUYA_CLIENT_ID, "USER123"),
    ]


def test_poll_login_times_out_and_never_sleeps_past_the_deadline() -> None:
    login = StubLoginControl(
        {"success": True, "result": {"qrcode": "QRTOKEN"}},
        [(False, {"success": False, "code": "PENDING"})] * 10,
    )
    session = auth.request_qr(login, "USER123")
    clock = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    with pytest.raises(auth.LoginTimeout):
        auth.poll_login(
            login,
            session,
            timeout=5.0,
            interval=2.0,
            sleep=fake_sleep,
            monotonic=lambda: clock[0],
        )

    assert clock[0] >= 5.0
    assert sum(sleeps) <= 5.0


def test_poll_login_surfaces_a_terminal_refusal_instead_of_timing_out() -> None:
    login = StubLoginControl(
        {"success": True, "result": {"qrcode": "QRTOKEN"}},
        [
            (
                False,
                {
                    "success": False,
                    "code": "USERCODE_INCORRECT",
                    "msg": "User Code Incorrect",
                },
            )
        ],
    )
    session = auth.request_qr(login, "USER123")

    with pytest.raises(auth.LoginError) as excinfo:
        auth.poll_login(login, session, timeout=30.0, interval=2.0)

    assert "USERCODE_INCORRECT" in str(excinfo.value)
    assert "User Code Incorrect" in str(excinfo.value)


def test_poll_login_keeps_retrying_when_the_api_omits_a_code() -> None:
    login = StubLoginControl(
        {"success": True, "result": {"qrcode": "QRTOKEN"}},
        [
            (False, {"success": False, "msg": "waiting for the QR code to be scanned"}),
            (False, {"success": False, "code": "USERCODE_NOT_SCANNED", "msg": "not scanned"}),
            (True, {"access_token": "at", "t": 123}),
        ],
    )
    session = auth.request_qr(login, "USER123")

    info = auth.poll_login(login, session, timeout=30.0, interval=2.0, sleep=lambda _s: None)

    assert info == {"access_token": "at", "t": 123}
    assert len(login.poll_calls) == 3


def test_poll_login_survives_a_transient_transport_failure() -> None:
    """A hiccup mid-poll must not abort a login nobody has scanned yet.

    A `null` body makes the SDK call `.get` on None, so AttributeError is part of
    this class and must be retried the same way a JSON decode failure is.
    """

    class FlakyLogin(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            self.poll_calls.append((token, client_id, user_code))
            if len(self.poll_calls) == 1:
                raise ValueError("Expecting value: line 1 column 1 (char 0)")
            if len(self.poll_calls) == 2:
                raise AttributeError("'NoneType' object has no attribute 'get'")
            return (True, {"access_token": "at", "t": 123})

    login = FlakyLogin({"success": True, "result": {"qrcode": "QRTOKEN"}}, [])
    session = auth.request_qr(login, "USER123")

    info = auth.poll_login(login, session, timeout=30.0, interval=2.0, sleep=lambda _s: None)

    assert info == {"access_token": "at", "t": 123}
    assert len(login.poll_calls) == 3


def test_poll_login_reports_the_transport_error_only_after_the_deadline() -> None:
    """Retrying forever would hide a dead endpoint, so the error is still raised."""

    class DeadLogin(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            raise requests.exceptions.Timeout("timed out")

    login = DeadLogin({"success": True, "result": {"qrcode": "QRTOKEN"}}, [])
    session = auth.request_qr(login, "USER123")
    clock = [0.0]

    def fake_sleep(seconds: float) -> None:
        clock[0] += seconds

    with pytest.raises(auth.LoginError, match="could not reach the Tuya cloud"):
        auth.poll_login(
            login,
            session,
            timeout=5.0,
            interval=2.0,
            sleep=fake_sleep,
            monotonic=lambda: clock[0],
        )

    assert clock[0] >= 5.0


def test_poll_login_wraps_a_malformed_poll_response() -> None:
    """A None/[]/null poll response must not escape as AttributeError/TypeError."""

    class MalformedLogin:
        def __init__(self, response: object) -> None:
            self.response = response

        def login_result(self, token: str, client_id: str, user_code: str) -> object:
            return self.response

    session = make_session()
    for response in (None, [], "null", (False, None), (False, [])):
        with pytest.raises(auth.LoginError, match="malformed"):
            auth.poll_login(MalformedLogin(response), session, timeout=5.0, interval=1.0)  # type: ignore[arg-type]


def test_poll_login_keeps_polling_unknown_codes_and_surfaces_them_once() -> None:
    """Unknown codes may be pending; aborting on them can make provisioning impossible."""
    login = StubLoginControl(
        {"success": True, "result": {"qrcode": "QRTOKEN"}},
        [
            (False, {"success": False, "code": "USERCODE_EXPIRED", "msg": "scan window expired"}),
            (False, {"success": False, "code": "USERCODE_EXPIRED", "msg": "scan window expired"}),
            (True, {"access_token": "at", "t": 123}),
        ],
    )
    session = auth.request_qr(login, "USER123")
    surfaced: list[tuple[str, str]] = []

    info = auth.poll_login(
        login,
        session,
        timeout=30.0,
        interval=2.0,
        sleep=lambda _seconds: None,
        on_unknown_code=lambda code, message: surfaced.append((code, message)),
    )

    assert info == {"access_token": "at", "t": 123}
    assert len(login.poll_calls) == 3
    # Surfaced once, not once per poll.
    assert surfaced == [("USERCODE_EXPIRED", "scan window expired")]


def test_render_qr_writes_block_characters() -> None:
    out = io.StringIO()

    auth.render_qr("tuyaSmart--qrLogin?token=ABC", out=out)

    text = out.getvalue()
    assert text.strip()
    assert any(character in text for character in "\u2588\u2580\u2584")


def test_account_device_from_customer_device() -> None:
    customer_device = SimpleNamespace(
        id="dev-1",
        name="Plug",
        local_key="0123456789abcdef",
        category="cz",
        product_id="abcdefghijklmnop",
        product_name="Test plug",
        online=True,
        ip="192.168.1.100",
        support_local=True,
    )

    device = auth.account_device_from(customer_device)

    assert device.id == "dev-1"
    assert device.name == "Plug"
    assert device.local_key == "0123456789abcdef"
    assert device.product_name == "Test plug"
    assert device.online is True
    assert device.ip == "192.168.1.100"
    assert device.support_local is True
    assert "0123456789abcdef" not in repr(device)


def test_account_device_from_tolerates_missing_attributes() -> None:
    device = auth.account_device_from(SimpleNamespace(id="dev-1", name="Plug"))

    assert device.id == "dev-1"
    assert device.local_key == ""
    assert device.online is False
    assert device.ip == ""


def test_fetch_devices_uses_the_login_response_credentials() -> None:
    created: dict = {}

    class FakeManager:
        def __init__(
            self,
            client_id: str,
            user_code: str,
            terminal_id: str,
            end_point: str,
            token_response: dict | None = None,
            listener: object | None = None,
        ) -> None:
            created.update(
                client_id=client_id,
                user_code=user_code,
                terminal_id=terminal_id,
                end_point=end_point,
                token_response=token_response,
            )
            self.device_map = {
                "dev-1": SimpleNamespace(
                    id="dev-1", name="Plug", local_key="key", ip="192.168.1.100"
                ),
            }

        def update_device_cache(self) -> None:
            created["cache_updated"] = True

    token_info = {
        "access_token": "at",
        "t": 123,
        "terminal_id": "term-1",
        "endpoint": "https://apigw.tuyaus.com",
    }

    devices = auth.fetch_devices(token_info, "USER123", manager_factory=FakeManager)

    assert created == {
        "client_id": auth.TUYA_CLIENT_ID,
        "user_code": "USER123",
        "terminal_id": "term-1",
        "end_point": "https://apigw.tuyaus.com",
        "token_response": token_info,
        "cache_updated": True,
    }
    assert [device.id for device in devices] == ["dev-1"]


def test_fetch_devices_requires_terminal_id_and_endpoint() -> None:
    with pytest.raises(auth.LoginError):
        auth.fetch_devices({"access_token": "at"}, "USER123", manager_factory=object)
