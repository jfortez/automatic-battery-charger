"""One-time local key provisioning through Tuya's public sharing client.

The only module that talks to the Tuya cloud: the User Code from the app, a QR
login, then list the account's devices and read their local keys.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import qrcode
from tuya_sharing import LoginControl, Manager

TUYA_CLIENT_ID = "HA_3y9q4ak7g4ephrvke"
TUYA_SCHEMA = "haauthorize"
QRCODE_URL_PREFIX = "tuyaSmart--qrLogin?token="
DEFAULT_POLL_TIMEOUT = 180.0
DEFAULT_POLL_INTERVAL = 2.0


class LoginError(Exception):
    """Raised when the QR login or the device listing fails."""


class UserCodeRejected(LoginError):
    """Raised when Tuya rejects the User Code entered by the user."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"Tuya rejected the user code ({code}): {message}")
        self.code = code
        self.message = message


class LoginTimeout(LoginError):
    """Raised when nobody scans the QR code before the deadline."""


# Only confirmed terminal codes abort; unknown codes keep polling.
_TERMINAL_LOGIN_CODES = frozenset({"USERCODE_INCORRECT"})


@dataclass(frozen=True)
class QrSession:
    """An in-flight QR login."""

    user_code: str
    token: str
    qr_data: str


@dataclass(frozen=True)
class AccountDevice:
    """A device as reported by the Tuya sharing cloud."""

    id: str
    name: str
    local_key: str = field(default="", repr=False)
    category: str = ""
    product_id: str = ""
    product_name: str = ""
    online: bool = False
    ip: str = ""
    support_local: bool = False


def request_qr(login_control: LoginControl, user_code: str) -> QrSession:
    """Request a QR token for this user code and render data."""
    try:
        response = login_control.qr_code(TUYA_CLIENT_ID, TUYA_SCHEMA, user_code)
    except (OSError, ValueError) as exc:
        # Transport and JSON errors become clean login errors, not tracebacks.
        raise LoginError(f"could not reach the Tuya cloud: {exc}") from exc
    if not isinstance(response, dict):
        # A non-dict body would escape as AttributeError or TypeError.
        raise LoginError(f"Tuya returned a malformed QR login response ({type(response).__name__})")
    if not response.get("success"):
        raise UserCodeRejected(
            str(response.get("code", "UNKNOWN")),
            str(response.get("msg", "Unknown error")),
        )
    result = response.get("result") or {}
    token = result.get("qrcode") if isinstance(result, dict) else None
    if not token:
        raise LoginError("QR login response did not contain a token")
    return QrSession(user_code=user_code, token=str(token), qr_data=QRCODE_URL_PREFIX + str(token))


def render_qr(qr_data: str, out: Any = None) -> None:
    """Render the QR payload as ASCII blocks in the terminal."""
    code = qrcode.QRCode(border=1)
    code.add_data(qr_data)
    code.make(fit=True)
    code.print_ascii(out=out, invert=True)


def poll_login(
    login_control: LoginControl,
    session: QrSession,
    *,
    timeout: float = DEFAULT_POLL_TIMEOUT,
    interval: float = DEFAULT_POLL_INTERVAL,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    on_unknown_code: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Poll until the QR code is scanned, returning the token response.

    ``on_unknown_code`` is called once per distinct unrecognised failure code
    so the operator can see it; polling continues because the code may simply
    mean the scan has not happened yet.

    A transport hiccup mid-poll is retried rather than fatal: the QR stays valid
    for the whole window, so an occasional empty or non-JSON response must not
    abort a login nobody has scanned yet. The failure is reported if the
    deadline passes without a successful response.
    """
    deadline = monotonic() + timeout
    surfaced: set[str] = set()
    while True:
        try:
            response = login_control.login_result(session.token, TUYA_CLIENT_ID, session.user_code)
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            # Transient cloud failures are retried until the deadline.
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise LoginError(f"could not reach the Tuya cloud: {exc}") from exc
            sleep(min(interval, remaining))
            continue
        if not (
            isinstance(response, tuple)
            and len(response) == 2
            and isinstance(response[0], bool)
            and isinstance(response[1], dict)
        ):
            raise LoginError(
                f"Tuya returned a malformed login poll response ({type(response).__name__})"
            )
        success, info = response
        if success:
            return info
        refusal = _terminal_login_failure(info)
        if refusal is not None:
            raise LoginError(refusal)
        code = str(info.get("code") or "").strip()
        if code and code.upper() not in surfaced:
            surfaced.add(code.upper())
            if on_unknown_code is not None:
                on_unknown_code(code, str(info.get("msg") or "Unknown error").strip())
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise LoginTimeout(f"QR login timed out after {timeout:g}s; run `abc auth` again")
        sleep(min(interval, remaining))


def _terminal_login_failure(info: dict[str, Any]) -> str | None:
    """Return a message only for failure codes known to be terminal.

    Unknown non-empty codes are assumed to still be pending; aborting on them
    can stop a login that would have completed, and retrying reproduces it.
    """
    code = str(info.get("code") or "").strip()
    if code.upper() not in _TERMINAL_LOGIN_CODES:
        return None
    message = str(info.get("msg") or "Unknown error").strip()
    return f"Tuya rejected the login ({code}): {message}"


def account_device_from(device: Any) -> AccountDevice:
    """Map a ``tuya_sharing.CustomerDevice`` to our small read-only model."""
    return AccountDevice(
        id=str(getattr(device, "id", "") or ""),
        name=str(getattr(device, "name", "") or ""),
        local_key=str(getattr(device, "local_key", "") or ""),
        category=str(getattr(device, "category", "") or ""),
        product_id=str(getattr(device, "product_id", "") or ""),
        product_name=str(getattr(device, "product_name", "") or ""),
        online=bool(getattr(device, "online", False)),
        ip=str(getattr(device, "ip", "") or ""),
        support_local=bool(getattr(device, "support_local", False)),
    )


def fetch_devices(
    token_info: dict[str, Any],
    user_code: str,
    *,
    manager_factory: Callable[..., Any] = Manager,
) -> list[AccountDevice]:
    """List every device on the account using the credentials from the QR login."""
    terminal_id = token_info.get("terminal_id")
    end_point = token_info.get("endpoint")
    if not terminal_id or not end_point:
        raise LoginError("login response did not include terminal_id/endpoint; cannot list devices")
    manager = manager_factory(
        TUYA_CLIENT_ID,
        user_code,
        terminal_id,
        end_point,
        token_response=token_info,
    )
    manager.update_device_cache()
    return [account_device_from(device) for device in manager.device_map.values()]
