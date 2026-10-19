"""CLI-level tests: verdicts, exit codes, QR rendering and secret redaction."""

from __future__ import annotations

import json
import socket
import stat
from pathlib import Path

import pytest
import requests
from typer.testing import CliRunner

from battery_charger import auth, cli, discovery, plug
from battery_charger.config import Config, DeviceConfig, load_config, write_config

runner = CliRunner()

TARGET_ID = "0123456789abcdef012345"
LOCAL_KEY = "0123456789abcdef"


def target_device() -> discovery.DiscoveredDevice:
    return discovery.DiscoveredDevice(
        ip="192.168.1.100",
        device_id=TARGET_ID,
        product_key="abcdefghijklmnop",
        version="3.5",
        tcp_open=True,
    )


def other_device() -> discovery.DiscoveredDevice:
    return discovery.DiscoveredDevice(
        ip="192.168.1.181",
        device_id="",
        product_key="",
        version="",
        tcp_open=True,
        discovered_via="tcp",
    )


def fake_discovery(devices: list[discovery.DiscoveredDevice]):
    def _discover(**_kwargs: object) -> discovery.DiscoveryResult:
        return discovery.DiscoveryResult(
            interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
            devices=list(devices),
        )

    return _discover


def account_device() -> auth.AccountDevice:
    return auth.AccountDevice(
        id="dev-1",
        name="Test plug",
        local_key=LOCAL_KEY,
        product_id="abcdefghijklmnop",
        product_name="Test plug",
        online=True,
        ip="192.168.1.100",
        support_local=True,
    )


class StubLoginControl:
    def __init__(self, poll_results: list[tuple[bool, dict]] | None = None) -> None:
        self.poll_results = list(
            poll_results
            or [
                (
                    True,
                    {
                        "access_token": "at",
                        "refresh_token": "rt",
                        "expire_time": 3600,
                        "uid": "uid-1",
                        "t": 123,
                        "terminal_id": "term-1",
                        "endpoint": "https://apigw.tuyaus.com",
                    },
                )
            ]
        )

    def qr_code(self, client_id: str, schema: str, user_code: str) -> dict:
        return {"success": True, "result": {"qrcode": "QRTOKEN"}, "t": 123}

    def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
        return self.poll_results.pop(0)


# --- doctor ---


def test_doctor_reports_the_configured_target_as_found(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100")), config_path)
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device(), other_device()]))

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == 0, result.output
    assert TARGET_ID in result.output
    assert "abcdefghijklmnop" in result.output
    assert "3.5" in result.output
    assert f"Target {TARGET_ID}: FOUND" in result.output


def test_doctor_exits_3_when_the_configured_target_is_absent(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id="missing-device-id")), config_path)
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == cli.TARGET_MISSING_EXIT_CODE == 3
    assert "ABSENT" in result.output


def test_doctor_lists_everything_and_exits_0_without_a_configured_id(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "missing-config.toml"
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device(), other_device()]))

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == 0, result.output
    assert "No device.id configured" in result.output
    assert "192.168.1.100" in result.output
    assert "192.168.1.181" in result.output
    assert not config_path.exists()


def test_doctor_exits_2_on_unreadable_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("low_threshold = [")
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "invalid TOML" in result.output


def test_doctor_exits_2_on_a_non_utf8_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_bytes(b"\xff\xfe\x00\x01")
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "UTF-8" in result.output


def test_doctor_no_scan_tcp_marks_the_column_as_not_probed(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "missing.toml"

    def discovery_without_tcp(**_kwargs: object) -> discovery.DiscoveryResult:
        return discovery.DiscoveryResult(
            interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
            devices=[target_device()],
            tcp_scanned=False,
        )

    monkeypatch.setattr(discovery, "discover", discovery_without_tcp)

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor", "--no-scan-tcp"])

    assert result.exit_code == 0, result.output
    assert "TCP/6668" in result.output
    assert "open" not in result.output


def test_format_device_table_marks_tcp_only_devices_unknown() -> None:
    text = cli.format_device_table([target_device(), other_device()], tcp_scanned=True)

    lines = text.splitlines()
    assert lines[0].startswith("IP")
    assert any(line.startswith("192.168.1.100") and "open" in line for line in lines[1:])
    assert any(line.startswith("192.168.1.181") and "(unknown)" in line for line in lines[1:])


def test_target_verdict_exit_code_mapping() -> None:
    assert cli.TargetVerdict(cli.TargetState.FOUND, "").exit_code == 0
    assert cli.TargetVerdict(cli.TargetState.INDETERMINATE, "").exit_code == 4
    assert cli.TargetVerdict(cli.TargetState.ABSENT, "").exit_code == 3


def sample_result(devices: list[discovery.DiscoveredDevice]) -> discovery.DiscoveryResult:
    return discovery.DiscoveryResult(
        interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
        devices=list(devices),
    )


def test_target_verdict_found_when_discovery_proves_identity() -> None:
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100"))

    verdict = cli.resolve_target(config, sample_result([target_device(), other_device()]))

    assert verdict.state is cli.TargetState.FOUND
    assert verdict.exit_code == 0
    assert "gwId" in verdict.evidence


def test_target_verdict_found_when_the_authenticated_round_trip_succeeds() -> None:
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100", local_key=LOCAL_KEY))
    calls: list[tuple[str, str, float]] = []

    def probe(ip: str, **kwargs: object) -> discovery.AuthenticatedProbe:
        calls.append((ip, str(kwargs["device_id"]), float(kwargs["version"])))
        return discovery.AuthenticatedProbe(connected=True, authenticated=True, detail="ok")

    verdict = cli.resolve_target(config, sample_result([other_device()]), probe=probe)

    assert verdict.state is cli.TargetState.FOUND
    assert verdict.exit_code == 0
    assert "authenticated" in verdict.evidence
    assert calls == [("192.168.1.100", TARGET_ID, 3.5)]


def test_target_verdict_indeterminate_when_the_probe_connects_but_auth_fails() -> None:
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100", local_key=LOCAL_KEY))

    def probe(*_args: object, **_kwargs: object) -> discovery.AuthenticatedProbe:
        return discovery.AuthenticatedProbe(
            connected=True,
            authenticated=False,
            detail="device returned 914: Check device key or version",
        )

    verdict = cli.resolve_target(config, sample_result([other_device()]), probe=probe)

    assert verdict.state is cli.TargetState.INDETERMINATE
    assert verdict.exit_code == cli.INDETERMINATE_EXIT_CODE == 4
    assert "did not authenticate" in verdict.evidence


def test_target_verdict_indeterminate_when_tcp_is_open_without_a_key() -> None:
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100"))
    tcp_only = discovery.DiscoveredDevice(ip="192.168.1.100", tcp_open=True, discovered_via="tcp")

    verdict = cli.resolve_target(config, sample_result([tcp_only]))

    assert verdict.state is cli.TargetState.INDETERMINATE
    assert verdict.exit_code == 4


def test_target_verdict_absent_without_any_evidence() -> None:
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100"))

    verdict = cli.resolve_target(config, sample_result([other_device()]))

    assert verdict.state is cli.TargetState.ABSENT
    assert verdict.exit_code == cli.TARGET_MISSING_EXIT_CODE == 3


def test_target_verdict_is_indeterminate_when_discovery_was_degraded() -> None:
    """A degraded sweep has not proven absence and must not report ABSENT."""
    config = Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100"))
    result = sample_result([other_device()])
    result.degraded = True
    result.degraded_reason = "UDP port 7000 stayed busy; ran on an ephemeral port"

    verdict = cli.resolve_target(config, result)

    assert verdict.state is cli.TargetState.INDETERMINATE
    assert verdict.exit_code == cli.INDETERMINATE_EXIT_CODE == 4
    assert "degraded" in verdict.evidence


def test_doctor_warns_and_reports_indeterminate_when_discovery_was_degraded(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100")), config_path)

    def degraded_discovery(**_kwargs: object) -> discovery.DiscoveryResult:
        return discovery.DiscoveryResult(
            interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
            devices=[],
            degraded=True,
            degraded_reason="UDP port 7000 stayed busy for 8.0s; ran on an ephemeral port",
        )

    monkeypatch.setattr(discovery, "discover", degraded_discovery)

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor", "--no-scan-tcp"])

    assert result.exit_code == cli.INDETERMINATE_EXIT_CODE == 4
    assert "warning" in result.output.lower()
    assert "ephemeral" in result.output
    assert "INDETERMINATE" in result.output
    assert "ABSENT" not in result.output


def test_doctor_warns_about_discarded_forged_announcements(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100")), config_path)

    def discovery_with_forged_frame(**_kwargs: object) -> discovery.DiscoveryResult:
        return discovery.DiscoveryResult(
            interface=discovery.InterfaceInfo(name="wlan0", address="192.168.1.229", prefixlen=24),
            devices=[target_device()],
            rejected_announcements=1,
        )

    monkeypatch.setattr(discovery, "discover", discovery_with_forged_frame)

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor", "--no-scan-tcp"])

    assert result.exit_code == 0, result.output
    assert "warning" in result.output.lower()
    assert "claimed" in result.output
    assert "packet source" in result.output


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.100",
        "169.254.9.9",
        "fc00::1",
        "fd12:3456::1",
    ],
)
def test_is_lan_address_accepts_private_link_local_and_ula(value: str) -> None:
    assert cli._is_lan_address(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-an-ip",
        "127.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "192.0.2.1",
        "203.0.113.9",
        "224.0.0.1",
        "198.18.0.1",
        "8.8.8.8",
        "203.0.113.10",
        "::1",
        "fe80::1",
    ],
)
def test_is_lan_address_rejects_loopback_unspecified_test_net_and_cgnat(value: str) -> None:
    assert not cli._is_lan_address(value)


def closed_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_doctor_reports_indeterminate_when_only_tcp_answers(
    tmp_path: Path, monkeypatch, loopback_tcp_listener
) -> None:
    listener = loopback_tcp_listener(host="127.0.0.2")
    real_result = discovery.discover(
        interface="127.0.0.1",
        timeout=0.1,
        interfaces=[discovery.InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
        discovery_port=closed_udp_port(),
        tcp_port=listener.port,
    )
    assert [device.ip for device in real_result.devices] == ["127.0.0.2"]

    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id="missing-target", ip="127.0.0.2")), config_path)
    monkeypatch.setattr(discovery, "discover", lambda **_kwargs: real_result)

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == cli.INDETERMINATE_EXIT_CODE == 4
    assert "INDETERMINATE" in result.output
    assert "did not prove identity" in result.output
    assert "127.0.0.2" in result.output


def test_doctor_reports_found_from_a_real_udp_reply(
    tmp_path: Path,
    monkeypatch,
    loopback_udp_responder,
    loopback_tcp_listener,
) -> None:
    responder = loopback_udp_responder(expected_senders=1)
    listener = loopback_tcp_listener(host="127.0.0.2")
    real_result = discovery.discover(
        interface="127.0.0.1",
        timeout=1.5,
        interfaces=[discovery.InterfaceInfo(name="lo-test", address="127.0.0.1", prefixlen=30)],
        discovery_port=responder.port,
        tcp_port=listener.port,
    )
    assert any(device.device_id == TARGET_ID for device in real_result.devices)

    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100")), config_path)
    monkeypatch.setattr(discovery, "discover", lambda **_kwargs: real_result)

    result = runner.invoke(cli.app, ["--config", str(config_path), "doctor"])

    assert result.exit_code == 0, result.output
    assert f"Target {TARGET_ID}: FOUND" in result.output
    assert "gwId" in result.output


# --- auth ---


def test_auth_writes_the_selected_device_without_leaking_the_local_key(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [account_device()])
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    assert any(character in result.output for character in "\u2588\u2580\u2584")
    assert LOCAL_KEY not in result.output
    assert "01...ef" in result.output
    assert "written" in result.output.lower()

    loaded = load_config(config_path)
    assert loaded.device.id == "dev-1"
    assert loaded.device.ip == "192.168.1.100"
    assert loaded.device.local_key == LOCAL_KEY
    assert loaded.device.version == 3.5
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_auth_interactive_picker_selects_by_number(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    second = auth.AccountDevice(id="dev-2", name="Second plug", local_key="fedcba9876543210")
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(
        auth, "fetch_devices", lambda token_info, user_code: [account_device(), second]
    )
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        ["--config", str(config_path), "auth", "--user-code", "USER123", "--timeout", "5"],
        input="2\n",
    )

    assert result.exit_code == 0, result.output
    assert "Second plug" in result.output
    loaded = load_config(config_path)
    assert loaded.device.id == "dev-2"
    assert loaded.device.local_key == "fedcba9876543210"
    assert loaded.device.version == 3.5


def test_auth_times_out_without_writing_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"

    class NeverScanned(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            return False, {"success": False, "code": "PENDING", "msg": "not scanned"}

    monkeypatch.setattr(auth, "LoginControl", NeverScanned)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [account_device()])
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "0.05",
            "--poll-interval",
            "0.01",
        ],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "timed out" in result.output.lower()
    assert not config_path.exists()


def test_auth_ctrl_c_aborts_without_writing_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"

    class Interrupted(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            raise KeyboardInterrupt

    monkeypatch.setattr(auth, "LoginControl", Interrupted)
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        ["--config", str(config_path), "auth", "--user-code", "USER123", "--timeout", "5"],
    )

    assert result.exit_code == 130
    assert "aborted" in result.output.lower()
    assert not config_path.exists()


def test_auth_refuses_a_device_without_a_local_key(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    keyless = auth.AccountDevice(id="dev-1", name="Plug", local_key="")
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [keyless])
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "no local key" in result.output
    assert not config_path.exists()


def test_auth_unknown_device_id_fails_without_writing_config(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [account_device()])
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "does-not-exist",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 2
    assert "does-not-exist" in result.output
    assert not config_path.exists()


def test_auth_never_persists_a_cloud_reported_wan_address(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    wan_device = auth.AccountDevice(
        id=TARGET_ID,
        name="Plug",
        local_key=LOCAL_KEY,
        product_name="Test plug",
        online=True,
        ip="203.0.113.10",
        support_local=True,
    )
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [wan_device])
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            TARGET_ID,
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = load_config(config_path)
    assert loaded.device.ip == "192.168.1.100"
    assert loaded.device.local_key == LOCAL_KEY
    assert "ignoring non-LAN address" in result.output


def test_auth_keeps_configured_ip_when_cloud_reports_a_wan_address(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(device=DeviceConfig(id="old-device", ip="192.168.1.100")), config_path)
    wan_device = auth.AccountDevice(
        id="dev-1",
        name="Plug",
        local_key=LOCAL_KEY,
        product_name="Test plug",
        online=True,
        ip="203.0.113.10",
        support_local=True,
    )
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [wan_device])
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = load_config(config_path)
    assert loaded.device.ip == "192.168.1.100"
    assert "ignoring non-LAN address" in result.output


def test_auth_leaves_device_ip_blank_when_only_a_wan_address_is_known(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"
    wan_device = auth.AccountDevice(
        id="dev-1",
        name="Plug",
        local_key=LOCAL_KEY,
        product_name="Test plug",
        online=True,
        ip="203.0.113.10",
        support_local=True,
    )
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [wan_device])
    monkeypatch.setattr(discovery, "discover", fake_discovery([]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = load_config(config_path)
    assert loaded.device.ip == ""
    assert "no LAN address" in result.output


def test_auth_reports_cloud_network_failures_without_a_traceback(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"

    class BrokenLogin:
        def qr_code(self, client_id: str, schema: str, user_code: str) -> dict:
            raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(auth, "LoginControl", BrokenLogin)

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "error:" in result.output
    assert "connection refused" in result.output
    assert not config_path.exists()


def test_auth_reports_json_decode_failures_without_a_traceback(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"

    class BadJsonLogin(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            raise json.JSONDecodeError("Expecting value", "<html>", 0)

    monkeypatch.setattr(auth, "LoginControl", BadJsonLogin)

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "error:" in result.output
    assert "Expecting value" in result.output
    assert not config_path.exists()


def test_auth_surfaces_terminal_login_refusals(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"

    class RefusedLogin(StubLoginControl):
        def login_result(self, token: str, client_id: str, user_code: str) -> tuple[bool, dict]:
            return False, {
                "success": False,
                "code": "USERCODE_INCORRECT",
                "msg": "User Code Incorrect",
            }

    monkeypatch.setattr(auth, "LoginControl", RefusedLogin)

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "USERCODE_INCORRECT" in result.output
    assert "User Code Incorrect" in result.output
    assert "timed out" not in result.output.lower()
    assert not config_path.exists()


def test_auth_surfaces_unknown_login_codes_and_keeps_polling(tmp_path: Path, monkeypatch) -> None:
    """An unknown code is not assumed terminal; it is shown and polling continues."""
    config_path = tmp_path / "config.toml"

    class UnknownCodeLogin(StubLoginControl):
        def __init__(self) -> None:
            super().__init__(
                poll_results=[
                    (
                        False,
                        {"success": False, "code": "SOME_NEW_PENDING_CODE", "msg": "waiting"},
                    ),
                    (
                        True,
                        {
                            "access_token": "at",
                            "terminal_id": "term-1",
                            "endpoint": "https://apigw.tuyaus.com",
                        },
                    ),
                ]
            )

    monkeypatch.setattr(auth, "LoginControl", UnknownCodeLogin)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [account_device()])
    monkeypatch.setattr(discovery, "discover", fake_discovery([target_device()]))

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
            "--poll-interval",
            "0.01",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "warning" in result.output.lower()
    assert "SOME_NEW_PENDING_CODE" in result.output
    loaded = load_config(config_path)
    assert loaded.device.local_key == LOCAL_KEY


def test_auth_reports_a_malformed_qr_response_without_a_traceback(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "config.toml"

    class MalformedLogin:
        def qr_code(self, client_id: str, schema: str, user_code: str) -> object:
            return None

    monkeypatch.setattr(auth, "LoginControl", MalformedLogin)

    result = runner.invoke(
        cli.app,
        ["--config", str(config_path), "auth", "--user-code", "USER123", "--timeout", "5"],
    )

    assert result.exit_code == cli.AUTH_FAILED_EXIT_CODE == 1
    assert "error:" in result.output
    assert "malformed" in result.output
    assert "Traceback" not in result.output
    assert not config_path.exists()


def test_auth_rejects_a_loopback_discovery_candidate(tmp_path: Path, monkeypatch) -> None:
    """A spoofed announcement must not get a loopback address written as the LAN IP."""
    config_path = tmp_path / "config.toml"
    wan_device = auth.AccountDevice(
        id="dev-1",
        name="Plug",
        local_key=LOCAL_KEY,
        product_name="Test plug",
        online=True,
        ip="203.0.113.10",
        support_local=True,
    )
    monkeypatch.setattr(auth, "LoginControl", StubLoginControl)
    monkeypatch.setattr(auth, "fetch_devices", lambda token_info, user_code: [wan_device])
    monkeypatch.setattr(
        discovery,
        "discover",
        fake_discovery([discovery.DiscoveredDevice(ip="127.0.0.1", device_id="dev-1")]),
    )

    result = runner.invoke(
        cli.app,
        [
            "--config",
            str(config_path),
            "auth",
            "--user-code",
            "USER123",
            "--device-id",
            "dev-1",
            "--timeout",
            "5",
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = load_config(config_path)
    assert loaded.device.ip == ""
    assert "no LAN address" in result.output


# --- plug commands ---


def plug_config_path(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    write_config(
        Config(device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100", local_key=LOCAL_KEY)),
        config_path,
    )
    return config_path


def install_fake_plug(monkeypatch, fake: plug.FakePlug) -> plug.FakePlug:
    monkeypatch.setattr(cli, "build_plug", lambda config, **kwargs: fake)
    return fake


def test_abc_status_prints_the_relay_state_and_address(tmp_path: Path, monkeypatch) -> None:
    config_path = plug_config_path(tmp_path)
    fake = install_fake_plug(monkeypatch, plug.FakePlug(initial_on=True, address="192.168.1.100"))

    result = runner.invoke(cli.app, ["--config", str(config_path), "status"])

    assert result.exit_code == 0, result.output
    assert "ON" in result.output
    assert "192.168.1.100" in result.output
    assert "re-resolved" not in result.output
    assert fake.calls == ["is_on", "close"]


def test_abc_status_prints_off_when_the_relay_is_open(tmp_path: Path, monkeypatch) -> None:
    config_path = plug_config_path(tmp_path)
    install_fake_plug(monkeypatch, plug.FakePlug(initial_on=False))

    result = runner.invoke(cli.app, ["--config", str(config_path), "status"])

    assert result.exit_code == 0, result.output
    assert "OFF" in result.output


def test_abc_status_states_plainly_when_the_address_was_re_resolved(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = plug_config_path(tmp_path)
    fake = plug.FakePlug(initial_on=False, address="192.168.1.101")
    fake.last_address_change = plug.AddressChange(
        previous_ip="192.168.1.100", current_ip="192.168.1.101"
    )
    install_fake_plug(monkeypatch, fake)

    result = runner.invoke(cli.app, ["--config", str(config_path), "status"])

    assert result.exit_code == 0, result.output
    assert "re-resolved" in result.output
    assert "192.168.1.100" in result.output
    assert "192.168.1.101" in result.output


def test_abc_on_turns_the_plug_on(tmp_path: Path, monkeypatch) -> None:
    config_path = plug_config_path(tmp_path)
    fake = install_fake_plug(monkeypatch, plug.FakePlug())

    result = runner.invoke(cli.app, ["--config", str(config_path), "on"])

    assert result.exit_code == 0, result.output
    assert "ON" in result.output
    assert fake.calls == ["turn_on", "close"]
    assert fake.is_on() is True


def test_abc_off_turns_the_plug_off(tmp_path: Path, monkeypatch) -> None:
    config_path = plug_config_path(tmp_path)
    fake = install_fake_plug(monkeypatch, plug.FakePlug(initial_on=True))

    result = runner.invoke(cli.app, ["--config", str(config_path), "off"])

    assert result.exit_code == 0, result.output
    assert "OFF" in result.output
    assert fake.calls == ["turn_off", "close"]
    assert fake.is_on() is False


def test_abc_on_reports_plug_failures_without_a_traceback(tmp_path: Path, monkeypatch) -> None:
    config_path = plug_config_path(tmp_path)
    fake = install_fake_plug(monkeypatch, plug.FakePlug())
    fake.fail_next("turn_on")

    result = runner.invoke(cli.app, ["--config", str(config_path), "on"])

    assert result.exit_code == cli.PLUG_FAILED_EXIT_CODE == 5
    assert "error:" in result.output
    assert "Traceback" not in result.output
    assert fake.calls == ["turn_on", "close"]


def test_abc_status_requires_a_configured_device(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(), config_path)

    result = runner.invoke(cli.app, ["--config", str(config_path), "status"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "no device configured" in result.output


def test_abc_status_reports_config_errors(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("low_threshold = [")

    result = runner.invoke(cli.app, ["--config", str(config_path), "status"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "invalid TOML" in result.output


def test_abc_plug_commands_pass_the_timeout_to_the_plug_builder(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = plug_config_path(tmp_path)
    captured: dict[str, object] = {}

    def build(config: Config, **kwargs: object) -> plug.FakePlug:
        captured.update(kwargs)
        return plug.FakePlug()

    monkeypatch.setattr(cli, "build_plug", build)

    result = runner.invoke(cli.app, ["--config", str(config_path), "status", "--timeout", "7.5"])

    assert result.exit_code == 0, result.output
    assert captured["timeout"] == 7.5


# --- run and report ---


def run_config_path(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    write_config(
        Config(
            low_threshold=25,
            high_threshold=85,
            device=DeviceConfig(id=TARGET_ID, ip="192.168.1.100", local_key=LOCAL_KEY),
        ),
        config_path,
    )
    return config_path


def scripted_battery(capacity: int, *, charged: bool = False):
    from battery_charger import battery

    status = "Charging" if charged else "Discharging"
    reading = battery.BatteryReading(
        capacity=capacity,
        status=status,
        ac_online=charged,
        energy_now=10_000_000 + capacity * 100_000,
        energy_full=60_000_000,
    )
    return battery.FakeBattery([reading])


def test_abc_run_once_dry_run_logs_the_decision_and_writes_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = run_config_path(tmp_path)
    db_path = tmp_path / "metrics.sqlite"
    fake = install_fake_plug(monkeypatch, plug.FakePlug(initial_on=False))
    monkeypatch.setattr(cli, "build_battery", lambda: scripted_battery(20))

    result = runner.invoke(
        cli.app,
        ["--config", str(config_path), "run", "--once", "--dry-run", "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert "dry run" in result.output
    assert "turn the plug ON" in result.output
    assert fake.calls == ["is_on", "close"]
    assert not db_path.exists()


def test_abc_run_once_actuates_the_plug_and_records_the_turn(tmp_path: Path, monkeypatch) -> None:
    from battery_charger import metrics

    config_path = run_config_path(tmp_path)
    db_path = tmp_path / "metrics.sqlite"
    fake = install_fake_plug(monkeypatch, plug.FakePlug(initial_on=False))
    monkeypatch.setattr(cli, "build_battery", lambda: scripted_battery(20))

    result = runner.invoke(
        cli.app,
        ["--config", str(config_path), "run", "--once", "--db", str(db_path)],
    )

    assert result.exit_code == 0, result.output
    assert fake.is_on() is True
    store = metrics.MetricsStore(db_path)
    try:
        transitions = store.plug_transitions()
        periods = store.discharge_periods()
    finally:
        store.close()
    assert [item.on for item in transitions] == [False, True]
    assert "low threshold" in transitions[1].reason
    assert len(periods) == 1


def test_abc_run_returns_6_when_the_loop_terminates(tmp_path: Path, monkeypatch) -> None:
    from battery_charger import daemon

    config_path = run_config_path(tmp_path)
    install_fake_plug(monkeypatch, plug.FakePlug())
    monkeypatch.setattr(cli, "build_battery", lambda: scripted_battery(20))

    class TerminatingDaemon:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def step(self, dry_run: bool = False) -> daemon.StepOutcome:
            return daemon.StepOutcome(
                daemon.StepResult.TERMINATED,
                "plug unreachable",
                exit_code=daemon.EXIT_PLUG_UNREACHABLE,
            )

    monkeypatch.setattr(cli.daemon_module, "Daemon", TerminatingDaemon)

    result = runner.invoke(cli.app, ["--config", str(config_path), "run", "--once"])

    assert result.exit_code == daemon.EXIT_PLUG_UNREACHABLE == 6
    assert "terminated" in result.output


def test_abc_run_requires_a_configured_device(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(Config(), config_path)

    result = runner.invoke(cli.app, ["--config", str(config_path), "run", "--once", "--dry-run"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "no device configured" in result.output


def test_abc_run_rejects_inconsistent_thresholds(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    write_config(
        Config(low_threshold=90, high_threshold=20, device=DeviceConfig(id=TARGET_ID)),
        config_path,
    )
    install_fake_plug(monkeypatch, plug.FakePlug())
    monkeypatch.setattr(cli, "build_battery", lambda: scripted_battery(50, charged=True))

    result = runner.invoke(cli.app, ["--config", str(config_path), "run", "--once", "--dry-run"])

    assert result.exit_code == cli.CONFIG_ERROR_EXIT_CODE == 2
    assert "low_threshold" in result.output


def test_abc_report_prints_daily_totals_and_turns(tmp_path: Path) -> None:
    import time as clock

    from battery_charger import battery, metrics

    db_path = tmp_path / "metrics.sqlite"
    store = metrics.MetricsStore(db_path)
    try:
        now = clock.time()
        store.observe(
            battery.BatteryReading(
                capacity=40,
                status="Charging",
                ac_online=True,
                energy_now=10_000_000,
                energy_full=60_000_000,
            ),
            now - 600,
        )
        store.observe(
            battery.BatteryReading(
                capacity=39,
                status="Discharging",
                ac_online=False,
                energy_now=9_900_000,
                energy_full=60_000_000,
            ),
            now - 300,
        )
    finally:
        store.close()

    result = runner.invoke(cli.app, ["report", "--db", str(db_path), "--days", "1"])

    assert result.exit_code == 0, result.output
    assert "Battery charger report" in result.output
    assert "Charge turns" in result.output
    assert "40->39%" in result.output
