"""Command line interface for the automatic battery charger.

Exit codes: 0 success, 1 auth failure, 2 usage/config error, 3 doctor found no
evidence, 4 doctor found inconclusive evidence, 5 a relay command failed after
the retry, 6 run terminated with the plug unreachable while action was required,
130 interrupted (the plug is returned to OFF first).
"""

from __future__ import annotations

import contextlib
import ipaddress
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from . import auth as auth_module
from . import battery as battery_module
from . import daemon as daemon_module
from . import discovery, plug
from .config import (
    Config,
    ConfigError,
    DeviceConfig,
    default_config_path,
    load_config,
    redact_secret,
    write_config,
)
from .metrics import MetricsStore, default_metrics_path, render_report

TARGET_MISSING_EXIT_CODE = 3
INDETERMINATE_EXIT_CODE = 4
CONFIG_ERROR_EXIT_CODE = 2
AUTH_FAILED_EXIT_CODE = 1
AUTH_ABORTED_EXIT_CODE = 130
PLUG_FAILED_EXIT_CODE = 5

app = typer.Typer(
    help="Keep the laptop battery charged by switching a Tuya WiFi plug locally.",
    no_args_is_help=True,
    add_completion=False,
)


@dataclass
class AppContext:
    """State shared by the subcommands, injected by the root callback."""

    config_path: Path


class TargetState(StrEnum):
    """Three-state doctor verdict for the configured target."""

    FOUND = "FOUND"
    INDETERMINATE = "INDETERMINATE"
    ABSENT = "ABSENT"


_TARGET_EXIT_CODES = {
    TargetState.FOUND: 0,
    TargetState.INDETERMINATE: INDETERMINATE_EXIT_CODE,
    TargetState.ABSENT: TARGET_MISSING_EXIT_CODE,
}


@dataclass(frozen=True)
class TargetVerdict:
    """A doctor verdict plus the evidence that produced it."""

    state: TargetState
    evidence: str

    @property
    def exit_code(self) -> int:
        """Return the documented exit code for this verdict."""
        return _TARGET_EXIT_CODES[self.state]


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to config.toml (default: $XDG_CONFIG_HOME/battery-charger/config.toml).",
        ),
    ] = None,
) -> None:
    """Automatic battery charger helpers."""
    ctx.obj = AppContext(config_path=config if config is not None else default_config_path())


@app.command()
def doctor(
    ctx: typer.Context,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds to wait for encrypted discovery replies."),
    ] = discovery.DEFAULT_DISCOVERY_TIMEOUT,
    interface: Annotated[
        str | None,
        typer.Option("--interface", help="Network interface name or local IPv4 address to use."),
    ] = None,
    scan_tcp: Annotated[
        bool,
        typer.Option(
            "--scan-tcp/--no-scan-tcp", help="Probe TCP/6668 across the subnet for liveness."
        ),
    ] = True,
) -> None:
    """Discover Tuya v3.4/v3.5 devices and report whether the configured target is present.

    Exit codes: 0 when the target is found (or no target is configured), 3 when
    there is no evidence of it, 4 when there is positive but inconclusive
    evidence (TCP/6668 open without proven identity), 2 on config/discovery
    errors.
    """
    app_context = _app_context(ctx)
    try:
        config = load_config(app_context.config_path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc

    selected_interface = interface or config.interface or None
    try:
        result = discovery.discover(
            interface=selected_interface,
            timeout=timeout,
            scan_tcp=scan_tcp,
        )
    except discovery.DiscoveryError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc

    typer.echo(
        f"Discovery via {result.interface.name} ({result.interface.cidr}): "
        f"{len(result.devices)} device(s) found."
    )
    if result.degraded:
        typer.echo(f"warning: {result.degraded_reason}", err=True)
    if result.rejected_announcements:
        typer.echo(
            f"warning: discarded {result.rejected_announcements} discovery announcement(s) "
            "whose claimed IP did not match the packet source",
            err=True,
        )
    typer.echo(format_device_table(result.devices, tcp_scanned=result.tcp_scanned))
    if any(device.discovered_via == "tcp" for device in result.devices):
        typer.echo(
            "Devices marked (unknown) answered TCP/6668 but not the encrypted discovery broadcast."
        )

    target_id = config.device.id.strip()
    if not target_id:
        typer.echo(
            f"No device.id configured in {app_context.config_path}; listing all devices found."
        )
        return

    verdict = resolve_target(config, result)
    typer.echo(f"Target {target_id}: {verdict.state.value} - {verdict.evidence}")
    if verdict.exit_code:
        raise typer.Exit(verdict.exit_code)


@app.command("auth")
def auth_command(
    ctx: typer.Context,
    user_code: Annotated[
        str | None,
        typer.Option(
            "--user-code",
            help="Smart Life/Tuya Smart User Code (Me > Account and Security).",
        ),
    ] = None,
    device_id: Annotated[
        str | None,
        typer.Option("--device-id", help="Select this device id instead of prompting."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Overall seconds to wait for the QR code to be scanned."),
    ] = auth_module.DEFAULT_POLL_TIMEOUT,
    poll_interval: Annotated[
        float,
        typer.Option("--poll-interval", help="Seconds between login polls."),
    ] = auth_module.DEFAULT_POLL_INTERVAL,
) -> None:
    """Provision the device local key with a one-time Tuya QR login.

    This is the only command that talks to the Tuya cloud. It writes
    device.id, device.ip, device.local_key and device.version to the config.
    """
    app_context = _app_context(ctx)
    try:
        config = load_config(app_context.config_path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc

    if not user_code:
        user_code = typer.prompt("Smart Life/Tuya Smart User Code", hide_input=True)
    user_code = user_code.strip()
    if not user_code:
        typer.echo("error: a user code is required to log in", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE)

    login = auth_module.LoginControl()
    try:
        session = auth_module.request_qr(login, user_code)
    except auth_module.UserCodeRejected as exc:
        typer.echo(f"error: {exc}", err=True)
        typer.echo(
            "Find the User Code in the Smart Life/Tuya Smart app: "
            "Me > Account and Security > User Code.",
            err=True,
        )
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc
    except auth_module.LoginError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc

    typer.echo("Scan this QR code with the Smart Life / Tuya Smart app to authorise access:")
    auth_module.render_qr(session.qr_data)

    def report_unknown_login_code(code: str, message: str) -> None:
        typer.echo(
            f"warning: Tuya login returned {code}: {message}; still waiting for the QR scan "
            "(run `abc auth` again if this repeats)",
            err=True,
        )

    try:
        token_info = auth_module.poll_login(
            login,
            session,
            timeout=timeout,
            interval=poll_interval,
            on_unknown_code=report_unknown_login_code,
        )
    except KeyboardInterrupt:
        typer.echo("Aborted by user; no changes written.")
        raise typer.Exit(AUTH_ABORTED_EXIT_CODE) from None
    except auth_module.LoginTimeout as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc
    except auth_module.LoginError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc

    try:
        devices = auth_module.fetch_devices(token_info, session.user_code)
    except Exception as exc:  # noqa: BLE001 - cloud SDK failures are reported as one error
        typer.echo(f"error: could not list devices: {exc}", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc

    if not devices:
        typer.echo("error: no devices found on this account", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE)

    typer.echo("Devices on this account:")
    for index, device in enumerate(devices, start=1):
        typer.echo(
            f"  {index}. {device.id}  {device.name}  [{device.product_name or '-'}]  "
            f"online={device.online}  local-ip={device.ip or '-'}"
        )

    selected = _select_device(devices, device_id)
    if not selected.local_key:
        typer.echo(
            f"error: device {selected.id} returned no local key; it may not support local control",
            err=True,
        )
        raise typer.Exit(AUTH_FAILED_EXIT_CODE)

    ip, version = _resolve_lan_details(selected, config)
    config.device = DeviceConfig(
        id=selected.id,
        ip=ip,
        local_key=selected.local_key,
        version=version,
    )
    try:
        written_path = write_config(config, app_context.config_path)
    except OSError as exc:
        typer.echo(f"error: could not write {app_context.config_path}: {exc}", err=True)
        raise typer.Exit(AUTH_FAILED_EXIT_CODE) from exc

    typer.echo(
        f"Local key {redact_secret(selected.local_key)} written to {written_path} (file mode 0600)."
    )


@app.command("on")
def on_command(
    ctx: typer.Context,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds per device network operation."),
    ] = plug.DEFAULT_TIMEOUT,
) -> None:
    """Turn the charger plug ON through the local Tuya protocol."""
    with _open_plug(ctx, timeout) as (_config, client):
        client.turn_on()
        typer.echo(f"Plug turned ON at {client.address}.")
        _report_address_change(client)


@app.command("off")
def off_command(
    ctx: typer.Context,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds per device network operation."),
    ] = plug.DEFAULT_TIMEOUT,
) -> None:
    """Turn the charger plug OFF through the local Tuya protocol."""
    with _open_plug(ctx, timeout) as (_config, client):
        client.turn_off()
        typer.echo(f"Plug turned OFF at {client.address}.")
        _report_address_change(client)


@app.command("status")
def status_command(
    ctx: typer.Context,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds per device network operation."),
    ] = plug.DEFAULT_TIMEOUT,
) -> None:
    """Show the relay state and the address currently in use."""
    with _open_plug(ctx, timeout) as (_config, client):
        state = client.is_on()
        typer.echo(f"Plug is {'ON' if state else 'OFF'} at {client.address}.")
        _report_address_change(client)


def build_plug(config: Config, *, timeout: float = plug.DEFAULT_TIMEOUT) -> plug.TuyaPlug:
    """Build the Tuya plug client; a seam so tests can inject a FakePlug."""
    return plug.TuyaPlug(
        config.device,
        interface=config.interface or None,
        timeout=timeout,
    )


@contextlib.contextmanager
def _open_plug(ctx: typer.Context, timeout: float) -> Iterator[tuple[Config, plug.Plug]]:
    """Load config, build the plug, report :class:`PlugError` as exit code 5."""
    app_context = _app_context(ctx)
    try:
        config = load_config(app_context.config_path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    if not config.device.id.strip():
        typer.echo(
            f"error: no device configured in {app_context.config_path}; run `abc auth` first",
            err=True,
        )
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE)
    try:
        client = build_plug(config, timeout=timeout)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    try:
        yield config, client
    except plug.PlugError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(PLUG_FAILED_EXIT_CODE) from exc
    finally:
        with contextlib.suppress(Exception):
            client.close()


def _report_address_change(client: plug.Plug) -> None:
    """Say plainly when the cached IP was re-resolved through discovery."""
    change = getattr(client, "last_address_change", None)
    if change is not None:
        typer.echo(
            f"Address re-resolved via discovery from {change.previous_ip} to "
            f"{change.current_ip} (gwId match); the configured IP was stale."
        )


def resolve_target(
    config: Config,
    result: discovery.DiscoveryResult,
    *,
    probe: Callable[..., discovery.AuthenticatedProbe] | None = None,
) -> TargetVerdict:
    """Decide whether the configured target is found, indeterminate or absent.

    Identity is proven by a ``gwId`` match on the decoded discovery replies or
    by an authenticated status round trip to the configured IP. TCP/6668 being
    open (or reachable but unauthenticated) is positive evidence of *a* device
    but not proof of identity, so it yields INDETERMINATE rather than ABSENT.
    """
    target_id = config.device.id.strip()
    target = discovery.find_device(result.devices, target_id)
    if target is not None:
        return TargetVerdict(
            TargetState.FOUND,
            f"discovery decoded gwId {target_id} at {target.ip}",
        )
    target_ip = config.device.ip.strip()
    if target_ip and config.device.local_key:
        probe_fn = probe if probe is not None else discovery.probe_authenticated
        outcome = probe_fn(
            target_ip,
            device_id=target_id,
            local_key=config.device.local_key,
            version=config.device.version,
        )
        if outcome.authenticated:
            return TargetVerdict(
                TargetState.FOUND,
                f"authenticated status round trip to {target_ip} succeeded",
            )
        if outcome.connected:
            return TargetVerdict(
                TargetState.INDETERMINATE,
                f"TCP/6668 is open at {target_ip} but the local key did not "
                f"authenticate ({outcome.detail})",
            )
    if target_ip and any(device.ip == target_ip and device.tcp_open for device in result.devices):
        return TargetVerdict(
            TargetState.INDETERMINATE,
            f"TCP/6668 is open at {target_ip} but discovery did not prove identity",
        )
    if result.degraded:
        return TargetVerdict(
            TargetState.INDETERMINATE,
            f"discovery ran degraded ({result.degraded_reason}); absence is not proven",
        )
    detail = f" at {target_ip}" if target_ip else ""
    return TargetVerdict(
        TargetState.ABSENT,
        f"no discovery gwId match and no TCP/6668 or authenticated evidence{detail}",
    )


def format_device_table(devices: list[discovery.DiscoveredDevice], *, tcp_scanned: bool) -> str:
    """Render the discovery table as plain aligned text."""
    headers = ("IP", "DEVICE ID", "PRODUCT KEY", "VERSION", "TCP/6668")
    rows = [
        (
            device.ip,
            device.device_id or "(unknown)",
            device.product_key or "-",
            device.version or "-",
            ("open" if device.tcp_open else "closed") if tcp_scanned else "-",
        )
        for device in devices
    ]
    table = [headers, *rows]
    widths = [max(len(row[column]) for row in table) for column in range(len(headers))]
    return "\n".join(
        "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()
        for row in table
    )


def _app_context(ctx: typer.Context) -> AppContext:
    if isinstance(ctx.obj, AppContext):
        return ctx.obj
    return AppContext(config_path=default_config_path())


def _select_device(
    devices: list[auth_module.AccountDevice], device_id: str | None
) -> auth_module.AccountDevice:
    if device_id:
        for device in devices:
            if device.id == device_id:
                return device
        raise typer.BadParameter(f"device id {device_id!r} was not found on this account")
    while True:
        choice = typer.prompt("Select device", type=int, default=1)
        if 1 <= choice <= len(devices):
            return devices[choice - 1]
        typer.echo(f"Enter a number between 1 and {len(devices)}.")


def _resolve_lan_details(device: auth_module.AccountDevice, config: Config) -> tuple[str, float]:
    """Best-effort LAN lookup for the device IP and protocol version.

    The Tuya cloud can report the device's public WAN address.
    Persisting that as ``device.ip`` would make every later local connection
    fail, so only private addresses are accepted; a LAN discovery sweep decides
    the rest and the previously configured IP is the fallback.
    """
    version = config.device.version
    cloud_ip = device.ip.strip()
    candidate = cloud_ip if _is_lan_address(cloud_ip) else ""
    if cloud_ip and not candidate:
        typer.echo(
            f"warning: ignoring non-LAN address {cloud_ip!r} reported by the cloud for {device.id}",
            err=True,
        )
    try:
        sweep = discovery.discover(interface=config.interface or None, scan_tcp=False)
    except discovery.DiscoveryError as exc:
        typer.echo(f"warning: LAN lookup failed ({exc})", err=True)
        sweep = None
    if sweep is not None:
        found = discovery.find_device(sweep.devices, device.id)
        if found is not None:
            if _is_lan_address(found.ip):
                candidate = found.ip
            if found.version:
                try:
                    version = float(found.version)
                except ValueError:
                    pass
    if not candidate:
        candidate = config.device.ip.strip()
        if not _is_lan_address(candidate):
            candidate = ""
    if not candidate:
        typer.echo(
            f"warning: no LAN address found for {device.id}; device.ip left blank. "
            "Run `abc doctor` on the device network before controlling the plug.",
            err=True,
        )
    return candidate, version


_LAN_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
    )
)


def _is_lan_address(value: str) -> bool:
    """Return whether ``value`` is an address a LAN device can plausibly own.

    An explicit allowlist avoids ``ipaddress.is_private`` accepting loopback,
    the unspecified address and TEST-NET while rejecting CGNAT: only RFC1918,
    IPv4 link-local and IPv6 ULA are accepted.
    """
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in _LAN_NETWORKS)


def build_battery() -> battery_module.BatterySource:
    """Build the sysfs battery source; a seam so tests can inject a FakeBattery."""
    return battery_module.SysfsBattery()


@app.command("report")
def report_command(
    days: Annotated[
        int,
        typer.Option("--days", help="Days to summarise, including today."),
    ] = 7,
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Metrics database path (default: XDG state directory)."),
    ] = None,
) -> None:
    """Print a short plain-text summary of charge turns and discharge periods."""
    if days < 1:
        typer.echo(f"error: --days must be at least 1, got {days}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE)
    try:
        store = MetricsStore(db if db is not None else default_metrics_path())
    except (OSError, sqlite3.Error) as exc:
        typer.echo(f"error: could not open the metrics database: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    try:
        typer.echo(render_report(store, days=days))
    finally:
        store.close()


@app.command("run")
def run_command(
    ctx: typer.Context,
    once: Annotated[
        bool,
        typer.Option("--once", help="Run a single poll iteration and exit."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Compute and log the decision but perform no relay write and record nothing.",
        ),
    ] = False,
    interval: Annotated[
        float | None,
        typer.Option("--interval", help="Seconds between polls (default: from the config)."),
    ] = None,
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Metrics database path (default: XDG state directory)."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Seconds per plug network operation."),
    ] = plug.DEFAULT_TIMEOUT,
) -> None:
    """Run the control loop in the foreground.

    Exit codes: 0 normally, 6 when the plug stayed unreachable while the
    battery state required action, 130 when interrupted (the plug is returned
    to OFF first). ``--once`` performs one iteration and, deliberately, does
    not run the shutdown write, so a systemd timer cannot toggle the relay on
    every tick.
    """
    app_context = _app_context(ctx)
    try:
        config = load_config(app_context.config_path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    if not config.device.id.strip():
        typer.echo(
            f"error: no device configured in {app_context.config_path}; run `abc auth` first",
            err=True,
        )
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE)
    try:
        battery = build_battery()
    except battery_module.BatteryError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    try:
        client = build_plug(config, timeout=timeout)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc

    store = None
    if not dry_run:
        try:
            store = MetricsStore(db if db is not None else default_metrics_path())
        except (OSError, sqlite3.Error) as exc:
            typer.echo(f"error: could not open the metrics database: {exc}", err=True)
            with contextlib.suppress(Exception):
                client.close()
            raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc
    try:
        loop = daemon_module.Daemon(battery, client, store, config, poll_interval=interval)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        with contextlib.suppress(Exception):
            client.close()
        if store is not None:
            with contextlib.suppress(Exception):
                store.close()
        raise typer.Exit(CONFIG_ERROR_EXIT_CODE) from exc

    try:
        if once:
            outcome = loop.step(dry_run=dry_run)
            typer.echo(f"{outcome.result.value}: {outcome.reason}")
            if outcome.result is daemon_module.StepResult.TERMINATED:
                raise typer.Exit(outcome.exit_code)
            return
        raise typer.Exit(loop.run_forever(dry_run=dry_run))
    finally:
        with contextlib.suppress(Exception):
            client.close()
        if store is not None:
            with contextlib.suppress(Exception):
                store.close()
