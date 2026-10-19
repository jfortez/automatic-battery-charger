# Automatic Battery Charger

Keep a laptop battery inside a healthy charge band by switching the mains supply
of a Tuya Wi-Fi smart plug, entirely on the local network. No Home Assistant and
no Tuya cloud at runtime.

`abc` reads the battery from Linux `sysfs`, decides with a hysteresis controller,
switches the plug's relay over the Tuya LAN protocol, records charge turns and
plug incidents in SQLite, and runs as a systemd user service. The only cloud step
is one-time local-key provisioning.

## How it works

```
battery (sysfs) -> controller -> Tuya plug (LAN)
                       |
                       +-> SQLite + journal notices
```

- Below `low_threshold` the relay closes; at or above `high_threshold` it opens.
  Inside the band nothing is written.
- A relay change requires consecutive settled readings, because `AC0/online`
  flips before `BAT0/status` after a switch.
- On SIGTERM/Ctrl-C, and whenever the systemd unit stops, the plug is returned
  to OFF.

## Device and compatibility

Tested with a **Tuya / Smart Life Wi-Fi smart plug** on protocol **v3.5**, with a
single boolean switch datapoint (the relay is found from the status payload, not
assumed). The runtime path never talks to the cloud; only `abc auth` does.

Requirements: a Tuya/Smart Life plug that supports a **local key**, is reachable
on **TCP/6668**, and exposes a **single boolean switch**. Discovery covers
protocol v3.4 and v3.5. Cloud-only, Bluetooth-only, Zigbee-without-hub and
multi-channel devices are out of scope. One plug per config.

Known device behavior this project handles:

- The IP is a DHCP cache; the stable identifier is the Tuya `gwId`, and a failed
  address is re-discovered and retried once.
- Re-pairing can rotate the local key (Tuya error `914`); re-run `abc auth` and
  restart the service.
- `relay_status` can disagree with the switch datapoint; only the switch
  datapoint is trusted.
- The tested plug can go silent to the encrypted UDP broadcast while still
  answering TCP, so liveness is an authenticated round trip, not a broadcast.
  Its discovery replies target UDP/7000, so that port is bound exclusively.

## Requirements

- Linux with the battery and AC adapter under `/sys/class/power_supply`
  (`BAT*`/`AC*` are autodetected).
- Python **3.12+** and [uv](https://docs.astral.sh/uv/).
- A Tuya plug on the same LAN.
- Optional: a writable `charge_control_end_threshold` for the firmware cap.

## Install with uv

`uv` manages the interpreter, the lockfile and `.venv`; you do not need to
activate anything.

```sh
# 1. install uv
curl -LsSf https://astral.sh/uv/install.sh | sh    # or: pipx install uv

# 2. clone and install
git clone https://github.com/jfortez/automatic-battery-charger.git automatic-battery-charger
cd automatic-battery-charger
uv sync                 # reproducible: uv sync --locked

# 3. check
uv run abc --help
uv run abc doctor
```

Every command below runs from the checkout with `uv run`. To install `abc`
globally, use `uv tool install .`; the systemd unit uses `.venv/bin/abc`.

## Provision the plug (one-time)

1. Add the plug to **Smart Life** or **Tuya Smart**.
2. Copy the **User Code** from *Me → Account and Security → User Code*.
3. Run `uv run abc auth`, enter the code, scan the QR code and select the plug.

This writes `device.id`, `device.ip`, `device.local_key` and `device.version` to
the config. Repeat only if the account changes or the key rotates.

## Configuration

`$XDG_CONFIG_HOME/battery-charger/config.toml` (default
`~/.config/battery-charger/config.toml`), mode `0600`. Use `--config PATH` for
another file.

```toml
low_threshold = 25
high_threshold = 85
poll_interval = 30
incident_threshold_s = 300
interface = ""               # optional discovery NIC, e.g. "wlan0"

[device]
id = "0123456789abcdef012345"
ip = "192.168.1.100"         # cache only
local_key = "from-abc-auth"
version = 3.5
```

Thresholds and intervals are read at startup; restart after editing.

## Commands

| Command | Purpose |
| --- | --- |
| `abc doctor` | Discover Tuya devices and report whether the configured target is present (`0` found/no target, `3` absent, `4` inconclusive, `2` error). |
| `abc auth` | One-time QR login; writes the local key. |
| `abc on` / `abc off` | Close/open the relay over the LAN. |
| `abc status` | Relay state and the address in use. |
| `abc run` | Control loop (`--once`, `--dry-run`, `--interval`, `--db`, `--timeout`). |
| `abc report` | Charge turns, discharge periods and incidents (`--days`, `--db`). |

Global option: `--config PATH`. Relay commands exit `5` when the plug cannot be
read or written after the retry; `abc run` exits `6` when it gives up while the
battery requires action, and `130` when interrupted (plug returned to OFF).

## Run as a systemd user service

```sh
uv sync
./deploy/install.sh
systemctl --user enable --now battery-charger.service
journalctl --user -u battery-charger.service -f

# optional: run without an active login
loginctl enable-linger "$USER"
```

`install.sh` writes `~/.config/systemd/user/battery-charger.service` and never
enables or starts it. The unit restarts on failure (`Restart=on-failure`,
`RestartSec=30`) and runs `abc off` in `ExecStopPost`, so a stop or crash returns
the relay to OFF. If `abc run` was started by hand, that watchdog does not exist.

Upgrade and uninstall:

```sh
git pull && uv sync --locked
systemctl --user restart battery-charger.service

systemctl --user disable --now battery-charger.service
rm -f ~/.config/systemd/user/battery-charger.service
systemctl --user daemon-reload
# optional: rm -rf ~/.config/battery-charger ~/.local/state/battery-charger
```

Re-run `deploy/install.sh` if you move the checkout.

## Optional firmware charge cap

If the battery exposes `charge_control_end_threshold`, cap it in firmware as a
fallback for when the plug is unreachable:

```sh
sudo ./deploy/install-charge-limit.sh 85
```

It installs a helper and a root unit into `multi-user` and the sleep targets.
Undo with `sudo systemctl disable --now charge-limit` and remove the two files.
The control loop does not depend on the cap.

## Failure policy and incidents

When the plug is unreachable:

- **At/below `low_threshold`:** one retry per `poll_interval`, every attempt
  logged as `ERROR DANGEROUS`; the relay is the only thing that can save the
  machine.
- **At/above `high_threshold`:** bounded exponential backoff (10 attempts), then
  a loud exit.
- **Inside the band:** observe; a failed read never terminates the loop alone.

A run of failed reads longer than `incident_threshold_s` opens one incident with
the first failure's time and battery. It survives a restart and closes on the
first successful read, logging `NOTICE CONNECTIVITY INCIDENT` and
`NOTICE CONNECTIVITY INCIDENT ENDED`. A move to another network is topology,
not an outage: it is explained once and not recorded; an open incident is closed
as unobserved. Machine-suspension time is measured from the end of the previous
poll, so the loop's own timeouts do not count.

Metrics live in SQLite at `$XDG_STATE_HOME/battery-charger/metrics.sqlite`
(`~/.local/state/battery-charger/metrics.sqlite`): charge turns, discharge
periods, plug transitions and incidents. `abc report` renders them; energy is
recorded only when `energy_now` is available.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `abc doctor` exits `3` | Plug offline or on another network; put both on the same LAN. |
| `abc doctor` exits `4` | TCP/6668 answers without identity: re-run `abc auth`. |
| `abc on/off/status` exits `5` | Plug unreachable; `914` means the local key rotated. |
| `abc status` prints a new address | Expected: the IP is a cache, re-discovered by `gwId`. |
| `abc run` exits `6` | Plug unreachable while the battery required action; check the last line. |
| `BatteryError` | No battery/AC adapter under `/sys/class/power_supply`. |
| `NOTICE CONNECTIVITY INCIDENT` | Unreachable past `incident_threshold_s`; `abc report` has the row. |

## Development

```sh
uv run pytest
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv build
```

Tests use `FakeBattery` and `FakePlug`; no hardware is required. The discovery
fixture is an anonymized v3.5 frame with synthetic identifiers. Modules:
`battery`, `controller`, `plug`, `discovery`, `auth`, `metrics`, `daemon`, `cli`.

## Limitations

- Linux only; one battery and one plug per config.
- No remote push notifications: the journal, SQLite and `abc report` are the
  durable record.
- The bottom of the band has no local guardrail; the optional firmware cap only
  caps the top.
- The plug is a single point of failure. If it loses Wi-Fi with its relay
  closed, the laptop charges until the firmware cap or 100%.
- Charge turns are inferred from the battery status; charging from another
  source while the plug is unobservable is still recorded, with the incident
  explaining the gap.

## License

MIT. See [LICENSE](LICENSE).
