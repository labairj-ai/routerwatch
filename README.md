# RouterWatch

RouterWatch is a Raspberry Pi based monitor for catching home internet/router trouble before it becomes invisible frustration. It records local router health, internet reachability, DNS behavior, latency, packet loss, and Wi-Fi signal strength, then sends Gmail alerts when the pattern looks bad.

The first deployment is designed to run internally on:

- `labairj@gameserver.local`
- `labairj@192.168.1.136` over Ethernet

Gmail alerting uses the same OAuth pattern as DansbyTracker: `credentials.json` plus `token.json` with the Gmail send scope.

## What It Watches

- Gateway reachability, currently your router at `192.168.1.1`
- Ethernet link state and negotiated speed, usually `eth0` at 1000 Mbps
- Public internet reachability by pinging stable targets
- DNS resolution latency and failures
- HTTPS reachability
- Wi-Fi signal strength from `iw dev <interface> link`
- Current default route and WAN-facing public IP
- Spectrum Basic Router Info fields when exposed locally: router model, firmware version, serial number, cloud status, router-page internet status, and connected pod serials
- Outage start/end times
- Failed degradation emails queued locally until connectivity returns
- Router restart attempts triggered through a configurable command
- Local read-only dashboard for current status, history, incidents, firmware,
  queued emails, and persisted local device inventory

## Project Layout

```text
routerwatch/
  routerwatch.py          Main monitor and CLI
  config.example.json     Copy to config.json and adjust
requirements.txt          Python dependencies
systemd/
  routerwatch.service     Run as a service on the Pi
  routerwatch.timer       Run every minute on the Pi
  routerwatch-weekly.*    Send the Saturday health report
  routerwatch-dashboard.service
                          Serve the local web dashboard
```

Runtime files are intentionally ignored by git:

- `routerwatch/config.json`
- `routerwatch.sqlite`
- `routerwatch.log`
- `token.json`
- `credentials.json`
- `venv/`

## Quick Start On The Pi

```bash
ssh labairj@gameserver.local
mkdir -p ~/routerwatch
```

Clone or copy this project folder to `~/routerwatch`, then on the Pi:

```bash
cd ~/routerwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp routerwatch/config.example.json routerwatch/config.json
```

For the current wired Pi deployment, `routerwatch/config.json` should include:

```json
{
  "router": {
    "gateway": "192.168.1.1",
    "admin_url": "https://192.168.1.1",
    "info_page_path": "/cgi-bin/index.cgi",
    "connectivity_api_path": "/cgi-bin/connectivity_api",
    "pods_api_path": "/cgi-bin/pods_api"
  },
  "monitor": {
    "display_timezone": "America/New_York",
    "ethernet_interface": "eth0",
    "wifi_interface": "wlan0"
  }
}
```

Copy Gmail OAuth files from the existing Gmail setup:

```bash
scp /path/to/token.json labairj@gameserver.local:~/routerwatch/token.json
scp /path/to/credentials.json labairj@gameserver.local:~/routerwatch/credentials.json
```

Then edit `routerwatch/config.json`.

## Basic Commands

Run one health check:

```bash
SENDER_EMAIL=labairj@gmail.com ./venv/bin/python routerwatch/routerwatch.py check --config routerwatch/config.json
```

Send a test alert:

```bash
SENDER_EMAIL=labairj@gmail.com ./venv/bin/python routerwatch/routerwatch.py send-test --config routerwatch/config.json
```

Run continuously:

```bash
SENDER_EMAIL=labairj@gmail.com ./venv/bin/python routerwatch/routerwatch.py watch --config routerwatch/config.json
```

Show recent history:

```bash
./venv/bin/python routerwatch/routerwatch.py status --config routerwatch/config.json
```

Send the weekly health report manually:

```bash
SENDER_EMAIL=labairj@gmail.com ./venv/bin/python routerwatch/routerwatch.py weekly-report --config routerwatch/config.json
```

Start the dashboard manually:

```bash
./venv/bin/python routerwatch/routerwatch.py dashboard --config routerwatch/config.json --host 0.0.0.0 --port 8765
```

Then open:

```text
http://gameserver.local:8765/
```

The dashboard is read-only. It shows the latest check, weekly and all-time
health metrics, recent latency/loss, outages and degradations, router firmware,
pending queued emails, and local device inventory. It refreshes itself every 30
seconds while the existing minute timer continues collecting data.

The device inventory is based on what the Pi observes in the local neighbor
table, not a Spectrum router-reported bandwidth list. It persists first seen,
last seen, seen count, current IP, IP history, hostname when resolvable, MAC
address, interface, state, status, vendor when the Pi has local OUI data
available, and whether the MAC looks locally administered/private.

RouterWatch can automatically pull or infer a limited amount of metadata:
hostname from local name resolution, vendor from MAC OUI data if available on
the Pi, private/randomized MAC detection, and conservative device-type guesses
from hostname/vendor strings such as Roku, printer, camera, router, or TV
brands. Exact device category, owner, and room are more reliable as manual
labels in `routerwatch/config.json`:

```json
"devices": {
  "recent_minutes": 15,
  "names": {
    "2e:67:be:3b:9e:b3": "Spectrum Router",
    "192.168.4.21": "Kitchen Display"
  },
  "types": {
    "2e:67:be:3b:9e:b3": "router",
    "192.168.4.21": "smart_display"
  },
  "owners": {
    "192.168.4.21": "Home"
  },
  "locations": {
    "2e:67:be:3b:9e:b3": "Network closet",
    "192.168.4.21": "Kitchen"
  },
  "vendors": {
    "2e:67:be:3b:9e:b3": "Spectrum"
  }
}
```

The weekly report covers the preceding seven days and includes uptime, latency
and packet-loss trends against the prior week, DNS failures, firmware changes,
and the times and durations of outages or degradations. Its all-time section
uses every persisted check to show lifetime uptime and the most common day and
hour for incident starts. If Gmail is unavailable, the completed report is
queued in SQLite and delivered after connectivity recovers.

Status output stores UTC internally but displays local time first. With the default config, timestamps are shown in `America/New_York` with the UTC value in parentheses.

If a complete internet outage prevents Gmail delivery, RouterWatch stores the
degradation email in its SQLite outbox. Once internet, DNS, and HTTPS checks
recover, the missed degradation email is sent automatically before the recovery
email. The queue survives service and Pi restarts, and only one degradation
email is queued for an active outage.

The recovery email includes the outage start and recovery times, total duration,
number of failed checks, worst observed latency, and worst observed packet loss.

For Spectrum routers that expose the unauthenticated Basic Router Info page, `check` and `status` also include informational router metadata. These fields are recorded for context only and do not trigger alerts:

```text
Router model: SAX2V1R
Router firmware: 1.5.1-1-774475-g202507222305-SAX2V1R-prod
Router serial: 61RP25110089620
Router page internet status: Connected
Router cloud status: Connected
Connected pods: N/A
```

Attempt the configured router restart command:

```bash
./venv/bin/python routerwatch/routerwatch.py restart-router --config routerwatch/config.json
```

## Router Restart

Router restart is intentionally model-specific. Set `restart.command` only when
the router provides a reliable local reboot command.

Examples:

```json
"restart": {
  "enabled": true,
  "command": ["bash", "-lc", "curl -fsS http://homeassistant.local:8123/api/webhook/reboot-router"]
}
```

or, if the router supports SSH reboot:

```json
"restart": {
  "enabled": true,
  "command": ["ssh", "admin@192.168.1.1", "reboot"]
}
```

RouterWatch will not restart anything unless `restart.enabled` is `true`.

## Systemd Timer

On the Pi:

```bash
sudo cp systemd/routerwatch.service /etc/systemd/system/
sudo cp systemd/routerwatch.timer /etc/systemd/system/
sudo cp systemd/routerwatch-weekly.service /etc/systemd/system/
sudo cp systemd/routerwatch-weekly.timer /etc/systemd/system/
sudo cp systemd/routerwatch-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now routerwatch.timer routerwatch-weekly.timer routerwatch-dashboard.service
```

Check logs:

```bash
journalctl -u routerwatch.service -n 100 --no-pager
journalctl -u routerwatch-weekly.service -n 100 --no-pager
journalctl -u routerwatch-dashboard.service -n 100 --no-pager
```

The monitoring timer runs every minute. The weekly timer runs Saturday at
6:00 AM `America/New_York`, including across daylight-saving changes. Both run
in the background without an SSH session.

The dashboard runs continuously at `http://gameserver.local:8765/` when
`routerwatch-dashboard.service` is enabled.

If you do not want to enter the Pi sudo password, the dashboard can run as the
`labairj` user:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/routerwatch-dashboard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now routerwatch-dashboard.service
```

## Healthy Baseline

The initial wired baseline from the Pi looked like this:

```text
Checked at local: 2026-07-06 08:02:54 AM EDT
Checked at UTC: 2026-07-06T12:02:54+00:00
Gateway OK: True
Internet ping OK: True
DNS OK: True
HTTPS OK: True
Latency: 13.371 ms
Packet loss: 0.0%
Ethernet state: up
Ethernet speed: 1000 Mbps
Ethernet duplex: full
Default gateway: 192.168.1.1
```

## Next Best Upgrade

Next useful additions are client count, Wi-Fi channel, WAN errors, and modem signal levels if the router or ISP exposes them locally. That data is usually the difference between "the internet died" and "the 5 GHz channel got noisy" or "the WAN link dropped."
