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
- Router restart attempts triggered through a configurable command

## Project Layout

```text
routerwatch/
  routerwatch.py          Main monitor and CLI
  config.example.json     Copy to config.json and adjust
requirements.txt          Python dependencies
systemd/
  routerwatch.service     Run as a service on the Pi
  routerwatch.timer       Run every minute on the Pi
```

Runtime files are intentionally ignored by git:

- `routerwatch/config.json`
- `routerwatch.sqlite`
- `routerwatch.log`
- `token.json`
- `credentials.json`
- `venv/`
- `wifi.env`
- Matter controller fabric state (stored outside the repository)

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

Status output stores UTC internally but displays local time first. With the default config, timestamps are shown in `America/New_York` with the UTC value in parentheses.

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

Router restart is intentionally model-specific. The safest general pattern is to put the router on a smart plug that can be controlled locally, then set `restart.command` in `config.json`.

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

## Matter Smart Plug

The Linkind `ZN10-2` plug has been commissioned to a Matter controller on the Pi
and verified with manual `off` and `on` commands. Install the controller
dependencies separately from the Python environment:

```bash
cd ~/routerwatch/matter
npm install
```

Create `~/routerwatch/matter/wifi.env` with mode `600`. Do not commit this file:

```bash
MATTER_WIFI_SSID='your-ssid'
MATTER_WIFI_PASSWORD='your-password'
MATTER_PAIRING_CODE='code-from-plug'
MATTER_PASSCODE='passcode-from-plug'
MATTER_SHORT_DISCRIMINATOR='discriminator-from-plug'
```

Load the settings and commission a factory-reset plug while its indicator is
blinking:

```bash
cd ~/routerwatch/matter
set -a
source wifi.env
set +a
NOBLE_MULTI_ROLE=1 node matter-plug.mjs commission
```

After commissioning, inspect or control the plug:

```bash
NOBLE_MULTI_ROLE=1 node matter-plug.mjs info
NOBLE_MULTI_ROLE=1 node matter-plug.mjs off
NOBLE_MULTI_ROLE=1 node matter-plug.mjs on
```

The controller fabric is persisted under
`~/.matter/routerwatch-controller`. The Pi's Node binary also needs Bluetooth
network capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/node
getcap /usr/bin/node
```

Do not use separate `off` and `on` commands to power-cycle the router. Turning
off the router also removes the Wi-Fi path the Pi needs to send the subsequent
`on` command. Automated router recovery requires a plug-local countdown/restart
feature or an independent control network. Until that is available, Matter plug
control is informational and manual only.

## Systemd Timer

On the Pi:

```bash
sudo cp systemd/routerwatch.service /etc/systemd/system/
sudo cp systemd/routerwatch.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now routerwatch.timer
```

Check logs:

```bash
journalctl -u routerwatch.service -n 100 --no-pager
```

The timer runs in the background. You do not need to keep an SSH session open.

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
