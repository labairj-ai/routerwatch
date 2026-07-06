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
    "admin_url": "http://192.168.1.1"
  },
  "monitor": {
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

Once you know the router model/admin interface, add a small vendor-specific collector that logs firmware version, channel, client count, WAN errors, and modem signal levels if available. That data is usually the difference between "the internet died" and "the 5 GHz channel got noisy" or "the WAN link dropped."
