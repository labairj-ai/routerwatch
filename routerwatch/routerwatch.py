#!/usr/bin/env python3

import argparse
import base64
import json
import os
import platform
import re
import socket
import sqlite3
import ssl
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape, unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.json")
OUI_VENDOR_CACHE: Optional[Dict[str, str]] = None


@dataclass
class CheckResult:
    checked_at: str
    gateway_ok: bool
    internet_ok: bool
    dns_ok: bool
    https_ok: bool
    avg_latency_ms: Optional[float]
    packet_loss_percent: Optional[float]
    ethernet_operstate: Optional[str]
    ethernet_speed_mbps: Optional[int]
    ethernet_duplex: Optional[str]
    wifi_rssi_dbm: Optional[int]
    wifi_tx_bitrate: Optional[str]
    default_gateway: Optional[str]
    public_ip: Optional[str]
    router_model: Optional[str]
    router_firmware_version: Optional[str]
    router_serial_number: Optional[str]
    router_internet_status: Optional[str]
    router_cloud_status: Optional[str]
    router_connected_pods: Optional[str]
    notes: List[str]

    @property
    def healthy(self) -> bool:
        return self.gateway_ok and self.internet_ok and self.dns_ok and self.https_ok

    @property
    def needs_attention(self) -> bool:
        warning_prefixes = ("high packet loss:", "high latency:", "weak Wi-Fi signal:")
        return (not self.healthy) or any(note.startswith(warning_prefixes) for note in self.notes)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def display_timezone(config: Dict[str, Any]) -> tzinfo:
    timezone_name = config.get("monitor", {}).get("display_timezone", "").strip()
    if timezone_name:
        try:
            return ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def format_time_pair(value: str, config: Dict[str, Any]) -> Tuple[str, str]:
    utc_dt = parse_utc(value)
    local_dt = utc_dt.astimezone(display_timezone(config))
    return (
        local_dt.strftime("%Y-%m-%d %I:%M:%S %p %Z"),
        utc_dt.isoformat(timespec="seconds"),
    )


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}. Copy config.example.json to config.json first.")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def resolve_path(config_path: Path, configured_path: str) -> Path:
    path = Path(configured_path).expanduser()
    if path.is_absolute():
        return path
    return config_path.parent.parent / path


def log(config: Dict[str, Any], config_path: Path, message: str) -> None:
    log_path = resolve_path(config_path, config["storage"].get("log_path", "routerwatch.log"))
    line = f"{utc_iso()} {message}\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def run_command(args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return completed.returncode, completed.stdout, completed.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, "", str(exc)


def ping(host: str, count: int) -> Tuple[bool, Optional[float], Optional[float], str]:
    system = platform.system().lower()
    args = ["ping", "-c", str(count), "-W", "2", host]
    if "darwin" in system:
        args = ["ping", "-c", str(count), "-W", "2000", host]

    code, stdout, stderr = run_command(args, timeout=max(6, count * 3))
    output = stdout + "\n" + stderr
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output)
    latency_match = re.search(r"(?:round-trip|rtt).*?=\s+[\d.]+/([\d.]+)/", output)
    loss = float(loss_match.group(1)) if loss_match else None
    latency = float(latency_match.group(1)) if latency_match else None
    return code == 0 and (loss is None or loss < 100), latency, loss, output.strip()


def first_successful_ping(hosts: List[str], count: int) -> Tuple[bool, Optional[float], Optional[float], List[str]]:
    notes = []
    best_latency = None
    worst_loss = None
    for host in hosts:
        ok, latency, loss, raw = ping(host, count)
        if loss is not None:
            worst_loss = loss if worst_loss is None else max(worst_loss, loss)
        if latency is not None:
            best_latency = latency if best_latency is None else min(best_latency, latency)
        if ok:
            return True, latency, loss, notes
        notes.append(f"ping {host} failed: {raw[-200:]}")
    return False, best_latency, worst_loss, notes


def dns_check(hosts: List[str]) -> Tuple[bool, List[str]]:
    notes = []
    for host in hosts:
        start = time.monotonic()
        try:
            socket.getaddrinfo(host, 443)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if elapsed_ms > 1000:
                notes.append(f"slow DNS for {host}: {elapsed_ms}ms")
            return True, notes
        except socket.gaierror as exc:
            notes.append(f"DNS failed for {host}: {exc}")
    return False, notes


def https_check(urls: List[str]) -> Tuple[bool, List[str]]:
    notes = []
    for url in urls:
        try:
            req = Request(url, headers={"User-Agent": "RouterWatch/1.0"})
            with urlopen(req, timeout=8) as response:
                if 200 <= response.status < 400:
                    return True, notes
                notes.append(f"HTTPS {url} returned {response.status}")
        except Exception as exc:
            notes.append(f"HTTPS failed for {url}: {exc}")
    return False, notes


def wifi_info(interface: str) -> Tuple[Optional[int], Optional[str], List[str]]:
    if not interface:
        return None, None, []
    code, stdout, stderr = run_command(["iw", "dev", interface, "link"], timeout=5)
    if code != 0:
        return None, None, [f"Wi-Fi info unavailable for {interface}: {(stderr or stdout).strip()}"]
    signal_match = re.search(r"signal:\s*(-?\d+)\s+dBm", stdout)
    bitrate_match = re.search(r"tx bitrate:\s*(.+)", stdout)
    rssi = int(signal_match.group(1)) if signal_match else None
    bitrate = bitrate_match.group(1).strip() if bitrate_match else None
    return rssi, bitrate, []


def read_sysfs_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def ethernet_info(interface: str) -> Tuple[Optional[str], Optional[int], Optional[str], List[str]]:
    if not interface:
        return None, None, None, []
    base = Path("/sys/class/net") / interface
    if not base.exists():
        return None, None, None, [f"Ethernet interface {interface} not found."]

    operstate = read_sysfs_text(base / "operstate")
    duplex = read_sysfs_text(base / "duplex")
    speed_raw = read_sysfs_text(base / "speed")
    speed = None
    if speed_raw:
        try:
            speed = int(speed_raw)
        except ValueError:
            pass

    notes = []
    if operstate and operstate.lower() != "up":
        notes.append(f"Ethernet {interface} is {operstate}.")
    return operstate, speed, duplex, notes


def default_gateway() -> Optional[str]:
    code, stdout, _ = run_command(["ip", "route", "show", "default"], timeout=5)
    if code != 0:
        code, stdout, _ = run_command(["route", "-n", "get", "default"], timeout=5)
        match = re.search(r"gateway:\s+(\S+)", stdout)
        return match.group(1) if match else None
    match = re.search(r"default via (\S+)", stdout)
    return match.group(1) if match else None


def public_ip() -> Optional[str]:
    try:
        req = Request("https://api.ipify.org", headers={"User-Agent": "RouterWatch/1.0"})
        with urlopen(req, timeout=8) as response:
            return response.read().decode("utf-8").strip()
    except Exception:
        return None


def strip_html(value: str) -> str:
    text = re.sub(r"<script\b.*?</script>", "", value, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def router_admin_request(url: str, method: str = "GET", data: Optional[bytes] = None) -> Optional[str]:
    context = ssl._create_unverified_context()
    try:
        req = Request(url, data=data, method=method, headers={"User-Agent": "RouterWatch/1.0"})
        with urlopen(req, timeout=8, context=context) as response:
            return response.read(50000).decode("utf-8", "replace")
    except Exception:
        return None


def router_basic_info(config: Dict[str, Any]) -> Dict[str, Optional[str]]:
    router = config.get("router", {})
    gateway = router.get("gateway") or default_gateway() or "192.168.1.1"
    admin_url = router.get("admin_url") or f"https://{gateway}"
    info_path = router.get("info_page_path", "/cgi-bin/index.cgi")
    info_url = urljoin(admin_url.rstrip("/") + "/", info_path.lstrip("/"))
    body = router_admin_request(info_url)

    values: Dict[str, Optional[str]] = {
        "router_model": None,
        "router_firmware_version": None,
        "router_serial_number": None,
        "router_internet_status": None,
        "router_cloud_status": None,
        "router_connected_pods": None,
    }
    if not body:
        return values

    rows: Dict[str, str] = {}
    row_pattern = re.compile(
        r"<div\s+class='data_name[^']*'[^>]*>(.*?)</div>\s*"
        r"<div\s+class='data_value[^']*'[^>]*>(.*?)</div>",
        re.IGNORECASE | re.DOTALL,
    )
    for name_html, value_html in row_pattern.findall(body):
        name = strip_html(name_html)
        value = strip_html(value_html)
        if name:
            rows[name] = value

    values["router_model"] = rows.get("Model")
    values["router_firmware_version"] = rows.get("FW Version")
    values["router_serial_number"] = rows.get("Serial Number")
    values["router_cloud_status"] = rows.get("Cloud Status")

    connectivity_path = router.get("connectivity_api_path", "/cgi-bin/connectivity_api")
    connectivity_url = urljoin(admin_url.rstrip("/") + "/", connectivity_path.lstrip("/"))
    values["router_internet_status"] = router_admin_request(connectivity_url, method="POST", data=b"")
    if not values["router_internet_status"]:
        values["router_internet_status"] = rows.get("Internet Status")

    pods_path = router.get("pods_api_path", "/cgi-bin/pods_api")
    pods_url = urljoin(admin_url.rstrip("/") + "/", pods_path.lstrip("/"))
    values["router_connected_pods"] = router_admin_request(pods_url, method="POST", data=b"")
    if not values["router_connected_pods"]:
        values["router_connected_pods"] = rows.get("Connected Pods S/N")

    return {key: strip_html(value) if value else None for key, value in values.items()}


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                gateway_ok INTEGER NOT NULL,
                internet_ok INTEGER NOT NULL,
                dns_ok INTEGER NOT NULL,
                https_ok INTEGER NOT NULL,
                avg_latency_ms REAL,
                packet_loss_percent REAL,
                ethernet_operstate TEXT,
                ethernet_speed_mbps INTEGER,
                ethernet_duplex TEXT,
                wifi_rssi_dbm INTEGER,
                wifi_tx_bitrate TEXT,
                default_gateway TEXT,
                public_ip TEXT,
                notes TEXT NOT NULL
            )
            """
        )
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(checks)").fetchall()
        }
        migrations = {
            "ethernet_operstate": "ALTER TABLE checks ADD COLUMN ethernet_operstate TEXT",
            "ethernet_speed_mbps": "ALTER TABLE checks ADD COLUMN ethernet_speed_mbps INTEGER",
            "ethernet_duplex": "ALTER TABLE checks ADD COLUMN ethernet_duplex TEXT",
            "router_model": "ALTER TABLE checks ADD COLUMN router_model TEXT",
            "router_firmware_version": "ALTER TABLE checks ADD COLUMN router_firmware_version TEXT",
            "router_serial_number": "ALTER TABLE checks ADD COLUMN router_serial_number TEXT",
            "router_internet_status": "ALTER TABLE checks ADD COLUMN router_internet_status TEXT",
            "router_cloud_status": "ALTER TABLE checks ADD COLUMN router_cloud_status TEXT",
            "router_connected_pods": "ALTER TABLE checks ADD COLUMN router_connected_pods TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing_columns:
                conn.execute(statement)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                subject TEXT NOT NULL,
                text_body TEXT NOT NULL,
                html_body TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'degradation',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            )
            """
        )
        outbox_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(alert_outbox)").fetchall()
        }
        if "kind" not in outbox_columns:
            conn.execute(
                "ALTER TABLE alert_outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'degradation'"
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_key TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0,
                current_ip TEXT,
                hostname TEXT,
                mac TEXT,
                vendor TEXT,
                friendly_name TEXT,
                device_type TEXT,
                owner TEXT,
                location TEXT,
                metadata TEXT,
                locally_administered INTEGER NOT NULL DEFAULT 0,
                interface TEXT,
                state TEXT
            )
            """
        )
        device_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        device_migrations = {
            "device_type": "ALTER TABLE devices ADD COLUMN device_type TEXT",
            "owner": "ALTER TABLE devices ADD COLUMN owner TEXT",
            "location": "ALTER TABLE devices ADD COLUMN location TEXT",
            "metadata": "ALTER TABLE devices ADD COLUMN metadata TEXT",
            "locally_administered": "ALTER TABLE devices ADD COLUMN locally_administered INTEGER NOT NULL DEFAULT 0",
        }
        for column, statement in device_migrations.items():
            if column not in device_columns:
                conn.execute(statement)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_ips (
                device_key TEXT NOT NULL,
                ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0,
                interface TEXT,
                PRIMARY KEY (device_key, ip)
            )
            """
        )
        conn.commit()


def save_check(db_path: Path, result: CheckResult) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO checks (
                checked_at, gateway_ok, internet_ok, dns_ok, https_ok, avg_latency_ms,
                packet_loss_percent, ethernet_operstate, ethernet_speed_mbps,
                ethernet_duplex, wifi_rssi_dbm, wifi_tx_bitrate, default_gateway,
                public_ip, router_model, router_firmware_version, router_serial_number,
                router_internet_status, router_cloud_status, router_connected_pods, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.checked_at,
                int(result.gateway_ok),
                int(result.internet_ok),
                int(result.dns_ok),
                int(result.https_ok),
                result.avg_latency_ms,
                result.packet_loss_percent,
                result.ethernet_operstate,
                result.ethernet_speed_mbps,
                result.ethernet_duplex,
                result.wifi_rssi_dbm,
                result.wifi_tx_bitrate,
                result.default_gateway,
                result.public_ip,
                result.router_model,
                result.router_firmware_version,
                result.router_serial_number,
                result.router_internet_status,
                result.router_cloud_status,
                result.router_connected_pods,
                "\n".join(result.notes),
            ),
        )
        conn.commit()


def save_event(db_path: Path, event_type: str, details: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO events (event_at, event_type, details) VALUES (?, ?, ?)",
            (utc_iso(), event_type, details),
        )
        conn.commit()


def recent_checks(db_path: Path, limit: int) -> List[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]


def recent_events(db_path: Path, limit: int) -> List[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]


def pending_alerts(db_path: Path) -> List[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, created_at, subject, kind, attempts, last_error
            FROM alert_outbox
            WHERE sent_at IS NULL
            ORDER BY id
            """
        ).fetchall()
        return [dict(row) for row in rows]


def parse_ip_neigh(output: str) -> List[Dict[str, Optional[str]]]:
    devices = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3 or "dev" not in parts:
            continue
        ip = parts[0]
        if ":" in ip:
            continue
        dev_index = parts.index("dev")
        interface = parts[dev_index + 1] if dev_index + 1 < len(parts) else None
        mac = None
        if "lladdr" in parts:
            mac_index = parts.index("lladdr")
            mac = parts[mac_index + 1] if mac_index + 1 < len(parts) else None
        state = parts[-1] if parts[-1].isupper() else None
        if state in {"FAILED", "INCOMPLETE"}:
            continue
        devices.append(
            {
                "ip": ip,
                "interface": interface,
                "mac": mac,
                "state": state,
            }
        )
    return devices


def hostname_for_ip(ip: str) -> Optional[str]:
    code, stdout, _ = run_command(["getent", "hosts", ip], timeout=2)
    if code != 0:
        return None
    parts = stdout.split()
    if len(parts) >= 2:
        return parts[1]
    return None


def observed_devices() -> List[Dict[str, Optional[str]]]:
    code, stdout, _ = run_command(["ip", "neigh", "show"], timeout=5)
    if code != 0:
        return []
    devices = parse_ip_neigh(stdout)
    for device in devices:
        device["hostname"] = hostname_for_ip(device["ip"] or "")
    return sorted(
        devices,
        key=lambda device: (
            device.get("interface") or "",
            device.get("ip") or "",
        ),
    )


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    return mac.lower() if mac else None


def normalize_oui(mac: Optional[str]) -> Optional[str]:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    parts = normalized.split(":")
    if len(parts) < 3:
        return None
    return "".join(parts[:3]).upper()


def configured_device_value(config: Dict[str, Any], key: str, device: Dict[str, Optional[str]]) -> Optional[str]:
    values = config.get("devices", {}).get(key, {})
    if not isinstance(values, dict):
        return None
    candidates = [
        normalize_mac(device.get("mac")),
        device.get("ip"),
        device.get("hostname"),
    ]
    for candidate in candidates:
        if candidate and candidate in values:
            return str(values[candidate])
    return None


def configured_device_metadata(config: Dict[str, Any], device: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    return {
        "friendly_name": configured_device_value(config, "names", device),
        "device_type": configured_device_value(config, "types", device),
        "owner": configured_device_value(config, "owners", device),
        "location": configured_device_value(config, "locations", device),
    }


def oui_paths(config: Dict[str, Any]) -> List[Path]:
    configured_path = config.get("devices", {}).get("oui_path")
    paths = []
    if configured_path:
        paths.append(Path(str(configured_path)).expanduser())
    paths.extend(
        [
            Path("routerwatch/oui.txt"),
            Path("/usr/share/ieee-data/oui.txt"),
            Path("/var/lib/ieee-data/oui.txt"),
            Path("/usr/share/misc/oui.txt"),
        ]
    )
    return paths


def load_oui_vendors(config: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    global OUI_VENDOR_CACHE
    if OUI_VENDOR_CACHE is not None:
        return OUI_VENDOR_CACHE
    vendors: Dict[str, str] = {}
    for path in oui_paths(config or {}):
        if not path.exists():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = re.match(
                    r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})\s+\(base 16\)\s+(.+)$",
                    line,
                )
                if not match:
                    match = re.match(
                        r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$",
                        line,
                    )
                    if match:
                        vendors[match.group(1).upper()] = match.group(2).strip()
                        continue
                if match:
                    vendors["".join(match.groups()[:3]).upper()] = match.group(4).strip()
        except OSError:
            continue
        if vendors:
            break
    OUI_VENDOR_CACHE = vendors
    return vendors


def device_vendor(config: Dict[str, Any], device: Dict[str, Optional[str]]) -> Optional[str]:
    configured = configured_device_value(config, "vendors", device)
    if configured:
        return configured
    oui = normalize_oui(device.get("mac"))
    return load_oui_vendors(config).get(oui or "")


def is_locally_administered_mac(mac: Optional[str]) -> bool:
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    try:
        first_octet = int(normalized.split(":")[0], 16)
    except (IndexError, ValueError):
        return False
    return bool(first_octet & 0x02)


def inferred_device_type(
    device: Dict[str, Optional[str]],
    vendor: Optional[str],
    configured_type: Optional[str],
) -> Tuple[Optional[str], Dict[str, Any]]:
    signals = {
        "hostname": device.get("hostname"),
        "vendor": vendor,
        "locally_administered_mac": is_locally_administered_mac(device.get("mac")),
    }
    if configured_type:
        signals["type_source"] = "config"
        return configured_type, signals

    haystack = " ".join(
        value.lower()
        for value in (device.get("hostname"), vendor)
        if value
    )
    type_rules = [
        ("router", ("router", "gateway", "sax2")),
        ("streaming_device", ("chromecast", "google cast", "apple tv", "fire tv")),
        ("streaming_device", ("roku",)),
        ("smart_tv", ("samsung", "vizio", "lg electronics", "bravia", "tcl")),
        ("printer", ("printer", "brother", "canon", "epson", "hp inc")),
        ("camera", ("camera", "ring", "arlo", "wyze", "nest cam")),
        ("phone", ("iphone", "android", "pixel", "samsung")),
        ("computer", ("macbook", "windows", "desktop", "laptop")),
    ]
    for device_type, markers in type_rules:
        if any(marker in haystack for marker in markers):
            signals["type_source"] = "inferred"
            return device_type, signals
    signals["type_source"] = "unknown"
    return None, signals


def device_key(device: Dict[str, Optional[str]]) -> str:
    mac = normalize_mac(device.get("mac"))
    if mac:
        return f"mac:{mac}"
    return f"ip:{device.get('interface') or 'unknown'}:{device.get('ip') or 'unknown'}"


def update_device_inventory(
    db_path: Path,
    config: Dict[str, Any],
    devices: List[Dict[str, Optional[str]]],
    seen_at: Optional[str] = None,
) -> None:
    seen_at = seen_at or utc_iso()
    with sqlite3.connect(db_path) as conn:
        for device in devices:
            key = device_key(device)
            mac = normalize_mac(device.get("mac"))
            configured = configured_device_metadata(config, device)
            friendly_name = configured["friendly_name"]
            router = config.get("router", {})
            if not friendly_name and device.get("ip") == router.get("gateway"):
                friendly_name = router.get("name", "Home Router")
            vendor = device_vendor(config, device)
            device_type, metadata = inferred_device_type(
                device, vendor, configured["device_type"]
            )
            metadata_json = json.dumps(metadata, sort_keys=True)
            locally_administered = int(is_locally_administered_mac(mac))
            conn.execute(
                """
                INSERT INTO devices (
                    device_key, first_seen, last_seen, seen_count, current_ip,
                    hostname, mac, vendor, friendly_name, device_type, owner,
                    location, metadata, locally_administered, interface, state
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_key) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    seen_count = devices.seen_count + 1,
                    current_ip = excluded.current_ip,
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    mac = COALESCE(excluded.mac, devices.mac),
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    friendly_name = COALESCE(excluded.friendly_name, devices.friendly_name),
                    device_type = COALESCE(excluded.device_type, devices.device_type),
                    owner = COALESCE(excluded.owner, devices.owner),
                    location = COALESCE(excluded.location, devices.location),
                    metadata = excluded.metadata,
                    locally_administered = excluded.locally_administered,
                    interface = excluded.interface,
                    state = excluded.state
                """,
                (
                    key,
                    seen_at,
                    seen_at,
                    device.get("ip"),
                    device.get("hostname"),
                    mac,
                    vendor,
                    friendly_name,
                    device_type,
                    configured["owner"],
                    configured["location"],
                    metadata_json,
                    locally_administered,
                    device.get("interface"),
                    device.get("state"),
                ),
            )
            conn.execute(
                """
                INSERT INTO device_ips (
                    device_key, ip, first_seen, last_seen, seen_count, interface
                ) VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(device_key, ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    seen_count = device_ips.seen_count + 1,
                    interface = excluded.interface
                """,
                (
                    key,
                    device.get("ip"),
                    seen_at,
                    seen_at,
                    device.get("interface"),
                ),
            )
        conn.commit()


def device_status(row: Dict[str, Any], now: datetime, config: Dict[str, Any]) -> str:
    last_seen = parse_utc(row["last_seen"])
    recent_minutes = int(config.get("devices", {}).get("recent_minutes", 15))
    if now - last_seen > timedelta(minutes=recent_minutes):
        return "offline"
    state = (row.get("state") or "").upper()
    if state in {"REACHABLE", "DELAY", "PROBE"}:
        return "active"
    if state == "STALE":
        return "recent"
    return "observed"


def device_ip_history(config: Dict[str, Any], db_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT device_key, ip, first_seen, last_seen, seen_count, interface
            FROM device_ips
            ORDER BY last_seen DESC
            """
        ).fetchall()
    history: Dict[str, List[Dict[str, Any]]] = {}
    for raw in rows:
        row = dict(raw)
        row["first_seen"] = local_display(row["first_seen"], config)
        row["last_seen"] = local_display(row["last_seen"], config)
        history.setdefault(row["device_key"], []).append(row)
    return history


def device_inventory(config: Dict[str, Any], db_path: Path) -> List[Dict[str, Any]]:
    now = utc_now()
    ip_history = device_ip_history(config, db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT device_key, first_seen, last_seen, seen_count, current_ip,
                   hostname, mac, vendor, friendly_name, device_type, owner,
                   location, metadata, locally_administered, interface, state
            FROM devices
            ORDER BY last_seen DESC, current_ip
            LIMIT 100
            """
        ).fetchall()
    inventory = []
    for raw in rows:
        row = dict(raw)
        row["status"] = device_status(row, now, config)
        row["first_seen"] = local_display(row["first_seen"], config)
        row["last_seen"] = local_display(row["last_seen"], config)
        row["ip_history"] = ip_history.get(row["device_key"], [])
        row["ip_history_summary"] = ", ".join(
            ip_row["ip"] for ip_row in row["ip_history"][:4]
        )
        if len(row["ip_history"]) > 4:
            row["ip_history_summary"] += f" +{len(row['ip_history']) - 4} more"
        try:
            row["metadata"] = json.loads(row["metadata"] or "{}")
        except json.JSONDecodeError:
            row["metadata"] = {}
        row["locally_administered"] = bool(row["locally_administered"])
        inventory.append(row)
    return inventory


def outage_checks_before_recovery(db_path: Path) -> List[Dict[str, Any]]:
    outage = []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM checks ORDER BY id DESC")
        next(rows, None)  # The current healthy check.
        for row in rows:
            check = dict(row)
            healthy = bool(
                check["gateway_ok"]
                and check["internet_ok"]
                and check["dns_ok"]
                and check["https_ok"]
            )
            if healthy:
                break
            outage.append(check)
    outage.reverse()
    return outage


def last_event(db_path: Path, event_type: str) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM events WHERE event_type = ? ORDER BY id DESC LIMIT 1",
            (event_type,),
        ).fetchone()
        return dict(row) if row else None


def pending_alert(db_path: Path, kind: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        if kind:
            row = conn.execute(
                """
                SELECT * FROM alert_outbox
                WHERE sent_at IS NULL AND kind = ?
                ORDER BY id LIMIT 1
                """,
                (kind,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM alert_outbox WHERE sent_at IS NULL ORDER BY id LIMIT 1"
            ).fetchone()
        return dict(row) if row else None


def queue_alert(
    db_path: Path,
    subject: str,
    text_body: str,
    html_body: str,
    error: str,
    kind: str = "degradation",
) -> None:
    if pending_alert(db_path, kind):
        return
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO alert_outbox (
                created_at, subject, text_body, html_body, kind, attempts, last_error
            ) VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (utc_iso(), subject, text_body, html_body, kind, error),
        )
        conn.commit()


def mark_alert_sent(db_path: Path, alert_id: int) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE alert_outbox
            SET sent_at = ?, attempts = attempts + 1, last_error = NULL
            WHERE id = ?
            """,
            (utc_iso(), alert_id),
        )
        conn.commit()


def record_alert_retry_failure(db_path: Path, alert_id: int, error: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE alert_outbox
            SET attempts = attempts + 1, last_error = ?
            WHERE id = ?
            """,
            (error, alert_id),
        )
        conn.commit()


def perform_check(config: Dict[str, Any]) -> CheckResult:
    router = config["router"]
    monitor = config["monitor"]
    notes: List[str] = []
    ping_count = int(monitor.get("ping_count", 4))

    gateway_host = router.get("gateway") or default_gateway()
    gateway_ok, gateway_latency, gateway_loss, gateway_raw = ping(gateway_host, ping_count)
    if not gateway_ok:
        notes.append(f"gateway ping failed for {gateway_host}: {gateway_raw[-200:]}")

    internet_ok, internet_latency, internet_loss, internet_notes = first_successful_ping(
        monitor.get("internet_ping_targets", []),
        ping_count,
    )
    notes.extend(internet_notes)

    dns_ok, dns_notes = dns_check(monitor.get("dns_hosts", []))
    notes.extend(dns_notes)

    https_ok, https_notes = https_check(monitor.get("https_urls", []))
    notes.extend(https_notes)

    eth_state, eth_speed, eth_duplex, eth_notes = ethernet_info(monitor.get("ethernet_interface", ""))
    notes.extend(eth_notes)

    rssi, bitrate, wifi_notes = wifi_info(monitor.get("wifi_interface", ""))
    notes.extend(wifi_notes)

    avg_latency = internet_latency if internet_latency is not None else gateway_latency
    packet_loss = internet_loss if internet_loss is not None else gateway_loss

    if packet_loss is not None and packet_loss >= float(monitor.get("packet_loss_alert_percent", 50)):
        notes.append(f"high packet loss: {packet_loss}%")
    if avg_latency is not None and avg_latency >= float(monitor.get("latency_alert_ms", 250)):
        notes.append(f"high latency: {avg_latency}ms")
    if rssi is not None and rssi <= int(monitor.get("wifi_weak_rssi_dbm", -70)):
        notes.append(f"weak Wi-Fi signal: {rssi} dBm")

    info = router_basic_info(config)

    return CheckResult(
        checked_at=utc_iso(),
        gateway_ok=gateway_ok,
        internet_ok=internet_ok,
        dns_ok=dns_ok,
        https_ok=https_ok,
        avg_latency_ms=avg_latency,
        packet_loss_percent=packet_loss,
        ethernet_operstate=eth_state,
        ethernet_speed_mbps=eth_speed,
        ethernet_duplex=eth_duplex,
        wifi_rssi_dbm=rssi,
        wifi_tx_bitrate=bitrate,
        default_gateway=default_gateway(),
        public_ip=public_ip() if internet_ok and https_ok else None,
        router_model=info.get("router_model"),
        router_firmware_version=info.get("router_firmware_version"),
        router_serial_number=info.get("router_serial_number"),
        router_internet_status=info.get("router_internet_status"),
        router_cloud_status=info.get("router_cloud_status"),
        router_connected_pods=info.get("router_connected_pods"),
        notes=notes,
    )


def gmail_service(token_path: Path):
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    scopes = ["https://www.googleapis.com/auth/gmail.send"]
    if not token_path.exists():
        raise FileNotFoundError(f"Gmail token not found: {token_path}")
    creds = Credentials.from_authorized_user_file(str(token_path), scopes)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        token_path.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds)


def send_gmail(config: Dict[str, Any], config_path: Path, subject: str, text_body: str, html_body: str) -> None:
    alerts = config["alerts"]
    sender = os.environ.get("SENDER_EMAIL", alerts.get("sender", "")).strip()
    recipients = alerts.get("recipients", [])
    if not sender:
        raise ValueError("SENDER_EMAIL is empty and alerts.sender is not configured.")
    if not recipients:
        raise ValueError("No alert recipients configured.")

    token_path = resolve_path(config_path, alerts.get("token_path", "token.json"))
    msg = MIMEMultipart("alternative")
    msg["To"] = ", ".join(recipients)
    msg["From"] = sender
    msg["Subject"] = subject
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    gmail_service(token_path).users().messages().send(userId="me", body={"raw": raw}).execute()


def result_summary(result: CheckResult, config: Optional[Dict[str, Any]] = None) -> str:
    status = "healthy" if not result.needs_attention else "needs attention"
    local_time, utc_time = format_time_pair(result.checked_at, config or {})
    lines = [
        f"RouterWatch status: {status}",
        f"Checked at local: {local_time}",
        f"Checked at UTC: {utc_time}",
        f"Gateway OK: {result.gateway_ok}",
        f"Internet ping OK: {result.internet_ok}",
        f"DNS OK: {result.dns_ok}",
        f"HTTPS OK: {result.https_ok}",
        f"Latency: {result.avg_latency_ms} ms",
        f"Packet loss: {result.packet_loss_percent}%",
        f"Ethernet state: {result.ethernet_operstate}",
        f"Ethernet speed: {result.ethernet_speed_mbps} Mbps",
        f"Ethernet duplex: {result.ethernet_duplex}",
        f"Wi-Fi RSSI: {result.wifi_rssi_dbm} dBm",
        f"Wi-Fi bitrate: {result.wifi_tx_bitrate}",
        f"Default gateway: {result.default_gateway}",
        f"Public IP: {result.public_ip}",
        f"Router model: {result.router_model}",
        f"Router firmware: {result.router_firmware_version}",
        f"Router serial: {result.router_serial_number}",
        f"Router page internet status: {result.router_internet_status}",
        f"Router cloud status: {result.router_cloud_status}",
        f"Connected pods: {result.router_connected_pods}",
        "",
        "Notes:",
        *(result.notes or ["No issues recorded."]),
    ]
    return "\n".join(lines)


def result_html(result: CheckResult, config: Optional[Dict[str, Any]] = None) -> str:
    local_time, utc_time = format_time_pair(result.checked_at, config or {})
    rows = [
        ("Gateway", result.gateway_ok),
        ("Internet ping", result.internet_ok),
        ("DNS", result.dns_ok),
        ("HTTPS", result.https_ok),
        ("Latency", f"{result.avg_latency_ms} ms"),
        ("Packet loss", f"{result.packet_loss_percent}%"),
        ("Ethernet state", result.ethernet_operstate),
        ("Ethernet speed", f"{result.ethernet_speed_mbps} Mbps"),
        ("Ethernet duplex", result.ethernet_duplex),
        ("Wi-Fi RSSI", f"{result.wifi_rssi_dbm} dBm"),
        ("Wi-Fi bitrate", result.wifi_tx_bitrate),
        ("Default gateway", result.default_gateway),
        ("Public IP", result.public_ip),
        ("Router model", result.router_model),
        ("Router firmware", result.router_firmware_version),
        ("Router serial", result.router_serial_number),
        ("Router page internet status", result.router_internet_status),
        ("Router cloud status", result.router_cloud_status),
        ("Connected pods", result.router_connected_pods),
    ]
    row_html = "".join(f"<tr><td>{name}</td><td>{value}</td></tr>" for name, value in rows)
    notes = "<br>".join(result.notes or ["No issues recorded."])
    color = "#1f7a3f" if result.healthy else "#b42318"
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:720px">
      <h2 style="color:{color};margin-bottom:8px">RouterWatch: {'Healthy' if not result.needs_attention else 'Needs attention'}</h2>
      <p>Checked at {local_time}<br><span style="color:#666">UTC: {utc_time}</span></p>
      <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;border:1px solid #ddd">
        {row_html}
      </table>
      <h3>Notes</h3>
      <p>{notes}</p>
    </div>
    """


def format_duration(started_at: str, recovered_at: str) -> str:
    seconds = max(0, int((parse_utc(recovered_at) - parse_utc(started_at)).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def recovery_outage_summary(
    config: Dict[str, Any],
    db_path: Path,
    result: CheckResult,
) -> Tuple[str, str]:
    checks = outage_checks_before_recovery(db_path)
    if not checks:
        return "", ""

    started_at = checks[0]["checked_at"]
    start_local, start_utc = format_time_pair(started_at, config)
    recovery_local, recovery_utc = format_time_pair(result.checked_at, config)
    latencies = [row["avg_latency_ms"] for row in checks if row["avg_latency_ms"] is not None]
    losses = [
        row["packet_loss_percent"]
        for row in checks
        if row["packet_loss_percent"] is not None
    ]
    worst_latency = f"{max(latencies):.3f} ms" if latencies else "N/A"
    worst_loss = f"{max(losses):.1f}%" if losses else "N/A"
    duration = format_duration(started_at, result.checked_at)

    text = "\n".join(
        [
            "Outage summary:",
            f"Start time: {start_local} (UTC {start_utc})",
            f"Recovery time: {recovery_local} (UTC {recovery_utc})",
            f"Duration: {duration}",
            f"Failed checks: {len(checks)}",
            f"Worst latency: {worst_latency}",
            f"Worst packet loss: {worst_loss}",
        ]
    )
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:720px">
      <h3>Outage summary</h3>
      <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;border:1px solid #ddd">
        <tr><td><strong>Start time</strong></td><td>{start_local}<br><span style="color:#666">UTC: {start_utc}</span></td></tr>
        <tr><td><strong>Recovery time</strong></td><td>{recovery_local}<br><span style="color:#666">UTC: {recovery_utc}</span></td></tr>
        <tr><td><strong>Duration</strong></td><td>{duration}</td></tr>
        <tr><td><strong>Failed checks</strong></td><td>{len(checks)}</td></tr>
        <tr><td><strong>Worst latency</strong></td><td>{worst_latency}</td></tr>
        <tr><td><strong>Worst packet loss</strong></td><td>{worst_loss}</td></tr>
      </table>
    </div>
    """
    return text, html


def new_metrics() -> Dict[str, Any]:
    return {
        "checks": 0,
        "available": 0,
        "dns_failures": 0,
        "latencies": [],
        "losses": [],
    }


def add_metric(metrics: Dict[str, Any], row: Dict[str, Any]) -> None:
    metrics["checks"] += 1
    available = bool(
        row["gateway_ok"] and row["internet_ok"] and row["dns_ok"] and row["https_ok"]
    )
    metrics["available"] += int(available)
    metrics["dns_failures"] += int(not row["dns_ok"])
    if row["avg_latency_ms"] is not None:
        metrics["latencies"].append(float(row["avg_latency_ms"]))
    if row["packet_loss_percent"] is not None:
        metrics["losses"].append(float(row["packet_loss_percent"]))


def percentile(values: List[float], percent: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent)))
    return ordered[index]


def metric_summary(metrics: Dict[str, Any]) -> Dict[str, Any]:
    checks = metrics["checks"]
    latencies = metrics["latencies"]
    losses = metrics["losses"]
    return {
        "checks": checks,
        "uptime": (metrics["available"] / checks * 100) if checks else None,
        "dns_failures": metrics["dns_failures"],
        "latency_avg": (sum(latencies) / len(latencies)) if latencies else None,
        "latency_p95": percentile(latencies, 0.95),
        "latency_worst": max(latencies) if latencies else None,
        "loss_avg": (sum(losses) / len(losses)) if losses else None,
        "loss_worst": max(losses) if losses else None,
    }


def health_analysis(
    config: Dict[str, Any],
    db_path: Path,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = now or utc_now()
    week_start = now - timedelta(days=7)
    prior_start = week_start - timedelta(days=7)
    lifetime = new_metrics()
    weekly = new_metrics()
    prior = new_metrics()
    episodes = []
    active = None
    episode_days: Counter = Counter()
    episode_hours: Counter = Counter()
    firmware_changes = []
    previous_firmware = None
    first_at = None

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT checked_at, gateway_ok, internet_ok, dns_ok, https_ok,
                   avg_latency_ms, packet_loss_percent, router_firmware_version, notes
            FROM checks ORDER BY id
            """
        )
        for raw in rows:
            row = dict(raw)
            checked_at = parse_utc(row["checked_at"])
            first_at = first_at or checked_at
            add_metric(lifetime, row)
            if checked_at >= week_start:
                add_metric(weekly, row)
            elif checked_at >= prior_start:
                add_metric(prior, row)

            firmware = row["router_firmware_version"]
            if firmware and previous_firmware and firmware != previous_firmware:
                firmware_changes.append(
                    {
                        "at": row["checked_at"],
                        "from": previous_firmware,
                        "to": firmware,
                    }
                )
            if firmware:
                previous_firmware = firmware

            core_failure = not bool(
                row["gateway_ok"]
                and row["internet_ok"]
                and row["dns_ok"]
                and row["https_ok"]
            )
            warning = any(
                marker in (row["notes"] or "")
                for marker in ("high packet loss:", "high latency:", "weak Wi-Fi signal:")
            )
            affected = core_failure or warning
            if affected and active is None:
                local_start = checked_at.astimezone(display_timezone(config))
                active = {
                    "start": checked_at,
                    "last": checked_at,
                    "outage": core_failure,
                }
                episode_days[local_start.strftime("%A")] += 1
                episode_hours[local_start.strftime("%-I %p")] += 1
            elif affected:
                active["last"] = checked_at
                active["outage"] = active["outage"] or core_failure
            elif active is not None:
                active["end"] = checked_at
                episodes.append(active)
                active = None

    if active is not None:
        active["end"] = now
        episodes.append(active)

    return {
        "generated_at": now,
        "week_start": week_start,
        "first_at": first_at,
        "weekly": metric_summary(weekly),
        "prior": metric_summary(prior),
        "lifetime": metric_summary(lifetime),
        "weekly_episodes": [
            episode for episode in episodes if episode["end"] >= week_start
        ],
        "lifetime_episode_count": len(episodes),
        "common_day": episode_days.most_common(1)[0] if episode_days else None,
        "common_hour": episode_hours.most_common(1)[0] if episode_hours else None,
        "weekly_firmware_changes": [
            change
            for change in firmware_changes
            if parse_utc(change["at"]) >= week_start
        ],
        "lifetime_firmware_changes": firmware_changes,
        "current_firmware": previous_firmware,
    }


def number(value: Optional[float], suffix: str = "", digits: int = 2) -> str:
    return "N/A" if value is None else f"{value:.{digits}f}{suffix}"


def trend(current: Optional[float], previous: Optional[float], suffix: str) -> str:
    if current is None or previous is None:
        return "prior-week comparison unavailable"
    delta = current - previous
    if abs(delta) < 0.005:
        return "unchanged from prior week"
    direction = "higher" if delta > 0 else "lower"
    return f"{abs(delta):.2f}{suffix} {direction} than prior week"


def weekly_report_content(
    config: Dict[str, Any],
    db_path: Path,
    now: Optional[datetime] = None,
) -> Tuple[str, str]:
    analysis = health_analysis(config, db_path, now)
    weekly = analysis["weekly"]
    prior = analysis["prior"]
    lifetime = analysis["lifetime"]
    tz = display_timezone(config)
    generated = analysis["generated_at"].astimezone(tz)
    week_start = analysis["week_start"].astimezone(tz)
    first_at = analysis["first_at"]

    lines = [
        "RouterWatch weekly health report",
        f"Period: {week_start.strftime('%Y-%m-%d %I:%M %p %Z')} to {generated.strftime('%Y-%m-%d %I:%M %p %Z')}",
        "",
        "THIS WEEK",
        f"Checks: {weekly['checks']}",
        f"Uptime: {number(weekly['uptime'], '%', 3)} ({trend(weekly['uptime'], prior['uptime'], ' percentage points')})",
        f"Latency: avg {number(weekly['latency_avg'], ' ms')}, p95 {number(weekly['latency_p95'], ' ms')}, worst {number(weekly['latency_worst'], ' ms')}",
        f"Latency trend: {trend(weekly['latency_avg'], prior['latency_avg'], ' ms')}",
        f"Packet loss: avg {number(weekly['loss_avg'], '%')}, worst {number(weekly['loss_worst'], '%')}",
        f"Packet-loss trend: {trend(weekly['loss_avg'], prior['loss_avg'], ' percentage points')}",
        f"DNS failures: {weekly['dns_failures']}",
        "",
        "OUTAGES AND DEGRADATIONS",
    ]

    weekly_episodes = analysis["weekly_episodes"]
    if weekly_episodes:
        for episode in weekly_episodes[:25]:
            start = episode["start"].astimezone(tz)
            end = episode["end"].astimezone(tz)
            kind = "Outage" if episode["outage"] else "Degradation"
            duration = format_duration(episode["start"].isoformat(), episode["end"].isoformat())
            lines.append(
                f"- {kind}: {start.strftime('%a %Y-%m-%d %I:%M %p %Z')} to "
                f"{end.strftime('%I:%M %p %Z')} ({duration})"
            )
        if len(weekly_episodes) > 25:
            lines.append(f"- {len(weekly_episodes) - 25} additional episodes omitted")
    else:
        lines.append("None recorded.")

    lines.extend(["", "FIRMWARE"])
    if analysis["weekly_firmware_changes"]:
        for change in analysis["weekly_firmware_changes"]:
            changed_local = parse_utc(change["at"]).astimezone(tz)
            lines.append(
                f"- {changed_local.strftime('%Y-%m-%d %I:%M %p %Z')}: "
                f"{change['from']} -> {change['to']}"
            )
    else:
        lines.append("No firmware changes this week.")
    lines.append(f"Current firmware: {analysis['current_firmware'] or 'unknown'}")

    history_start = (
        first_at.astimezone(tz).strftime("%Y-%m-%d %I:%M %p %Z")
        if first_at
        else "no data"
    )
    common_day = analysis["common_day"]
    common_hour = analysis["common_hour"]
    lines.extend(
        [
            "",
            f"ALL-TIME TREND (since {history_start})",
            f"Checks: {lifetime['checks']}",
            f"Uptime: {number(lifetime['uptime'], '%', 3)}",
            f"Latency: avg {number(lifetime['latency_avg'], ' ms')}, p95 {number(lifetime['latency_p95'], ' ms')}, worst {number(lifetime['latency_worst'], ' ms')}",
            f"Packet loss: avg {number(lifetime['loss_avg'], '%')}, worst {number(lifetime['loss_worst'], '%')}",
            f"DNS failures: {lifetime['dns_failures']}",
            f"Outage/degradation episodes: {analysis['lifetime_episode_count']}",
            (
                f"Most common start day: {common_day[0]} ({common_day[1]} episodes)"
                if common_day
                else "Most common start day: no episodes"
            ),
            (
                f"Most common start hour: {common_hour[0]} ({common_hour[1]} episodes)"
                if common_hour
                else "Most common start hour: no episodes"
            ),
            f"Firmware changes recorded: {len(analysis['lifetime_firmware_changes'])}",
        ]
    )
    text = "\n".join(lines)
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:800px">'
        "<h2>RouterWatch weekly health report</h2>"
        f'<pre style="font-family:Arial,sans-serif;white-space:pre-wrap;line-height:1.45">{escape(text)}</pre>'
        "</div>"
    )
    return text, html


def local_iso(value: str, config: Dict[str, Any]) -> str:
    return parse_utc(value).astimezone(display_timezone(config)).isoformat(timespec="seconds")


def local_display(value: str, config: Dict[str, Any]) -> str:
    return parse_utc(value).astimezone(display_timezone(config)).strftime("%Y-%m-%d %I:%M:%S %p %Z")


def row_healthy(row: Dict[str, Any]) -> bool:
    return bool(row["gateway_ok"] and row["internet_ok"] and row["dns_ok"] and row["https_ok"])


def row_needs_attention(row: Dict[str, Any]) -> bool:
    notes = row.get("notes") or ""
    return (not row_healthy(row)) or any(
        marker in notes
        for marker in ("high packet loss:", "high latency:", "weak Wi-Fi signal:")
    )


def dashboard_payload(config: Dict[str, Any], db_path: Path) -> Dict[str, Any]:
    init_db(db_path)
    update_device_inventory(db_path, config, observed_devices())
    checks = recent_checks(db_path, 240)
    latest = checks[0] if checks else None
    analysis = health_analysis(config, db_path)
    tz = display_timezone(config)
    monitor = config.get("monitor", {})
    thresholds = {
        "latency_alert_ms": float(monitor.get("latency_alert_ms", 250)),
        "packet_loss_alert_percent": float(monitor.get("packet_loss_alert_percent", 50)),
    }

    timeline = []
    for row in reversed(checks[:120]):
        timeline.append(
            {
                "checked_at": local_iso(row["checked_at"], config),
                "label": parse_utc(row["checked_at"]).astimezone(tz).strftime("%I:%M %p"),
                "healthy": row_healthy(row),
                "needs_attention": row_needs_attention(row),
                "latency_ms": row["avg_latency_ms"],
                "packet_loss_percent": row["packet_loss_percent"],
            }
        )

    recent = []
    for row in checks[:30]:
        recent.append(
            {
                "checked_at": local_display(row["checked_at"], config),
                "status": "healthy" if not row_needs_attention(row) else "needs attention",
                "gateway_ok": bool(row["gateway_ok"]),
                "internet_ok": bool(row["internet_ok"]),
                "dns_ok": bool(row["dns_ok"]),
                "https_ok": bool(row["https_ok"]),
                "latency_ms": row["avg_latency_ms"],
                "packet_loss_percent": row["packet_loss_percent"],
                "notes": row["notes"] or "",
            }
        )

    weekly_episodes = []
    newest_weekly_episodes = sorted(
        analysis["weekly_episodes"],
        key=lambda episode: episode["end"],
        reverse=True,
    )
    for episode in newest_weekly_episodes[:20]:
        start = episode["start"].astimezone(tz)
        end = episode["end"].astimezone(tz)
        weekly_episodes.append(
            {
                "kind": "outage" if episode["outage"] else "degradation",
                "start": start.strftime("%a %Y-%m-%d %I:%M %p %Z"),
                "end": end.strftime("%I:%M %p %Z"),
                "duration": format_duration(episode["start"].isoformat(), episode["end"].isoformat()),
            }
        )

    latest_payload = None
    if latest:
        latest_payload = {
            "checked_at": local_display(latest["checked_at"], config),
            "status": "healthy" if not row_needs_attention(latest) else "needs attention",
            "healthy": row_healthy(latest),
            "needs_attention": row_needs_attention(latest),
            "gateway_ok": bool(latest["gateway_ok"]),
            "internet_ok": bool(latest["internet_ok"]),
            "dns_ok": bool(latest["dns_ok"]),
            "https_ok": bool(latest["https_ok"]),
            "latency_ms": latest["avg_latency_ms"],
            "packet_loss_percent": latest["packet_loss_percent"],
            "ethernet_operstate": latest.get("ethernet_operstate"),
            "ethernet_speed_mbps": latest.get("ethernet_speed_mbps"),
            "ethernet_duplex": latest.get("ethernet_duplex"),
            "wifi_rssi_dbm": latest.get("wifi_rssi_dbm"),
            "wifi_tx_bitrate": latest.get("wifi_tx_bitrate"),
            "default_gateway": latest.get("default_gateway"),
            "public_ip": latest.get("public_ip"),
            "router_model": latest.get("router_model"),
            "router_firmware_version": latest.get("router_firmware_version"),
            "router_serial_number": latest.get("router_serial_number"),
            "router_internet_status": latest.get("router_internet_status"),
            "router_cloud_status": latest.get("router_cloud_status"),
            "router_connected_pods": latest.get("router_connected_pods"),
            "notes": latest["notes"] or "",
        }

    return {
        "generated_at": utc_now().astimezone(tz).strftime("%Y-%m-%d %I:%M:%S %p %Z"),
        "router_name": config.get("router", {}).get("name", "Home Router"),
        "latest": latest_payload,
        "weekly": analysis["weekly"],
        "prior": analysis["prior"],
        "lifetime": analysis["lifetime"],
        "weekly_episodes": weekly_episodes,
        "lifetime_episode_count": analysis["lifetime_episode_count"],
        "common_day": analysis["common_day"],
        "common_hour": analysis["common_hour"],
        "current_firmware": analysis["current_firmware"],
        "weekly_firmware_changes": [
            {
                "at": local_display(change["at"], config),
                "from": change["from"],
                "to": change["to"],
            }
            for change in analysis["weekly_firmware_changes"]
        ],
        "pending_alerts": [
            {
                **alert,
                "created_at": local_display(alert["created_at"], config),
            }
            for alert in pending_alerts(db_path)
        ],
        "events": [
            {
                **event,
                "event_at": local_display(event["event_at"], config),
            }
            for event in recent_events(db_path, 20)
        ],
        "thresholds": thresholds,
        "timeline": timeline,
        "recent_checks": recent,
        "devices": device_inventory(config, db_path),
    }


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RouterWatch Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #647084;
      --line: #d9dee8;
      --good: #177245;
      --bad: #b42318;
      --warn: #a15c07;
      --blue: #2457a6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: #172033;
      color: #fff;
      padding: 18px 24px;
      display: flex;
      gap: 16px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
    }
    h1 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 16px; }
    main { max-width: 1280px; margin: 0 auto; padding: 20px; }
    .muted { color: var(--muted); }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .dot { width: 11px; height: 11px; border-radius: 50%; background: var(--muted); }
    .good .dot { background: var(--good); }
    .bad .dot { background: var(--bad); }
    .grid { display: grid; gap: 16px; }
    .cards { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .two { grid-template-columns: minmax(0, 1.25fr) minmax(320px, .75fr); }
    section, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    .metric .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
    .metric .value { font-size: 26px; font-weight: 750; margin-top: 4px; }
    .metric .sub { color: var(--muted); margin-top: 4px; min-height: 20px; }
    .checks { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-top: 14px; }
    .check {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px;
      font-weight: 650;
      display: flex;
      justify-content: space-between;
      gap: 8px;
    }
    .ok { color: var(--good); }
    .fail { color: var(--bad); }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 8px 6px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    .chart-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }
    .legend { color: var(--muted); font-size: 12px; }
    .legend::before {
      content: "";
      display: inline-block;
      width: 22px;
      height: 10px;
      margin-right: 6px;
      background: rgba(23, 114, 69, .14);
      border: 1px solid rgba(23, 114, 69, .35);
      vertical-align: -1px;
    }
    .timeline-wrap { position: relative; }
    .timeline {
      height: 180px;
      display: flex;
      align-items: end;
      gap: 2px;
      border-left: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      padding: 8px 0 0 8px;
      overflow: hidden;
      position: relative;
      z-index: 1;
    }
    .healthy-band {
      position: absolute;
      left: 1px;
      right: 0;
      bottom: 1px;
      background: rgba(23, 114, 69, .14);
      border-top: 1px solid rgba(23, 114, 69, .45);
      pointer-events: none;
      z-index: 0;
    }
    .threshold-label,
    .scale-label {
      position: absolute;
      right: 8px;
      font-size: 12px;
      background: rgba(255, 255, 255, .9);
      padding: 1px 5px;
      border-radius: 4px;
      z-index: 2;
    }
    .threshold-label { color: var(--good); transform: translateY(50%); }
    .scale-label { color: var(--muted); }
    .scale-label.top { top: 4px; }
    .scale-label.bottom { bottom: 4px; }
    .bar { flex: 1 1 4px; min-width: 3px; background: var(--blue); border-radius: 3px 3px 0 0; opacity: .9; }
    .bar.warn { background: var(--warn); }
    .bar.bad { background: var(--bad); }
    .details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 18px; }
    .details div { display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--line); padding: 6px 0; }
    .details span:first-child { color: var(--muted); }
    .notes { white-space: pre-wrap; color: var(--muted); }
    @media (max-width: 900px) {
      main { padding: 14px; }
      .cards, .two, .checks, .details { grid-template-columns: 1fr; }
      header { padding: 16px; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1 id="title">RouterWatch</h1>
      <div class="muted" id="generated">Loading...</div>
    </div>
    <div class="status" id="status"><span class="dot"></span><span>Loading</span></div>
  </header>
  <main class="grid">
    <section>
      <h2>Current Check</h2>
      <div id="latestLine" class="muted">Waiting for data.</div>
      <div class="checks" id="checks"></div>
    </section>

    <div class="grid cards">
      <div class="card metric"><div class="label">Weekly uptime</div><div class="value" id="weeklyUptime">N/A</div><div class="sub" id="weeklyChecks"></div></div>
      <div class="card metric"><div class="label">Latency avg / p95</div><div class="value" id="latency">N/A</div><div class="sub" id="latencyWorst"></div></div>
      <div class="card metric"><div class="label">Packet loss avg / worst</div><div class="value" id="loss">N/A</div><div class="sub" id="dns"></div></div>
      <div class="card metric"><div class="label">All-time incidents</div><div class="value" id="incidents">N/A</div><div class="sub" id="common"></div></div>
    </div>

    <div class="grid two">
      <section>
        <div class="chart-head">
          <h2>Recent Latency And Loss</h2>
          <div class="legend" id="healthyLegend">Healthy range</div>
        </div>
        <div class="timeline-wrap">
          <div class="healthy-band" id="healthyBand"></div>
          <div class="threshold-label" id="thresholdLabel"></div>
          <div class="scale-label top" id="scaleTop"></div>
          <div class="scale-label bottom" id="scaleBottom"></div>
          <div class="timeline" id="timeline"></div>
        </div>
      </section>
      <section>
        <h2>Router Details</h2>
        <div class="details" id="details"></div>
      </section>
    </div>

    <div class="grid two">
      <section>
        <h2>Outages And Degradations This Week</h2>
        <table><thead><tr><th>Type</th><th>Start</th><th>End</th><th>Duration</th></tr></thead><tbody id="episodes"></tbody></table>
      </section>
      <section>
        <h2>Email Queue And Firmware</h2>
        <div id="queue" class="muted"></div>
        <div style="margin-top:12px" id="firmware" class="muted"></div>
      </section>
    </div>

    <section>
      <h2>Local Device Inventory</h2>
      <div class="muted" style="margin-bottom:8px">Persisted devices seen by the Pi on local interfaces. This is presence data, not router-reported bandwidth usage.</div>
      <table><thead><tr><th>Name</th><th>Type</th><th>Status</th><th>IP</th><th>IP History</th><th>Interface</th><th>Last Seen</th><th>First Seen</th><th>Seen</th><th>Vendor</th><th>MAC</th></tr></thead><tbody id="devices"></tbody></table>
    </section>

    <section>
      <h2>Recent Checks</h2>
      <table><thead><tr><th>Time</th><th>Status</th><th>Latency</th><th>Loss</th><th>Notes</th></tr></thead><tbody id="recent"></tbody></table>
    </section>
  </main>
  <script>
    const fmt = (value, suffix = "", digits = 2) => value === null || value === undefined ? "N/A" : Number(value).toFixed(digits) + suffix;
    const text = (id, value) => { document.getElementById(id).textContent = value; };
    const cell = (value) => String(value ?? "");
    function row(values) {
      return "<tr>" + values.map((value) => "<td>" + cell(value) + "</td>").join("") + "</tr>";
    }
    function render(data) {
      text("title", data.router_name + " Dashboard");
      text("generated", "Updated " + data.generated_at);
      const status = document.getElementById("status");
      status.className = "status " + (data.latest?.needs_attention ? "bad" : "good");
      status.lastElementChild.textContent = data.latest?.status || "No data";
      text("latestLine", data.latest ? data.latest.checked_at : "No checks recorded yet.");

      const checkItems = [["Gateway", data.latest?.gateway_ok], ["Internet", data.latest?.internet_ok], ["DNS", data.latest?.dns_ok], ["HTTPS", data.latest?.https_ok]];
      document.getElementById("checks").innerHTML = checkItems.map(([name, ok]) => `<div class="check"><span>${name}</span><span class="${ok ? "ok" : "fail"}">${ok ? "OK" : "Fail"}</span></div>`).join("");

      text("weeklyUptime", fmt(data.weekly.uptime, "%", 3));
      text("weeklyChecks", data.weekly.checks + " checks this week");
      text("latency", fmt(data.weekly.latency_avg, " ms") + " / " + fmt(data.weekly.latency_p95, " ms"));
      text("latencyWorst", "Worst " + fmt(data.weekly.latency_worst, " ms"));
      text("loss", fmt(data.weekly.loss_avg, "%") + " / " + fmt(data.weekly.loss_worst, "%"));
      text("dns", data.weekly.dns_failures + " DNS failures");
      text("incidents", data.lifetime_episode_count);
      const common = [data.common_day ? `${data.common_day[0]} (${data.common_day[1]})` : "no common day", data.common_hour ? `${data.common_hour[0]} (${data.common_hour[1]})` : "no common hour"].join(" · ");
      text("common", common);

      const latencyThreshold = data.thresholds?.latency_alert_ms ?? 250;
      const lossThreshold = data.thresholds?.packet_loss_alert_percent ?? 50;
      const latencyValues = data.timeline.map((point) => point.latency_ms).filter((value) => value !== null && value !== undefined).map(Number);
      const observedMinLatency = latencyValues.length ? Math.min(...latencyValues) : 0;
      const observedMaxLatency = latencyValues.length ? Math.max(...latencyValues) : latencyThreshold;
      const observedRange = Math.max(1, observedMaxLatency - observedMinLatency);
      const scalePadding = Math.max(2, observedRange * 0.25);
      const visualMinLatency = Math.max(0, observedMinLatency - scalePadding);
      const visualMaxLatency = Math.max(visualMinLatency + 1, observedMaxLatency + scalePadding);
      const visualRange = visualMaxLatency - visualMinLatency;
      const thresholdInView = latencyThreshold >= visualMinLatency && latencyThreshold <= visualMaxLatency;
      const bandHeight = thresholdInView ? Math.min(100, Math.max(0, (latencyThreshold - visualMinLatency) / visualRange * 100)) : 100;
      document.getElementById("healthyBand").style.height = bandHeight + "%";
      document.getElementById("thresholdLabel").style.bottom = bandHeight + "%";
      document.getElementById("thresholdLabel").style.display = thresholdInView ? "block" : "none";
      text("thresholdLabel", "< " + fmt(latencyThreshold, " ms", 0));
      text("scaleTop", fmt(visualMaxLatency, " ms", 0));
      text("scaleBottom", fmt(visualMinLatency, " ms", 0));
      text("healthyLegend", "Zoomed latency scale; healthy: < " + fmt(latencyThreshold, " ms", 0) + " and loss < " + fmt(lossThreshold, "%", 0));
      const bars = data.timeline.map((point) => {
        const latency = point.latency_ms ?? 0;
        const loss = point.packet_loss_percent ?? 0;
        const height = Math.max(6, Math.min(100, (latency - visualMinLatency) / visualRange * 100));
        const overThreshold = latency >= latencyThreshold || loss >= lossThreshold;
        const cls = !point.healthy ? "bad" : overThreshold || point.needs_attention ? "warn" : "";
        return `<div class="bar ${cls}" title="${point.label}: ${fmt(point.latency_ms, " ms")} latency, ${fmt(point.packet_loss_percent, "%")} loss" style="height:${height}%"></div>`;
      }).join("");
      document.getElementById("timeline").innerHTML = bars || "<div class='muted'>No timeline data yet.</div>";

      const latest = data.latest || {};
      const details = [
        ["Model", latest.router_model], ["Firmware", latest.router_firmware_version || data.current_firmware],
        ["Serial", latest.router_serial_number], ["Router internet", latest.router_internet_status],
        ["Cloud", latest.router_cloud_status], ["Pods", latest.router_connected_pods],
        ["Ethernet", [latest.ethernet_operstate, latest.ethernet_speed_mbps ? latest.ethernet_speed_mbps + " Mbps" : null, latest.ethernet_duplex].filter(Boolean).join(" / ")],
        ["Wi-Fi", [latest.wifi_rssi_dbm ? latest.wifi_rssi_dbm + " dBm" : null, latest.wifi_tx_bitrate].filter(Boolean).join(" / ")],
        ["Gateway", latest.default_gateway], ["Public IP", latest.public_ip]
      ];
      document.getElementById("details").innerHTML = details.map(([k, v]) => `<div><span>${k}</span><strong>${cell(v || "N/A")}</strong></div>`).join("");

      document.getElementById("episodes").innerHTML = data.weekly_episodes.length ? data.weekly_episodes.map((e) => row([e.kind, e.start, e.end, e.duration])).join("") : row(["None recorded", "", "", ""]);
      document.getElementById("queue").textContent = data.pending_alerts.length ? data.pending_alerts.map((a) => `${a.kind}: ${a.subject} (${a.attempts} attempts)`).join("\\n") : "No pending email alerts.";
      document.getElementById("firmware").textContent = data.weekly_firmware_changes.length ? data.weekly_firmware_changes.map((f) => `${f.at}: ${f.from} -> ${f.to}`).join("\\n") : "No firmware changes this week. Current: " + (data.current_firmware || "unknown");
      document.getElementById("devices").innerHTML = data.devices.length ? data.devices.map((d) => {
        const mac = (d.mac || "") + (d.locally_administered ? " (private)" : "");
        return row([d.friendly_name || d.hostname || "", d.device_type || "", d.status, d.current_ip, d.ip_history_summary || "", d.interface, d.last_seen, d.first_seen, d.seen_count, d.vendor || "", mac]);
      }).join("") : row(["No devices observed", "", "", "", "", "", "", "", "", "", ""]);
      document.getElementById("recent").innerHTML = data.recent_checks.map((r) => row([r.checked_at, r.status, fmt(r.latency_ms, " ms"), fmt(r.packet_loss_percent, "%"), `<span class="notes">${cell(r.notes || "No issues recorded.")}</span>`])).join("");
    }
    async function refresh() {
      const response = await fetch("/api/status", { cache: "no-store" });
      if (!response.ok) throw new Error("status request failed");
      render(await response.json());
    }
    refresh().catch((error) => {
      text("generated", "Dashboard failed to load: " + error.message);
    });
    setInterval(() => refresh().catch(() => {}), 30000);
  </script>
</body>
</html>
"""


def command_dashboard(config: Dict[str, Any], config_path: Path, host: str, port: int) -> int:
    db_path = resolve_path(config_path, config["storage"].get("database_path", "routerwatch.sqlite"))
    init_db(db_path)

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            log(config, config_path, "dashboard " + (format % args))

        def send_content(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in ("/", "/index.html"):
                self.send_content(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
                return
            if self.path == "/api/status":
                body = json.dumps(dashboard_payload(config, db_path), default=str).encode("utf-8")
                self.send_content(200, "application/json; charset=utf-8", body)
                return
            self.send_content(404, "text/plain; charset=utf-8", b"Not found")

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"RouterWatch dashboard listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0


def should_alert(config: Dict[str, Any], db_path: Path, result: CheckResult) -> Tuple[bool, str]:
    if not config["alerts"].get("enabled", True):
        return False, "alerts disabled"
    monitor = config["monitor"]
    recent = recent_checks(db_path, int(monitor.get("outage_checks_before_alert", 2)))
    if len(recent) < int(monitor.get("outage_checks_before_alert", 2)):
        return False, "not enough history"
    sustained_warning = result.needs_attention and all(
        (
            not bool(row["gateway_ok"] and row["internet_ok"] and row["dns_ok"] and row["https_ok"])
            or "high packet loss:" in row["notes"]
            or "high latency:" in row["notes"]
            or "weak Wi-Fi signal:" in row["notes"]
        )
        for row in recent
    )
    if sustained_warning:
        if pending_alert(db_path, "degradation"):
            return False, "degradation alert pending delivery"
        last = last_event(db_path, "alert_sent")
        if last:
            last_at = datetime.fromisoformat(last["event_at"])
            cooldown = timedelta(minutes=int(config["alerts"].get("cooldown_minutes", 30)))
            if utc_now() - last_at < cooldown:
                return False, "alert cooldown active"
        return True, "consecutive degraded checks"
    return False, "current issue not sustained"


def maybe_send_pending_alert(
    config: Dict[str, Any],
    config_path: Path,
    db_path: Path,
    result: CheckResult,
) -> None:
    alert = pending_alert(db_path)
    if not alert:
        return
    if not (result.internet_ok and result.dns_ok and result.https_ok):
        return
    try:
        send_gmail(
            config,
            config_path,
            alert["subject"],
            alert["text_body"],
            alert["html_body"],
        )
        mark_alert_sent(db_path, alert["id"])
        if alert["kind"] == "degradation":
            event_type = "alert_sent"
            message = "queued degradation alert delivered"
        else:
            event_type = "weekly_report_sent"
            message = "queued weekly report delivered"
        save_event(db_path, event_type, message)
        log(config, config_path, message)
    except Exception as exc:
        record_alert_retry_failure(db_path, alert["id"], str(exc))
        save_event(db_path, "alert_retry_failed", str(exc))
        log(config, config_path, f"queued alert retry failed: {exc}")


def maybe_send_recovery(config: Dict[str, Any], config_path: Path, db_path: Path, result: CheckResult) -> None:
    if not config["monitor"].get("recovery_email", True) or not result.healthy:
        return
    recent = recent_checks(db_path, 2)
    if len(recent) < 2:
        return
    previous = recent[1]
    was_unhealthy = not bool(previous["gateway_ok"] and previous["internet_ok"] and previous["dns_ok"] and previous["https_ok"])
    if was_unhealthy:
        try:
            summary_text, summary_html = recovery_outage_summary(config, db_path, result)
            text_body = "\n\n".join(part for part in (summary_text, result_summary(result, config)) if part)
            html_body = summary_html + result_html(result, config)
            send_gmail(config, config_path, "RouterWatch recovered", text_body, html_body)
            save_event(db_path, "recovery_sent", "Network recovered.")
        except Exception as exc:
            save_event(db_path, "recovery_email_failed", str(exc))


def restart_router(config: Dict[str, Any], db_path: Path) -> str:
    restart = config.get("restart", {})
    if not restart.get("enabled", False):
        return "Router restart is disabled."
    command = restart.get("command") or []
    if not command:
        return "Router restart command is empty."

    last = last_event(db_path, "restart_attempt")
    if last:
        last_at = datetime.fromisoformat(last["event_at"])
        cooldown = timedelta(minutes=int(restart.get("cooldown_minutes", 60)))
        if utc_now() - last_at < cooldown:
            return "Restart cooldown is active."

    code, stdout, stderr = run_command(command, timeout=60)
    details = f"command={command} code={code} stdout={stdout[-500:]} stderr={stderr[-500:]}"
    save_event(db_path, "restart_attempt", details)
    return details


def maybe_auto_restart(config: Dict[str, Any], db_path: Path) -> Optional[str]:
    restart = config.get("restart", {})
    threshold = int(restart.get("auto_restart_after_failed_checks", 0))
    if threshold <= 0:
        return None
    recent = recent_checks(db_path, threshold)
    if len(recent) < threshold:
        return None
    if all(not bool(row["gateway_ok"] and row["internet_ok"] and row["dns_ok"] and row["https_ok"]) for row in recent):
        return restart_router(config, db_path)
    return None


def command_check(config: Dict[str, Any], config_path: Path) -> int:
    db_path = resolve_path(config_path, config["storage"].get("database_path", "routerwatch.sqlite"))
    init_db(db_path)
    result = perform_check(config)
    save_check(db_path, result)
    update_device_inventory(db_path, config, observed_devices(), result.checked_at)
    print(result_summary(result, config))

    maybe_send_pending_alert(config, config_path, db_path, result)
    alert, reason = should_alert(config, db_path, result)
    if alert:
        subject = "RouterWatch alert: network degraded"
        text_body = result_summary(result, config)
        html_body = result_html(result, config)
        try:
            send_gmail(config, config_path, subject, text_body, html_body)
            save_event(db_path, "alert_sent", reason)
            log(config, config_path, f"alert sent: {reason}")
        except Exception as exc:
            queue_alert(db_path, subject, text_body, html_body, str(exc))
            save_event(db_path, "alert_failed", str(exc))
            log(config, config_path, f"alert failed and queued: {exc}")
    else:
        log(config, config_path, f"no alert: {reason}")

    maybe_send_recovery(config, config_path, db_path, result)
    restart_result = maybe_auto_restart(config, db_path)
    if restart_result:
        log(config, config_path, f"auto restart: {restart_result}")
    return 0 if result.healthy else 2


def command_watch(config: Dict[str, Any], config_path: Path) -> int:
    interval = int(config["monitor"].get("interval_seconds", 60))
    while True:
        try:
            command_check(config, config_path)
        except Exception as exc:
            log(config, config_path, f"watch error: {exc}")
        time.sleep(interval)


def command_status(config: Dict[str, Any], config_path: Path) -> int:
    db_path = resolve_path(config_path, config["storage"].get("database_path", "routerwatch.sqlite"))
    init_db(db_path)
    rows = recent_checks(db_path, 20)
    if not rows:
        print("No checks recorded yet.")
        return 0
    for row in rows:
        healthy = bool(row["gateway_ok"] and row["internet_ok"] and row["dns_ok"] and row["https_ok"])
        local_time, utc_time = format_time_pair(row["checked_at"], config)
        wifi = f"{row['wifi_rssi_dbm']}dBm" if row["wifi_rssi_dbm"] is not None else "unknown"
        print(
            f"{local_time} (UTC {utc_time}) status={'healthy' if healthy else 'degraded'} "
            f"latency={row['avg_latency_ms']}ms loss={row['packet_loss_percent']}% "
            f"ethernet={row.get('ethernet_operstate')}@{row.get('ethernet_speed_mbps')}Mbps "
            f"wifi={wifi} "
            f"router={row.get('router_model') or 'unknown'} firmware={row.get('router_firmware_version') or 'unknown'}"
        )
    return 0


def command_send_test(config: Dict[str, Any], config_path: Path) -> int:
    result = CheckResult(
        checked_at=utc_iso(),
        gateway_ok=True,
        internet_ok=True,
        dns_ok=True,
        https_ok=True,
        avg_latency_ms=20.0,
        packet_loss_percent=0.0,
        ethernet_operstate="up",
        ethernet_speed_mbps=1000,
        ethernet_duplex="full",
        wifi_rssi_dbm=-55,
        wifi_tx_bitrate="test",
        default_gateway=config["router"].get("gateway"),
        public_ip="test",
        router_model="test",
        router_firmware_version="test",
        router_serial_number="test",
        router_internet_status="test",
        router_cloud_status="test",
        router_connected_pods="test",
        notes=["This is a RouterWatch test alert."],
    )
    send_gmail(config, config_path, "RouterWatch test alert", result_summary(result, config), result_html(result, config))
    print("Test alert sent.")
    return 0


def command_weekly_report(config: Dict[str, Any], config_path: Path) -> int:
    db_path = resolve_path(config_path, config["storage"].get("database_path", "routerwatch.sqlite"))
    text_body, html_body = weekly_report_content(config, db_path)
    local_date = utc_now().astimezone(display_timezone(config)).strftime("%Y-%m-%d")
    subject = f"RouterWatch weekly health report: {local_date}"
    try:
        send_gmail(config, config_path, subject, text_body, html_body)
        save_event(db_path, "weekly_report_sent", subject)
        print("Weekly health report sent.")
    except Exception as exc:
        queue_alert(
            db_path,
            subject,
            text_body,
            html_body,
            str(exc),
            kind="weekly_report",
        )
        save_event(db_path, "weekly_report_queued", str(exc))
        log(config, config_path, f"weekly report queued: {exc}")
        print("Weekly health report queued for delivery after connectivity recovers.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor home router and internet health.")
    parser.add_argument(
        "command",
        choices=[
            "check",
            "watch",
            "status",
            "send-test",
            "weekly-report",
            "dashboard",
            "restart-router",
        ],
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--host", default="0.0.0.0", help="Dashboard bind host")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard bind port")
    args = parser.parse_args()

    config_path = Path(args.config).expanduser().resolve()
    config = load_config(config_path)
    db_path = resolve_path(config_path, config["storage"].get("database_path", "routerwatch.sqlite"))
    init_db(db_path)

    if args.command == "check":
        return command_check(config, config_path)
    if args.command == "watch":
        return command_watch(config, config_path)
    if args.command == "status":
        return command_status(config, config_path)
    if args.command == "send-test":
        return command_send_test(config, config_path)
    if args.command == "weekly-report":
        return command_weekly_report(config, config_path)
    if args.command == "dashboard":
        return command_dashboard(config, config_path, args.host, args.port)
    if args.command == "restart-router":
        print(restart_router(config, db_path))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
