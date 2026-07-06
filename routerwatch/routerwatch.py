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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from html import unescape
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.json")


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
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
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


def last_event(db_path: Path, event_type: str) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM events WHERE event_type = ? ORDER BY id DESC LIMIT 1",
            (event_type,),
        ).fetchone()
        return dict(row) if row else None


def pending_alert(db_path: Path) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
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
) -> None:
    if pending_alert(db_path):
        return
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO alert_outbox (
                created_at, subject, text_body, html_body, attempts, last_error
            ) VALUES (?, ?, ?, ?, 1, ?)
            """,
            (utc_iso(), subject, text_body, html_body, error),
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
        if pending_alert(db_path):
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
        save_event(db_path, "alert_sent", "queued degradation alert delivered")
        log(config, config_path, "queued degradation alert delivered")
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
            send_gmail(config, config_path, "RouterWatch recovered", result_summary(result, config), result_html(result, config))
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor home router and internet health.")
    parser.add_argument("command", choices=["check", "watch", "status", "send-test", "restart-router"])
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config.json")
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
    if args.command == "restart-router":
        print(restart_router(config, db_path))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
