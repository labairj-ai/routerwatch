#!/usr/bin/env python3

import argparse
import base64
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen


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
        conn.commit()


def save_check(db_path: Path, result: CheckResult) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO checks (
                checked_at, gateway_ok, internet_ok, dns_ok, https_ok, avg_latency_ms,
                packet_loss_percent, ethernet_operstate, ethernet_speed_mbps,
                ethernet_duplex, wifi_rssi_dbm, wifi_tx_bitrate, default_gateway,
                public_ip, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def result_summary(result: CheckResult) -> str:
    status = "healthy" if not result.needs_attention else "needs attention"
    lines = [
        f"RouterWatch status: {status}",
        f"Checked at: {result.checked_at}",
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
        "",
        "Notes:",
        *(result.notes or ["No issues recorded."]),
    ]
    return "\n".join(lines)


def result_html(result: CheckResult) -> str:
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
    ]
    row_html = "".join(f"<tr><td>{name}</td><td>{value}</td></tr>" for name, value in rows)
    notes = "<br>".join(result.notes or ["No issues recorded."])
    color = "#1f7a3f" if result.healthy else "#b42318"
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:720px">
      <h2 style="color:{color};margin-bottom:8px">RouterWatch: {'Healthy' if not result.needs_attention else 'Needs attention'}</h2>
      <p>Checked at {result.checked_at}</p>
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
        last = last_event(db_path, "alert_sent")
        if last:
            last_at = datetime.fromisoformat(last["event_at"])
            cooldown = timedelta(minutes=int(config["alerts"].get("cooldown_minutes", 30)))
            if utc_now() - last_at < cooldown:
                return False, "alert cooldown active"
        return True, "consecutive degraded checks"
    return False, "current issue not sustained"


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
            send_gmail(config, config_path, "RouterWatch recovered", result_summary(result), result_html(result))
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
    print(result_summary(result))

    alert, reason = should_alert(config, db_path, result)
    if alert:
        subject = "RouterWatch alert: network degraded"
        try:
            send_gmail(config, config_path, subject, result_summary(result), result_html(result))
            save_event(db_path, "alert_sent", reason)
            log(config, config_path, f"alert sent: {reason}")
        except Exception as exc:
            save_event(db_path, "alert_failed", str(exc))
            log(config, config_path, f"alert failed: {exc}")
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
        print(
            f"{row['checked_at']} status={'healthy' if healthy else 'degraded'} "
            f"latency={row['avg_latency_ms']}ms loss={row['packet_loss_percent']}% "
            f"ethernet={row.get('ethernet_operstate')}@{row.get('ethernet_speed_mbps')}Mbps "
            f"wifi={row['wifi_rssi_dbm']}dBm"
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
        notes=["This is a RouterWatch test alert."],
    )
    send_gmail(config, config_path, "RouterWatch test alert", result_summary(result), result_html(result))
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
