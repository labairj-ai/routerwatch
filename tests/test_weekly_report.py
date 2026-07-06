import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from routerwatch import routerwatch


def result(checked_at, healthy=True, latency=20.0, loss=0.0, firmware="1.0"):
    return routerwatch.CheckResult(
        checked_at=checked_at,
        gateway_ok=healthy,
        internet_ok=healthy,
        dns_ok=healthy,
        https_ok=healthy,
        avg_latency_ms=latency,
        packet_loss_percent=loss,
        ethernet_operstate="up",
        ethernet_speed_mbps=1000,
        ethernet_duplex="full",
        wifi_rssi_dbm=None,
        wifi_tx_bitrate=None,
        default_gateway="192.168.1.1",
        public_ip=None,
        router_model="router",
        router_firmware_version=firmware,
        router_serial_number=None,
        router_internet_status=None,
        router_cloud_status=None,
        router_connected_pods=None,
        notes=[] if healthy else ["internet ping failed"],
    )


class WeeklyReportTest(unittest.TestCase):
    def test_report_includes_weekly_incidents_and_lifetime_trends(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "routerwatch.sqlite"
            routerwatch.init_db(db_path)
            routerwatch.save_check(
                db_path, result("2026-06-27T10:00:00+00:00", latency=10.0)
            )
            routerwatch.save_check(
                db_path, result("2026-07-04T10:00:00+00:00", latency=20.0)
            )
            routerwatch.save_check(
                db_path,
                result(
                    "2026-07-04T10:01:00+00:00",
                    healthy=False,
                    latency=400.0,
                    loss=100.0,
                ),
            )
            routerwatch.save_check(
                db_path,
                result("2026-07-04T10:03:00+00:00", firmware="2.0"),
            )
            now = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)

            text, html = routerwatch.weekly_report_content(
                {"monitor": {"display_timezone": "America/New_York"}},
                db_path,
                now,
            )

            self.assertIn("Uptime: 66.667%", text)
            self.assertIn("worst 400.00 ms", text)
            self.assertIn("Outage:", text)
            self.assertIn("2m 0s", text)
            self.assertIn("1.0 -> 2.0", text)
            self.assertIn("ALL-TIME TREND", text)
            self.assertIn("Most common start day: Saturday", text)
            self.assertIn("RouterWatch weekly health report", html)


if __name__ == "__main__":
    unittest.main()
