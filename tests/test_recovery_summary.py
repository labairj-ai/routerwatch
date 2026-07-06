import tempfile
import unittest
from pathlib import Path

from routerwatch import routerwatch


def result(checked_at, healthy, latency, loss):
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
        router_model=None,
        router_firmware_version=None,
        router_serial_number=None,
        router_internet_status=None,
        router_cloud_status=None,
        router_connected_pods=None,
        notes=[] if healthy else ["internet ping failed"],
    )


class RecoverySummaryTest(unittest.TestCase):
    def test_summarizes_contiguous_failed_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "routerwatch.sqlite"
            routerwatch.init_db(db_path)
            routerwatch.save_check(
                db_path, result("2026-07-06T12:00:00+00:00", True, 12.0, 0.0)
            )
            routerwatch.save_check(
                db_path, result("2026-07-06T12:01:00+00:00", False, 300.0, 50.0)
            )
            routerwatch.save_check(
                db_path, result("2026-07-06T12:02:00+00:00", False, None, 100.0)
            )
            recovered = result("2026-07-06T12:03:30+00:00", True, 15.0, 0.0)
            routerwatch.save_check(db_path, recovered)

            text, html = routerwatch.recovery_outage_summary(
                {"monitor": {"display_timezone": "America/New_York"}},
                db_path,
                recovered,
            )

            self.assertIn("Duration: 2m 30s", text)
            self.assertIn("Failed checks: 2", text)
            self.assertIn("Worst latency: 300.000 ms", text)
            self.assertIn("Worst packet loss: 100.0%", text)
            self.assertIn("Outage summary", html)


if __name__ == "__main__":
    unittest.main()
