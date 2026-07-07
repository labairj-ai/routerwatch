import tempfile
import unittest
from pathlib import Path

from routerwatch import routerwatch


def result(checked_at, healthy=True):
    return routerwatch.CheckResult(
        checked_at=checked_at,
        gateway_ok=healthy,
        internet_ok=healthy,
        dns_ok=healthy,
        https_ok=healthy,
        avg_latency_ms=18.5,
        packet_loss_percent=0.0 if healthy else 100.0,
        ethernet_operstate="up",
        ethernet_speed_mbps=1000,
        ethernet_duplex="full",
        wifi_rssi_dbm=-55,
        wifi_tx_bitrate="72.2 MBit/s",
        default_gateway="192.168.1.1",
        public_ip="203.0.113.10",
        router_model="SAX2V1R",
        router_firmware_version="1.0",
        router_serial_number="serial",
        router_internet_status="Connected",
        router_cloud_status="Connected",
        router_connected_pods="N/A",
        notes=[] if healthy else ["internet ping failed"],
    )


class DashboardTest(unittest.TestCase):
    def test_payload_includes_latest_metrics_and_recent_history(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "routerwatch.sqlite"
            routerwatch.init_db(db_path)
            routerwatch.save_check(
                db_path, result("2026-07-06T12:00:00+00:00", healthy=False)
            )
            routerwatch.save_check(
                db_path, result("2026-07-06T12:01:00+00:00", healthy=True)
            )
            routerwatch.save_check(
                db_path, result("2026-07-06T13:00:00+00:00", healthy=False)
            )
            routerwatch.save_check(
                db_path, result("2026-07-06T13:01:00+00:00", healthy=True)
            )

            payload = routerwatch.dashboard_payload(
                {
                    "router": {"name": "Test Router"},
                    "monitor": {
                        "display_timezone": "America/New_York",
                        "latency_alert_ms": 250,
                        "packet_loss_alert_percent": 50,
                    },
                },
                db_path,
            )

            self.assertEqual("Test Router", payload["router_name"])
            self.assertEqual("healthy", payload["latest"]["status"])
            self.assertEqual("SAX2V1R", payload["latest"]["router_model"])
            self.assertEqual(4, payload["weekly"]["checks"])
            self.assertEqual(4, len(payload["timeline"]))
            self.assertEqual(4, len(payload["recent_checks"]))
            self.assertEqual(2, payload["lifetime_episode_count"])
            self.assertEqual(250, payload["thresholds"]["latency_alert_ms"])
            self.assertEqual(50, payload["thresholds"]["packet_loss_alert_percent"])
            self.assertEqual(2, len(payload["weekly_episodes"]))
            self.assertIn("09:00 AM", payload["weekly_episodes"][0]["start"])
            self.assertIn("08:00 AM", payload["weekly_episodes"][1]["start"])


if __name__ == "__main__":
    unittest.main()
