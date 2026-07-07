import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
    def test_parse_ip_neigh_keeps_observed_ipv4_devices(self):
        devices = routerwatch.parse_ip_neigh(
            "\n".join(
                [
                    "192.168.1.1 dev eth0 lladdr 2e:67:be:3b:9e:b3 REACHABLE",
                    "192.168.4.21 dev wlan0 lladdr 7c:61:66:5b:32:a3 STALE",
                    "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE",
                    "192.168.1.80 dev eth0 FAILED",
                ]
            )
        )

        self.assertEqual(
            [
                {
                    "ip": "192.168.1.1",
                    "interface": "eth0",
                    "mac": "2e:67:be:3b:9e:b3",
                    "state": "REACHABLE",
                },
                {
                    "ip": "192.168.4.21",
                    "interface": "wlan0",
                    "mac": "7c:61:66:5b:32:a3",
                    "state": "STALE",
                },
            ],
            devices,
        )

    def test_scan_targets_respects_configured_subnets_and_host_cap(self):
        config = {
            "devices": {
                "scan_subnets": ["192.168.1.0/30", "10.0.0.0/24"],
                "scan_max_hosts": 10,
            }
        }

        self.assertEqual(
            ["192.168.1.1", "192.168.1.2"],
            routerwatch.scan_targets(config),
        )

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

            config = {
                "router": {"name": "Test Router"},
                "monitor": {
                    "display_timezone": "America/New_York",
                    "latency_alert_ms": 250,
                    "packet_loss_alert_percent": 50,
                },
                "devices": {
                    "names": {"2e:67:be:3b:9e:b3": "Spectrum Router"},
                    "types": {"2e:67:be:3b:9e:b3": "router"},
                    "owners": {"2e:67:be:3b:9e:b3": "ISP"},
                    "locations": {"2e:67:be:3b:9e:b3": "Network closet"},
                    "vendors": {"2e:67:be:3b:9e:b3": "Spectrum"},
                },
            }
            with patch.object(
                routerwatch,
                "inventory_devices",
                return_value=[
                    {
                        "ip": "192.168.1.1",
                        "interface": "eth0",
                        "mac": "2e:67:be:3b:9e:b3",
                        "state": "REACHABLE",
                        "hostname": "SAX2V1R.lan",
                    },
                ],
            ):
                payload = routerwatch.dashboard_payload(config, db_path)

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
            self.assertEqual(1, len(payload["devices"]))
            self.assertEqual("Spectrum Router", payload["devices"][0]["friendly_name"])
            self.assertEqual("router", payload["devices"][0]["device_type"])
            self.assertEqual("ISP", payload["devices"][0]["owner"])
            self.assertEqual("Network closet", payload["devices"][0]["location"])
            self.assertEqual("Spectrum", payload["devices"][0]["vendor"])
            self.assertEqual(1, payload["devices"][0]["seen_count"])
            self.assertEqual("192.168.1.1", payload["devices"][0]["ip_history_summary"])

    def test_device_inventory_updates_seen_count_and_ip_history(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "routerwatch.sqlite"
            routerwatch.init_db(db_path)
            config = {
                "monitor": {"display_timezone": "America/New_York"},
                "devices": {
                    "recent_minutes": 999999,
                    "names": {"192.168.4.21": "Kitchen Display"},
                },
            }
            device = {
                "ip": "192.168.4.21",
                "interface": "wlan0",
                "mac": "ba:1e:49:4f:82:a5",
                "state": "STALE",
                "hostname": "roku-bedroom",
            }

            routerwatch.update_device_inventory(
                db_path, config, [device], "2026-07-06T12:00:00+00:00"
            )
            device["ip"] = "192.168.4.22"
            routerwatch.update_device_inventory(
                db_path, config, [device], "2026-07-06T12:01:00+00:00"
            )

            inventory = routerwatch.device_inventory(config, db_path)
            self.assertEqual(1, len(inventory))
            self.assertEqual("Kitchen Display", inventory[0]["friendly_name"])
            self.assertEqual("streaming_device", inventory[0]["device_type"])
            self.assertEqual(2, inventory[0]["seen_count"])
            self.assertEqual("recent", inventory[0]["status"])
            self.assertTrue(inventory[0]["locally_administered"])
            self.assertEqual(2, len(inventory[0]["ip_history"]))
            self.assertIn("192.168.4.22", inventory[0]["ip_history_summary"])
            self.assertIn("192.168.4.21", inventory[0]["ip_history_summary"])


if __name__ == "__main__":
    unittest.main()
