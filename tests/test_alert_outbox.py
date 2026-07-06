import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from routerwatch import routerwatch


class AlertOutboxTest(unittest.TestCase):
    def test_failed_alert_is_queued_once_and_sent_after_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "routerwatch.sqlite"
            routerwatch.init_db(db_path)

            routerwatch.queue_alert(db_path, "subject", "text", "<p>html</p>", "offline")
            routerwatch.queue_alert(db_path, "duplicate", "text", "<p>html</p>", "offline")
            pending = routerwatch.pending_alert(db_path)
            self.assertEqual(pending["subject"], "subject")
            self.assertEqual(pending["attempts"], 1)

            config = {"storage": {"log_path": "routerwatch.log"}}
            offline = SimpleNamespace(internet_ok=False, dns_ok=False, https_ok=False)
            online = SimpleNamespace(internet_ok=True, dns_ok=True, https_ok=True)

            with patch.object(routerwatch, "send_gmail") as send:
                routerwatch.maybe_send_pending_alert(
                    config, Path(directory) / "config.json", db_path, offline
                )
                send.assert_not_called()

                routerwatch.maybe_send_pending_alert(
                    config, Path(directory) / "config.json", db_path, online
                )
                send.assert_called_once()

            self.assertIsNone(routerwatch.pending_alert(db_path))
            self.assertEqual(
                routerwatch.last_event(db_path, "alert_sent")["details"],
                "queued degradation alert delivered",
            )


if __name__ == "__main__":
    unittest.main()
