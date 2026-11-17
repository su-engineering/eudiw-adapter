"""Verifies the shared vector, which the adapter's own signer reproduces (WebhookVectorTest in the service)."""

import base64
import json
import unittest
from pathlib import Path

from server import SeenWebhooks, WebhookError, verify_webhook

VECTOR = json.loads((Path(__file__).resolve().parent.parent / "shared" / "webhook-vector.json").read_text())
BODY = VECTOR["body"].encode()
AT = int(VECTOR["headers"]["webhook-timestamp"])


class WebhookTest(unittest.TestCase):
    def test_accepts_what_the_adapter_signs_with_either_secret(self):
        self.assertEqual(verify_webhook(BODY, VECTOR["headers"], [VECTOR["secret"]], AT)["data"]["status"], "verified")
        self.assertEqual(verify_webhook(BODY, VECTOR["headers"], [VECTOR["previous_secret"]], AT)["data"]["status"], "verified")

    def test_rejects_tampering_wrong_secret_old_timestamp_and_missing_headers(self):
        secrets = [VECTOR["secret"]]
        with self.assertRaises(WebhookError):
            verify_webhook(VECTOR["body"].replace("verified", "rejected").encode(), VECTOR["headers"], secrets, AT)
        with self.assertRaises(WebhookError):
            verify_webhook(BODY, VECTOR["headers"], ["whsec_" + base64.b64encode(bytes(32)).decode()], AT)
        with self.assertRaises(WebhookError):
            verify_webhook(BODY, VECTOR["headers"], secrets, AT + 301)
        with self.assertRaises(WebhookError):
            verify_webhook(BODY, {**VECTOR["headers"], "webhook-signature": None}, secrets, AT)
        with self.assertRaises(WebhookError):
            verify_webhook(BODY, {**VECTOR["headers"], "webhook-id": "msg_" + "f" * 32}, secrets, AT)


class SeenWebhooksTest(unittest.TestCase):
    def test_a_replayed_webhook_id_is_recognised_until_it_ages_out(self):
        seen = SeenWebhooks(ttl=600, limit=3)
        t = 1_800_000_000
        self.assertTrue(seen.first_time("msg_1", t))
        self.assertFalse(seen.first_time("msg_1", t + 1))
        self.assertTrue(seen.first_time("msg_2", t + 2))
        self.assertTrue(seen.first_time("msg_1", t + 601))
        for i in range(10):
            seen.first_time(f"flood_{i}", t + 602)
        self.assertLessEqual(len(seen.seen), 3)


if __name__ == "__main__":
    unittest.main()
