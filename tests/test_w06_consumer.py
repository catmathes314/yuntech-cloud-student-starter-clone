"""Offline checks for Lab 6 consumer allow-listing and API result classification."""
import importlib.util
import io
from pathlib import Path
import urllib.error
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w06_consumer", ROOT / "app/consumer.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ConsumerAllowList(unittest.TestCase):
    def setUp(self):
        self.allowed = {f"g03-m2-d{number:02d}" for number in range(1, 11)}
        self.event = (
            b'{"event_id":"g03-m2-r1-d01-01",'
            b'"device_id":"g03-m2-d01","observed_at":"2026-10-13T02:00:00Z",'
            b'"type":"status"}'
        )

    def call(self, payload, result):
        output = io.StringIO()
        with patch.object(consumer, "urlopen", return_value=FakeResponse(result)) as request:
            with redirect_stdout(output):
                consumer.forward_event(payload, self.allowed, "synthetic-secret-token")
        return output.getvalue().strip(), request

    def test_required_reporter_token_stays_text_for_http_header(self):
        environment = {
            "IOT_ENDPOINT": "example-ats.iot.us-east-1.amazonaws.com",
            "IOT_TOPIC": "cxe/g03-m2/gw/events",
            "IOT_CLIENT_ID": "consumer-g03-m2",
            "IOT_DEVICE_IDS": ",".join(sorted(self.allowed)),
            "IOT_CA": "/etc/inspection/iot/AmazonRootCA1.pem",
            "IOT_CERT": "/etc/inspection/iot/consumer.cert.pem",
            "IOT_KEY": "/etc/inspection/iot/consumer.private.key",
            "REPORTER_TOKEN": "synthetic-secret-token",
        }
        with patch.dict(consumer.os.environ, environment, clear=True):
            settings, _ = consumer.required_environment()
        self.assertEqual(settings["REPORTER_TOKEN"], "synthetic-secret-token")
        self.assertIsInstance(settings["REPORTER_TOKEN"], str)

    def test_allow_list_is_checked_before_api_request(self):
        payload = self.event.replace(b"g03-m2-d01", b"g03-m2-d99")
        output, request = self.call(payload, 201)
        self.assertEqual(output, "event_id=g03-m2-r1-d01-01 result=rejected")
        request.assert_not_called()

    def test_api_responses_are_classified_without_logging_token(self):
        expected = {201: "created", 200: "duplicate", 409: "rejected", 503: "error"}
        for status, result in expected.items():
            with self.subTest(status=status):
                output, request = self.call(self.event, status)
                self.assertEqual(
                    output,
                    f"event_id=g03-m2-r1-d01-01 result={result}",
                )
                self.assertNotIn("synthetic-secret-token", output)
                request.assert_called_once()

    def test_connection_failure_is_counted_as_error(self):
        output = io.StringIO()
        with patch.object(
            consumer, "urlopen", side_effect=urllib.error.URLError("unavailable")
        ):
            with redirect_stdout(output):
                consumer.forward_event(self.event, self.allowed, "synthetic-secret-token")
        self.assertEqual(output.getvalue().strip(), "event_id=g03-m2-r1-d01-01 result=error")

    def test_invalid_payload_is_rejected_without_api_request(self):
        output, request = self.call(b"not-json", 201)
        self.assertEqual(output, "event_id=unknown result=rejected")
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
