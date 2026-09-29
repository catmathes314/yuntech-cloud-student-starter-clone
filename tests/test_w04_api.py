"""Offline public-contract checks for the W4 event API and display page."""
import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
FIXTURES = ROOT / "tests/fixtures"
REPORTER_TOKEN = "synthetic-reporter-token"
OPERATOR_TOKEN = "synthetic-operator-token"


class EventApiContract(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        version_file = Path(self.temp_dir.name) / "version"
        version_file.write_text("a" * 40, encoding="utf-8")
        self.environment = patch.dict(os.environ, {
            "REPORTER_TOKEN": REPORTER_TOKEN,
            "OPERATOR_TOKEN": OPERATOR_TOKEN,
        })
        self.environment.start()
        self.server = service.make_server(version_file, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.environment.stop()
        self.temp_dir.cleanup()

    def fixture(self, name):
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def request(self, method, path, body=None, token=None, content_type="application/json"):
        if isinstance(body, bytes):
            data = body
        elif body is None:
            data = None
        else:
            data = json.dumps(body).encode("utf-8")
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            try:
                result = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                result = {"raw": raw.decode("utf-8", errors="replace")}
            return response.status, result

    def assert_error(self, result, field):
        self.assertEqual(set(result), {"error", "field"})
        self.assertEqual(result["field"], field)

    def test_health_is_public_and_reports_auth_configuration(self):
        status, result = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["service"], "inspection")
        self.assertEqual(result["version"], "a" * 40)
        self.assertIs(result["auth_configured"], True)

    def test_fixtures_create_and_reject_events(self):
        status, created = self.request(
            "POST", "/events", self.fixture("event-valid.json"), REPORTER_TOKEN
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["event_id"], "group7-1-0001")
        received_at = datetime.fromisoformat(created["received_at"].replace("Z", "+00:00"))
        self.assertEqual(received_at.utcoffset(), timezone.utc.utcoffset(received_at))

        status, result = self.request(
            "POST", "/events", self.fixture("event-missing-timezone.json"), REPORTER_TOKEN
        )
        self.assertEqual(status, 400)
        self.assert_error(result, "observed_at")

        status, result = self.request(
            "POST", "/events", self.fixture("event-extra-field.json"), REPORTER_TOKEN
        )
        self.assertEqual(status, 400)
        self.assert_error(result, "unexpected")

    def test_authentication_precedes_body_validation_and_roles_are_separate(self):
        status, result = self.request("POST", "/events", b"not-json", token=None)
        self.assertEqual(status, 401)
        self.assert_error(result, "authorization")

        status, result = self.request("GET", "/events", token="reportér-token")
        self.assertEqual(status, 401)
        self.assert_error(result, "authorization")

        status, result = self.request(
            "POST", "/events", self.fixture("event-valid.json"), OPERATOR_TOKEN
        )
        self.assertEqual(status, 403)
        self.assert_error(result, "authorization")

        status, result = self.request("GET", "/events", token=REPORTER_TOKEN)
        self.assertEqual(status, 403)
        self.assert_error(result, "authorization")

    def test_duplicate_and_operator_event_queries(self):
        event = self.fixture("event-valid.json")
        status, created = self.request("POST", "/events", event, REPORTER_TOKEN)
        self.assertEqual(status, 201)

        status, result = self.request("POST", "/events", event, REPORTER_TOKEN)
        self.assertEqual(status, 409)
        self.assert_error(result, "event_id")

        status, events = self.request("GET", "/events", token=OPERATOR_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual([item["event_id"] for item in events], [created["event_id"]])

        status, result = self.request(
            "GET", "/events/" + created["event_id"], token=OPERATOR_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["event_id"], created["event_id"])

        status, result = self.request("GET", "/events/not-found", token=OPERATOR_TOKEN)
        self.assertEqual(status, 404)
        self.assert_error(result, "event_id")

    def test_operator_list_returns_only_latest_50_events(self):
        event = self.fixture("event-valid.json")
        for index in range(51):
            event["event_id"] = f"group7-1-{index:04d}"
            status, _ = self.request("POST", "/events", event, REPORTER_TOKEN)
            self.assertEqual(status, 201)

        status, events = self.request("GET", "/events", token=OPERATOR_TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 50)
        self.assertEqual(events[0]["event_id"], "group7-1-0050")
        self.assertEqual(events[-1]["event_id"], "group7-1-0001")

    def test_content_type_and_body_size_are_bounded(self):
        status, result = self.request(
            "POST", "/events", self.fixture("event-valid.json"), REPORTER_TOKEN,
            content_type="text/plain",
        )
        self.assertEqual(status, 400)
        self.assert_error(result, "content_type")

        status, result = self.request("POST", "/events", b" " * 4097, REPORTER_TOKEN)
        self.assertEqual(status, 400)
        self.assert_error(result, "body")

    def test_non_string_event_type_is_rejected(self):
        event = self.fixture("event-valid.json")
        event["type"] = []
        status, result = self.request("POST", "/events", event, REPORTER_TOKEN)
        self.assertEqual(status, 400)
        self.assert_error(result, "type")

    def test_display_page_uses_text_content_without_persisting_token(self):
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        source = page["raw"]
        self.assertIn("textContent", source)
        self.assertNotIn("innerHTML", source)
        self.assertNotIn("localStorage", source)
        self.assertNotIn("sessionStorage", source)
        self.assertNotIn("?token=", source)
        self.assertNotIn(REPORTER_TOKEN, source)
        self.assertNotIn(OPERATOR_TOKEN, source)


if __name__ == "__main__":
    unittest.main()
