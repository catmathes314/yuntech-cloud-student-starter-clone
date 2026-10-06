"""Offline checks for W5 PostgreSQL-backed persistence and idempotency."""
import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w05_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class FakeDatabase:
    rows = {}
    calls = []


class FakeCursor:
    def __init__(self):
        self.row = None
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, statement, params=None):
        FakeDatabase.calls.append((statement, params))
        if statement.startswith("CREATE TABLE"):
            return
        if statement.startswith("INSERT INTO events"):
            event_id, device_id, observed_at, event_type, note = params
            if event_id in FakeDatabase.rows:
                self.row = None
                return
            received_at = datetime.now(timezone.utc)
            row = (
                event_id,
                device_id,
                datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
                event_type,
                note,
                received_at,
            )
            FakeDatabase.rows[event_id] = row
            self.row = row
            return
        if "FROM events WHERE event_id = %s" in statement:
            self.row = FakeDatabase.rows.get(params[0])
            return
        if "FROM events ORDER BY" in statement:
            limit = params[0]
            ordered = sorted(
                FakeDatabase.rows.values(),
                key=lambda item: (item[5], item[0]),
                reverse=True,
            )
            self.rows = ordered[:limit]
            return
        raise AssertionError("unexpected SQL statement")

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def cursor(self):
        return FakeCursor()


class FakePsycopg2(types.ModuleType):
    class Error(Exception):
        pass

    def connect(self, **kwargs):
        self.connection_options = kwargs
        return FakeConnection()


class PostgresEventApi(unittest.TestCase):
    def setUp(self):
        FakeDatabase.rows = {}
        FakeDatabase.calls = []
        self.driver = FakePsycopg2("psycopg2")
        self.driver.Error = FakePsycopg2.Error
        self.directory = tempfile.TemporaryDirectory()
        self.version_file = Path(self.directory.name) / "version"
        self.version_file.write_text("b" * 40, encoding="utf-8")
        self.environment = patch.dict(os.environ, {
            "REPORTER_TOKEN": "synthetic-reporter-token",
            "OPERATOR_TOKEN": "synthetic-operator-token",
            "DB_HOST": "db.example.invalid",
            "DB_PORT": "5432",
            "DB_NAME": "inspection",
            "DB_USER": "inspection",
            "DB_PASSWORD": "synthetic-database-password",
        })
        self.modules = patch.dict(sys.modules, {"psycopg2": self.driver})
        self.environment.start()
        self.modules.start()
        self.start_server()

    def start_server(self):
        self.server = service.make_server(self.version_file, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def tearDown(self):
        self.stop_server()
        self.modules.stop()
        self.environment.stop()
        self.directory.cleanup()

    def request(self, method, path, body=None, token=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            response = urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def event(self, note="same event"):
        return {
            "event_id": "group7-1-w05-0001",
            "device_id": "g7-device-01",
            "observed_at": "2026-10-06T13:00:00Z",
            "type": "test",
            "note": note,
        }

    def test_health_reports_database_configuration_without_exposing_secrets(self):
        status, response = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(response["db_configured"])
        self.assertNotIn("DB_PASSWORD", json.dumps(response))
        self.request("POST", "/events", self.event(), "synthetic-reporter-token")
        self.assertEqual(self.driver.connection_options["sslmode"], "verify-full")
        self.assertEqual(
            self.driver.connection_options["sslrootcert"],
            "/etc/inspection/rds-ca.pem",
        )

    def test_duplicate_content_is_idempotent_and_conflicts_are_rejected(self):
        event = self.event()
        status, created = self.request(
            "POST", "/events", event, "synthetic-reporter-token"
        )
        self.assertEqual(status, 201)
        self.assertIn("received_at", created)

        status, duplicate = self.request(
            "POST", "/events", event, "synthetic-reporter-token"
        )
        self.assertEqual(status, 200)
        self.assertEqual(duplicate, created)

        status, conflict = self.request(
            "POST", "/events", self.event("different"), "synthetic-reporter-token"
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict, {"error": "event_id_conflict", "field": "event_id"})

        status, events = self.request("GET", "/events", token="synthetic-operator-token")
        self.assertEqual(status, 200)
        self.assertEqual(len(events), 1)

    def test_event_survives_service_restart(self):
        event = self.event()
        status, _ = self.request("POST", "/events", event, "synthetic-reporter-token")
        self.assertEqual(status, 201)
        self.stop_server()
        self.start_server()

        status, result = self.request(
            "GET", "/events/" + event["event_id"], token="synthetic-operator-token"
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["event_id"], event["event_id"])

    def test_sql_values_are_passed_as_parameters(self):
        status, _ = self.request(
            "POST", "/events", self.event(), "synthetic-reporter-token"
        )
        self.assertEqual(status, 201)
        insert = next(
            (sql, params) for sql, params in FakeDatabase.calls
            if sql.startswith("INSERT INTO events")
        )
        self.assertIn("%s", insert[0])
        self.assertEqual(insert[1][0], "group7-1-w05-0001")
        self.assertNotIn("group7-1-w05-0001", insert[0])


if __name__ == "__main__":
    unittest.main()
