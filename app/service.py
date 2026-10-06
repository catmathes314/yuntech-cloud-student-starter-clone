#!/usr/bin/env python3
"""W3 supplied inspection-service prototype; extend routes in later Sprints."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import logging
import os
from pathlib import Path
import re
import threading
from urllib.parse import unquote, urlsplit


DISPLAY_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Inspection events</title>
  <style>
    body { font: 16px system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; padding: 0 1rem; }
    input, button { font: inherit; padding: .5rem; }
    li { border-bottom: 1px solid #ccc; padding: .75rem 0; }
  </style>
</head>
<body>
  <h1>Inspection events</h1>
  <form id="token-form">
    <label for="operator-token">Operator token</label>
    <input id="operator-token" type="password" autocomplete="off" required>
    <button type="submit">Load events</button>
  </form>
  <p id="message" role="status"></p>
  <ol id="events"></ol>
  <script>
    const form = document.querySelector('#token-form');
    const tokenInput = document.querySelector('#operator-token');
    const message = document.querySelector('#message');
    const eventList = document.querySelector('#events');
    let operatorToken = '';
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      operatorToken = tokenInput.value;
      tokenInput.value = '';
      message.textContent = 'Loading…';
      eventList.replaceChildren();
      try {
        const response = await fetch('/events', {
          headers: { 'Authorization': 'Bearer ' + operatorToken }
        });
        if (!response.ok) {
          message.textContent = 'Unable to load events (' + response.status + ').';
          return;
        }
        const events = await response.json();
        for (const item of events) {
          const row = document.createElement('li');
          const summary = document.createElement('p');
          summary.textContent = item.event_id + ' | ' + item.device_id + ' | ' + item.type;
          row.appendChild(summary);
          const note = document.createElement('p');
          note.textContent = item.note || '';
          row.appendChild(note);
          const times = document.createElement('p');
          times.textContent = item.observed_at + ' | received ' + item.received_at;
          row.appendChild(times);
          eventList.appendChild(row);
        }
        message.textContent = events.length + ' event(s).';
      } catch {
        message.textContent = 'Unable to reach the inspection service.';
      }
    });
  </script>
</body>
</html>
"""

LOGGER = logging.getLogger(__name__)


def make_server(version_file, port=8080):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        reporter_token = os.environ.get("REPORTER_TOKEN", "").encode("ascii")
        operator_token = os.environ.get("OPERATOR_TOKEN", "").encode("ascii")
    except UnicodeEncodeError:
        reporter_token = operator_token = b""
    auth_configured = bool(
        reporter_token and operator_token and not hmac.compare_digest(reporter_token, operator_token)
    )
    db_host = os.environ.get("DB_HOST", "")
    db_name = os.environ.get("DB_NAME", "")
    db_user = os.environ.get("DB_USER", "")
    db_password = os.environ.get("DB_PASSWORD", "")
    db_port_text = os.environ.get("DB_PORT", "5432")
    try:
        db_port = int(db_port_text)
    except ValueError:
        db_port = 0
    db_configured = bool(
        db_host and db_name and db_user and db_password and 1 <= db_port <= 65535
    )
    events = {}
    events_lock = threading.Lock()

    def event_from_row(row):
        event = dict(zip(
            ("event_id", "device_id", "observed_at", "type", "note", "received_at"),
            row,
        ))
        for field in ("observed_at", "received_at"):
            value = event[field]
            if isinstance(value, datetime):
                event[field] = value.isoformat().replace("+00:00", "Z")
        return event

    def ensure_events_table(cursor):
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "event_id TEXT PRIMARY KEY, "
            "device_id TEXT NOT NULL, "
            "observed_at TIMESTAMPTZ NOT NULL, "
            "event_type TEXT NOT NULL, "
            "note TEXT, "
            "received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def send_json(self, status, body):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def send_error_json(self, status, error, field):
            self.send_json(status, {"error": error, "field": field})

        def postgres_driver(self):
            try:
                import psycopg2
            except ImportError:
                LOGGER.error("PostgreSQL driver is unavailable.")
                self.send_error_json(503, "database_unavailable", "database")
                return None
            return psycopg2

        def postgres_connection(self, psycopg2):
            return psycopg2.connect(
                host=db_host,
                port=db_port,
                dbname=db_name,
                user=db_user,
                password=db_password,
                sslmode="verify-full",
                sslrootcert="/etc/inspection/rds-ca.pem",
                connect_timeout=5,
            )

        def report_database_error(self, error):
            LOGGER.warning("PostgreSQL operation failed (%s).", type(error).__name__)
            self.send_error_json(503, "database_unavailable", "database")

        def send_page(self):
            data = DISPLAY_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def authorize(self, expected_role):
            if not auth_configured:
                self.send_error_json(503, "authentication_not_configured", "authorization")
                return False
            header = self.headers.get("Authorization", "")
            try:
                token = (header[7:] if header.startswith("Bearer ") else "").encode("ascii")
            except UnicodeEncodeError:
                self.send_error_json(401, "unauthorized", "authorization")
                return False
            is_reporter = hmac.compare_digest(token, reporter_token)
            is_operator = hmac.compare_digest(token, operator_token)
            if not (is_reporter or is_operator):
                self.send_error_json(401, "unauthorized", "authorization")
                return False
            role = "reporter" if is_reporter else "operator"
            if role != expected_role:
                self.send_error_json(403, "forbidden", "authorization")
                return False
            return True

        def read_event(self):
            if self.headers.get_content_type() != "application/json":
                self.send_error_json(400, "content_type_must_be_application_json", "content_type")
                return None
            length = self.headers.get("Content-Length", "")
            if not length.isdecimal():
                self.send_error_json(400, "invalid_content_length", "body")
                return None
            size = int(length)
            if size > 4096:
                self.send_error_json(400, "body_too_large", "body")
                return None
            raw = self.rfile.read(size)
            if len(raw) != size:
                self.send_error_json(400, "incomplete_body", "body")
                return None
            try:
                body = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error_json(400, "invalid_json", "body")
                return None
            if not isinstance(body, dict):
                self.send_error_json(400, "body_must_be_an_object", "body")
                return None
            return body

        def validate_event(self, body):
            allowed = {"event_id", "device_id", "observed_at", "type", "note"}
            required = ("event_id", "device_id", "observed_at", "type")
            extra = sorted(set(body) - allowed)
            if extra:
                self.send_error_json(400, "unexpected_field", extra[0])
                return False
            for field in required:
                if field not in body:
                    self.send_error_json(400, "missing_field", field)
                    return False
            for field, limit in (("event_id", 64), ("device_id", 32)):
                value = body[field]
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1," + str(limit) + r"}", value):
                    self.send_error_json(400, "invalid_identifier", field)
                    return False
            observed_at = body["observed_at"]
            if not isinstance(observed_at, str):
                self.send_error_json(400, "invalid_timestamp", "observed_at")
                return False
            try:
                parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            except ValueError:
                self.send_error_json(400, "invalid_timestamp", "observed_at")
                return False
            if parsed.utcoffset() is None:
                self.send_error_json(400, "timestamp_timezone_required", "observed_at")
                return False
            if not isinstance(body["type"], str) or body["type"] not in {"status", "anomaly", "test"}:
                self.send_error_json(400, "invalid_type", "type")
                return False
            if "note" in body and (not isinstance(body["note"], str) or len(body["note"]) > 200):
                self.send_error_json(400, "invalid_note", "note")
                return False
            return True

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                self.send_json(200, {
                    "status": "ok",
                    "service": "inspection",
                    "version": version,
                    "started_at": started,
                    "auth_configured": auth_configured,
                    "db_configured": db_configured,
                })
                return
            if path == "/":
                self.send_page()
                return
            if path == "/events":
                if not self.authorize("operator"):
                    return
                if db_configured:
                    psycopg2 = self.postgres_driver()
                    if psycopg2 is None:
                        return
                    try:
                        with self.postgres_connection(psycopg2) as connection:
                            with connection.cursor() as cursor:
                                ensure_events_table(cursor)
                                cursor.execute(
                                    "SELECT event_id, device_id, observed_at, event_type, note, received_at "
                                    "FROM events ORDER BY received_at DESC, event_id DESC LIMIT %s",
                                    (50,),
                                )
                                latest = [event_from_row(row) for row in cursor.fetchall()]
                    except psycopg2.Error as error:
                        self.report_database_error(error)
                        return
                else:
                    with events_lock:
                        latest = list(reversed(list(events.values())))[:50]
                self.send_json(200, latest)
                return
            if path.startswith("/events/"):
                if not self.authorize("operator"):
                    return
                event_id = unquote(path[len("/events/"):])
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event_id):
                    self.send_error_json(404, "not_found", "event_id")
                    return
                if db_configured:
                    psycopg2 = self.postgres_driver()
                    if psycopg2 is None:
                        return
                    try:
                        with self.postgres_connection(psycopg2) as connection:
                            with connection.cursor() as cursor:
                                ensure_events_table(cursor)
                                cursor.execute(
                                    "SELECT event_id, device_id, observed_at, event_type, note, received_at "
                                    "FROM events WHERE event_id = %s",
                                    (event_id,),
                                )
                                row = cursor.fetchone()
                                item = event_from_row(row) if row is not None else None
                    except psycopg2.Error as error:
                        self.report_database_error(error)
                        return
                else:
                    with events_lock:
                        item = events.get(event_id)
                if item is None:
                    self.send_error_json(404, "not_found", "event_id")
                    return
                self.send_json(200, item)
                return
            self.send_error_json(404, "not_found", "path")

        def do_POST(self):
            if urlsplit(self.path).path != "/events":
                self.send_error_json(404, "not_found", "path")
                return
            if not self.authorize("reporter"):
                return
            body = self.read_event()
            if body is None or not self.validate_event(body):
                return
            event_id = body["event_id"]
            if db_configured:
                psycopg2 = self.postgres_driver()
                if psycopg2 is None:
                    return
                try:
                    with self.postgres_connection(psycopg2) as connection:
                        with connection.cursor() as cursor:
                            ensure_events_table(cursor)
                            cursor.execute(
                                "INSERT INTO events "
                                "(event_id, device_id, observed_at, event_type, note) "
                                "VALUES (%s, %s, %s, %s, %s) "
                                "ON CONFLICT (event_id) DO NOTHING "
                                "RETURNING event_id, device_id, observed_at, event_type, note, received_at",
                                (
                                    body["event_id"],
                                    body["device_id"],
                                    body["observed_at"],
                                    body["type"],
                                    body.get("note"),
                                ),
                            )
                            row = cursor.fetchone()
                            if row is not None:
                                item = event_from_row(row)
                                status = 201
                            else:
                                cursor.execute(
                                    "SELECT event_id, device_id, observed_at, event_type, note, received_at "
                                    "FROM events WHERE event_id = %s",
                                    (event_id,),
                                )
                                existing_row = cursor.fetchone()
                                if existing_row is None:
                                    self.send_error_json(500, "database_error", "database")
                                    return
                                item = event_from_row(existing_row)
                                existing_time = datetime.fromisoformat(
                                    item["observed_at"].replace("Z", "+00:00")
                                )
                                request_time = datetime.fromisoformat(
                                    body["observed_at"].replace("Z", "+00:00")
                                )
                                identical = (
                                    item["device_id"] == body["device_id"]
                                    and existing_time == request_time
                                    and item["type"] == body["type"]
                                    and item["note"] == body.get("note")
                                )
                                if not identical:
                                    self.send_error_json(409, "event_id_conflict", "event_id")
                                    return
                                status = 200
                except psycopg2.Error as error:
                    self.report_database_error(error)
                    return
                self.send_json(status, item)
                return
            with events_lock:
                if event_id in events:
                    self.send_error_json(409, "duplicate_event_id", "event_id")
                    return
                item = dict(body)
                item["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                events[event_id] = item
            self.send_json(201, item)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
