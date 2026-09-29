#!/usr/bin/env python3
"""Run the seven W4 HTTP checks without printing bearer tokens."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
EXPECTED_STATUSES = (201, 401, 403, 400, 409, 403, 200)
MAX_RESPONSE_BYTES = 128 * 1024


class MatrixError(Exception):
    pass


def load_tokens(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise MatrixError("Token file is missing or is a symlink.")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise MatrixError("Token file permissions must be 600.")
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or key in values:
                raise ValueError
            values[key] = value
        reporter = values["REPORTER_TOKEN"].encode("ascii")
        operator = values["OPERATOR_TOKEN"].encode("ascii")
    except (KeyError, UnicodeEncodeError, OSError, ValueError):
        raise MatrixError("Token file must contain two distinct ASCII tokens.") from None
    if not reporter or not operator or reporter == operator:
        raise MatrixError("Token file must contain two distinct non-empty tokens.")
    return reporter.decode("ascii"), operator.decode("ascii")


def request(base_url, method, path, token=None, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = Request(base_url.rstrip("/") + path, data=data, headers=headers, method=method)
    try:
        response = urlopen(req, timeout=8)
    except HTTPError as error:
        response = error
    except (URLError, TimeoutError, OSError) as error:
        raise MatrixError("HTTP request failed: " + type(error).__name__) from None
    with response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MatrixError("HTTP response exceeds the safe reporting limit.")
        try:
            body_value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_value = {"raw": raw.decode("utf-8", errors="replace")}
        return response.status, body_value


def run_matrix(base_url, reporter_token, operator_token, event_id=None):
    status, health = request(base_url, "GET", "/health")
    if status != 200 or not isinstance(health, dict):
        raise MatrixError("Health preflight failed.")
    version = health.get("version", "")
    if not re.fullmatch(r"[0-9a-f]{40}", version) or health.get("auth_configured") is not True:
        raise MatrixError("Health preflight did not confirm version and auth configuration.")

    event = json.loads((FIXTURES / "event-valid.json").read_text(encoding="utf-8"))
    if event_id is None:
        event_id = event["event_id"].rsplit("-", 1)[0] + "-" + str(time.time_ns())
    event["event_id"] = event_id
    missing_timezone = json.loads(
        (FIXTURES / "event-missing-timezone.json").read_text(encoding="utf-8")
    )
    missing_timezone["event_id"] = event_id + "-tz"
    operator_event = dict(event, event_id=event_id + "-operator")

    cases = [
        ("POST", "/events", reporter_token, event),
        ("POST", "/events", None, event),
        ("POST", "/events", operator_token, operator_event),
        ("POST", "/events", reporter_token, missing_timezone),
        ("POST", "/events", reporter_token, event),
        ("GET", "/events", reporter_token, None),
        ("GET", "/events", operator_token, None),
    ]
    rows = []
    for number, (method, path, token, body) in enumerate(cases, start=1):
        status, response_body = request(base_url, method, path, token, body)
        expected = EXPECTED_STATUSES[number - 1]
        if status != expected:
            raise MatrixError(f"Matrix row {number}: expected HTTP {expected}, got {status}.")
        rows.append({"row": number, "status": status, "body": response_body})

    if rows[0]["body"].get("event_id") != event_id:
        raise MatrixError("Matrix row 1 did not return the submitted event.")
    if rows[3]["body"].get("field") != "observed_at":
        raise MatrixError("Matrix row 4 did not identify observed_at.")
    if not isinstance(rows[6]["body"], list) or not any(
        isinstance(item, dict) and item.get("event_id") == event_id
        for item in rows[6]["body"]
    ):
        raise MatrixError("Matrix row 7 did not list the event from row 1.")
    return version, rows


def render_report(version, rows, tokens=()):
    lines = ["version=" + version]
    for row in rows:
        body = json.dumps(row["body"], ensure_ascii=False, separators=(",", ":"))
        for token in tokens:
            body = body.replace(token, "[REDACTED]")
        lines.append(f"{row['row']} {row['status']} {body}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="Current inspection service URL, e.g. http://host")
    parser.add_argument("--token-file", type=Path, default=ROOT / ".local/app.env")
    args = parser.parse_args(argv)
    try:
        reporter, operator = load_tokens(args.token_file)
        version, rows = run_matrix(args.base_url, reporter, operator)
        print(render_report(version, rows, (reporter, operator)))
    except MatrixError as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
