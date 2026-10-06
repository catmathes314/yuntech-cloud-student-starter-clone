#!/usr/bin/env python3
"""Run the five W5 idempotency checks without printing tokens or passwords."""
import json
import re
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE_BYTES = 128 * 1024


class MatrixError(Exception):
    pass


def read_assignments(path, allowed):
    values = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in allowed or key in values:
                raise ValueError
            values[key] = value
    except (OSError, UnicodeError, ValueError):
        raise MatrixError(Path(path).name + " has an invalid format.") from None
    return values


def load_tokens(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise MatrixError("Token file is missing or is a symlink.")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise MatrixError("Token file permissions must be 600.")
    values = read_assignments(path, {"REPORTER_TOKEN", "OPERATOR_TOKEN"})
    try:
        reporter = values["REPORTER_TOKEN"].encode("ascii")
        operator = values["OPERATOR_TOKEN"].encode("ascii")
    except (KeyError, UnicodeEncodeError):
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
    request_value = Request(
        base_url.rstrip("/") + path, data=data, headers=headers, method=method
    )
    try:
        response = urlopen(request_value, timeout=10)
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


def ssh_command(key_path, target, remote_command, input_text=None):
    try:
        result = subprocess.run(
            [
                "ssh", "-i", str(key_path), "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
                target, remote_command,
            ],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MatrixError("SSH operation failed: " + type(error).__name__) from None
    if result.returncode:
        raise MatrixError("SSH operation failed with exit status " + str(result.returncode) + ".")
    return result.stdout.strip()


def run_matrix():
    config = read_assignments(
        ROOT / ".local/config",
        {"GROUP", "OWNER", "SOURCE_CIDR", "REGION", "AMI_ID", "SUBNET_ID",
         "INSTANCE_TYPE", "KEY_NAME", "SG_NAME", "SSH_USER"},
    )
    resources = json.loads((ROOT / ".local/resources.json").read_text(encoding="utf-8"))
    public_ip = resources.get("public_ip")
    if not isinstance(public_ip, str) or not re.fullmatch(r"[0-9.]+", public_ip):
        raise MatrixError("Resource manifest has no valid current EC2 public IP.")
    key_path = Path.home() / ".ssh" / config["KEY_NAME"]
    if key_path.is_symlink() or not key_path.is_file() or stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise MatrixError("SSH private key is missing, unsafe, or not mode 600.")
    reporter_token, operator_token = load_tokens(ROOT / ".local/app.env")
    base_url = "http://" + public_ip

    status, health = request(base_url, "GET", "/health")
    if (status != 200 or not isinstance(health, dict)
            or not re.fullmatch(r"[0-9a-f]{40}", health.get("version", ""))
            or health.get("db_configured") is not True):
        raise MatrixError("Health preflight did not confirm a deployed version and configured database.")

    event_id = "group7-1-w05-" + str(time.time_ns())
    event = {
        "event_id": event_id,
        "device_id": "g7-device-01",
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": "test",
        "note": "W5 idempotency matrix",
    }
    rows = []

    status, body = request(base_url, "POST", "/events", reporter_token, event)
    if status != 201:
        raise MatrixError(f"Matrix row 1: expected HTTP 201, got {status}.")
    rows.append({"row": 1, "status": status, "body": body})

    status, body = request(base_url, "POST", "/events", reporter_token, event)
    if status != 200:
        raise MatrixError(f"Matrix row 2: expected HTTP 200, got {status}.")
    rows.append({"row": 2, "status": status, "body": body})

    conflicting = dict(event, note="changed note")
    status, body = request(base_url, "POST", "/events", reporter_token, conflicting)
    if status != 409:
        raise MatrixError(f"Matrix row 3: expected HTTP 409, got {status}.")
    rows.append({"row": 3, "status": status, "body": body})

    target = config["SSH_USER"] + "@" + public_ip
    ssh_command(key_path, target, "sudo systemctl restart inspection")
    status, body = request(
        base_url, "GET", "/events/" + event_id, operator_token
    )
    if status != 200 or body.get("event_id") != event_id:
        raise MatrixError(f"Matrix row 4: event did not survive service restart (HTTP {status}).")
    rows.append({"row": 4, "status": status, "body": body})

    remote = """set -euo pipefail
EVENT_ID="$1"
set -a
. /etc/inspection/app.env
set +a
export PGPASSWORD="$DB_PASSWORD"
psql --no-psqlrc --tuples-only --no-align \\
  "host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" \\
  --set=event_id="$EVENT_ID" <<'SQL'
SELECT count(*) FROM events WHERE event_id = :'event_id';
SQL
"""
    count_text = ssh_command(
        key_path,
        target,
        "sudo bash -s -- " + shlex.quote(event_id),
        remote,
    )
    if count_text != "1":
        raise MatrixError("Matrix row 5: expected exactly one database row for the event.")
    rows.append({"row": 5, "status": 200, "body": {"event_id": event_id, "count": 1}})
    return health["version"], health["db_configured"], rows, (reporter_token, operator_token)


def render_report(version, db_configured, rows, tokens=()):
    lines = [
        "version=" + version,
        "db_configured=" + str(db_configured).lower(),
    ]
    for row in rows:
        body = json.dumps(row["body"], ensure_ascii=False, separators=(",", ":"))
        for token in tokens:
            body = body.replace(token, "[REDACTED]")
        lines.append(f"{row['row']} {row['status']} {body}")
    return "\n".join(lines)


def main():
    try:
        version, db_configured, rows, tokens = run_matrix()
        print(render_report(version, db_configured, rows, tokens))
    except (MatrixError, OSError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
