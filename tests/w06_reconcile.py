#!/usr/bin/env python3
"""Reconcile Lab 6 MQTT acknowledgements, consumer logs, database rows, and filter results."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE_BYTES = 128 * 1024


class ReconcileError(Exception):
    pass


REMOTE_RECONCILE = r"""set -euo pipefail
PREFIX="$1"
if [[ ! "$PREFIX" =~ ^[A-Za-z0-9-]{1,40}$ ]]; then
  echo "STOP: invalid run prefix" >&2
  exit 1
fi
set -a
. /etc/inspection/app.env
set +a
if [[ -z "${DB_HOST:-}" || -z "${DB_NAME:-}" || -z "${DB_USER:-}" || -z "${DB_PASSWORD:-}" ]]; then
  echo "STOP: database settings are missing from app.env" >&2
  exit 1
fi
export PGPASSWORD="$DB_PASSWORD"
deadline=$((SECONDS + 60))
while true; do
  raw_counts="$(sudo journalctl -u inspection-consumer -o cat --no-pager \
    | grep -F "event_id=${PREFIX}-" \
    | sed -nE 's/.*result=(created|duplicate|rejected|error).*/\1/p' \
    | sort | uniq -c || true)"
  created=0
  duplicate=0
  rejected=0
  errors=0
  while read -r count result; do
    case "$result" in
      created) created="$count" ;;
      duplicate) duplicate="$count" ;;
      rejected) rejected="$count" ;;
      error) errors="$count" ;;
    esac
  done <<< "$raw_counts"
  database_count="$(psql --no-psqlrc --tuples-only --no-align --quiet \
    "host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem connect_timeout=5" \
    --set=prefix="${PREFIX}-" <<'SQL' 2>/dev/null || true
SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';
SQL
)"
  database_count="$(printf '%s' "$database_count" | tr -d '[:space:]')"
  if [[ ! "$database_count" =~ ^[0-9]+$ ]]; then database_count="unavailable"; fi
  total=$((created + duplicate + rejected + errors))
  if (( total >= 32 || SECONDS >= deadline )); then
    break
  fi
  sleep 5
done
printf 'consumer_created=%s\nconsumer_duplicate=%s\nconsumer_rejected=%s\nconsumer_error=%s\ndatabase_count=%s\n' \
  "$created" "$duplicate" "$rejected" "$errors" "$database_count"
printf '%s\n' 'consumer_log_begin'
sudo journalctl -u inspection-consumer -o cat --no-pager \
  | grep -E "event_id=${PREFIX}-d(01-01|99-01) " || true
printf '%s\n' 'consumer_log_end'
"""


def read_assignments(path, allowed):
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in allowed or key in values or not value:
                raise ValueError
            values[key] = value
    except (OSError, UnicodeError, ValueError):
        raise ReconcileError(path.name + " has an invalid format.") from None
    return values


def load_token():
    local_dir = ROOT / ".local"
    if local_dir.is_symlink() or not local_dir.is_dir():
        raise ReconcileError("Missing or unsafe .local directory.")
    path = ROOT / ".local/app.env"
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ReconcileError(".local/app.env is missing, unsafe, or not mode 600.")
    values = read_assignments(path, {"REPORTER_TOKEN", "OPERATOR_TOKEN"})
    try:
        reporter = values["REPORTER_TOKEN"].encode("ascii")
        operator = values["OPERATOR_TOKEN"].encode("ascii")
    except (KeyError, UnicodeEncodeError):
        raise ReconcileError(".local/app.env must contain two distinct ASCII tokens.") from None
    if not reporter or not operator or reporter == operator:
        raise ReconcileError(".local/app.env must contain two distinct non-empty tokens.")
    return operator.decode("ascii")


def load_target():
    local_dir = ROOT / ".local"
    if local_dir.is_symlink() or not local_dir.is_dir():
        raise ReconcileError("Missing or unsafe .local directory.")
    config_path = ROOT / ".local/config"
    config = read_assignments(
        config_path,
        {"GROUP", "OWNER", "SOURCE_CIDR", "REGION", "AMI_ID", "SUBNET_ID",
         "INSTANCE_TYPE", "KEY_NAME", "SG_NAME", "SSH_USER"},
    )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", config.get("KEY_NAME", "")):
        raise ReconcileError("Configured SSH key name is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", config.get("SSH_USER", "")):
        raise ReconcileError("Configured SSH user is invalid.")

    resources_path = ROOT / ".local/resources.json"
    if resources_path.is_symlink() or not resources_path.is_file():
        raise ReconcileError("Resource manifest is missing or unsafe.")
    try:
        resources = json.loads(resources_path.read_text(encoding="utf-8"))
        public_ip = str(ipaddress.IPv4Address(resources["public_ip"]))
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        raise ReconcileError("Resource manifest has no valid current EC2 public IP.") from None

    key_path = Path.home() / ".ssh" / config["KEY_NAME"]
    if (key_path.is_symlink() or not key_path.is_file()
            or stat.S_IMODE(key_path.stat().st_mode) != 0o600):
        raise ReconcileError("SSH private key is missing, unsafe, or not mode 600.")
    return config["SSH_USER"] + "@" + public_ip, key_path, public_ip


def http_json(url, token=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = Request(url, headers=headers, method="GET")
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    except (URLError, TimeoutError, OSError) as error:
        raise ReconcileError("HTTP request failed: " + type(error).__name__) from None
    with response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ReconcileError("HTTP response exceeds the safe reporting limit.")
    try:
        return response.status, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ReconcileError("HTTP response was not valid JSON.") from None


def ssh_command(key_path, target, remote_command, input_text):
    try:
        result = subprocess.run(
            [
                "ssh", "-i", str(key_path), "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
                target, remote_command,
            ],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=80,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReconcileError("SSH operation failed: " + type(error).__name__) from None
    if result.returncode:
        raise ReconcileError("SSH reconciliation failed with exit status " + str(result.returncode) + ".")
    return result.stdout.strip()


def parse_remote(output):
    result = {}
    log_lines = []
    in_logs = False
    for line in output.splitlines():
        if line == "consumer_log_begin":
            in_logs = True
            continue
        if line == "consumer_log_end":
            in_logs = False
            continue
        if in_logs:
            if re.fullmatch(r"event_id=[A-Za-z0-9_-]{1,64} result=(created|duplicate|rejected|error)", line):
                log_lines.append(line)
            continue
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    expected = {
        "consumer_created", "consumer_duplicate", "consumer_rejected",
        "consumer_error", "database_count",
    }
    if not expected.issubset(result):
        raise ReconcileError("Remote reconciliation output is incomplete.")
    for key in expected - {"database_count"}:
        if not result[key].isdecimal():
            raise ReconcileError("Remote reconciliation returned an invalid counter.")
    if result["database_count"] != "unavailable" and not result["database_count"].isdecimal():
        raise ReconcileError("Remote reconciliation returned an invalid database count.")
    return result, log_lines


def run(code, run_id):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", code):
        raise ReconcileError("Code must match [A-Za-z0-9-]{1,40}.")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", run_id):
        raise ReconcileError("Run must match [A-Za-z0-9-]{1,40}.")
    prefix = f"{code}-{run_id}"
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", prefix):
        raise ReconcileError("Combined run prefix must match [A-Za-z0-9-]{1,40}.")

    local_dir = ROOT / ".local"
    if local_dir.is_symlink() or not local_dir.is_dir():
        raise ReconcileError("Missing or unsafe .local directory.")
    last_run_path = ROOT / ".local/w06-last-run.json"
    if (last_run_path.is_symlink() or not last_run_path.is_file()
            or stat.S_IMODE(last_run_path.stat().st_mode) != 0o600):
        raise ReconcileError(".local/w06-last-run.json is missing, unsafe, or not mode 600.")
    try:
        last_run = json.loads(last_run_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ReconcileError("The saved gateway run record is invalid.") from None
    if (not isinstance(last_run, dict) or last_run.get("prefix") != prefix
            or type(last_run.get("puback_ok")) is not int
            or not 0 <= last_run["puback_ok"] <= 32):
        raise ReconcileError("The saved gateway run does not match this prefix.")

    operator_token = load_token()
    target, key_path, public_ip = load_target()
    health_status, health = http_json(f"http://{public_ip}/health")
    if (health_status != 200 or not isinstance(health, dict)
            or health.get("db_configured") is not True
            or not re.fullmatch(r"[0-9a-f]{40}", health.get("version", ""))):
        raise ReconcileError("Health preflight did not confirm a deployed version and configured database.")

    device_id = f"{code}-d01"
    query = urlencode({"device_id": device_id})
    filter_status, filtered = http_json(
        f"http://{public_ip}/events?{query}",
        operator_token,
    )
    if filter_status != 200 or not isinstance(filtered, list):
        raise ReconcileError("Device filter response is not an event list.")
    filtered_ids = [
        event["event_id"] for event in filtered
        if isinstance(event, dict)
        and isinstance(event.get("event_id"), str)
        and event["event_id"].startswith(prefix + "-")
    ]

    remote_output = ssh_command(
        key_path,
        target,
        "sudo bash -s -- " + shlex.quote(prefix),
        REMOTE_RECONCILE,
    )
    remote, logs = parse_remote(remote_output)
    report = [
        "version=" + health["version"],
        "db_configured=true",
        "prefix=" + prefix,
        f"puback_ok={last_run['puback_ok']}/32",
        "consumer="
        + "/".join(
            remote[key]
            for key in (
                "consumer_created", "consumer_duplicate",
                "consumer_rejected", "consumer_error",
            )
        ),
        "database_count=" + remote["database_count"],
        "device_id=" + device_id,
        "filtered_event_ids=" + ",".join(filtered_ids),
        "filtered_count=" + str(len(filtered_ids)),
        "consumer_logs:",
        *logs,
    ]
    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your group-member code, e.g. g03-m2")
    parser.add_argument("--run", dest="run_id", required=True, help="Run suffix used by gateway_sim.py")
    args = parser.parse_args()
    try:
        print(run(args.code, args.run_id))
    except (ReconcileError, OSError, ValueError, TypeError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
