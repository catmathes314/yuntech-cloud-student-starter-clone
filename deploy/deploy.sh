#!/usr/bin/env bash
# W4 deploy/deploy.sh — deploy a committed service to the existing W3 instance.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-.local/config}"
RESOURCES=".local/resources.json"
APP_ENV=".local/app.env"
if [[ ! -f "$CONFIG" || -L "$CONFIG" ]]; then
  echo "STOP: missing or unsafe $CONFIG" >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG"
: "${GROUP:?}"; : "${OWNER:?}"; : "${REGION:?}"; : "${KEY_NAME:?}"; : "${SSH_USER:?}"

if [[ ! -f "$RESOURCES" || -L "$RESOURCES" ]]; then
  echo "STOP: missing or unsafe $RESOURCES" >&2
  exit 1
fi
INSTANCE_ID="$(python3 - "$RESOURCES" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("instance_id", ""))
PY
)"
if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]]; then
  echo "STOP: resources file has no valid instance_id" >&2
  exit 1
fi

if [[ ! -f "$APP_ENV" || -L "$APP_ENV" ]]; then
  echo "STOP: missing or unsafe $APP_ENV" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$APP_ENV")" != "600" ]]; then
  echo "STOP: $APP_ENV permissions must be 600" >&2
  exit 1
fi
python3 - "$APP_ENV" <<'PY'
import sys
from pathlib import Path
values = {}
try:
    for line in Path(sys.argv[1]).read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or key in values or not value:
            raise ValueError
        values[key] = value
    if set(values) != {"REPORTER_TOKEN", "OPERATOR_TOKEN"} or values["REPORTER_TOKEN"] == values["OPERATOR_TOKEN"]:
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit("STOP: token file must contain two distinct ASCII tokens.") from None
PY

COMMIT_REF="${1:-HEAD}"
FULL_COMMIT="$(git rev-parse --verify --end-of-options "${COMMIT_REF}^{commit}")"
if ! git ls-files --error-unmatch deploy/deploy.sh >/dev/null 2>&1 || [[ -n "$(git status --porcelain -- deploy/deploy.sh)" ]]; then
  echo "STOP: commit deploy/deploy.sh before deployment" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain -- app/service.py deploy/nginx.conf)" ]]; then
  echo "STOP: commit app/service.py and deploy/nginx.conf before deployment" >&2
  exit 1
fi
if ! git cat-file -e "${FULL_COMMIT}:app/service.py" || ! git cat-file -e "${FULL_COMMIT}:deploy/nginx.conf"; then
  echo "STOP: selected commit lacks a deployable service or nginx config" >&2
  exit 1
fi

KEY_FILE="$HOME/.ssh/${KEY_NAME}"
if [[ ! -f "$KEY_FILE" || -L "$KEY_FILE" || "$(stat -c '%a' "$KEY_FILE")" != "600" ]]; then
  echo "STOP: expected SSH private key is missing, unsafe, or not mode 600" >&2
  exit 1
fi
command -v curl >/dev/null || { echo "STOP: curl is required" >&2; exit 1; }
command -v ssh >/dev/null || { echo "STOP: ssh is required" >&2; exit 1; }

bash scripts/verify-aws.sh
CURRENT_IP="$(curl --fail --silent --show-error --max-time 10 https://checkip.amazonaws.com | tr -d '\r\n')"
CURRENT_CIDR="${CURRENT_IP}/32"
INSTANCE_INFO="$(python3 - "$INSTANCE_ID" "$GROUP" "$OWNER" "$REGION" "$CURRENT_CIDR" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
import lab
instance_id, group_name, owner, expected_region, cidr = sys.argv[1:]
ctx = lab.context()
if ctx["region"] != expected_region:
    raise SystemExit("STOP: configured region differs from verified Learner Lab region.")
region = ctx["region"]
try:
    out = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], region)
    instances = [item for reservation in out.get("Reservations", []) for item in reservation.get("Instances", [])]
    if len(instances) != 1:
        raise ValueError
    instance = instances[0]
    tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
    expected_tags = {"course": "yuntech-115-1", "week": "w03", "group": group_name, "owner": owner}
    if any(tags.get(key) != value for key, value in expected_tags.items()):
        raise ValueError
    if instance.get("State", {}).get("Name") != "running" or not instance.get("PublicIpAddress"):
        raise ValueError
    security_groups = instance.get("SecurityGroups", [])
    if len(security_groups) != 1:
        raise ValueError
    sg_id = security_groups[0]["GroupId"]
    sg = lab.run_aws(["ec2", "describe-security-groups", "--group-ids", sg_id], region)["SecurityGroups"][0]
    sg_tags = {item["Key"]: item["Value"] for item in sg.get("Tags", [])}
    if any(sg_tags.get(key) != value for key, value in expected_tags.items()):
        raise ValueError
    rules = []
    for permission in sg.get("IpPermissions", []):
        if permission.get("IpProtocol") != "tcp" or permission.get("FromPort") != permission.get("ToPort"):
            raise ValueError
        sources = [entry["CidrIp"] for entry in permission.get("IpRanges", [])]
        if len(sources) != 1 or permission.get("Ipv6Ranges") or permission.get("UserIdGroupPairs") or permission.get("PrefixListIds"):
            raise ValueError
        rules.append((permission["FromPort"], sources[0]))
    if sorted(rules) != [(22, cidr), (80, cidr)]:
        raise ValueError
except (lab.LabError, KeyError, IndexError, TypeError, ValueError):
    raise SystemExit("STOP: instance ownership, state, or current /32 security-group rules do not match; no deployment performed.") from None
print(json.dumps({"instance_id": instance_id, "public_ip": instance["PublicIpAddress"], "security_group_id": sg_id, "state": instance["State"]["Name"]}))
PY
)"
PUBLIC_IP="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["public_ip"])' "$INSTANCE_INFO")"
SG_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["security_group_id"])' "$INSTANCE_INFO")"

HEALTH_OUTPUT="$(curl --silent --show-error --max-time 8 --write-out $'\nHTTP_CODE:%{http_code}' "http://${PUBLIC_IP}/health")" || {
  echo "STOP: existing /health is unreachable; no deployment performed" >&2
  exit 1
}
if [[ "$HEALTH_OUTPUT" != *"HTTP_CODE:200"* ]]; then
  echo "STOP: existing /health is not HTTP 200; no deployment performed" >&2
  exit 1
fi
OLD_VERSION="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1].rsplit("HTTP_CODE:",1)[0])["version"])' "$HEALTH_OUTPUT")"
if [[ ! "$OLD_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: existing /health returned an invalid version; no deployment performed" >&2
  exit 1
fi
if ! git cat-file -e "${OLD_VERSION}^{commit}" 2>/dev/null; then
  echo "STOP: current service version is not available as a local commit; rollback cannot be prepared" >&2
  exit 1
fi
EXPECT_AUTH=false
if git grep -q '"auth_configured"' "$FULL_COMMIT" -- app/service.py; then
  EXPECT_AUTH=true
fi

USER_DATA=".local/w04-user-data-${FULL_COMMIT}.sh"
if [[ -e "$USER_DATA" || -L "$USER_DATA" ]]; then
  echo "STOP: generated bundle path already exists; inspect it before retrying" >&2
  exit 1
fi
python3 deploy/make_user_data.py "$FULL_COMMIT" "$USER_DATA"
trap 'rm -f -- "$USER_DATA"' EXIT

cat <<PREVIEW
W4 deployment preview (no AWS resources will be created or Security Group rules changed):
  Instance       : $INSTANCE_ID ($PUBLIC_IP, running)
  Security Group : $SG_ID (TCP 22/80 remain restricted to $CURRENT_CIDR)
  Current version: $OLD_VERSION
  New commit     : $FULL_COMMIT
  Rollback       : redeploy current version $OLD_VERSION if W4 verification fails
  Secret file    : local mode 600; sent only over SSH stdin; remote root-owned mode 600
  Service impact : inspection restarts; in-memory events are cleared; brief HTTP interruption
  New resources  : none; no additional resource charges. Existing running EC2/EBS/IP charges continue.
  Recovery       : rerun with $OLD_VERSION and the same token file; W3 rollback will not expose W4 endpoints.
PREVIEW
if [[ ! -t 0 ]]; then
  echo "STOP: interactive confirmation is required; no deployment performed" >&2
  exit 1
fi
read -r -p 'Type exactly DEPLOY to continue: ' CONFIRM
if [[ "$CONFIRM" != "DEPLOY" ]]; then
  echo "Cancelled; no deployment performed."
  exit 0
fi

SSH_OPTIONS=(-i "$KEY_FILE" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
SSH_TARGET="${SSH_USER}@${PUBLIC_IP}"
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" true
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo bash -s' < "$USER_DATA"
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo install -d -o root -g root -m 700 /etc/inspection'
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo python3 -c '\''import os,sys; data=sys.stdin.buffer.read(4097); allowed={b"REPORTER_TOKEN=",b"OPERATOR_TOKEN="}; lines=data.splitlines(); keys=[line.partition(b"=")[0]+b"=" for line in lines]; values=[line.partition(b"=")[2] for line in lines]; assert len(data)<=4096 and len(lines)==2 and set(keys)==allowed and all(values) and values[0]!=values[1]; fd=os.open("/etc/inspection/app.env",os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.fchown(fd,0,0); os.fchmod(fd,0o600); stream=os.fdopen(fd,"wb"); stream.write(data); stream.close()'\''' < "$APP_ENV"
REMOTE_SECRET_MODE="$(ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo stat -c "%a %U %G" /etc/inspection/app.env')"
if [[ "$REMOTE_SECRET_MODE" != "600 root root" ]]; then
  echo "STOP: remote secret-file owner or mode is incorrect" >&2
  exit 1
fi
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo systemctl restart inspection'

HEALTH_OUTPUT="$(curl --silent --show-error --max-time 8 --write-out $'\nHTTP_CODE:%{http_code}' "http://${PUBLIC_IP}/health")" || {
  echo "STOP: deployed /health is unreachable; use the recovery procedure above" >&2
  exit 1
}
if [[ "$HEALTH_OUTPUT" != *"HTTP_CODE:200"* ]]; then
  echo "STOP: deployed /health is not HTTP 200; use the recovery procedure above" >&2
  exit 1
fi
python3 - "$HEALTH_OUTPUT" "$FULL_COMMIT" "$EXPECT_AUTH" <<'PY'
import json, sys
body, expected, expect_auth = sys.argv[1].rsplit("HTTP_CODE:", 1)[0], sys.argv[2], sys.argv[3] == "true"
try:
    result = json.loads(body)
except json.JSONDecodeError:
    raise SystemExit("STOP: deployed health response is invalid JSON.") from None
if result.get("version") != expected or (expect_auth and result.get("auth_configured") is not True):
  raise SystemExit("STOP: deployed version or auth configuration does not match the selected commit.")
print(f"Verified /health: HTTP 200, version matches commit, auth_configured={result.get('auth_configured', 'absent')}.")
PY

echo "W4 deployment completed for $INSTANCE_ID at $PUBLIC_IP, commit $FULL_COMMIT."
