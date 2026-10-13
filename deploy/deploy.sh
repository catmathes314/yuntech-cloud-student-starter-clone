#!/usr/bin/env bash
# W4 deploy/deploy.sh — deploy a committed service to the existing W3 instance.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-.local/config}"
RESOURCES=".local/resources.json"
APP_ENV=".local/app.env"
DB_ENV=".local/db.env"
if [[ -L ".local" || ! -d ".local" ]]; then
  echo "STOP: missing or unsafe .local directory" >&2
  exit 1
fi
if [[ ! -f "$CONFIG" || -L "$CONFIG" ]]; then
  echo "STOP: missing or unsafe $CONFIG" >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG"
: "${GROUP:?}"; : "${OWNER:?}"; : "${REGION:?}"; : "${KEY_NAME:?}"; : "${SSH_USER:?}"
CODE="${GROUP}-${OWNER}"
if [[ ! "$CODE" =~ ^[A-Za-z0-9-]{1,40}$ ]]; then
  echo "STOP: configured group/member code is invalid" >&2
  exit 1
fi

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
if [[ -e "$DB_ENV" || -L "$DB_ENV" ]]; then
  if [[ ! -f "$DB_ENV" || -L "$DB_ENV" || "$(stat -c '%a' "$DB_ENV")" != "600" ]]; then
    echo "STOP: $DB_ENV is unsafe or permissions are not 600" >&2
    exit 1
  fi
  python3 - "$DB_ENV" <<'PY'
import re, sys
from pathlib import Path
expected = {"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"}
values = {}
try:
    for line in Path(sys.argv[1]).read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in expected or key in values or not value:
            raise ValueError
        values[key] = value
    if (set(values) != expected or values["DB_PORT"] != "5432"
            or values["DB_NAME"] != "inspection" or values["DB_USER"] != "inspection"
            or not re.fullmatch(r"[A-Za-z0-9.-]+", values["DB_HOST"])
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,}", values["DB_PASSWORD"])):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit("STOP: database secret file has an invalid format.") from None
PY
fi

IOT_DIR=".local/iot"
if [[ ! -d "$IOT_DIR" || -L "$IOT_DIR" || "$(stat -c '%a' "$IOT_DIR")" != "700" ]]; then
  echo "STOP: missing or unsafe $IOT_DIR (directory mode must be 700)" >&2
  exit 1
fi
for IOT_FILE in endpoint AmazonRootCA1.pem consumer.cert.pem consumer.private.key; do
  if [[ ! -f "$IOT_DIR/$IOT_FILE" || -L "$IOT_DIR/$IOT_FILE" ]]; then
    echo "STOP: missing or unsafe $IOT_DIR/$IOT_FILE" >&2
    exit 1
  fi
  if [[ "$(stat -c '%a' "$IOT_DIR/$IOT_FILE")" != "600" ]]; then
    echo "STOP: $IOT_DIR/$IOT_FILE permissions must be 600" >&2
    exit 1
  fi
done
IOT_ENDPOINT="$(tr -d '\r\n' < "$IOT_DIR/endpoint")"
if [[ ! "$IOT_ENDPOINT" =~ ^[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com$ ]]; then
  echo "STOP: IoT endpoint file has an invalid value" >&2
  exit 1
fi
IOT_TOPIC="cxe/$CODE/gw/events"
IOT_CLIENT_ID="consumer-$CODE"
IOT_DEVICE_IDS=""
for DEVICE_NUMBER in {1..10}; do
  printf -v DEVICE_ID '%s-d%02d' "$CODE" "$DEVICE_NUMBER"
  IOT_DEVICE_IDS+="${IOT_DEVICE_IDS:+,}$DEVICE_ID"
done

COMMIT_REF="${1:-HEAD}"
FULL_COMMIT="$(git rev-parse --verify --end-of-options "${COMMIT_REF}^{commit}")"
if ! git ls-files --error-unmatch deploy/deploy.sh >/dev/null 2>&1 || [[ -n "$(git status --porcelain -- deploy/deploy.sh)" ]]; then
  echo "STOP: commit deploy/deploy.sh before deployment" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain -- app/service.py app/consumer.py deploy/nginx.conf deploy/make_user_data.py)" ]]; then
  echo "STOP: commit the W6 service, consumer, deploy config, and bundler before deployment" >&2
  exit 1
fi
if ! git cat-file -e "${FULL_COMMIT}:app/service.py" \
    || ! git cat-file -e "${FULL_COMMIT}:app/consumer.py" \
    || ! git cat-file -e "${FULL_COMMIT}:deploy/nginx.conf" \
    || ! git cat-file -e "${FULL_COMMIT}:deploy/make_user_data.py"; then
  echo "STOP: selected commit lacks the W6 service, consumer, or deployment bundle inputs" >&2
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
EXPECT_DB=false
if [[ -f "$DB_ENV" ]]; then
  if git grep -q '"db_configured"' "$FULL_COMMIT" -- app/service.py; then
    EXPECT_DB=true
  fi
fi

USER_DATA=".local/w04-user-data-${FULL_COMMIT}.sh"
if [[ -e "$USER_DATA" || -L "$USER_DATA" ]]; then
  echo "STOP: generated bundle path already exists; inspect it before retrying" >&2
  exit 1
fi
python3 deploy/make_user_data.py "$FULL_COMMIT" "$USER_DATA"
trap 'rm -f -- "$USER_DATA"' EXIT

cat <<PREVIEW
W6 deployment preview (no AWS resources will be created or Security Group rules changed):
  Instance       : $INSTANCE_ID ($PUBLIC_IP, running)
  Security Group : $SG_ID (TCP 22/80 remain restricted to $CURRENT_CIDR)
  Current version: $OLD_VERSION
  New commit     : $FULL_COMMIT
  Previous       : $OLD_VERSION
  Secret files   : local mode 600; tokens, DB settings, and consumer certificates sent only over SSH stdin;
                   app.env root-owned mode 600; /etc/inspection/iot inspection-owned mode 700/600
  Service impact : inspection and inspection-consumer restart; brief HTTP/MQTT interruption
  New resources  : none; no additional resource charges. Existing running EC2/EBS/IP charges continue.
  Recovery       : redeploy the previous commit using this reviewed W6 deployment procedure.
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
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo install -d -o root -g root -m 755 /etc/inspection'
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo install -d -o inspection -g inspection -m 700 /etc/inspection/iot'
for IOT_FILE in AmazonRootCA1.pem consumer.cert.pem consumer.private.key; do
  printf -v REMOTE_COPY_COMMAND \
    "sudo sh -c 'umask 077; cat > /etc/inspection/iot/%s; chown inspection:inspection /etc/inspection/iot/%s; chmod 600 /etc/inspection/iot/%s'" \
    "$IOT_FILE" "$IOT_FILE" "$IOT_FILE"
  # The filename is selected from the fixed allowlist in this loop.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" \
    "$REMOTE_COPY_COMMAND" \
    < "$IOT_DIR/$IOT_FILE"
done
COMBINED_ENV="$(mktemp .local/deploy-env.XXXXXX)"
trap 'rm -f -- "$USER_DATA" "$COMBINED_ENV"' EXIT
cat "$APP_ENV" > "$COMBINED_ENV"
if [[ -f "$DB_ENV" && ! -L "$DB_ENV" ]]; then
  cat "$DB_ENV" >> "$COMBINED_ENV"
fi
printf 'IOT_ENDPOINT=%s\nIOT_TOPIC=%s\nIOT_CLIENT_ID=%s\nIOT_DEVICE_IDS=%s\nIOT_CA=/etc/inspection/iot/AmazonRootCA1.pem\nIOT_CERT=/etc/inspection/iot/consumer.cert.pem\nIOT_KEY=/etc/inspection/iot/consumer.private.key\n' \
  "$IOT_ENDPOINT" "$IOT_TOPIC" "$IOT_CLIENT_ID" "$IOT_DEVICE_IDS" >> "$COMBINED_ENV"
chmod 600 "$COMBINED_ENV"
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo python3 -c '\''import os,re,sys; data=sys.stdin.buffer.read(8193); allowed={b"REPORTER_TOKEN=",b"OPERATOR_TOKEN=",b"DB_HOST=",b"DB_PORT=",b"DB_NAME=",b"DB_USER=",b"DB_PASSWORD=",b"IOT_ENDPOINT=",b"IOT_TOPIC=",b"IOT_CLIENT_ID=",b"IOT_DEVICE_IDS=",b"IOT_CA=",b"IOT_CERT=",b"IOT_KEY="}; required={b"REPORTER_TOKEN=",b"OPERATOR_TOKEN=",b"IOT_ENDPOINT=",b"IOT_TOPIC=",b"IOT_CLIENT_ID=",b"IOT_DEVICE_IDS=",b"IOT_CA=",b"IOT_CERT=",b"IOT_KEY="}; db={b"DB_HOST=",b"DB_PORT=",b"DB_NAME=",b"DB_USER=",b"DB_PASSWORD="}; lines=data.splitlines(); keys=[line.partition(b"=")[0]+b"=" for line in lines]; values=[line.partition(b"=")[2] for line in lines]; assert len(data)<=8192 and len(set(keys))==len(keys) and set(keys) in (required,required|db) and set(keys).issubset(allowed) and all(values); v=dict(zip(keys,values)); assert v[b"REPORTER_TOKEN="] != v[b"OPERATOR_TOKEN="]; code=v[b"IOT_CLIENT_ID="].decode("ascii").removeprefix("consumer-"); assert re.fullmatch(r"[A-Za-z0-9-]{1,40}",code) and v[b"IOT_TOPIC="]==b"cxe/"+code.encode()+b"/gw/events"; assert re.fullmatch(rb"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com",v[b"IOT_ENDPOINT="]); assert v[b"IOT_DEVICE_IDS="]==b",".join(code.encode()+b"-d%02d"%i for i in range(1,11)); assert v[b"IOT_CA="]==b"/etc/inspection/iot/AmazonRootCA1.pem" and v[b"IOT_CERT="]==b"/etc/inspection/iot/consumer.cert.pem" and v[b"IOT_KEY="]==b"/etc/inspection/iot/consumer.private.key"; assert set(v)&db in (set(),db); fd=os.open("/etc/inspection/app.env",os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.fchown(fd,0,0); os.fchmod(fd,0o600); stream=os.fdopen(fd,"wb"); stream.write(data); stream.close()'\''' < "$COMBINED_ENV"
REMOTE_SECRET_MODE="$(ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo stat -c "%a %U %G" /etc/inspection/app.env')"
if [[ "$REMOTE_SECRET_MODE" != "600 root root" ]]; then
  echo "STOP: remote secret-file owner or mode is incorrect" >&2
  exit 1
fi
REMOTE_IOT_MODES="$(ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo sh -c '\''stat -c "%a %U %n" /etc/inspection /etc/inspection/iot /etc/inspection/iot/*'\''')"
EXPECTED_IOT_MODES="$(printf '%s\n' \
  '755 root /etc/inspection' \
  '700 inspection /etc/inspection/iot' \
  '600 inspection /etc/inspection/iot/AmazonRootCA1.pem' \
  '600 inspection /etc/inspection/iot/consumer.cert.pem' \
  '600 inspection /etc/inspection/iot/consumer.private.key')"
if [[ "$REMOTE_IOT_MODES" != "$EXPECTED_IOT_MODES" ]]; then
  echo "STOP: remote IoT file ownership or permissions are incorrect" >&2
  exit 1
fi
printf 'Remote IoT permissions:\n%s\n' "$REMOTE_IOT_MODES"
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo systemctl restart inspection inspection-consumer'
ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'sudo systemctl is-active inspection inspection-consumer'

HEALTH_OUTPUT="$(curl --silent --show-error --max-time 8 --write-out $'\nHTTP_CODE:%{http_code}' "http://${PUBLIC_IP}/health")" || {
  echo "STOP: deployed /health is unreachable; use the recovery procedure above" >&2
  exit 1
}
if [[ "$HEALTH_OUTPUT" != *"HTTP_CODE:200"* ]]; then
  echo "STOP: deployed /health is not HTTP 200; use the recovery procedure above" >&2
  exit 1
fi
python3 - "$HEALTH_OUTPUT" "$FULL_COMMIT" "$EXPECT_AUTH" "$EXPECT_DB" <<'PY'
import json, sys
body, expected = sys.argv[1].rsplit("HTTP_CODE:", 1)[0], sys.argv[2]
expect_auth, expect_db = sys.argv[3] == "true", sys.argv[4] == "true"
try:
    result = json.loads(body)
except json.JSONDecodeError:
    raise SystemExit("STOP: deployed health response is invalid JSON.") from None
if (result.get("version") != expected
        or (expect_auth and result.get("auth_configured") is not True)
        or (expect_db and result.get("db_configured") is not True)):
  raise SystemExit("STOP: deployed version or auth configuration does not match the selected commit.")
print(
    "Verified /health: HTTP 200, version matches commit, "
    f"auth_configured={result.get('auth_configured', 'absent')}, "
    f"db_configured={result.get('db_configured', 'absent')}."
)
PY

echo "W6 deployment completed for $INSTANCE_ID at $PUBLIC_IP, commit $FULL_COMMIT."
