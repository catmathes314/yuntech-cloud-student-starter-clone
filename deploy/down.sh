#!/usr/bin/env bash
# W3 deploy/down.sh — 只處理 .local/resources.json 內的 ID；刪除前核對標籤。
# 用法：
#   bash deploy/down.sh          完整回收（terminate instance + 刪 SG + 刪 key pair）
#   bash deploy/down.sh --stop   只停止 instance（保留到下週），不刪除其他資源
# AWS 呼叫一律經 scripts/lab.py run_aws（learnerlab profile）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-.local/config}"
if [[ ! -f "$CONFIG" ]]; then
  echo "STOP: 缺少 $CONFIG" >&2; exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG"
: "${GROUP:?}"; : "${OWNER:?}"

RESOURCES=".local/resources.json"
MODE="full"
if [[ "${1:-}" == "--stop" ]]; then MODE="stop"; fi

if [[ ! -f "$RESOURCES" ]]; then
  echo "STOP: 沒有 $RESOURCES（沒有可回收的資源）" >&2; exit 1
fi

# --- 共用 python：標籤核對與存在性讀回（不刪除、不變更）---
pycheck() { # pycheck <action> <type> <id>
  python3 - "$1" "$2" "$3" <<'PY'
import sys, json, os
sys.path.insert(0, "scripts")
import lab
action, rtype, rid = sys.argv[1], sys.argv[2], sys.argv[3]
group = os.environ["GROUP"]
owner = os.environ["OWNER"]
ctx = lab.context()
region = ctx["region"]

def fetch():
    if rtype == "instance":
        return lab.run_aws(["ec2", "describe-instances", "--instance-ids", rid], region)
    if rtype == "security-group":
        return lab.run_aws(["ec2", "describe-security-groups", "--group-ids", rid], region)
    if rtype == "key-pair":
        return lab.run_aws(["ec2", "describe-key-pairs", "--key-names", rid], region)
    if rtype == "volume":
        return lab.run_aws(["ec2", "describe-volumes", "--filters",
                            "Name=attachment.instance-id,Values=" + rid], region)
    if rtype == "network-interface":
        return lab.run_aws(["ec2", "describe-network-interfaces", "--filters",
                            "Name=attachment.instance-id,Values=" + rid], region)
    raise ValueError(rtype)

def tags_of(out):
    if rtype == "instance":
        return {t["Key"]: t["Value"] for t in out["Reservations"][0]["Instances"][0].get("Tags", [])}
    if rtype == "security-group":
        return {t["Key"]: t["Value"] for t in out["SecurityGroups"][0].get("Tags", [])}
    if rtype == "key-pair":
        return {t["Key"]: t["Value"] for t in out["KeyPairs"][0].get("Tags", [])}
    if rtype in ("volume", "network-interface"):
        return {"attached_to": rid}  # 以 attachment 為擁有權證據，不另設標籤

try:
    out = fetch()
except lab.LabError as exc:
    if action == "exists" and ("NotFound" in str(exc) or "Invalid" in str(exc)):
        print("absent")
        sys.exit(0)
    print("error: " + str(exc), file=sys.stderr)
    sys.exit(1)

if action == "exists":
    if rtype == "instance":
        state = out["Reservations"][0]["Instances"][0]["State"]["Name"]
        print("present" if state != "terminated" else "absent")
    elif rtype in ("volume", "network-interface"):
        items = out["Volumes"] if rtype == "volume" else out["NetworkInterfaces"]
        print("present" if items else "absent")
    else:
        print("present")
    sys.exit(0)

if action == "tags":
    tags = tags_of(out)
    ok = tags.get("group") == group and tags.get("owner") == owner and tags.get("week") == "w03"
    print("ok" if ok else "mismatch " + json.dumps(tags))
    sys.exit(0)
PY
}

aws() {
  python3 -c '
import sys, json
sys.path.insert(0, "scripts")
import lab
try:
    ctx = lab.context()
    out = lab.run_aws(sys.argv[1:], ctx["region"])
    print(json.dumps(out) if not isinstance(out, str) else out)
except lab.LabError as exc:
    print("STOP: " + str(exc), file=sys.stderr)
    sys.exit(1)
' "$@"
}

require_approval() { # require_approval <env_var> <說明>
  if [[ -n "${!1:-}" ]]; then return 0; fi
  echo "STOP: $2" >&2
  echo "      若你已在對話中核准，請以 env $1=1 重新執行。" >&2
  exit 1
}

# --- 讀入 resources.json ---
read_resource() {
  python3 - "$1" <<'PY'
import json, sys
with open(".local/resources.json", encoding="utf-8") as resources:
    print(json.load(resources).get(sys.argv[1], ""))
PY
}
INSTANCE_ID="$(read_resource instance_id)"
SG_ID="$(read_resource sg_id)"
KEY_NAME="$(read_resource key_name)"
KEY_ID="$(read_resource key_pair_id)"

[[ -n "$INSTANCE_ID" ]] || { echo "STOP: resources.json 沒有 instance_id" >&2; exit 1; }

export GROUP OWNER  # 供 pycheck 讀取

INSTANCE_STATE=""
if [[ "$MODE" == "full" ]]; then
  INSTANCE_STATE="$(pycheck exists instance "$INSTANCE_ID")"
fi

if [[ "$MODE" == "stop" ]]; then
  echo "== --stop 模式：只停止主機，不刪除 =="
  echo "將停止 instance: $INSTANCE_ID"
  echo "目前狀態: $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name')"
  require_approval APPROVE_STOP "尚未核准停止主機。"
  [[ "$(pycheck tags instance "$INSTANCE_ID")" == "ok" ]] || { echo "STOP: instance 標籤與 group=$GROUP owner=$OWNER 不符，拒絕操作" >&2; exit 1; }
  aws ec2 stop-instances --instance-ids "$INSTANCE_ID" >/dev/null
  for i in $(seq 1 40); do
    ST="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name')"
    if [[ "$ST" == "stopped" ]]; then break; fi
    sleep 3
  done
  echo "最終狀態: $ST"
  [[ "$ST" == "stopped" ]] || { echo "STOP: 主機未停止" >&2; exit 1; }
  echo "OK：主機已停止並保留（下週 W4 啟動：公開 IP 會變，需重新核對）。"
  exit 0
fi

echo "== full 模式：完整回收 =="
cat <<PREVIEW
將依 .local/resources.json 的 ID 回收：
  instance  : $INSTANCE_ID           （terminate；根 EBS、ENI 隨之刪除）
  SG        : $SG_ID                  （確認無 ENI 使用後刪除）
  key pair  : $KEY_NAME ($KEY_ID)     （刪除）
所有刪除前都會核對標籤 group=$GROUP owner=$OWNER；
不改動 default SG、vockey、既有 VPC／子網／IGW／路由表。
PREVIEW
require_approval APPROVE_DOWN "尚未核准回收。"

echo "== 1/5 核對 instance 標籤並終止 =="
if [[ "$INSTANCE_STATE" == "present" ]]; then
  [[ "$(pycheck tags instance "$INSTANCE_ID")" == "ok" ]] || { echo "STOP: instance 標籤不符，拒絕操作" >&2; exit 1; }
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null
  for i in $(seq 1 60); do
    [[ "$(pycheck exists instance "$INSTANCE_ID")" == "absent" ]] && break
    sleep 3
  done
fi
[[ "$(pycheck exists instance "$INSTANCE_ID")" == "absent" ]] || { echo "STOP: instance 尚未終止" >&2; exit 1; }
echo "instance 已終止或先前已終止。"

echo "== 2/5 讀回根 EBS 已刪除 =="
for i in $(seq 1 30); do
  [[ "$(pycheck exists volume "$INSTANCE_ID")" == "absent" ]] && break
  sleep 3
done
EBS_STATE="$(pycheck exists volume "$INSTANCE_ID")"
echo "根 EBS 讀回: $EBS_STATE（應為 absent）"
[[ "$EBS_STATE" == "absent" ]] || { echo "STOP: 找到仍存在的附加磁碟；不繼續刪除其他資源" >&2; exit 1; }

echo "== 3/5 讀回 ENI 已釋放 =="
for i in $(seq 1 30); do
  [[ "$(pycheck exists network-interface "$INSTANCE_ID")" == "absent" ]] && break
  sleep 3
done
ENI_STATE="$(pycheck exists network-interface "$INSTANCE_ID")"
echo "ENI 讀回: $ENI_STATE（應為 absent）"
[[ "$ENI_STATE" == "absent" ]] || { echo "STOP: 找到仍存在的附加網路介面；不繼續刪除其他資源" >&2; exit 1; }

if [[ -n "$SG_ID" ]]; then
  echo "== 4/5 核對 SG 標籤並刪除 =="
  [[ "$(pycheck tags security-group "$SG_ID")" == "ok" ]] || { echo "STOP: SG 標籤不符，拒絕操作" >&2; exit 1; }
  aws ec2 delete-security-group --group-id "$SG_ID" >/dev/null
  echo "SG 已刪除: $SG_ID"
else
  echo "== 4/5 無 SG ID，跳過 =="
fi

if [[ -n "$KEY_ID" || -n "$KEY_NAME" ]]; then
  echo "== 5/5 核對 key pair 標籤並刪除 =="
  [[ "$(pycheck tags key-pair "${KEY_NAME:-$KEY_ID}")" == "ok" ]] || { echo "STOP: key pair 標籤不符，拒絕操作" >&2; exit 1; }
  aws ec2 delete-key-pair --key-name "${KEY_NAME:-$KEY_ID}" >/dev/null
  echo "key pair 已刪除: ${KEY_NAME:-$KEY_ID}"
else
  echo "== 5/5 無 key pair ID，跳過 =="
fi

echo "== 讀回五項（應全部 absent）=="
echo "  instance   : $(pycheck exists instance "$INSTANCE_ID")"
echo "  根 EBS     : $(pycheck exists volume "$INSTANCE_ID")"
echo "  ENI        : $(pycheck exists network-interface "$INSTANCE_ID")"
if [[ -n "$SG_ID" ]]; then
  echo "  SG         : $(pycheck exists security-group "$SG_ID")"
else
  echo "  SG         : absent（無 SG 記錄）"
fi
if [[ -n "${KEY_NAME:-$KEY_ID}" ]]; then
  echo "  key pair   : $(pycheck exists key-pair "${KEY_NAME:-$KEY_ID}")"
else
  echo "  key pair   : absent（無 key pair 記錄）"
fi
echo "OK：五項皆不存在。resources.json 保留供查核（不進 Git）。"