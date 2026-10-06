#!/usr/bin/env bash
# W3 deploy/up.sh — 建立 1 SG + 1 匯入 key pair + 1 台 EC2，部署 inspection 雛型並驗證 /health。
# 用法：bash deploy/up.sh [COMMIT]   （COMMIT 預設 HEAD）
# 參數從 .local/config 讀取（不含秘密）；AWS 呼叫一律經 scripts/lab.py run_aws（learnerlab profile）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-.local/config}"
if [[ ! -f "$CONFIG" ]]; then
  echo "STOP: 缺少 $CONFIG（請先建立 .local/config，見 deploy/up.sh 說明）" >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG"

: "${GROUP:?}"; : "${OWNER:?}"; : "${SOURCE_CIDR:?}"; : "${REGION:?}"
: "${AMI_ID:?}"; : "${SUBNET_ID:?}"; : "${INSTANCE_TYPE:?}"
: "${KEY_NAME:?}"; : "${SG_NAME:?}"; : "${SSH_USER:?}"

COMMIT="${1:-HEAD}"
RESOURCES=".local/resources.json"
USER_DATA=".local/w03-user-data.sh"
KEY_FILE="$HOME/.ssh/${KEY_NAME}"
KNOWN_HOSTS="$HOME/.ssh/known_hosts"

# --- AWS helper：一律走 lab.py run_aws ---
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

json_get() { # json_get <json> <.path>
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}
have_jq=''
command -v jq >/dev/null 2>&1 && have_jq=1

write_resource() { # write_resource <key> <value>
  python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
key, value = sys.argv[1], sys.argv[2]
p = Path(".local/resources.json")
data = json.loads(p.read_text()) if p.exists() else {}
data[key] = value
p.write_text(json.dumps(data, indent=2) + "\n")
print(f"resources.json 已更新: {key}={value}")
PY
}

read_resource() { # read_resource <key> -> stdout（不存在回空字串）
  python3 -c '
import json, sys
from pathlib import Path
p = Path(".local/resources.json")
try:
    d = json.loads(p.read_text())
except Exception:
    sys.exit(0)
print(d.get(sys.argv[1], ""), end="")
' "$1"
}

require_approval() { # require_approval <env_var> <說明>
  if [[ -n "${!1:-}" ]]; then return 0; fi
  echo "STOP: $2" >&2
  echo "      若你已在對話中核准，請以 env $1=1 重新執行。" >&2
  exit 1
}

# =====================================================================
echo "== 1/8 前置檢查 =="
command -v aws >/dev/null || { echo "STOP: 缺少 AWS CLI" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "STOP: 缺少 ssh-keygen" >&2; exit 1; }
# 身分核對（唯讀）
aws sts get-caller-identity >/dev/null
echo "身分 OK（learnerlab, ${REGION}）"

echo "== 2/8 解析部署 commit =="
FULL_COMMIT="$(git rev-parse --verify --end-of-options "${COMMIT}^{commit}")"
echo "部署 commit: $FULL_COMMIT"
[[ -n "$FULL_COMMIT" ]] || { echo "STOP: commit $COMMIT 無法解析" >&2; exit 1; }

echo "== 3/8 SSH 私鑰（ed25519，本機 ~/.ssh，權限 600，不放 Git）=="
if [[ ! -f "$KEY_FILE" ]]; then
  ssh-keygen -q -t ed25519 -f "$KEY_FILE" -N "" -C "w03-${OWNER}-${GROUP}"
  chmod 600 "$KEY_FILE"
  echo "已產生 $KEY_FILE（Agent 不讀取內容）"
else
  echo "已存在 $KEY_FILE，沿用"
fi

echo "== 4/8 打包 user data（只含已 commit 的白名單檔案）=="
rm -f "$USER_DATA"
bash deploy/make-user-data.sh "$FULL_COMMIT" "$USER_DATA"
ls -l "$USER_DATA"

# ---------------------------------------------------------------------
echo "== 5/8 預覽將建立資源（未核准不建立）=="
cat <<PREVIEW
  Security Group : $SG_NAME（VPC 預設 vpc 內，僅入站 TCP 22、80 來源 $SOURCE_CIDR）
  Key pair       : $KEY_NAME（匯入本機產生的 ed25519 公鑰，含標籤）
  EC2 instance   : $AMI_ID / $INSTANCE_TYPE / $SUBNET_ID
                   根磁碟 gp3+Encrypted+DeleteOnTermination / IMDSv2 required
                   user data: $USER_DATA（$(wc -c < "$USER_DATA") bytes < 16384）
  標籤           : course=yuntech-115-1, week=w03, group=$GROUP, owner=$OWNER
PREVIEW
require_approval APPROVE_UP "尚未核准建立資源。"

# ---------------------------------------------------------------------
echo "== 6/8 建立資源（逐項檢查：缺什麼補建什麼）=="

SG_ID="$(read_resource sg_id)"
if [[ -z "$SG_ID" ]]; then
  echo "-- 6a/建立 Security Group --"
  DEFAULT_VPC="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0]')"
  VPC_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["VpcId"])' "$DEFAULT_VPC")"
  SG_JSON="$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "W3 inspection ${GROUP}-${OWNER}" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=course,Value=yuntech-115-1},{Key=week,Value=w03},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER}]")"
  SG_ID="$(json_get "$SG_JSON" GroupId)"
  write_resource sg_id "$SG_ID"

  echo "-- 6a2/加入入站規則（僅 TCP 22、80，來源 /32）--"
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" --ip-permissions \
    "[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"$SOURCE_CIDR\"}]},{\"IpProtocol\":\"tcp\",\"FromPort\":80,\"ToPort\":80,\"IpRanges\":[{\"CidrIp\":\"$SOURCE_CIDR\"}]}]" >/dev/null
else
  echo "-- 6a/SG 已存在: $SG_ID，跳過（含入站規則）--"
fi

KEY_PAIR_ID="$(read_resource key_pair_id)"
if [[ -z "$KEY_PAIR_ID" ]]; then
  echo "-- 6b/匯入 Key Pair（公鑰先自行 base64；此環境 CLI 對 file:// 不自動編碼）--"
  PUBKEY="$(ssh-keygen -y -f "$KEY_FILE")"
  PUBKEY_B64="$(printf '%s' "$PUBKEY" | base64 -w0)"
  KP_JSON="$(aws ec2 import-key-pair \
    --key-name "$KEY_NAME" \
    --public-key-material "$PUBKEY_B64" \
    --tag-specifications "ResourceType=key-pair,Tags=[{Key=course,Value=yuntech-115-1},{Key=week,Value=w03},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER}]")"
  KEY_PAIR_ID="$(json_get "$KP_JSON" KeyPairId)"
  write_resource key_pair_id "$KEY_PAIR_ID"
  write_resource key_file "$KEY_FILE"
else
  echo "-- 6b/key pair 已存在: $KEY_PAIR_ID，跳過 --"
fi

INSTANCE_ID="$(read_resource instance_id)"
if [[ -z "$INSTANCE_ID" ]]; then
  echo "-- 6c/啟動 EC2 instance --"
  RUN_JSON="$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --key-name "$KEY_NAME" \
    --user-data "file://$USER_DATA" \
    --block-device-mappings "[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true,\"Encrypted\":true}}]" \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=course,Value=yuntech-115-1},{Key=week,Value=w03},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER},{Key=Name,Value=w03-${GROUP}-${OWNER}}]" \
    --query 'Instances[0].{Id:InstanceId}' )"
  INSTANCE_ID="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["Id"])' <<<"$RUN_JSON")"
  write_resource instance_id "$INSTANCE_ID"
  write_resource commit "$FULL_COMMIT"
  write_resource created_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "instance: $INSTANCE_ID"
else
  echo "-- 6c/instance 已存在: $INSTANCE_ID，跳過 --"
fi

INSTANCE_ID="$(read_resource instance_id)"
[[ -n "$INSTANCE_ID" ]] || { echo "STOP: 沒有 instance ID" >&2; exit 1; }

# =====================================================================
echo "== 7/8 等待與五層觀測 =="
T() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# t1: running
T1=""
for i in $(seq 1 60); do
  ST="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].State.Name')"
  if [[ "$ST" == "running" ]]; then T1="$(T)"; echo "t1 running:        $T1"; break; fi
  sleep 3
done
[[ -n "$T1" ]] || { echo "STOP: instance did not reach running state within 3 minutes" >&2; exit 1; }
PUBLIC_IP=""
for i in $(seq 1 30); do
  PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' | tr -d '"')"
  [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != "null" ]] && break
  sleep 2
done
write_resource public_ip "$PUBLIC_IP"
echo "public ip: $PUBLIC_IP"

# early curl（記錄「服務還沒好」的真實失敗樣子）
echo "--- early curl（立即試一次 /health，預期失敗）---"
set +e
curl -sS --max-time 8 "http://${PUBLIC_IP}/health"; RC=$?
set -e
echo "--- curl exit=$RC（HTTP 000 表示沒收到 HTTP 回應）---"
echo "early_curl_exit=$RC" > .local/early-curl.txt

# t2: status checks 2/2
for i in $(seq 1 60); do
  S="$(aws ec2 describe-instance-status --instance-ids "$INSTANCE_ID" --query 'InstanceStatuses[0].{S:InstanceStatus.Status,SC:SystemStatus.Status}')"
  if [[ "$S" == *'"Impaired"'* ]] || [[ -z "$S" ]]; then sleep 5; continue; fi
  if [[ "$S" == *'"ok"'*'"ok"'* ]]; then T2="$(T)"; echo "t2 status 2/2:     $T2"; break; fi
  sleep 5
done

# SSH host key 核對（第一次連線，不關閉主機金鑰驗證）
echo "--- 核對主機指紋 ---"
HOSTKEY_LINE="$(ssh-keyscan -t ed25519 "$PUBLIC_IP" 2>/dev/null | head -1 || true)"
if [[ -z "$HOSTKEY_LINE" ]]; then echo "STOP: ssh-keyscan 拿不到 host key" >&2; exit 1; fi
FINGERPRINT="$(echo "$HOSTKEY_LINE" | ssh-keygen -lf -)"
echo "主機 ed25519 指紋：$FINGERPRINT"
if [[ "$(ssh-keygen -F "$PUBLIC_IP" >/dev/null 2>&1; echo $?)" != "0" ]]; then
  echo "$HOSTKEY_LINE" >> "$KNOWN_HOSTS"
  chmod 600 "$KNOWN_HOSTS"
  echo "host key 已加入 known_hosts（請你核對上方指紋）"
fi

SSH_CMD=(ssh -i "$KEY_FILE" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
  "${SSH_USER}@${PUBLIC_IP}")

# 等 SSH 可用（cloud-init 安裝中可能未就緒，最長 3 分鐘）
for i in $(seq 1 60); do
  if "${SSH_CMD[@]}" true >/dev/null 2>&1; then break; fi
  sleep 3
done

# t3: cloud-init 完成
echo "--- cloud-init status --wait（記錄執行前後）---"
T3_BEFORE="$(T)"
CI_OUT="$("${SSH_CMD[@]}" "sudo cloud-init status --wait 2>&1")"
T3_AFTER="$(T)"
echo "cloud-init: $CI_OUT  (before=$T3_BEFORE after=$T3_AFTER)"
T3="$T3_AFTER"
echo "t3 cloud-init done: $T3"

# t4: nginx 在 80、inspection 在 127.0.0.1:8080 監聽
LISTEN="$("${SSH_CMD[@]}" "sudo ss -tln 2>/dev/null | grep -E ':80 |:8080 ' || true")"
echo "--- 監聽狀態 ---"
echo "$LISTEN"
if [[ "$LISTEN" == *":80 "* && "$LISTEN" == *":8080 "* ]]; then
  T4="$(T)"; echo "t4 監聽(80/8080): $T4"
else
  echo "STOP: 監聽未齊全" >&2; exit 1
fi

# t5: /health 200 且 version=commit
for i in $(seq 1 20); do
  HEALTH="$(curl -sS --max-time 5 -w '\nHTTP_CODE:%{http_code}' "http://${PUBLIC_IP}/health" || true)"
  if [[ "$HEALTH" == *"HTTP_CODE:200"* ]]; then break; fi
  sleep 3
done
echo "--- /health ---"
echo "$HEALTH"
if [[ "$HEALTH" != *"HTTP_CODE:200"* ]]; then
  echo "STOP: /health 未回 200" >&2; exit 1
fi
BODY="$(echo "$HEALTH" | sed 's/HTTP_CODE:200//')"
VERSION_REPORTED="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["version"])' <<<"$BODY")"
HAS_OK="$(python3 -c 'import json,sys;d=json.loads(sys.stdin.read());print(d.get("status")=="ok" and d.get("service")=="inspection")' <<<"$BODY")"
if [[ "$VERSION_REPORTED" != "$FULL_COMMIT" ]]; then
  echo "STOP: version 不符（report=$VERSION_REPORTED expect=$FULL_COMMIT）" >&2
  exit 1
fi
if [[ "$HAS_OK" != "True" ]]; then
  echo "STOP: status/service 不符" >&2; exit 1
fi
T5="$(T)"
echo "t5 /health 200 + version 相符: $T5"

echo "== 8/8 完成 =="
echo "五層時間："
echo "  t1 running:        $T1"
echo "  t2 status 2/2:     $T2"
echo "  t3 cloud-init done: $T3"
echo "  t4 nginx+inspection 監聽: $T4"
echo "  t5 /health 200+version:  $T5"
echo "instance: $INSTANCE_ID  public_ip: $PUBLIC_IP  commit: $FULL_COMMIT"
echo "資源已記於 .local/resources.json；報告請另存五層時間（UTC）。"