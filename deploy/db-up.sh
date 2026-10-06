#!/usr/bin/env bash
# W5 T2: build two private DB subnets and one private PostgreSQL RDS instance.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-.local/config}"
RESOURCES=".local/resources.json"
DB_ENV=".local/db.env"
if [[ ! -f "$CONFIG" || -L "$CONFIG" || ! -f "$RESOURCES" || -L "$RESOURCES" ]]; then
  echo "STOP: missing or unsafe .local configuration/resource manifest" >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG"
: "${GROUP:?}"; : "${OWNER:?}"; : "${REGION:?}"

command -v python3 >/dev/null || { echo "STOP: python3 is required" >&2; exit 1; }
bash scripts/verify-aws.sh

aws_json() {
  python3 - "$@" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
import lab
try:
    ctx = lab.context()
    result = lab.run_aws(sys.argv[1:], ctx["region"])
except lab.LabError as exc:
    raise SystemExit("STOP: " + str(exc)) from None
print(json.dumps(result))
PY
}

read_resource() {
  python3 - "$1" <<'PY'
import json, sys
with open(".local/resources.json", encoding="utf-8") as stream:
    print(json.load(stream).get(sys.argv[1], ""))
PY
}

write_resource() {
  python3 - "$1" "$2" <<'PY'
import json, os, sys
from pathlib import Path
path = Path(".local/resources.json")
data = json.loads(path.read_text(encoding="utf-8"))
data[sys.argv[1]] = sys.argv[2]
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
temporary.chmod(0o600)
os.replace(temporary, path)
PY
}

INSTANCE_ID="$(read_resource instance_id)"
if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]+$ ]]; then
  echo "STOP: active resource manifest has no valid EC2 instance_id" >&2
  exit 1
fi
SUBNET_A_ID="$(read_resource db_private_subnet_a_id)"
SUBNET_B_ID="$(read_resource db_private_subnet_b_id)"
MANIFEST_SUBNET_A_ID="$SUBNET_A_ID"
MANIFEST_SUBNET_B_ID="$SUBNET_B_ID"
ROUTE_TABLE_ID="$(read_resource db_private_route_table_id)"
DB_SG_ID="$(read_resource db_security_group_id)"
DB_SUBNET_GROUP="$(read_resource db_subnet_group_name)"
DB_INSTANCE_ID="$(read_resource db_instance_identifier)"
DB_INSTANCE_ID="${DB_INSTANCE_ID:-w05-${GROUP}-${OWNER}-postgres}"
DB_SUBNET_GROUP="${DB_SUBNET_GROUP:-w05-${GROUP}-${OWNER}-subnets}"

PLAN="$(python3 - "$INSTANCE_ID" "$GROUP" "$OWNER" "$REGION" "$SUBNET_A_ID" "$SUBNET_B_ID" <<'PY'
import ipaddress
import json
import sys
sys.path.insert(0, "scripts")
import lab

instance_id, group, owner, expected_region, subnet_a_id, subnet_b_id = sys.argv[1:]
try:
    ctx = lab.context()
    if ctx["region"] != expected_region:
        raise ValueError("verified region differs from .local/config")
    region = ctx["region"]
    result = lab.run_aws(["ec2", "describe-instances", "--instance-ids", instance_id], region)
    instances = [i for reservation in result.get("Reservations", []) for i in reservation.get("Instances", [])]
    if len(instances) != 1:
        raise ValueError("EC2 instance not found")
    instance = instances[0]
    tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
    expected_tags = {"course": "yuntech-115-1", "week": "w03", "group": group, "owner": owner}
    if any(tags.get(key) != value for key, value in expected_tags.items()):
        raise ValueError("EC2 ownership tags do not match")
    if instance.get("State", {}).get("Name") != "running":
        raise ValueError("EC2 instance is not running")
    security_groups = instance.get("SecurityGroups", [])
    if len(security_groups) != 1:
        raise ValueError("expected exactly one EC2 security group")
    ec2_sg_id = security_groups[0]["GroupId"]
    sg_result = lab.run_aws(["ec2", "describe-security-groups", "--group-ids", ec2_sg_id], region)
    ec2_sg = sg_result["SecurityGroups"][0]
    sg_tags = {item["Key"]: item["Value"] for item in ec2_sg.get("Tags", [])}
    if any(sg_tags.get(key) != value for key, value in expected_tags.items()):
        raise ValueError("EC2 security-group ownership tags do not match")

    vpc_result = lab.run_aws(["ec2", "describe-vpcs", "--vpc-ids", instance["VpcId"]], region)
    vpc = vpc_result["Vpcs"][0]
    vpc_cidrs = [ipaddress.ip_network(item["CidrBlock"]) for item in vpc.get("CidrBlockAssociationSet", [])
                 if item.get("CidrBlockState", {}).get("State") == "associated"]
    if not vpc_cidrs:
        vpc_cidrs = [ipaddress.ip_network(vpc["CidrBlock"])]

    subnet_result = lab.run_aws(["ec2", "describe-subnets", "--filters",
                                 "Name=vpc-id,Values=" + instance["VpcId"]], region)
    existing_subnets = subnet_result.get("Subnets", [])
    existing_networks = [ipaddress.ip_network(item["CidrBlock"]) for item in existing_subnets]
    available_azs = sorted(
        item["ZoneName"] for item in lab.run_aws(
            ["ec2", "describe-availability-zones", "--filters", "Name=state,Values=available"], region
        ).get("AvailabilityZones", []) if item.get("State") == "available"
    )
    expected_names = {"a": f"w05-{group}-{owner}-db-a", "b": f"w05-{group}-{owner}-db-b"}
    expected_subnet_tags = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}
    existing_by_id = {item["SubnetId"]: item for item in existing_subnets}
    subnet_data = {}
    for label, subnet_id in (("a", subnet_a_id), ("b", subnet_b_id)):
        if not subnet_id:
            named = [item for item in existing_subnets if any(
                tag.get("Key") == "Name" and tag.get("Value") == expected_names[label]
                for tag in item.get("Tags", [])
            )]
            if len(named) > 1:
                raise ValueError(f"multiple W05 subnet {label} resources found; inspect before retrying")
            if named:
                subnet = named[0]
                subnet_id = subnet["SubnetId"]
            else:
                continue
        else:
            subnet = existing_by_id.get(subnet_id)
        if subnet is None:
            raise ValueError(f"manifest subnet {label} does not exist in the EC2 VPC")
        subnet_tags = {item["Key"]: item["Value"] for item in subnet.get("Tags", [])}
        if (subnet.get("VpcId") != instance["VpcId"]
                or any(subnet_tags.get(key) != value for key, value in expected_subnet_tags.items())
                or subnet_tags.get("Name") != expected_names[label]):
            raise ValueError(f"manifest subnet {label} ownership does not match")
        subnet_data[label] = {
            "id": subnet_id,
            "cidr": subnet["CidrBlock"],
            "az": subnet["AvailabilityZone"],
        }

    occupied = list(existing_networks)
    for value in subnet_data.values():
        network = ipaddress.ip_network(value["cidr"])
        occupied = [item for item in occupied if item != network]

    def next_free():
        for network in sorted((item for base in vpc_cidrs for item in base.subnets(new_prefix=24)),
                              key=lambda item: (int(item.network_address), item.prefixlen)):
            if all(not network.overlaps(existing) for existing in occupied):
                occupied.append(network)
                return network
        raise ValueError("cannot find two non-overlapping /24s")

    selected_azs = [value["az"] for value in subnet_data.values()]
    if len(set(selected_azs)) != len(selected_azs):
        raise ValueError("private DB subnets must use different AZs")
    for label in ("a", "b"):
        if label in subnet_data:
            continue
        network = next_free()
        zone = next((az for az in available_azs if az not in selected_azs), None)
        if zone is None:
            raise ValueError("cannot find two distinct available AZs")
        subnet_data[label] = {"id": "", "cidr": str(network), "az": zone}
        selected_azs.append(zone)

    print(json.dumps({
        "instance_id": instance_id,
        "vpc_id": instance["VpcId"],
        "ec2_sg_id": ec2_sg_id,
        "private_subnet_a_id": subnet_data["a"]["id"],
        "private_subnet_a_cidr": subnet_data["a"]["cidr"],
        "private_subnet_a_az": subnet_data["a"]["az"],
        "private_subnet_b_id": subnet_data["b"]["id"],
        "private_subnet_b_cidr": subnet_data["b"]["cidr"],
        "private_subnet_b_az": subnet_data["b"]["az"],
    }))
except (lab.LabError, KeyError, IndexError, TypeError, ValueError) as exc:
    raise SystemExit("STOP: network/ownership preflight failed: " + str(exc)) from None
PY
)"

VPC_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["vpc_id"])' "$PLAN")"
EC2_SG_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["ec2_sg_id"])' "$PLAN")"
SUBNET_A_CIDR="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_a_cidr"])' "$PLAN")"
SUBNET_A_AZ="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_a_az"])' "$PLAN")"
SUBNET_B_CIDR="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_b_cidr"])' "$PLAN")"
SUBNET_B_AZ="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_b_az"])' "$PLAN")"
PLAN_SUBNET_A_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_a_id"])' "$PLAN")"
PLAN_SUBNET_B_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["private_subnet_b_id"])' "$PLAN")"
if [[ -z "$SUBNET_A_ID" && -n "$PLAN_SUBNET_A_ID" ]]; then
  SUBNET_A_ID="$PLAN_SUBNET_A_ID"
fi
if [[ -z "$SUBNET_B_ID" && -n "$PLAN_SUBNET_B_ID" ]]; then
  SUBNET_B_ID="$PLAN_SUBNET_B_ID"
fi

cat <<PREVIEW
W5 T2 preview (no AWS writes until the confirmation below):
  EC2 instance     : $INSTANCE_ID (running; no EC2 change)
  VPC              : $VPC_ID
  Private subnet A : $SUBNET_A_CIDR in $SUBNET_A_AZ
  Private subnet B : $SUBNET_B_CIDR in $SUBNET_B_AZ
  New route table  : W05 private-only (local route; no IGW/NAT routes)
  DB security group: TCP 5432 only, source EC2 SG $EC2_SG_ID
  DB subnet group  : $DB_SUBNET_GROUP
  RDS instance     : $DB_INSTANCE_ID, PostgreSQL, db.t3.micro, 20 GiB gp3,
                     encrypted, Single-AZ, PubliclyAccessible=false
  Local secret     : $DB_ENV (mode 600; password never printed or passed as an argument)
  Network exposure: Codespace cannot connect to RDS; only the EC2 SG can reach TCP 5432.
  Cost exposure    : RDS instance-hours and 20 GiB storage while provisioned; EC2 continues
                     billing while running. RDS storage (and retained backup storage) may
                     still incur charges while stopped. Exact Learner Lab credits and
                     public price lookup are unavailable in this session; no USD quote
                     or spending cap can be asserted.
  Recovery         : T4 stops the DB and EC2; RDS may restart automatically after 7 days.
                     This script does not delete resources.
PREVIEW
if [[ ! -t 0 ]]; then
  echo "STOP: interactive confirmation is required; no RDS resources created" >&2
  exit 1
fi
read -r -p 'Type exactly CREATE-W05-RDS to continue: ' CONFIRM
if [[ "$CONFIRM" != "CREATE-W05-RDS" ]]; then
  echo "Cancelled; no AWS resources created."
  exit 0
fi
if [[ -z "$MANIFEST_SUBNET_A_ID" && -n "$SUBNET_A_ID" ]]; then
  write_resource db_private_subnet_a_id "$SUBNET_A_ID"
fi
if [[ -z "$MANIFEST_SUBNET_B_ID" && -n "$SUBNET_B_ID" ]]; then
  write_resource db_private_subnet_b_id "$SUBNET_B_ID"
fi

if [[ -e "$DB_ENV" || -L "$DB_ENV" ]]; then
  if [[ -L "$DB_ENV" || "$(stat -c '%a' "$DB_ENV")" != "600" ]]; then
    echo "STOP: $DB_ENV exists but is unsafe; no AWS resources created" >&2
    exit 1
  fi
  python3 - "$DB_ENV" <<'PY'
import re, sys
from pathlib import Path
allowed = {"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"}
values = {}
try:
    for line in Path(sys.argv[1]).read_text(encoding="ascii").splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in allowed or key in values or "\n" in value:
            raise ValueError
        values[key] = value
    if set(values) != allowed or values["DB_PORT"] != "5432" or values["DB_NAME"] != "inspection" \
            or values["DB_USER"] != "inspection" or not re.fullmatch(r"[A-Za-z0-9_-]{32,}", values["DB_PASSWORD"]):
        raise ValueError
except (OSError, UnicodeError, ValueError):
    raise SystemExit("STOP: existing database secret file has an invalid format.") from None
PY
else
  python3 - "$DB_ENV" <<'PY'
import os, secrets, sys
from pathlib import Path
path = Path(sys.argv[1])
password = secrets.token_urlsafe(36)
with path.open("x", encoding="ascii") as stream:
    os.chmod(path, 0o600)
    stream.write("DB_HOST=\nDB_PORT=5432\nDB_NAME=inspection\nDB_USER=inspection\nDB_PASSWORD=" + password + "\n")
PY
fi
[[ "$(stat -c '%a' "$DB_ENV")" == "600" ]] || { echo "STOP: database secret file is not mode 600" >&2; exit 1; }
# shellcheck disable=SC1090
. "$DB_ENV"

TAGS="[{Key=course,Value=yuntech-115-1},{Key=week,Value=w05},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER}]"
TAGS_JSON="$(python3 - "$GROUP" "$OWNER" <<'PY'
import json, sys
group, owner = sys.argv[1:]
print(json.dumps([
    {"Key": "course", "Value": "yuntech-115-1"},
    {"Key": "week", "Value": "w05"},
    {"Key": "group", "Value": group},
    {"Key": "owner", "Value": owner},
]))
PY
)"
ROUTE_TABLE_TAGS="[{Key=course,Value=yuntech-115-1},{Key=week,Value=w05},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER},{Key=Name,Value=w05-${GROUP}-${OWNER}-db-private}]"
SUBNET_A_TAGS="[{Key=course,Value=yuntech-115-1},{Key=week,Value=w05},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER},{Key=Name,Value=w05-${GROUP}-${OWNER}-db-a}]"
SUBNET_B_TAGS="[{Key=course,Value=yuntech-115-1},{Key=week,Value=w05},{Key=group,Value=$GROUP},{Key=owner,Value=$OWNER},{Key=Name,Value=w05-${GROUP}-${OWNER}-db-b}]"

if [[ -z "$SUBNET_A_ID" ]]; then
  SUBNET_A_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("Subnet",{}).get("SubnetId",""))' \
    "$(aws_json ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$SUBNET_A_CIDR" --availability-zone "$SUBNET_A_AZ" \
      --tag-specifications "ResourceType=subnet,Tags=$SUBNET_A_TAGS")")"
  write_resource db_private_subnet_a_id "$SUBNET_A_ID"
fi
if [[ -z "$SUBNET_B_ID" ]]; then
  SUBNET_B_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("Subnet",{}).get("SubnetId",""))' \
    "$(aws_json ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$SUBNET_B_CIDR" --availability-zone "$SUBNET_B_AZ" \
      --tag-specifications "ResourceType=subnet,Tags=$SUBNET_B_TAGS")")"
  write_resource db_private_subnet_b_id "$SUBNET_B_ID"
fi
if [[ -z "$ROUTE_TABLE_ID" ]]; then
  ROUTE_TABLE_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("RouteTable",{}).get("RouteTableId",""))' \
    "$(aws_json ec2 create-route-table --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=route-table,Tags=$ROUTE_TABLE_TAGS")")"
  write_resource db_private_route_table_id "$ROUTE_TABLE_ID"
fi
python3 - "$ROUTE_TABLE_ID" "$GROUP" "$OWNER" \
  "$(aws_json ec2 describe-route-tables --route-table-ids "$ROUTE_TABLE_ID")" <<'PY'
import json, sys
table_id, group, owner, raw = sys.argv[1:]
tables = json.loads(raw).get("RouteTables", [])
if len(tables) != 1 or tables[0].get("RouteTableId") != table_id:
    raise SystemExit("STOP: private route table not found.")
routes = tables[0].get("Routes", [])
tags = {item["Key"]: item["Value"] for item in tables[0].get("Tags", [])}
expected = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}
if any(tags.get(key) != value for key, value in expected.items()):
    raise SystemExit("STOP: route-table ownership tags do not match.")
if (len(routes) != 1 or routes[0].get("GatewayId") != "local"
        or routes[0].get("State") != "active" or not routes[0].get("DestinationCidrBlock")):
    raise SystemExit("STOP: route table is not verified as local-only.")
PY
for SUBNET_ID in "$SUBNET_A_ID" "$SUBNET_B_ID"; do
  aws_json ec2 modify-subnet-attribute --subnet-id "$SUBNET_ID" --no-map-public-ip-on-launch >/dev/null
  SUBNET_READBACK="$(aws_json ec2 describe-subnets --subnet-ids "$SUBNET_ID")"
  python3 - "$SUBNET_READBACK" "$VPC_ID" "$GROUP" "$OWNER" <<'PY'
import json, sys
raw, vpc, group, owner = sys.argv[1:]
subnets = json.loads(raw).get("Subnets", [])
if len(subnets) != 1:
    raise SystemExit("STOP: expected exactly one DB subnet.")
subnet = subnets[0]
tags = {item["Key"]: item["Value"] for item in subnet.get("Tags", [])}
expected = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}
if (subnet.get("VpcId") != vpc or subnet.get("MapPublicIpOnLaunch") is not False
        or any(tags.get(key) != value for key, value in expected.items())):
    raise SystemExit("STOP: DB subnet is not private or ownership tags do not match.")
PY
  ASSOCIATIONS="$(aws_json ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$SUBNET_ID")"
  EXISTING_ROUTE_TABLE="$(python3 - "$ASSOCIATIONS" <<'PY'
import json, sys
tables = json.loads(sys.argv[1]).get("RouteTables", [])
if len(tables) > 1:
    raise SystemExit("STOP: subnet has multiple explicit route-table associations.")
print(tables[0]["RouteTableId"] if tables else "")
PY
)"
  if [[ -n "$EXISTING_ROUTE_TABLE" && "$EXISTING_ROUTE_TABLE" != "$ROUTE_TABLE_ID" ]]; then
    echo "STOP: DB subnet is explicitly associated with another route table" >&2
    exit 1
  fi
  if [[ -z "$EXISTING_ROUTE_TABLE" ]]; then
    aws_json ec2 associate-route-table --route-table-id "$ROUTE_TABLE_ID" --subnet-id "$SUBNET_ID" >/dev/null
  fi
done

if [[ -z "$DB_SG_ID" ]]; then
  DB_SG_ID="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("GroupId",""))' \
    "$(aws_json ec2 create-security-group --group-name "w05-${GROUP}-${OWNER}-db" \
      --description "W05 PostgreSQL access only from the course EC2 security group" --vpc-id "$VPC_ID" \
      --tag-specifications "ResourceType=security-group,Tags=$TAGS")")"
  write_resource db_security_group_id "$DB_SG_ID"
fi
DB_SG_INFO="$(aws_json ec2 describe-security-groups --group-ids "$DB_SG_ID")"
DB_SG_INGRESS="$(python3 - "$DB_SG_INFO" "$GROUP" "$OWNER" "$EC2_SG_ID" <<'PY'
import json, sys
result = json.loads(sys.argv[1])["SecurityGroups"]
group, owner, source = sys.argv[2:]
if len(result) != 1:
    raise SystemExit("STOP: W05 database security group not found.")
sg = result[0]
tags = {item["Key"]: item["Value"] for item in sg.get("Tags", [])}
expected = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}
if any(tags.get(key) != value for key, value in expected.items()):
    raise SystemExit("STOP: database security-group ownership tags do not match.")
permissions = sg.get("IpPermissions", [])
if not permissions:
    print("missing")
elif len(permissions) == 1:
    pairs = permissions[0].get("UserIdGroupPairs", [])
    if (permissions[0].get("IpProtocol") == "tcp"
            and permissions[0].get("FromPort") == 5432 and permissions[0].get("ToPort") == 5432
            and len(pairs) == 1 and pairs[0].get("GroupId") == source
            and not permissions[0].get("IpRanges") and not permissions[0].get("Ipv6Ranges")
            and not permissions[0].get("PrefixListIds")):
        print("correct")
    else:
        raise SystemExit("STOP: database security group has unexpected inbound rules.")
else:
    raise SystemExit("STOP: database security group has unexpected inbound rules.")
PY
)"
if [[ "$DB_SG_INGRESS" == "missing" ]]; then
  aws_json ec2 authorize-security-group-ingress --group-id "$DB_SG_ID" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":5432,\"ToPort\":5432,\"UserIdGroupPairs\":[{\"GroupId\":\"$EC2_SG_ID\"}]}]" >/dev/null
fi

if [[ -z "$(read_resource db_subnet_group_name)" ]]; then
  aws_json rds create-db-subnet-group --db-subnet-group-name "$DB_SUBNET_GROUP" \
    --db-subnet-group-description "W05 private PostgreSQL subnets" \
    --subnet-ids "$SUBNET_A_ID" "$SUBNET_B_ID" --tags "$TAGS_JSON" >/dev/null
  write_resource db_subnet_group_name "$DB_SUBNET_GROUP"
fi

if [[ -z "$(read_resource db_instance_identifier)" ]]; then
  REQUEST_FILE="$(mktemp .local/rds-create.XXXXXX.json)"
  trap 'rm -f -- "$REQUEST_FILE"' EXIT
  python3 - "$REQUEST_FILE" "$DB_ENV" "$DB_INSTANCE_ID" "$DB_SG_ID" "$DB_SUBNET_GROUP" "$GROUP" "$OWNER" <<'PY'
import json, os, sys
from pathlib import Path
request_path, env_path, identifier, security_group, subnet_group, group, owner = sys.argv[1:]
values = {}
for line in Path(env_path).read_text(encoding="ascii").splitlines():
    key, _, value = line.partition("=")
    values[key] = value
request = {
    "DBInstanceIdentifier": identifier,
    "Engine": "postgres",
    "DBInstanceClass": "db.t3.micro",
    "AllocatedStorage": 20,
    "StorageType": "gp3",
    "StorageEncrypted": True,
    "Port": 5432,
    "DBName": values["DB_NAME"],
    "MasterUsername": values["DB_USER"],
    "MasterUserPassword": values["DB_PASSWORD"],
    "DBSubnetGroupName": subnet_group,
    "VpcSecurityGroupIds": [security_group],
    "PubliclyAccessible": False,
    "MultiAZ": False,
    "Tags": [
        {"Key": "course", "Value": "yuntech-115-1"},
        {"Key": "week", "Value": "w05"},
        {"Key": "group", "Value": group},
        {"Key": "owner", "Value": owner},
    ],
}
path = Path(request_path)
path.write_text(json.dumps(request), encoding="utf-8")
os.chmod(path, 0o600)
PY
  aws_json rds create-db-instance --cli-input-json "file://$REQUEST_FILE" >/dev/null
  rm -f -- "$REQUEST_FILE"
  trap - EXIT
  write_resource db_instance_identifier "$DB_INSTANCE_ID"
fi

echo "Waiting for RDS instance to become available (this can take several minutes)."
DB_INFO=""
DB_STATUS=""
for attempt in $(seq 1 60); do
  DB_INFO="$(aws_json rds describe-db-instances --db-instance-identifier "$DB_INSTANCE_ID")"
  DB_STATUS="$(python3 -c 'import json,sys; rows=json.loads(sys.argv[1]).get("DBInstances",[]); print(rows[0].get("DBInstanceStatus","missing") if len(rows)==1 else "missing")' "$DB_INFO")"
  if [[ "$DB_STATUS" == "available" ]]; then
    break
  fi
  if [[ "$DB_STATUS" == "failed" || "$DB_STATUS" == "inaccessible-encryption-credentials-recoverable" ]]; then
    echo "STOP: RDS entered terminal/unavailable status '$DB_STATUS'; inspect before recovery." >&2
    exit 1
  fi
  echo "RDS status: $DB_STATUS (check $attempt/60)"
  sleep 15
done
[[ "$DB_STATUS" == "available" ]] || {
  echo "STOP: RDS did not become available within the polling window; status=$DB_STATUS" >&2
  exit 1
}
DB_ARN="$(python3 - "$DB_INFO" "$DB_INSTANCE_ID" <<'PY'
import json, sys
instances = json.loads(sys.argv[1]).get("DBInstances", [])
if len(instances) != 1 or instances[0].get("DBInstanceIdentifier") != sys.argv[2]:
    raise SystemExit("STOP: expected exactly one RDS instance in read-back.")
print(instances[0]["DBInstanceArn"])
PY
)"
DB_TAGS="$(aws_json rds list-tags-for-resource --resource-name "$DB_ARN")"
DB_HOST="$(python3 - "$DB_INFO" "$DB_TAGS" "$DB_INSTANCE_ID" "$DB_SG_ID" "$DB_SUBNET_GROUP" "$SUBNET_A_ID" "$SUBNET_B_ID" "$GROUP" "$OWNER" <<'PY'
import json, sys
raw, tags_raw, identifier, security_group, subnet_group, subnet_a, subnet_b, group, owner = sys.argv[1:]
instances = json.loads(raw).get("DBInstances", [])
if len(instances) != 1:
    raise SystemExit("STOP: expected exactly one RDS instance in read-back.")
result = instances[0]
expected_tags = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}
tags = {item["Key"]: item["Value"] for item in json.loads(tags_raw).get("TagList", [])}
security_groups = {item["VpcSecurityGroupId"] for item in result.get("VpcSecurityGroups", [])}
subnet_ids = {item["SubnetIdentifier"] for item in
              result.get("DBSubnetGroup", {}).get("Subnets", [])}
if (result.get("DBInstanceIdentifier") != identifier
        or result.get("DBInstanceStatus") != "available"
        or result.get("Engine") != "postgres"
        or result.get("DBInstanceClass") != "db.t3.micro"
        or result.get("AllocatedStorage") != 20
        or result.get("StorageType") != "gp3"
        or result.get("StorageEncrypted") is not True
        or result.get("Endpoint", {}).get("Port") != 5432
        or result.get("PubliclyAccessible") is not False
        or result.get("MultiAZ") is not False
        or result.get("DBName") != "inspection"
        or result.get("DBSubnetGroup", {}).get("DBSubnetGroupName") != subnet_group
        or subnet_ids != {subnet_a, subnet_b}
        or security_groups != {security_group}
        or any(tags.get(key) != value for key, value in expected_tags.items())):
    raise SystemExit("STOP: RDS read-back does not match the approved private configuration.")
print(result["Endpoint"]["Address"])
PY
)"
python3 - "$DB_ENV" "$DB_HOST" <<'PY'
import os, sys
from pathlib import Path
path, host = Path(sys.argv[1]), sys.argv[2]
values = {}
for line in path.read_text(encoding="ascii").splitlines():
    key, _, value = line.partition("=")
    values[key] = value
values["DB_HOST"] = host
temporary = path.with_suffix(".env.tmp")
temporary.write_text("".join(key + "=" + values[key] + "\n" for key in
                             ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")),
                     encoding="ascii")
temporary.chmod(0o600)
os.replace(temporary, path)
PY
write_resource db_endpoint "$DB_HOST"
write_resource db_instance_arn "$DB_ARN"
echo "RDS available; PubliclyAccessible=false; endpoint stored in .local/db.env (not printed)."
