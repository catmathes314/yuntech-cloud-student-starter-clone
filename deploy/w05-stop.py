#!/usr/bin/env python3
"""Stop only the verified W5 EC2 and private RDS instance; never delete resources."""
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab


def read_assignments(path, allowed):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in allowed or key in values or not value:
            raise ValueError(f"{path.name} has an invalid format")
        values[key] = value
    return values


def tag_map(items):
    return {item["Key"]: item["Value"] for item in items}


def has_expected_tags(items, expected):
    actual = tag_map(items)
    return all(actual.get(key) == value for key, value in expected.items())


def validate_ingress(permissions, expected):
    actual = set()
    for permission in permissions:
        if (permission.get("IpProtocol") != "tcp"
                or permission.get("Ipv6Ranges")
                or permission.get("PrefixListIds")):
            raise ValueError("security-group ingress differs from the approved rules")
        for item in permission.get("IpRanges", []):
            actual.add((
                permission.get("FromPort"),
                permission.get("ToPort"),
                item.get("CidrIp"),
            ))
        for item in permission.get("UserIdGroupPairs", []):
            actual.add((
                permission.get("FromPort"),
                permission.get("ToPort"),
                item.get("GroupId"),
            ))
    if actual != expected:
        raise ValueError("security-group ingress differs from the approved rules")


def load_scope():
    config = read_assignments(
        ROOT / ".local/config",
        {"GROUP", "OWNER", "REGION", "SOURCE_CIDR", "AMI_ID", "SUBNET_ID",
         "INSTANCE_TYPE", "KEY_NAME", "SG_NAME", "SSH_USER"},
    )
    resources_path = ROOT / ".local/resources.json"
    if resources_path.is_symlink():
        raise ValueError("resource manifest must not be a symlink")
    resources = json.loads(resources_path.read_text(encoding="utf-8"))
    values = {
        "instance_id": resources.get("instance_id"),
        "db_instance_identifier": resources.get("db_instance_identifier"),
        "db_security_group_id": resources.get("db_security_group_id"),
    }
    if (not re.fullmatch(r"i-[0-9a-f]+", str(values["instance_id"]))
            or not re.fullmatch(r"[A-Za-z0-9-]{1,63}", str(values["db_instance_identifier"]))
            or not re.fullmatch(r"sg-[0-9a-f]+", str(values["db_security_group_id"]))):
        raise ValueError("resource manifest is missing valid W05 resource IDs")
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}/32", config["SOURCE_CIDR"]):
        raise ValueError(".local/config must contain a single IPv4 /32 source")
    return config, values


def inspect(config, resources, region):
    group, owner = config["GROUP"], config["OWNER"]
    ec2_tags = {"course": "yuntech-115-1", "week": "w03", "group": group, "owner": owner}
    w05_tags = {"course": "yuntech-115-1", "week": "w05", "group": group, "owner": owner}

    result = lab.run_aws(
        ["ec2", "describe-instances", "--instance-ids", resources["instance_id"]],
        region,
    )
    instances = [
        item
        for reservation in result.get("Reservations", [])
        for item in reservation.get("Instances", [])
    ]
    if len(instances) != 1:
        raise ValueError("expected exactly one EC2 instance")
    instance = instances[0]
    if not has_expected_tags(instance.get("Tags", []), ec2_tags):
        raise ValueError("EC2 ownership tags do not match this course resource")
    instance_state = instance.get("State", {}).get("Name")
    if instance_state not in {"running", "stopped"}:
        raise ValueError(f"EC2 state is not safe to stop: {instance_state}")
    ec2_groups = instance.get("SecurityGroups", [])
    if len(ec2_groups) != 1:
        raise ValueError("expected exactly one EC2 security group")
    ec2_sg_id = ec2_groups[0]["GroupId"]
    sg_result = lab.run_aws(
        ["ec2", "describe-security-groups", "--group-ids", ec2_sg_id],
        region,
    )
    ec2_sgs = sg_result.get("SecurityGroups", [])
    if len(ec2_sgs) != 1 or not has_expected_tags(ec2_sgs[0].get("Tags", []), ec2_tags):
        raise ValueError("EC2 security-group ownership tags do not match")
    validate_ingress(
        ec2_sgs[0].get("IpPermissions", []),
        {(22, 22, config["SOURCE_CIDR"]), (80, 80, config["SOURCE_CIDR"])},
    )

    db_result = lab.run_aws(
        ["rds", "describe-db-instances", "--db-instance-identifier",
         resources["db_instance_identifier"]],
        region,
    )
    databases = db_result.get("DBInstances", [])
    if len(databases) != 1:
        raise ValueError("expected exactly one W05 RDS instance")
    database = databases[0]
    if (database.get("DBInstanceIdentifier") != resources["db_instance_identifier"]
            or database.get("Engine") != "postgres"
            or database.get("DBInstanceClass") != "db.t3.micro"
            or database.get("AllocatedStorage") != 20
            or database.get("StorageEncrypted") is not True
            or database.get("PubliclyAccessible") is not False):
        raise ValueError("RDS configuration does not match the approved private W05 database")
    db_state = database.get("DBInstanceStatus")
    if db_state not in {"available", "stopping", "stopped"}:
        raise ValueError(f"RDS state is not safe to stop: {db_state}")
    db_arns = [database.get("DBInstanceArn")]
    if not db_arns[0]:
        raise ValueError("RDS response is missing its resource ARN")
    tag_result = lab.run_aws(["rds", "list-tags-for-resource", "--resource-name", db_arns[0]], region)
    if not has_expected_tags(tag_result.get("TagList", []), w05_tags):
        raise ValueError("RDS ownership tags do not match this course resource")
    db_sgs = database.get("VpcSecurityGroups", [])
    if [item.get("VpcSecurityGroupId") for item in db_sgs] != [resources["db_security_group_id"]]:
        raise ValueError("RDS is not attached only to the manifest DB security group")
    db_sg_result = lab.run_aws(
        ["ec2", "describe-security-groups", "--group-ids", resources["db_security_group_id"]],
        region,
    )
    db_sg_list = db_sg_result.get("SecurityGroups", [])
    if len(db_sg_list) != 1 or not has_expected_tags(db_sg_list[0].get("Tags", []), w05_tags):
        raise ValueError("DB security-group ownership tags do not match")
    validate_ingress(
        db_sg_list[0].get("IpPermissions", []),
        {(5432, 5432, ec2_sg_id)},
    )
    return instance_state, db_state


def wait_for_state(service, identifier, expected, region, attempts, interval):
    if service == "rds":
        args = ["rds", "describe-db-instances", "--db-instance-identifier", identifier]
        get_state = lambda result: result.get("DBInstances", [{}])[0].get("DBInstanceStatus")
    else:
        args = ["ec2", "describe-instances", "--instance-ids", identifier]
        get_state = lambda result: result.get("Reservations", [{}])[0].get(
            "Instances", [{}]
        )[0].get("State", {}).get("Name")
    for _ in range(attempts):
        state = get_state(lab.run_aws(args, region))
        if state == expected:
            return
        time.sleep(interval)
    raise lab.LabError(f"{service} did not reach {expected} within the wait limit")


def main():
    try:
        config, resources = load_scope()
        context = lab.verify()
        if context["region"] != config["REGION"]:
            raise ValueError(".local/config region does not match the verified Learner Lab region")
        instance_state, db_state = inspect(config, resources, context["region"])
        print(
            "W05 T4 stop preview (no resources will be deleted):\n"
            f"  EC2: {resources['instance_id']} ({instance_state})\n"
            f"  RDS: {resources['db_instance_identifier']} ({db_state}), PostgreSQL, "
            "20 GiB encrypted, PubliclyAccessible=false\n"
            "  Network: EC2 inbound remains restricted to the configured /32 on TCP 22/80; "
            "RDS TCP 5432 remains limited to the EC2 security group.\n"
            "  Cost: stopped RDS instance-hours pause, but storage/backups may still incur "
            "charges; RDS automatically restarts after at most 7 consecutive stopped days. "
            "Exact Learner Lab credits and USD spend are unavailable.\n"
            "  Recovery: start RDS and wait for available, then start EC2; its public IP "
            "will change. This script does not delete or alter network resources."
        )
        if not sys.stdin.isatty() or input("Type exactly STOP-W05 to continue: ").strip() != "STOP-W05":
            raise lab.LabError("Cancelled; no resources were stopped.")

        if db_state in {"available", "stopping"}:
            if db_state == "available":
                lab.run_aws(
                    ["rds", "stop-db-instance", "--db-instance-identifier",
                     resources["db_instance_identifier"]],
                    context["region"],
                )
            wait_for_state(
                "rds", resources["db_instance_identifier"], "stopped",
                context["region"], 120, 5,
            )
        print(f"RDS {resources['db_instance_identifier']}: stopped")

        if instance_state == "running":
            lab.run_aws(
                ["ec2", "stop-instances", "--instance-ids", resources["instance_id"]],
                context["region"],
            )
            wait_for_state(
                "ec2", resources["instance_id"], "stopped",
                context["region"], 60, 3,
            )
        print(f"EC2 {resources['instance_id']}: stopped")
        print("W05 T4 complete; retained resources were not deleted.")
    except (lab.LabError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
