#!/usr/bin/env python3
"""Create the narrowly scoped Lab 6 IoT identities and local credential files."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab


class SetupError(Exception):
    pass


def write_new_secret(path, value):
    if path.is_symlink() or path.exists():
        raise SetupError(f"Refusing to overwrite existing credential file: {path.name}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_replace(path, value):
    lab.atomic_write(path, value)
    os.chmod(path, 0o600)


def load_resources(path):
    if path.is_symlink() or not path.is_file():
        raise SetupError("Missing or unsafe .local/resources.json.")
    try:
        resources = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SetupError("Invalid .local/resources.json.") from None
    if not isinstance(resources, dict):
        raise SetupError("Invalid .local/resources.json.")
    return resources


def persist_resources(path, resources):
    write_replace(path, json.dumps(resources, indent=2, sort_keys=True) + "\n")


def expected_policy(role, code, region, account):
    topic = f"cxe/{code}/gw/events"
    if role == "gw":
        client_id = f"gw-{code}"
        actions = [
            ("iot:Connect", f"client/{client_id}"),
            ("iot:Publish", f"topic/{topic}"),
        ]
    else:
        client_id = f"consumer-{code}"
        actions = [
            ("iot:Connect", f"client/{client_id}"),
            ("iot:Subscribe", f"topicfilter/{topic}"),
            ("iot:Receive", f"topic/{topic}"),
        ]
    statements = [
        {
            "Effect": "Allow",
            "Action": action,
            "Resource": f"arn:aws:iot:{region}:{account}:{resource}",
        }
        for action, resource in actions
    ]
    return f"cxe-{code}-{role}", {"Version": "2012-10-17", "Statement": statements}


def ensure_policy(name, document, region):
    expected = json.dumps(document, separators=(",", ":"), sort_keys=True)
    try:
        policy = lab.run_aws(["iot", "get-policy", "--policy-name", name], region)
    except lab.LabError as error:
        if "ResourceNotFoundException" not in str(error):
            raise
        policy = lab.run_aws(
            ["iot", "create-policy", "--policy-name", name, "--policy-document", expected],
            region,
        )
        return policy["policyArn"]

    version = lab.run_aws(
        [
            "iot", "get-policy-version", "--policy-name", name,
            "--policy-version-id", policy["defaultVersionId"],
        ],
        region,
    )
    try:
        actual = json.loads(version["policyDocument"])
    except (KeyError, TypeError, json.JSONDecodeError):
        raise SetupError(f"Could not safely verify existing policy {name}.") from None
    if actual != document:
        raise SetupError(f"Existing policy {name} differs from the required least-privilege policy.")
    return policy["policyArn"]


def ensure_certificate(role, code, resources, iot_dir, region):
    id_key = f"iot_{role}_cert_id"
    cert_name = f"{role}.cert.pem"
    key_name = f"{role}.private.key"
    certificate_id = resources.get(id_key)
    if certificate_id is not None:
        if not isinstance(certificate_id, str) or not re.fullmatch(r"[0-9a-f]{64}", certificate_id):
            raise SetupError(f"Invalid {id_key} in .local/resources.json.")
        for filename in (cert_name, key_name):
            path = iot_dir / filename
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
                raise SetupError(f"Existing {filename} is missing, unsafe, or not mode 600.")
        return certificate_id

    if (iot_dir / cert_name).exists() or (iot_dir / key_name).exists():
        raise SetupError(f"Credential files for {role} exist but its resource ID is missing; inspect before retrying.")
    result = lab.run_aws(
        ["iot", "create-keys-and-certificate", "--set-as-active"],
        region,
    )
    certificate_id = result.get("certificateId")
    certificate_pem = result.get("certificatePem")
    private_key = result.get("keyPair", {}).get("PrivateKey")
    if (not isinstance(certificate_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", certificate_id)
            or not isinstance(certificate_pem, str)
            or not certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
            or not isinstance(private_key, str)
            or not private_key.startswith("-----BEGIN")):
        raise SetupError(f"AWS returned an invalid {role} certificate response.")
    cert_path = iot_dir / cert_name
    key_path = iot_dir / key_name
    created = []
    try:
        write_new_secret(cert_path, certificate_pem)
        created.append(cert_path)
        write_new_secret(key_path, private_key)
        created.append(key_path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    resources[id_key] = certificate_id
    persist_resources(ROOT / ".local/resources.json", resources)
    return certificate_id


def ensure_root_ca(iot_dir):
    path = iot_dir / "AmazonRootCA1.pem"
    if path.is_symlink():
        raise SetupError("Refusing a symlink for AmazonRootCA1.pem.")
    if path.is_file():
        if path.stat().st_mode & 0o777 != 0o600:
            raise SetupError("AmazonRootCA1.pem must have mode 600.")
        if not path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----"):
            raise SetupError("Existing AmazonRootCA1.pem is invalid.")
        return
    try:
        with urlopen(
            "https://www.amazontrust.com/repository/AmazonRootCA1.pem",
            timeout=15,
        ) as response:
            data = response.read(1024 * 1024 + 1)
    except (URLError, TimeoutError, OSError) as error:
        raise SetupError("Could not download Amazon Root CA 1: " + type(error).__name__) from None
    if len(data) > 1024 * 1024 or not data.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise SetupError("Downloaded Amazon Root CA 1 is invalid.")
    write_new_secret(path, data.decode("ascii"))


def run(code):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", code):
        raise SetupError("Code must match [A-Za-z0-9-]{1,40}.")
    context = lab.verify()
    region = context["region"]
    account = context["account"]
    local_dir = ROOT / ".local"
    if local_dir.is_symlink() or not local_dir.is_dir():
        raise SetupError("Missing or unsafe .local directory.")
    iot_dir = ROOT / ".local/iot"
    iot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if iot_dir.is_symlink() or not iot_dir.is_dir():
        raise SetupError("Refusing an unsafe .local/iot directory.")
    os.chmod(iot_dir, 0o700)
    resources_path = ROOT / ".local/resources.json"
    resources = load_resources(resources_path)

    endpoint_file = iot_dir / "endpoint"
    if endpoint_file.is_symlink():
        raise SetupError("Refusing a symlink for the IoT endpoint file.")
    if not endpoint_file.is_file():
        endpoint = lab.run_aws(
            ["iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS"],
            region,
        ).get("endpointAddress", "")
        if not isinstance(endpoint, str) or not re.fullmatch(
            r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint
        ):
            raise SetupError("AWS returned an invalid IoT data endpoint.")
        write_replace(endpoint_file, endpoint + "\n")
    elif endpoint_file.stat().st_mode & 0o777 != 0o600:
        raise SetupError("Existing IoT endpoint file must have mode 600.")
    endpoint = endpoint_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(
        r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint
    ):
        raise SetupError("Existing IoT endpoint file is invalid.")
    ensure_root_ca(iot_dir)

    cert_ids = {}
    policy_names = {}
    for role in ("gw", "consumer"):
        cert_id = ensure_certificate(role, code, resources, iot_dir, region)
        cert_ids[role] = cert_id
        policy_name, document = expected_policy(role, code, region, account)
        existing_name = resources.get(f"iot_{role}_policy")
        if existing_name is not None and existing_name != policy_name:
            raise SetupError(f"Existing {role} policy name does not match this code.")
        ensure_policy(policy_name, document, region)
        lab.run_aws(
            [
                "iot", "attach-policy",
                "--policy-name", policy_name,
                "--target", f"arn:aws:iot:{region}:{account}:cert/{cert_id}",
            ],
            region,
        )
        resources[f"iot_{role}_policy"] = policy_name
        persist_resources(resources_path, resources)
        policy_names[role] = policy_name

    for role, cert_id in cert_ids.items():
        status = lab.run_aws(
            ["iot", "describe-certificate", "--certificate-id", cert_id],
            region,
        ).get("certificateDescription", {}).get("status")
        if status != "ACTIVE":
            raise SetupError(f"The {role} certificate is not ACTIVE.")
    print("IoT setup verified: gateway and consumer certificates ACTIVE; scoped policies attached.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your group-member code, e.g. g03-m2")
    args = parser.parse_args()
    try:
        run(args.code)
    except (SetupError, lab.LabError, OSError, KeyError, TypeError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
