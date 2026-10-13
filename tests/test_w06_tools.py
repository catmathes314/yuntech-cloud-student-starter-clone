"""Offline checks for Lab 6 IoT policies, message shape, and reconciliation safety."""
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iot_up = load_module("w06_iot_up", "deploy/iot_up.py")
gateway = load_module("w06_gateway", "tools/gateway_sim.py")
mqtt_check = load_module("w06_mqtt_check", "tools/mqtt_check.py")
reconcile = load_module("w06_reconcile", "tests/w06_reconcile.py")


class IoTPolicyTests(unittest.TestCase):
    def test_gateway_policy_is_exactly_scoped(self):
        name, document = iot_up.expected_policy("gw", "g03-m2", "us-east-1", "123456789012")
        self.assertEqual(name, "cxe-g03-m2-gw")
        self.assertEqual(
            [(statement["Action"], statement["Resource"]) for statement in document["Statement"]],
            [
                ("iot:Connect", "arn:aws:iot:us-east-1:123456789012:client/gw-g03-m2"),
                ("iot:Publish", "arn:aws:iot:us-east-1:123456789012:topic/cxe/g03-m2/gw/events"),
            ],
        )
        self.assertNotIn("*", str(document))

    def test_iot_setup_writes_private_credentials_once_without_printing_them(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, limit):
                return b"-----BEGIN CERTIFICATE-----\nroot-ca\n"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / ".local"
            local.mkdir()
            resources_path = local / "resources.json"
            resources_path.write_text('{"instance_id":"i-0123456789abcdef0"}\n')
            calls = []
            policies = {}
            certificate_count = 0

            def fake_aws(args, region):
                nonlocal certificate_count
                calls.append((args, region))
                if args[:2] == ["iot", "describe-endpoint"]:
                    return {"endpointAddress": "example-ats.iot.us-east-1.amazonaws.com"}
                if args[:2] == ["iot", "create-keys-and-certificate"]:
                    certificate_count += 1
                    return {
                        "certificateId": f"{certificate_count:064x}",
                        "certificatePem": "-----BEGIN CERTIFICATE-----\ncertificate\n",
                        "keyPair": {"PrivateKey": "-----BEGIN PRIVATE KEY-----SYNTHETIC"},
                    }
                if args[:2] == ["iot", "get-policy"]:
                    name = args[args.index("--policy-name") + 1]
                    if name not in policies:
                        raise iot_up.lab.LabError(
                            "iot get-policy: ResourceNotFoundException."
                        )
                    return {"policyArn": "arn:policy", "defaultVersionId": "1"}
                if args[:2] == ["iot", "create-policy"]:
                    name = args[args.index("--policy-name") + 1]
                    policy = json.loads(args[args.index("--policy-document") + 1])
                    policies[name] = policy
                    return {"policyArn": "arn:policy"}
                if args[:2] == ["iot", "get-policy-version"]:
                    name = args[args.index("--policy-name") + 1]
                    return {"policyDocument": json.dumps(policies[name])}
                if args[:2] == ["iot", "describe-certificate"]:
                    return {"certificateDescription": {"status": "ACTIVE"}}
                if args[:2] == ["iot", "attach-policy"]:
                    return {}
                raise AssertionError("unexpected AWS operation")

            output = io.StringIO()
            with (
                patch.object(iot_up, "ROOT", root),
                patch.object(iot_up.lab, "verify", return_value={
                    "region": "us-east-1",
                    "account": "123456789012",
                }),
                patch.object(iot_up.lab, "run_aws", side_effect=fake_aws),
                patch.object(iot_up, "urlopen", return_value=FakeResponse()),
                patch("sys.stdout", output),
            ):
                iot_up.run("g03-m2")
                iot_up.run("g03-m2")

            self.assertEqual(certificate_count, 2)
            self.assertEqual(
                sum(args[:2] == ["iot", "create-policy"] for args, _ in calls),
                2,
            )
            self.assertNotIn("SYNTHETIC", output.getvalue())
            iot_dir = local / "iot"
            self.assertEqual(iot_dir.stat().st_mode & 0o777, 0o700)
            for filename in (
                "gw.private.key", "consumer.private.key", "gw.cert.pem",
                "consumer.cert.pem", "AmazonRootCA1.pem", "endpoint",
            ):
                self.assertEqual((iot_dir / filename).stat().st_mode & 0o777, 0o600)
            resources = json.loads(resources_path.read_text(encoding="utf-8"))
            self.assertEqual(resources["iot_gw_cert_id"], "0" * 63 + "1")
            self.assertEqual(resources["iot_consumer_cert_id"], "0" * 63 + "2")

    def test_consumer_policy_uses_topicfilter_for_subscribe(self):
        name, document = iot_up.expected_policy(
            "consumer", "g03-m2", "us-east-1", "123456789012"
        )
        self.assertEqual(name, "cxe-g03-m2-consumer")
        resources = {
            statement["Action"]: statement["Resource"]
            for statement in document["Statement"]
        }
        self.assertEqual(
            resources["iot:Subscribe"],
            "arn:aws:iot:us-east-1:123456789012:topicfilter/cxe/g03-m2/gw/events",
        )
        self.assertNotIn("*", str(document))

    def test_gateway_sends_thirty_events_duplicate_and_out_of_list_device(self):
        events = gateway.build_events("g03-m2", "g03-m2-r1")
        self.assertEqual(len(events), 32)
        self.assertEqual(events[0], events[30])
        self.assertEqual(events[-1]["device_id"], "g03-m2-d99")
        self.assertEqual(events[-1]["event_id"], "g03-m2-r1-d99-01")
        self.assertEqual(
            {event["type"] for event in events},
            {"status"},
        )

    def test_gateway_checks_combined_prefix_before_network_setup(self):
        with self.assertRaises(gateway.GatewayError):
            gateway.run("invalid code", "r1")


class MqttCheckTests(unittest.TestCase):
    def test_secret_reader_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gw.private.key"
            path.write_text("synthetic-key", encoding="ascii")
            path.chmod(0o644)
            with patch.object(mqtt_check, "IOT_DIR", Path(directory)):
                with self.assertRaises(mqtt_check.MqttCheckError):
                    mqtt_check.read_iot_file(path.name)
            path.chmod(0o600)
            with patch.object(mqtt_check, "IOT_DIR", Path(directory)):
                self.assertEqual(mqtt_check.read_iot_file(path.name), "synthetic-key")


class ReconciliationTests(unittest.TestCase):
    def test_remote_reconciliation_shell_parses(self):
        result = subprocess.run(
            ["bash", "-n"],
            input=reconcile.REMOTE_RECONCILE,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prefix_is_passed_as_psql_variable_not_sql_text(self):
        self.assertIn('--set=prefix="${PREFIX}-"', reconcile.REMOTE_RECONCILE)
        self.assertIn("length(:'prefix')", reconcile.REMOTE_RECONCILE)
        self.assertNotIn("event_id LIKE", reconcile.REMOTE_RECONCILE)

    def test_remote_counts_and_safe_log_lines_are_parsed(self):
        output = (
            "consumer_created=30\n"
            "consumer_duplicate=1\n"
            "consumer_rejected=1\n"
            "consumer_error=0\n"
            "database_count=30\n"
            "consumer_log_begin\n"
            "event_id=g03-m2-r1-d01-01 result=created\n"
            "event_id=g03-m2-r1-d99-01 result=rejected\n"
            "consumer_log_end"
        )
        result, logs = reconcile.parse_remote(output)
        self.assertEqual(result["database_count"], "30")
        self.assertEqual(len(logs), 2)
        self.assertNotIn("unknown sensitive output", logs)


if __name__ == "__main__":
    unittest.main()
