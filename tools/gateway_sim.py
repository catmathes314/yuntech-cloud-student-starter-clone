#!/usr/bin/env python3
"""Send the Lab 6 32-message gateway simulation and record PUBACK results."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mqtt_check import (
    MqttCheckError,
    read_iot_file,
    reason_value,
    validated_iot_path,
)

ROOT = Path(__file__).resolve().parents[1]


class GatewayError(Exception):
    pass


def store_last_run(prefix, puback_ok):
    directory = ROOT / ".local"
    if directory.is_symlink() or not directory.is_dir():
        raise GatewayError("Missing or unsafe .local directory.")
    path = directory / "w06-last-run.json"
    if path.is_symlink():
        raise GatewayError("Refusing a symlink for .local/w06-last-run.json.")
    fd, temporary = tempfile.mkstemp(prefix=".w06-last-run-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                {"prefix": prefix, "puback_ok": puback_ok},
                stream,
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_events(code, prefix):
    events = []
    first_event = None
    for device_number in range(1, 11):
        device_id = f"{code}-d{device_number:02d}"
        for sequence in range(1, 4):
            event = {
                "event_id": f"{prefix}-d{device_number:02d}-{sequence:02d}",
                "device_id": device_id,
                "observed_at": (
                    datetime.now(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z")
                ),
                "type": "status",
            }
            if first_event is None:
                first_event = event
            events.append(event)
    events.append(dict(first_event))
    events.append({
        "event_id": f"{prefix}-d99-01",
        "device_id": f"{code}-d99",
        "observed_at": (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        ),
        "type": "status",
    })
    return events


def run(code, run_id):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", code):
        raise GatewayError("Code must match [A-Za-z0-9-]{1,40}.")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", run_id):
        raise GatewayError("Run must match [A-Za-z0-9-]{1,40}.")
    prefix = f"{code}-{run_id}"
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", prefix):
        raise GatewayError("Combined run prefix must match [A-Za-z0-9-]{1,40}.")

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise GatewayError("paho-mqtt 2.1.0 is required; install it in the Codespace as directed by the Lab.") from None

    endpoint = read_iot_file("endpoint").strip()
    if not re.fullmatch(r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint):
        raise GatewayError("The IoT endpoint file is invalid.")
    cert_file = validated_iot_path("gw.cert.pem")
    key_file = validated_iot_path("gw.private.key")
    ca_file = validated_iot_path("AmazonRootCA1.pem")

    connected = threading.Event()
    connection_result = {}
    publish_results = {}

    def on_connect(client, userdata, flags, reason_code, properties):
        connection_result["reason"] = reason_value(reason_code)
        print(f"connack={connection_result['reason']}", flush=True)
        connected.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        publish_results[mid] = reason_value(reason_code)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"gw-{code}",
        protocol=mqtt.MQTTv5,
    )
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.tls_set(
        ca_certs=str(ca_file),
        certfile=str(cert_file),
        keyfile=str(key_file),
    )
    client.connect(endpoint, port=8883, keepalive=60)
    client.loop_start()
    acknowledged = 0
    try:
        try:
            if not connected.wait(15):
                raise GatewayError("Timed out waiting for MQTT CONNACK.")
            if connection_result["reason"] != 0:
                raise GatewayError(f"MQTT connection was refused (connack={connection_result['reason']}).")
            topic = f"cxe/{code}/gw/events"
            for event in build_events(code, prefix):
                payload = json.dumps(event, separators=(",", ":"))
                info = client.publish(topic, payload, qos=1)
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    raise GatewayError(f"MQTT publish could not be queued (rc={int(info.rc)}).")
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and info.mid not in publish_results:
                    time.sleep(0.05)
                if info.mid not in publish_results:
                    raise GatewayError(f"Timed out waiting for PUBACK on message {info.mid}.")
                reason = publish_results[info.mid]
                if reason >= 128:
                    raise GatewayError(f"Broker rejected publish with PUBACK reason {reason}.")
                acknowledged += 1
        finally:
            try:
                client.disconnect()
            finally:
                client.loop_stop()
    finally:
        store_last_run(prefix, acknowledged)
    print(f"puback_ok={acknowledged}/32", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your group-member code, e.g. g03-m2")
    parser.add_argument("--run", dest="run_id", required=True, help="Unique run suffix, e.g. r1")
    args = parser.parse_args()
    try:
        return run(args.code, args.run_id)
    except (GatewayError, MqttCheckError, OSError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
