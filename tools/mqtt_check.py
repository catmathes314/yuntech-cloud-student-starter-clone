#!/usr/bin/env python3
"""Check one Lab 6 MQTT identity against its scoped IoT policy."""
import argparse
import json
from pathlib import Path
import re
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
IOT_DIR = ROOT / ".local/iot"


class MqttCheckError(Exception):
    pass


def validated_iot_path(name):
    path = IOT_DIR / name
    local_dir = ROOT / ".local"
    if (local_dir.is_symlink() or IOT_DIR.is_symlink()
            or not IOT_DIR.is_dir() or IOT_DIR.stat().st_mode & 0o777 != 0o700
            or path.is_symlink() or not path.is_file()):
        raise MqttCheckError(f"Missing or unsafe .local/iot/{name}.")
    if path.stat().st_mode & 0o777 != 0o600:
        raise MqttCheckError(f".local/iot/{name} permissions must be 600.")
    return path


def read_iot_file(name):
    path = validated_iot_path(name)
    try:
        return path.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise MqttCheckError(f"Invalid .local/iot/{name}.") from None


def reason_value(reason_code):
    value = getattr(reason_code, "value", reason_code)
    try:
        return int(value)
    except (TypeError, ValueError):
        raise MqttCheckError("MQTT broker returned an invalid reason code.") from None


def run(args):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", args.code):
        raise MqttCheckError("Code must match [A-Za-z0-9-]{1,40}.")
    if args.wait < 0 or args.wait > 300:
        raise MqttCheckError("--wait must be between 0 and 300 seconds.")
    if args.subscribe is None and args.wait:
        raise MqttCheckError("--wait is only valid with --sub.")

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise MqttCheckError("paho-mqtt 2.1.0 is required; install it in the Codespace as directed by the Lab.") from None

    endpoint = read_iot_file("endpoint").strip()
    if not re.fullmatch(r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint):
        raise MqttCheckError("The IoT endpoint file is invalid.")
    role = args.identity
    client_id = ("gw-" if role == "gw" else "consumer-") + args.code
    cert_file = validated_iot_path(f"{role}.cert.pem")
    key_file = validated_iot_path(f"{role}.private.key")
    ca_file = validated_iot_path("AmazonRootCA1.pem")

    connected = threading.Event()
    subscribed = threading.Event()
    received = threading.Event()
    publish_result = {}
    subscribe_result = {}
    receive_result = {}
    output_lock = threading.Lock()

    def on_connect(client, userdata, flags, reason_code, properties):
        code = reason_value(reason_code)
        print(f"connack={code}", flush=True)
        connected.set()

    def on_publish(client, userdata, mid, reason_code, properties):
        publish_result[mid] = reason_value(reason_code)

    def on_subscribe(client, userdata, mid, reason_code_list, properties):
        codes = [reason_value(code) for code in reason_code_list]
        subscribe_result["mid"] = mid
        subscribe_result["reasons"] = codes
        print("suback=" + ",".join(str(code) for code in codes), flush=True)
        subscribed.set()

    def on_message(client, userdata, message):
        with output_lock:
            print(
                f"recv topic={message.topic} payload={message.payload.decode('utf-8', errors='replace')}",
                flush=True,
            )
        receive_result["received"] = True
        received.set()

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv5,
    )
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.tls_set(
        ca_certs=str(ca_file),
        certfile=str(cert_file),
        keyfile=str(key_file),
    )
    client.connect(endpoint, port=8883, keepalive=60)
    client.loop_start()
    try:
        if not connected.wait(15):
            raise MqttCheckError("Timed out waiting for MQTT CONNACK.")
        if args.publish is not None:
            if not args.publish:
                raise MqttCheckError("--pub topic cannot be empty.")
            payload = json.dumps(
                {"check": "t2", "code": args.code},
                separators=(",", ":"),
            )
            info = client.publish(args.publish, payload, qos=1)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise MqttCheckError(f"MQTT publish could not be queued (rc={int(info.rc)}).")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and info.mid not in publish_result:
                time.sleep(0.05)
            if info.mid not in publish_result:
                raise MqttCheckError("Timed out waiting for the matching PUBACK.")
            print(f"puback={publish_result[info.mid]}", flush=True)
            return 0

        if not args.subscribe:
            raise MqttCheckError("--sub topic filter cannot be empty.")
        result, mid = client.subscribe(args.subscribe, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            raise MqttCheckError(f"MQTT subscription could not be queued (rc={int(result)}).")
        if not subscribed.wait(15):
            raise MqttCheckError("Timed out waiting for SUBACK.")
        if subscribe_result.get("mid") != mid:
            raise MqttCheckError("Received a SUBACK for an unexpected message ID.")
        if args.wait and not received.wait(args.wait):
            return 0
        return 0
    finally:
        client.disconnect()
        client.loop_stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your group-member code, e.g. g03-m2")
    parser.add_argument("--as", dest="identity", choices=("gw", "consumer"), required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--pub", dest="publish", metavar="TOPIC")
    operation.add_argument("--sub", dest="subscribe", metavar="TOPIC_FILTER")
    parser.add_argument("--wait", type=int, default=0, help="Seconds to wait for a subscribed message")
    try:
        return run(parser.parse_args())
    except (MqttCheckError, OSError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
