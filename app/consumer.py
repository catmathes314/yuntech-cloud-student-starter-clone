#!/usr/bin/env python3
"""Forward allow-listed IoT events to the local inspection API."""
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_EVENT_BYTES = 4096
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
EVENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
CODE_RE = re.compile(r"[A-Za-z0-9-]{1,40}\Z")


class ConsumerError(Exception):
    pass


def required_environment():
    values = {}
    for name in (
        "IOT_ENDPOINT", "IOT_TOPIC", "IOT_CLIENT_ID", "IOT_DEVICE_IDS",
        "IOT_CA", "IOT_CERT", "IOT_KEY", "REPORTER_TOKEN",
    ):
        value = os.environ.get(name, "")
        if not value:
            raise ConsumerError(f"Required environment setting {name} is missing.")
        values[name] = value

    client_match = re.fullmatch(r"consumer-([A-Za-z0-9-]{1,40})", values["IOT_CLIENT_ID"])
    if client_match is None:
        raise ConsumerError("IOT_CLIENT_ID is invalid.")
    code = client_match.group(1)
    if not CODE_RE.fullmatch(code):
        raise ConsumerError("IOT_CLIENT_ID is invalid.")
    if not re.fullmatch(
        r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", values["IOT_ENDPOINT"]
    ):
        raise ConsumerError("IOT_ENDPOINT is invalid.")
    if values["IOT_TOPIC"] != f"cxe/{code}/gw/events":
        raise ConsumerError("IOT_TOPIC does not match IOT_CLIENT_ID.")
    device_ids = values["IOT_DEVICE_IDS"].split(",")
    expected_ids = [f"{code}-d{number:02d}" for number in range(1, 11)]
    if (len(device_ids) != 10 or len(set(device_ids)) != 10
            or set(device_ids) != set(expected_ids)):
        raise ConsumerError("IOT_DEVICE_IDS must list this code's ten devices.")
    try:
        values["REPORTER_TOKEN"].encode("ascii")
    except UnicodeEncodeError:
        raise ConsumerError("REPORTER_TOKEN must be ASCII.") from None
    return values, set(device_ids)


def validate_secret_file(filename):
    path = Path(filename)
    if (not path.is_absolute() or path.parent != Path("/etc/inspection/iot")
            or path.is_symlink() or not path.is_file()):
        raise ConsumerError("An IoT credential file is missing or unsafe.")
    file_stat = path.stat()
    if stat.S_IMODE(file_stat.st_mode) != 0o600 or file_stat.st_uid != os.geteuid():
        raise ConsumerError("IoT credential files must belong to the consumer and have mode 600.")
    return path


def result_event_id(event):
    event_id = event.get("event_id") if isinstance(event, dict) else None
    return event_id if isinstance(event_id, str) and EVENT_ID_RE.fullmatch(event_id) else "unknown"


def send_result(event_id, result):
    print(f"event_id={event_id} result={result}", flush=True)


def forward_event(payload, allowed_devices, reporter_token):
    if len(payload) > MAX_EVENT_BYTES:
        send_result("unknown", "rejected")
        return
    try:
        event = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        send_result("unknown", "rejected")
        return
    if not isinstance(event, dict):
        send_result("unknown", "rejected")
        return

    event_id = result_event_id(event)
    device_id = event.get("device_id")
    if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
        send_result(event_id, "rejected")
        return
    if device_id not in allowed_devices:
        send_result(event_id, "rejected")
        return
    request = Request(
        "http://127.0.0.1:8080/events",
        data=payload,
        headers={
            "Authorization": "Bearer " + reporter_token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
        error.close()
    except (URLError, TimeoutError, OSError):
        send_result(event_id, "error")
        return

    if status == 201:
        result = "created"
    elif status == 200:
        result = "duplicate"
    elif 400 <= status < 500:
        result = "rejected"
    else:
        result = "error"
    send_result(event_id, result)


def run():
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        raise ConsumerError("paho-mqtt 2.1.0 is unavailable.") from None

    settings, allowed_devices = required_environment()
    ca_file = validate_secret_file(settings["IOT_CA"])
    cert_file = validate_secret_file(settings["IOT_CERT"])
    key_file = validate_secret_file(settings["IOT_KEY"])
    try:
        reporter_token = settings["REPORTER_TOKEN"].encode("ascii")
    except UnicodeEncodeError:
        raise ConsumerError("REPORTER_TOKEN must be ASCII.") from None

    def on_connect(client, userdata, flags, reason_code, properties):
        reason = int(getattr(reason_code, "value", reason_code))
        if reason != 0:
            print(f"mqtt connect rejected rc={reason}", flush=True)
            return
        result, _ = client.subscribe(settings["IOT_TOPIC"], qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            print(f"mqtt subscribe failed rc={int(result)}", flush=True)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        codes = [int(getattr(code, "value", code)) for code in reason_codes]
        print("subscribed rc=" + ",".join(str(code) for code in codes), flush=True)
        if any(code >= 128 for code in codes):
            client.disconnect()

    def on_message(client, userdata, message):
        forward_event(message.payload, allowed_devices, reporter_token)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=settings["IOT_CLIENT_ID"],
        protocol=mqtt.MQTTv5,
    )
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.tls_set(
        ca_certs=str(ca_file),
        certfile=str(cert_file),
        keyfile=str(key_file),
    )
    client.connect(settings["IOT_ENDPOINT"], port=8883, keepalive=60)
    result = client.loop_forever()
    if result != mqtt.MQTT_ERR_SUCCESS:
        raise ConsumerError(f"MQTT network loop stopped (rc={int(result)}).")


def main():
    try:
        run()
    except (ConsumerError, OSError, ValueError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
