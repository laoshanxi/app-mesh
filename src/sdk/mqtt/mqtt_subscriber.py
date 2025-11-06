# mqtt_subscriber.py
# pylint: disable=line-too-long,broad-exception-caught
import json
import time
import paho.mqtt.client as mqtt
from appmesh import AppMeshClient

import config
from config import BROKER, PORT, TOPIC

CLIENT_ID = "iot-data-processor"

appmesh_client = AppMeshClient()
appmesh_client.login("admin", "admin123")


def process_device_data(data):
    """Local processing logic - send to App Mesh"""
    appmesh_client.run_task(app_name="pytask", data=data)
    print("Sent to App Mesh")


def on_connect(client, userdata, flags, reason_code, props=None):
    """Handle connection event."""
    print(f"[MQTT] Connected ({reason_code})")
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    """Handle incoming messages."""
    try:
        payload = msg.payload.decode('utf-8')
        # data = json.loads(payload)
        print(f"[RECEIVED] {payload}")
        process_device_data(payload)
    except Exception as e:
        print(f"[ERROR] {e}")


def on_disconnect(client, userdata, reason_code, properties=None):
    """Handle disconnection."""
    print(f"[MQTT] Disconnected: {reason_code}")


def main():
    """MQTT subscriber main loop."""
    client = mqtt.Client(client_id=CLIENT_ID, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=1, max_delay=30)  # Auto-reconnect
    client.connect(BROKER, PORT, keepalive=60)
    client.loop_forever()  # Blocking call


if __name__ == "__main__":
    main()
