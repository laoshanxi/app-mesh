# iot_mqtt_publisher.py
import time
import json
import uuid
import random
import paho.mqtt.client as mqtt

import config
from config import BROKER, PORT, TOPIC


# Logical device ID (this identifies your device in the backend)
DEVICE_ID = "device-001"

# MQTT client ID must be globally unique per connection
CLIENT_ID = f"{DEVICE_ID}-{uuid.uuid4().hex[:6]}"


def simulate_device_data():
    """Generate fake telemetry data."""
    return json.dumps(
        {
            "device_id": DEVICE_ID,
            "temperature": round(random.uniform(20, 30), 2),
            "humidity": round(random.uniform(30, 70), 2),
            "timestamp": int(time.time()),
        }
    )


def on_connect(client, userdata, flags, reason_code, properties=None):
    """Handle connection result."""
    print(f"[MQTT] Connected ({reason_code})")


def on_disconnect(client, userdata, flags, reason_code, properties=None):
    """Handle disconnection result."""
    print(f"[MQTT] Disconnected. Reason code: {reason_code}")


def main():
    """MQTT publisher main loop."""
    client = mqtt.Client(client_id=CLIENT_ID, callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=1, max_delay=30)  # Auto-reconnect
    client.connect(BROKER, PORT, keepalive=60)
    client.loop_start()

    # Wait until connected
    while not client.is_connected():
        time.sleep(0.1)

    while True:
        message = simulate_device_data()
        print(f"[PUBLISH] {message}")
        client.publish(TOPIC, message)
        time.sleep(2)  # every 2 seconds


if __name__ == "__main__":
    main()
