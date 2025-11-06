# iot_mqtt_publisher.py
import time
import json
import random
import paho.mqtt.client as mqtt

BROKER = "localhost"  # MQTT broker address
PORT = 1883
TOPIC = "devices/temperature"


def simulate_device_data():
    """Simulate send device data."""
    data = {
        "device_id": "sensor-001",
        "temperature": round(random.uniform(20, 30), 2),
        "humidity": round(random.uniform(30, 70), 2),
        "timestamp": int(time.time()),
    }
    return json.dumps(data)


def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.connect(BROKER, PORT, 60)

    while True:
        message = simulate_device_data()
        client.publish(TOPIC, message)
        print(f"[PUBLISH] {message}")
        time.sleep(2)  # every 2 seconds


if __name__ == "__main__":
    main()
