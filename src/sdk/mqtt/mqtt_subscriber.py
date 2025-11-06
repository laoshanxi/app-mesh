# mqtt_subscriber.py
import json
import time
import paho.mqtt.client as mqtt
from appmesh import AppMeshClient

BROKER = "localhost"  # MQTT broker address
PORT = 1883
TOPIC = "devices/temperature"

appmesh_client = AppMeshClient()
appmesh_client.login("admin", "admin123")


def process_device_data(data):
    """Simulate local processing logic"""
    # Process data in remote App Mesh application
    appmesh_client.run_task(app_name="pytask", data=data)
    print(f"[PROCESSING] Device {data['device_id']} - Temp: {data['temperature']}°C, Humidity: {data['humidity']}%")


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected to MQTT Broker!")
        client.subscribe(TOPIC)
    else:
        print(f"Failed to connect, reason code {reason_code}")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print(f"[RECEIVED] {data}")
        process_device_data(data)
    except Exception as e:
        print(f"Error processing message: {e}")


def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT, 60)
    client.loop_forever()  # Blocking call


if __name__ == "__main__":
    main()
