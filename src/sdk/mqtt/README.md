# MQTT IoT Message Processing with App Mesh

App Mesh provides robust capabilities for IoT data management and processing through distributed application instances. Learn how to set up MQTT messaging with App Mesh.

## MQTT Broker Setup

Deploy a local MQTT broker using Docker:

```bash
docker run -d --name mosquitto \
  -p 1883:1883 -p 9001:9001 \
  -e ALLOW_ANONYMOUS=true \
  eclipse-mosquitto
```

Available ports:

- 1883: MQTT TCP port (primary)
- 9001: WebSocket port (optional)

Note: The default configuration enables anonymous access for testing purposes. Configure authentication for production use.

## Prerequisites

Install the Python MQTT client:

```bash
pip install paho-mqtt
```

## Usage Examples

Send test IoT messages:

```bash
python3 iot_mqtt_publisher.py
```

Receive and process messages (forward to backend application) with App Mesh:

```bash
python3 mqtt_subscriber.py
```
