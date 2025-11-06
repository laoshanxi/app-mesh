# Receive IoT Messages with App Mesh

App Mesh provides capabilities for managing and processing IoT data through application instances. In IoT scenarios, App Mesh can be used to receive messages centrally and handle them efficiently.

## MQTT Broker Setup

Deploy a MQTT broker using Docker:

```bash
docker run -d --name mosquitto \
  -p 1883:1883 -p 9001:9001 \
  -e ALLOW_ANONYMOUS=true \
  eclipse-mosquitto
```

Port configuration:

- 1883: MQTT TCP port
- 9001: WebSocket port (optional)

Note: Default configuration allows anonymous access (no authentication required)

## Python Dependencies

Install required MQTT client library:

```bash
pip install paho-mqtt
```

## Simulate MQTT data

`shell
python3 iot_mqtt_publisher.py
`

## App Mesh handle and process in backend

`shell
python3 iot_mqtt_publisher.py
`
