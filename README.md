![alt text](https://github.com/provokingchaos/waterguru2mqtt/blob/main/waterguru.png)

waterguru2mqtt

waterguru2mqtt is a lightweight Dockerized service that:

1. Logs into the WaterGuru backend using your WaterGuru account
2. Fetches your WaterGuru dashboard JSON
3. Publishes both raw and parsed readings into MQTT
4. Exposes an optional Flask endpoint to trigger a manual refresh

The container supports two scheduled fetch times per day, publishes data using MQTT v5, and integrates easily with Home Assistant.

All pool naming is dynamic — the container automatically detects the pool(s) returned by WaterGuru and generates a slug for each (e.g., "Park Meadow Pool" → park_meadow_pool).
Your specific pool name does not need to be configured manually.

---

## Features

- Automatic authentication to WaterGuru using AWS Cognito
- Publishes raw JSON under waterguru/raw
- Publishes per-pool structured data under waterguru/<pool_slug>/...
- Supports multiple pools
- MQTT v5 compatible
- Two configurable refresh times each day
- Optional manual refresh endpoint: GET /api/wg
- Works on Unraid, Docker, GHCR, or any Linux host
- Includes complete Home Assistant MQTT sensor examples (sensors.yaml)

---

## Environment Variables

### Required (WaterGuru Login)

WG_USER | WaterGuru account email
WG_PASS | WaterGuru account password

### Optional (Flask API)

WG_PORT | Port for Flask API | Default: 53255

### MQTT Configuration

MQTT_HOST | MQTT broker hostname/IP | mqtt-broker.local
MQTT_PORT | MQTT port | 1883
MQTT_USERNAME | MQTT username | (none)
MQTT_PASSWORD | MQTT password | (none)
MQTT_CLIENT_ID | Client ID | waterguru2mqtt
MQTT_BASE_TOPIC | Base MQTT topic | waterguru
MQTT_USE_TLS | Enable TLS | false

### Scheduling

WG_RUN_TIME_1 | First daily run time (HH:MM) | Default: 00:00
WG_RUN_TIME_2 | Second daily run time (HH:MM) | Default: 12:00
TZ | Timezone | Default: UTC

---

## MQTT Topic Structure

Example topics:

waterguru/raw
waterguru/[<pool_slug>]/status
waterguru/[<pool_slug>]/water_temp
waterguru/[<pool_slug>]/latest_measure_time
waterguru/[<pool_slug>]/refillables/cassette/pct_left
waterguru/[<pool_slug>]/refillables/battery/percent_left
waterguru/[<pool_slug>]/measurement/free_cl/value
waterguru/[<pool_slug>]/measurement/free_cl/alerts/0/text
waterguru/[<pool_slug>]/alerts/summary

Full topic mapping + HA examples: see sensors.yaml

---

## Running via Docker (GHCR Example)

docker run -d \
  --name waterguru2mqtt \
  --restart unless-stopped \
  -e WG_USER="your_email@example.com" \
  -e WG_PASS="your_password_here" \
  -e WG_PORT="53255" \
  -e MQTT_HOST="mqtt-broker.local" \
  -e MQTT_PORT="1883" \
  -e MQTT_USERNAME="" \
  -e MQTT_PASSWORD="" \
  -e MQTT_BASE_TOPIC="waterguru" \
  -e MQTT_CLIENT_ID="waterguru2mqtt" \
  -e WG_RUN_TIME_1="00:00" \
  -e WG_RUN_TIME_2="12:00" \
  -e TZ="America/Chicago" \
  -p 53255:53255 \
  provokingchaos/waterguru2mqtt:latest

Manual refresh:
http://[<your_container_ip>]:53255/api/wg

---

## Home Assistant

Sensor examples available in sensors.yaml  
Replace [<your_pool_slug>] with your pool slug discovered in MQTT Explorer.

---

## License

MIT License

---

## Credits

Based on original API research from:  
https://github.com/bdwilson/waterguru-api  
Not affiliated with WaterGuru.
