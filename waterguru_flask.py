#!/usr/local/bin/python
#
# WaterGuru API → MQTT publisher
# Auto-updates at two configurable times per day (local TZ, set in Dockerfile).
#

from flask import Flask, jsonify, Response
import os
import json
import threading
import time as time_module
from datetime import datetime, time, timedelta

from pycognito import Cognito
import boto3
from pycognito.aws_srp import AWSSRP
import requests
from requests_aws4auth import AWS4Auth
import paho.mqtt.client as mqtt

# ---------------------------------------------------------------------
# App config
# ---------------------------------------------------------------------
DEBUG = False
app = Flask(__name__)
app.config["SECRET_KEY"] = "32624076087108375603827608353"

# WaterGuru config from environment
config = {
    "port": os.environ.get("WG_PORT", "5000"),
    "user": os.environ.get("WG_USER", ""),
    "pass": os.environ.get("WG_PASS", ""),
}

# ---------------------------------------------------------------------
# MQTT CONFIG
# ---------------------------------------------------------------------
MQTT_HOST = os.environ.get("MQTT_HOST")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME", "")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD", "")
MQTT_CLIENT_ID = os.environ.get("MQTT_CLIENT_ID", "waterguru_flask")
MQTT_BASE_TOPIC = os.environ.get("MQTT_BASE_TOPIC", "waterguru")

mqtt_client = None

# ---------------------------------------------------------------------
# Home Assistant REST API CONFIG (for min/max/target attrs)
# ---------------------------------------------------------------------
HA_BASE_URL = os.environ.get("HA_BASE_URL")  # e.g. http://homeassistant:8123
HA_TOKEN = os.environ.get("HA_TOKEN")        # Long-lived access token

# Mapping of entities -> enforced attributes (from AppDaemon WaterGuruAttrs)
ENTITY_ATTRS = {
    "sensor.waterguru_park_meadow_pool_calcium_hardness": {
        "min": 0,
        "max": 1600,
        "target": 300.0,
    },
    "sensor.waterguru_park_meadow_pool_cyanuric_acid_stabilizer": {
        "min": 0,
        "max": 300,
        "target": 65.0,
    },
    "sensor.waterguru_park_meadow_pool_free_chlorine": {
        "min": 0.0,
        "max": 10.0,
        "target": 3.0,
    },
    "sensor.waterguru_park_meadow_pool_ph": {
        "min": 6.5,
        "max": 8.5,
        "target": 7.5,
    },
    "sensor.waterguru_park_meadow_pool_skimmer_flow": {
        "min": 0,
        "max": 90,
        "target": 15.0,
    },
    "sensor.waterguru_park_meadow_pool_total_alkalinity": {
        "min": 0,
        "max": 240,
        "target": 100.0,
    },
    "sensor.waterguru_park_meadow_pool_total_hardness": {
        "min": 0,
        "max": 1600,
        "target": 300.0,
    },
}


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def slugify(value: str) -> str:
    """Simple slug to make safe topic components."""
    if not value:
        return "pool"
    value = value.strip().lower()
    for ch in [" ", "/", "\\", ".", ",", ":", ";"]:
        value = value.replace(ch, "_")
    while "__" in value:
        value = value.replace("__", "_")
    return value.strip("_") or "pool"


def setup_mqtt():
    """Initialize MQTT v5 client and connect."""
    global mqtt_client

    if not MQTT_HOST:
        print("[MQTT] MQTT_HOST not set; MQTT disabled.")
        return

    mqtt_client = mqtt.Client(
        client_id=MQTT_CLIENT_ID,
        protocol=mqtt.MQTTv5,  # MQTT v5
        transport="tcp",
    )

    if MQTT_USERNAME:
        mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    # MQTT v5 connect callback
    def on_connect(client, userdata, flags, reasonCode, properties=None):
        if reasonCode == 0:
            print(f"[MQTT] Connected to {MQTT_HOST}:{MQTT_PORT} (MQTT v5)")
        else:
            print(f"[MQTT] Connection failed, reasonCode={reasonCode}")

    mqtt_client.on_connect = on_connect

    try:
        mqtt_client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[MQTT] Connection error: {e}")
        mqtt_client = None


def publish_leaf(topic: str, value):
    """Publish a single value as retained MQTT."""
    if not mqtt_client:
        return
    payload = "" if value is None else str(value)
    try:
        info = mqtt_client.publish(topic, payload=payload, qos=1, retain=True)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"[MQTT] Publish failed rc={info.rc} for topic {topic}")
    except Exception as e:
        print(f"[MQTT] Error publishing {topic}: {e}")


def publish_raw_dashboard(json_str: str):
    """Publish the full dashboard JSON to waterguru/raw."""
    if not mqtt_client or not json_str:
        return
    topic = f"{MQTT_BASE_TOPIC}/raw"
    publish_leaf(topic, json_str)
    print(f"[MQTT] Published dashboard JSON → {topic}")


# ---------------------------------------------------------------------
# Home Assistant attribute enforcement (min/max/target)
# ---------------------------------------------------------------------
def ha_api_request(method: str, path: str, **kwargs):
    """
    Call Home Assistant's REST API.
    Returns requests.Response or None if HA not configured.
    """
    if not HA_BASE_URL or not HA_TOKEN:
        return None

    url = HA_BASE_URL.rstrip("/") + path
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {HA_TOKEN}")
    headers.setdefault("Content-Type", "application/json")

    try:
        resp = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        return resp
    except Exception as e:
        print(f"[HA] Error calling {url}: {e}")
        return None


def apply_attrs_to_entity(entity_id: str, desired: dict):
    """
    Mimic AppDaemon WaterGuruAttrs.apply_attrs:
    - Fetch current state/attributes
    - Merge in desired min/max/target
    - Post updated state back if changed
    """
    if not desired:
        return

    resp = ha_api_request("GET", f"/api/states/{entity_id}")
    if resp is None:
        # HA not configured
        return
    if not resp.ok:
        print(f"[HA] Failed to read {entity_id}: {resp.status_code} {resp.text}")
        return

    try:
        cur = resp.json()
    except Exception as e:
        print(f"[HA] Failed to parse JSON for {entity_id}: {e}")
        return

    state = cur.get("state")
    attrs = dict(cur.get("attributes") or {})

    changed = False
    for k, v in desired.items():
        if attrs.get(k) != v:
            attrs[k] = v
            changed = True

    if not changed:
        return

    payload = {"state": state, "attributes": attrs}
    resp2 = ha_api_request(
        "POST",
        f"/api/states/{entity_id}",
        data=json.dumps(payload),
    )
    if not resp2:
        return
    if not resp2.ok:
        print(
            f"[HA] Failed to update {entity_id}: {resp2.status_code} {resp2.text}"
        )
    else:
        print(f"[HA] Updated attributes on {entity_id}: {desired}")


def apply_all_attrs():
    """
    Apply min/max/target attributes to all configured WaterGuru entities.
    Called after each successful WaterGuru → MQTT publish.
    """
    if not HA_BASE_URL or not HA_TOKEN:
        # Don't spam; just one note on first call
        print("[HA] HA_BASE_URL or HA_TOKEN not set; skipping attribute updates.")
        return

    for ent, desired in ENTITY_ATTRS.items():
        apply_attrs_to_entity(ent, desired)


# ---------------------------------------------------------------------
# Per-pool metrics, refillables, alerts, ranges, last measurement
# ---------------------------------------------------------------------
def publish_pools_and_metrics(data: dict):
    """
    Publish per-pool metrics, refillables, alerts, ranges, and pool JSON.

    Example topics for "Park Meadow Pool":
      - waterguru/park_meadow_pool/status
      - waterguru/park_meadow_pool/water_temp
      - waterguru/park_meadow_pool/latest_measure_time
      - waterguru/park_meadow_pool/measurement/free_cl/value
      - waterguru/park_meadow_pool/measurement/free_cl/measure_time
      - waterguru/park_meadow_pool/measurement/free_cl/ranges/red_min
      - waterguru/park_meadow_pool/measurement/free_cl/alerts/0/text
      - waterguru/park_meadow_pool/refillables/cassette/reads_left
      - waterguru/park_meadow_pool/refillables/battery/percent_left
      - waterguru/park_meadow_pool/refillables/battery/voltage
      - waterguru/park_meadow_pool/alerts/count
      - waterguru/park_meadow_pool/alerts/total_count
      - waterguru/park_meadow_pool/alerts/summary
      - waterguru/park_meadow_pool/raw
    """
    if not mqtt_client or not isinstance(data, dict):
        return

    water_bodies = data.get("waterBodies", [])
    if not isinstance(water_bodies, list):
        return

    for wb in water_bodies:
        # Pool name / ID
        water_body_obj = wb.get("waterBody") or {}
        wb_name = wb.get("name") or water_body_obj.get("label") or "Pool"
        wb_id = wb.get("waterBodyId") or water_body_obj.get("waterBodyId")
        slug = slugify(wb_name)
        base = f"{MQTT_BASE_TOPIC}/{slug}"

        measurements = wb.get("measurements", []) or []
        alerts = wb.get("alerts", []) or []
        pods = wb.get("pods", []) or []

        print(
            f"[WG] Pool '{wb_name}' (slug={slug}) -> "
            f"{len(measurements)} measurements, {len(alerts)} pool alerts, {len(pods)} pods"
        )

        # Track total alerts (pool-level + measurement-level) and summary text
        total_alerts = 0
        alert_texts = []

        # High-level info including latest measurement time
        simple = {
            "water_body_id": wb_id,
            "status": wb.get("status"),
            "overall_status": data.get("status"),
            "water_temp": wb.get("waterTemp"),
            "water_temp_time": wb.get("waterTempTime"),
            "sanitizer_type": wb.get("sanitizerType"),
            "latest_measure_time": wb.get("latestMeasureTime"),
            "latest_measure_time_human": wb.get("latestMeasureTimeHuman"),
        }
        for key, val in simple.items():
            publish_leaf(f"{base}/{key}", val)

        # Measurements + ranges + measurement-level alerts
        for meas in measurements:
            m_type = (meas.get("type") or "").lower()
            if not m_type:
                continue

            mtopic = f"{base}/measurement/{m_type}"

            # Choose numeric value where possible
            if meas.get("floatValue") is not None:
                value = meas["floatValue"]
            elif meas.get("intValue") is not None:
                value = meas["intValue"]
            else:
                value = meas.get("value")

            fields = {
                "title": meas.get("title"),
                "status": meas.get("status"),
                "value": value,
                "target": meas.get("target"),
                "measure_time": meas.get("measureTime"),
                "color": meas.get("color"),
            }
            for key, val in fields.items():
                publish_leaf(f"{mtopic}/{key}", val)

            # Ranges for this measurement (for HA color/state logic)
            cfg = meas.get("cfg") or {}
            ranges_src = (
                cfg.get("floatRanges")
                or cfg.get("intRanges")
                or cfg.get("ranges")
                or {}
            )
            if isinstance(ranges_src, dict):
                for rkey, rval in ranges_src.items():
                    publish_leaf(
                        f"{mtopic}/ranges/{str(rkey).lower()}",
                        rval,
                    )

            # Measurement-level alerts
            m_alerts = meas.get("alerts", []) or []
            publish_leaf(f"{mtopic}/alerts/count", len(m_alerts))
            total_alerts += len(m_alerts)
            for idx, alert in enumerate(m_alerts):
                a_base = f"{mtopic}/alerts/{idx}"
                publish_leaf(f"{a_base}/category", alert.get("category"))
                publish_leaf(f"{a_base}/source", alert.get("source"))
                publish_leaf(f"{a_base}/condition", alert.get("condition"))
                publish_leaf(f"{a_base}/icon", alert.get("icon"))
                publish_leaf(f"{a_base}/status", alert.get("status"))
                publish_leaf(f"{a_base}/color", alert.get("color"))
                publish_leaf(f"{a_base}/text", alert.get("text"))

                text = alert.get("text")
                if text:
                    alert_texts.append(text)

                advice = alert.get("advice") or {}
                action = advice.get("action") or {}
                publish_leaf(f"{a_base}/advice/url", advice.get("url"))
                publish_leaf(f"{a_base}/advice/summary", action.get("summary"))

        # Pool-level alerts (variable count: 0..N)
        publish_leaf(f"{base}/alerts/count", len(alerts))
        total_alerts += len(alerts)
        for idx, alert in enumerate(alerts):
            a_base = f"{base}/alerts/{idx}"
            publish_leaf(f"{a_base}/category", alert.get("category"))
            publish_leaf(f"{a_base}/source", alert.get("source"))
            publish_leaf(f"{a_base}/condition", alert.get("condition"))
            publish_leaf(f"{a_base}/icon", alert.get("icon"))
            publish_leaf(f"{a_base}/status", alert.get("status"))
            publish_leaf(f"{a_base}/color", alert.get("color"))
            publish_leaf(f"{a_base}/text", alert.get("text"))

            text = alert.get("text")
            if text:
                alert_texts.append(text)

            advice = alert.get("advice") or {}
            action = advice.get("action") or {}
            publish_leaf(f"{a_base}/advice/url", advice.get("url"))
            publish_leaf(f"{a_base}/advice/summary", action.get("summary"))

        # Total alerts (pool + measurement), and a summary string of all texts
        publish_leaf(f"{base}/alerts/total_count", total_alerts)
        summary = " | ".join(alert_texts) if alert_texts else ""
        publish_leaf(f"{base}/alerts/summary", summary)

        # Refillables (cassette + battery) from pods
        for pod_wrapper in pods:
            refillables = pod_wrapper.get("refillables", []) or []
            print(
                f"[WG] Pool '{wb_name}' pod has {len(refillables)} refillables"
            )
            for ref in refillables:
                r_type = (ref.get("type") or "").upper()  # LAB / BATT
                label = ref.get("label") or r_type
                if r_type == "LAB":
                    r_slug = "cassette"
                elif r_type == "BATT":
                    r_slug = "battery"
                else:
                    r_slug = slugify(label or r_type or "refillable")

                r_base = f"{base}/refillables/{r_slug}"

                # Common fields
                publish_leaf(f"{r_base}/label", label)
                publish_leaf(f"{r_base}/status", ref.get("status"))
                publish_leaf(f"{r_base}/color", ref.get("color"))
                publish_leaf(f"{r_base}/unit", ref.get("unit"))
                publish_leaf(f"{r_base}/time_left_text", ref.get("timeLeftText"))
                publish_leaf(f"{r_base}/pct_left", ref.get("pctLeft"))
                publish_leaf(f"{r_base}/amount_left", ref.get("amountLeft"))
                publish_leaf(f"{r_base}/max_amount", ref.get("maxAmount"))
                publish_leaf(f"{r_base}/urgent", ref.get("urgent"))

                # Battery-specific: percent remaining + voltage
                if r_type == "BATT":
                    publish_leaf(f"{r_base}/percent_left", ref.get("pctLeft"))
                    publish_leaf(f"{r_base}/voltage", ref.get("amountLeft"))

                # Cassette-specific: compute reads_left (30 reads per cassette)
                if r_type == "LAB":
                    pct = ref.get("pctLeft")
                    reads_left = None
                    try:
                        if pct is not None:
                            reads_left = int(float(pct) * 30.0 / 100.0)
                    except Exception:
                        reads_left = None
                    publish_leaf(f"{r_base}/reads_left", reads_left)

        # Full per-pool JSON for this waterBody
        pool_raw_topic = f"{base}/raw"
        try:
            pool_raw_payload = json.dumps(wb, separators=(",", ":"))
            publish_leaf(pool_raw_topic, pool_raw_payload)
        except Exception as e:
            print(f"[MQTT] Error publishing {pool_raw_topic}: {e}")


# ---------------------------------------------------------------------
# WaterGuru API
# ---------------------------------------------------------------------
def doWg():
    """Call the WaterGuru dashboard Lambda and return the raw JSON string."""
    region = "us-west-2"
    pool_id = "us-west-2_icsnuWQWw"
    id_pool = "us-west-2:691e3287-5776-40f2-a502-759de65a8f1c"
    client_id = "7pk5du7fitqb419oabb3r92lni"
    idp = "cognito-idp.us-west-2.amazonaws.com/" + pool_id

    boto3.setup_default_session(region_name=region)

    client = boto3.client("cognito-idp", region_name=region)
    aws = AWSSRP(
        username=config["user"],
        password=config["pass"],
        pool_id=pool_id,
        client_id=client_id,
        client=client,
    )
    tokens = aws.authenticate_user()

    id_token = tokens["AuthenticationResult"]["IdToken"]
    access_token = tokens["AuthenticationResult"]["AccessToken"]
    refresh_token = tokens["AuthenticationResult"]["RefreshToken"]

    u = Cognito(
        pool_id,
        client_id,
        id_token=id_token,
        refresh_token=refresh_token,
        access_token=access_token,
        user_pool_region=region,
    )
    user = u.get_user()
    userId = user._metadata["username"]

    identity = boto3.client("cognito-identity", region_name=region)
    identity_id = identity.get_id(IdentityPoolId=id_pool)["IdentityId"]

    creds = identity.get_credentials_for_identity(
        IdentityId=identity_id, Logins={idp: id_token}
    )["Credentials"]

    auth = AWS4Auth(
        creds["AccessKeyId"],
        creds["SecretKey"],
        region,
        "lambda",
        session_token=creds["SessionToken"],
    )

    response = requests.post(
        "https://lambda.us-west-2.amazonaws.com/2015-03-31/functions/"
        "prod-getDashboardView/invocations",
        auth=auth,
        json={"userId": userId, "clientType": "WEB_APP", "clientVersion": "0.2.3"},
        headers={
            "User-Agent": "aws-sdk-iOS/2.24.3",
            "Content-Type": "application/x-amz-json-1.0",
        },
    )

    return response.text


def run_and_publish():
    """Single cycle: call WaterGuru, publish dashboard + per-pool topics."""
    val = doWg()
    if not val:
        print("[WG] No data returned")
        return None

    try:
        data = json.loads(val)
    except Exception as e:
        print(f"[WG] JSON parse error: {e}")
        return None

    # Full dashboard JSON
    publish_raw_dashboard(val)

    # Per-pool JSON + flattened metrics + ranges + refillables + alerts
    publish_pools_and_metrics(data)

    # After MQTT updates, enforce min/max/target attributes via HA REST API
    apply_all_attrs()

    print("[WG] Publish complete")
    return val


# ---------------------------------------------------------------------
# Scheduler – 2 configurable run times
# ---------------------------------------------------------------------
def parse_time_str(s: str, default: time) -> time:
    """Parse 'HH:MM' into a time object, with a safe fallback."""
    try:
        parts = s.split(":")
        if len(parts) != 2:
            return default
        h = int(parts[0])
        m = int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return default
        return time(h, m, 0)
    except Exception:
        return default


def scheduler_loop():
    """
    Background scheduler: run at two times per day, configurable via env:
      WG_RUN_TIME_1 (default '00:00')
      WG_RUN_TIME_2 (default '12:00')
    """
    print("[SCHED] Started scheduler")

    t1_str = os.environ.get("WG_RUN_TIME_1", "00:00")
    t2_str = os.environ.get("WG_RUN_TIME_2", "12:00")

    t1 = parse_time_str(t1_str, time(0, 0, 0))
    t2 = parse_time_str(t2_str, time(12, 0, 0))

    times = sorted([t1, t2], key=lambda t: (t.hour, t.minute, t.second))
    print(f"[SCHED] Using run times: {times[0]} and {times[1]}")

    while True:
        now = datetime.now()
        today = now.date()

        # Build candidate run times for today
        candidates = []
        for t in times:
            dt = datetime.combine(today, t)
            if dt > now:
                candidates.append(dt)

        if candidates:
            next_run = min(candidates)
        else:
            # Both times passed today -> run at earliest time tomorrow
            tomorrow = today + timedelta(days=1)
            next_run = datetime.combine(tomorrow, times[0])

        wait = int((next_run - now).total_seconds())
        print(f"[SCHED] Next run at {next_run}, waiting {wait} sec")

        time_module.sleep(max(wait, 1))

        print(f"[SCHED] Running scheduled update at {datetime.now()}")
        run_and_publish()


# ---------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------
@app.route("/api/wg", methods=["GET"])
def api():
    """Manual trigger: call WG, publish to MQTT, return JSON."""
    val = run_and_publish()
    if not val:
        return jsonify({"error": "No data"}), 500
    return Response(val, mimetype="application/json")


@app.route("/", methods=["GET"])
def info():
    return "WaterGuru API → MQTT publisher"


# ---------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------
if __name__ == "__main__":
    setup_mqtt()
    print("[INIT] No initial run; waiting for configured schedule")

    threading.Thread(target=scheduler_loop, daemon=True).start()

    app.run(host="0.0.0.0", port=int(config["port"]), debug=False)
