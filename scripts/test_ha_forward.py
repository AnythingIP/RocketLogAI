#!/usr/bin/env python3
"""
Test helper: inject realistic Home Assistant addon / core / supervisor syslog messages
into a RocketLogAI instance (to verify the mib1185/ha-addon-syslog forwarder path or
manual HA log shipping).

Usage (from /Volumes/logsentinel):
  python scripts/test_ha_forward.py --host 192.168.20.138 --port 5140

Then:
- Wait 45-90s for the next analysis cycle.
- In the RocketLogAI web UI: visit /logs and search for "GROK-HA-TEST" or "addon_grok".
- Or tail data/logsentinel.log | grep -E "GROK|homeassistant/addon"
- Or ask the AI Assistant: "Any recent logs from Home Assistant addons or with the string GROK?"
- Check threats or the analyzer summaries for the injected entries.
- You can also trigger real traffic by restarting a HA addon (e.g. the nut UPS one) or causing a sensor error.

The messages use both RFC3164 and RFC5424 styles (the addon typically produces lines that parse nicely).
"""
import argparse
import socket
import time
import datetime
import sys

def send_ha_style_logs(host: str, port: int, count: int = 4, marker: str | None = None):
    if marker is None:
        marker = "GROK-HA-TEST-" + datetime.datetime.utcnow().strftime("%H%M%S")
    now = datetime.datetime.utcnow()
    ts3164 = now.strftime("%b %d %H:%M:%S")
    iso = now.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

    # Mix of formats the parser handles, with appnames/tags that match what the HA syslog addon produces
    messages = [
        # RFC3164 style (common)
        f"<134>{ts3164} homeassistant addon_grok_z2m[1234]: zigbee2mqtt:info MQTT publish sensor {marker}",
        f"<134>{ts3164} homeassistant addon_grok_esph[567]: [bed-light] INFO ESPHome started {marker}",
        # RFC5424 style (explicit appname, what produces "homeassistant/addon_..." in summaries)
        f"<134>1 {iso} homeassistant homeassistant/addon_grok_nut 42 - - UPS driver reconnect attempt {marker}",
        f"<134>1 {iso} hassio supervisor 1 - - supervisor addon core_mosquitto restart {marker}",
        # Error style that may trigger rules/LLM
        f"<131>{ts3164} homeassistant homeassistant[999]: ERROR sensor setup failed for test_sensor {marker} connection refused",
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for _ in range(count):
        for m in messages:
            try:
                sock.sendto(m.encode("utf-8", "replace"), (host, port))
                sent += 1
            except Exception as e:
                print(f"[warn] send to {host}:{port} failed: {e}", file=sys.stderr)
            time.sleep(0.05)
    sock.close()
    print(f"Sent {sent} HA-style test messages (marker={marker}) to {host}:{port}")
    print("Wait ~60s then look in UI /logs or data/logsentinel.log for the marker or 'homeassistant/addon_grok'.")
    return marker

def main():
    p = argparse.ArgumentParser(description="Inject test HA addon logs into RocketLogAI syslog for verification.")
    p.add_argument("--host", default="192.168.20.138", help="RocketLogAI syslog host (the IP you configured in the HA addon)")
    p.add_argument("--port", type=int, default=5140, help="Syslog port (usually 5140)")
    p.add_argument("--count", type=int, default=2, help="How many rounds of messages to send")
    p.add_argument("--marker", default=None, help="Custom marker string (default: GROK-HA-TEST-...)")
    args = p.parse_args()

    marker = send_ha_style_logs(args.host, args.port, args.count, args.marker)
    print("\nVerification tips:")
    print("  - Web UI: http://<rocket-ip>:8787/logs  (search marker or 'addon_grok' or 'homeassistant')")
    print("  - App log: tail -f data/logsentinel.log | grep -E 'GROK|addon_grok|homeassistant/addon'")
    print("  - AI Assistant (in UI): ask 'show recent logs containing GROK or from homeassistant addons' or 'what HA UPS logs have you seen?'")
    print("  - To generate real traffic: in HA, restart the 'Network UPS Tools' (nut) addon or another one.")
    print(f"\nMarker used: {marker}")

if __name__ == "__main__":
    main()
