# RocketLogAI (by AnythingIP)

**AI-powered local syslog server + security analyzer** that uses offline LLMs (LM Studio, Ollama, etc.) to detect threats and anomalies in real time.

- Receives syslog (UDP + TCP)
- Fast deterministic rule engine for common attacks
- Sends suspicious logs to your local LLM for deep analysis
- Stores everything in SQLite
- Zero cloud, zero data exfiltration
- **Fully offline IP geolocation** (optional free MaxMind GeoLite2 DB)
- **Deep Home Assistant integration** — enriches threats with your actual devices and can fire rich alerts inside HA
- **Active Heartbeat Monitoring** — not just port checks. Verify that the *correct* website version is running, SSH is up-to-date, etc. Outdated or down services become first-class threats that go through LLM analysis, alerting, and HA automation. Safe remediation actions (e.g. "update SSH") can be triggered after human confirmation.
- Remediation hooks exist but are **disabled and heavily guarded** by default

## Philosophy

Most "SIEM + AI" products phone home or require expensive licenses.  
RocketLogAI is the opposite: everything runs on your machine, against your local model, with full transparency and strong safety rails around any automated response. (From AnythingIP)

## Quick Start

### 1. Install

```bash
cd logsentinel
pip install -e ".[web]"     # recommended (includes FastAPI dashboard + extras)
# or for the absolute minimum core
pip install -e .
# or (if you can't use editable install)
pip install -r requirements.txt
```

### 2. Start LM Studio (or Ollama with OpenAI compat)

- LM Studio: Load a good security-aware model (Qwen2.5-14B, Llama-3.1-8B, Command-R, etc.)
- Enable the local server (usually `http://localhost:1234/v1`)

### 3. Run with defaults (non-privileged ports)

```bash
logsentinel run
```

It will listen on UDP/TCP 5140 and use whatever model is loaded in LM Studio.

### 4. Send it some test logs

```bash
# From another terminal
echo '<13>Mar  5 12:34:56 myserver sshd[1234]: Failed password for root from 10.0.0.55 port 22' | nc -u -w1 127.0.0.1 5140
```

Watch the analysis kick in.

## Advanced: Fully Offline Geo + Home Assistant Integration (the killer feature)

RocketLogAI can now deeply understand your actual environment:

- **Offline Geo** — Drop a free MaxMind GeoLite2-City.mmdb anywhere reasonable and every threat automatically gets country/city/lat/lon with zero internet calls.
- **Home Assistant Superpowers** — Pulls your device registry, matches IPs/MACs from logs to real lights, sensors, switches, etc., and shows "🏠 Bedroom Temp Sensor" right next to the threat.
- When you hit **"CONFIRM THREAT"**, it can:
  - Create a persistent_notification in HA
  - Fire a custom `logsentinel.major_threat` event (build any automation you want)
  - Call your mobile notify services
  - Update live sensors (`sensor.logsentinel_last_threat`, etc.)

See `example-config.yaml` for the full `home_assistant:` block.

This turns RocketLogAI into the perfect local "someone is brute forcing my IoT stuff" watchdog that actually talks to your smart home.

## Configuration

Copy the example:

```bash
logsentinel example-config -o config.yaml
```

Edit `config.yaml`:

- Change ports to 514 if you want real syslog (requires root / `sudo` / launchd socket)
- Point `llm.base_url` at your local server
- Tune analysis frequency and severity thresholds
- **Leave `remediation.enabled: false`** until you have tested extensively

## Architecture

```
Syslog UDP/TCP
      ↓
Parser (RFC3164 + RFC5424 + best-effort)
      ↓
Storage (SQLite)
      ↓
Rule Engine (fast regex + heuristics)
      ↓
Analyzer (periodic)
      ├── High-value logs → Local LLM (structured JSON)
      └── Rule matches → Threat store
      ↓
Alerting (console + webhooks)
      ↓
Remediation Engine (stub, disabled by default)
```

## Commands

| Command            | Description                              |
|--------------------|------------------------------------------|
| `logsentinel run`  | Full daemon (server + continuous analysis) |
| `logsentinel analyze` | One-shot analysis on recent logs       |
| `logsentinel logs` | Show recent raw logs                     |
| `logsentinel threats` | Show AI + rule detections             |
| `logsentinel status` | DB stats + health check                 |
| `logsentinel example-config` | Generate commented config file     |

## Security & Safety Notes

**Remediation / "auto-fix"**

The ability to "plug into devices and fix them" is intentionally **not implemented** in a usable way yet.

- `remediation.enabled` defaults to `false`
- Even when enabled, it defaults to `dry_run: true`
- A third safety: `require_confirmation: true`

Any real automated response system must have:
- Explicit host + action allow-lists
- Full audit trail
- Circuit breakers
- Human approval workflow
- Tested rollback procedures

Until that exists and you have personally reviewed the code, **do not enable remediation**.

## Supported Models (LM Studio / Ollama)

Good results have been seen with:
- Qwen2.5 14B / 32B (excellent structured output)
- Llama-3.1 8B / 70B
- Command-R / Command-R+
- DeepSeek-R1 (distilled)

Smaller 7B models work but produce noisier JSON.

## Running on Real Syslog Port (514)

On macOS/Linux you usually need root or capabilities:

```bash
sudo logsentinel run -c /etc/logsentinel/config.yaml
```

On macOS, consider using a launchd plist that keeps the process alive and binds the privileged port.

Alternative (recommended for most people): keep it on 5140 and have your network devices or `rsyslog`/`syslog-ng` forward to it.

## Docker (Recommended for Production / Easy Deploy)

### Quick Start with Docker Compose (easiest)

```bash
cd logsentinel
docker compose up -d --build
```

Then open http://localhost:8787

Data (database, blacklists, learned device profiles, SSL certs, etc.) is stored in a named Docker volume (`rocketlogai_data`).

### Build & Run Manually

```bash
# Build the image
docker build -t rocketlogai:1.0-beta .

# Run with persistent data
docker run -d \
  --name rocketlogai \
  -p 8787:8787 \
  -p 5140:5140/udp \
  -p 5140:5140/tcp \
  -v rocketlogai_data:/app/data \
  rocketlogai:1.0-beta
```

### Using Your Own Config

```bash
docker run -d \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v rocketlogai_data:/app/data \
  -p 8787:8787 \
  rocketlogai:1.0-beta run --web
```

**Notes:**
- The web UI runs on port 8787 by default.
- For real syslog port 514 you will likely need `--privileged` or `--cap-add=NET_BIND_SERVICE` (or just forward from another syslog daemon to 5140).
- All learned data, blacklists, and generated SSL certs live in the mounted volume.

## Future Work (Contributions Welcome)

- Proper web dashboard (FastAPI + HTMX or React)
- Webhook + email + Slack alerting
- Better structured output enforcement + few-shot examples
- Responder plugins (SSH, API, agent)
- Threat correlation across time windows
- GeoIP / ASN enrichment (optional offline DB)
- Export to STIX / MISP / Wazuh format

## License

MIT

## Disclaimer

This is a powerful security tool. Automated analysis of production logs is inherently noisy. Never blindly trust AI output for security decisions. Always have a human in the loop, especially before enabling any remediation features.
