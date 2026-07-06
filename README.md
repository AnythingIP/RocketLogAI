# RocketLogAI v2.0 (by AnythingIP)

**Local-first security platform (hobby / homelab)** — syslog monitoring, AI threat detection, guarded remediation, WAF/AV shield, and mobile assistant. [MIT licensed](LICENSE) · [Disclaimer](DISCLAIMER.md) — no warranty, use at your own risk.

**Website:** [anythingip.github.io/RocketLogAI](https://anythingip.github.io/RocketLogAI/) · **Latest release:** [v2.0.0](https://github.com/AnythingIP/RocketLogAI/releases/tag/v2.0.0)

## v2 Ecosystem

| Product | Description |
|---------|-------------|
| **RocketLogAI** | Core syslog server, AI assistant, devices, daily briefing, config |
| **RocketRemediate** | Dry-run remediation, approval workflow, backups, rollback |
| **RocketShield** | WAF + AV on decrypted traffic, parental controls (inline/SPAN) |
| **RocketAI Mobile** | iOS/Android/TV API — QR pairing, sync, remote PC/Mac control |

**New in v2:** Unified AI brain (MCP + vector RAG), UEBA anomaly detection, full audit logging, Prometheus metrics, organization tasks, per-section config saves, Helm chart, pytest CI, pfSense/OPNsense/Wazuh integrations.

See [docs/architecture.md](docs/architecture.md) for full architecture.

---

**AI-powered local syslog server + security analyzer** that uses offline LLMs (LM Studio, Ollama, etc.) to detect threats and anomalies in real time.

- Receives syslog (UDP + TCP)
- Fast deterministic rule engine for common attacks
- Sends suspicious logs to your local LLM for deep analysis
- Stores everything in SQLite
- Zero cloud, zero data exfiltration
- **Fully offline IP geolocation** (optional free MaxMind GeoLite2 DB)
- **Deep Home Assistant integration** — enriches threats with your actual devices and can fire rich alerts inside HA
- **Active Heartbeat Monitoring** — not just port checks. Verify that the *correct* website version is running, SSH is up-to-date, etc. Outdated or down services become first-class threats that go through LLM analysis, alerting, and HA automation. Safe remediation actions (e.g. "update SSH") can be triggered after human confirmation.
- **Conversational Device Operator (Phase 3 in the AI Assistant)** — Talk to the 🤖 Assistant exactly like Grok Build or Open Interpreter using natural English:
  - "Use this token ghp_xxx to connect to GitHub and create an issue summarizing today's logs"
  - "Download the latest Wireshark and deploy it to these 3 computers"
  - "Create a PowerPoint presentation summarizing network activity for the executives"
  - "Connect to my Home Assistant with this password and turn on the lights"
  - "Analyze why the firewall admin logged in at 3am"
  Powered by Open Interpreter (primary backend) inside a strict safety controller (`logsentinel/ai_assistant/controller.py`). Always shows a detailed Action Plan first, requires explicit confirmation for any changes, accepts & securely stores credentials from conversation, supports dynamic tools, OS adaptation, automatic backups, rollback guidance, and full audit logging. Install `open-interpreter` (and optionally `python-pptx`) for maximum power. Safety-first at every layer.
- Remediation hooks exist but are **disabled and heavily guarded** by default

## Philosophy

Most "SIEM + AI" products phone home or require expensive licenses.  
RocketLogAI is the opposite: everything runs on your machine, against your local model, with full transparency and strong safety rails around any automated response. (From AnythingIP)

## Quick Start

**Easiest:** clone and run the setup wizard — it handles install, upgrade, Docker, backup, and Python 3.12 selection:

```bash
git clone https://github.com/AnythingIP/RocketLogAI.git && cd RocketLogAI && ./scripts/setup.sh
```

```powershell
git clone https://github.com/AnythingIP/RocketLogAI.git; cd RocketLogAI; .\scripts\setup.ps1
```

### 1. Install (manual)

```bash
pip install -e ".[web,v2]"   # core v2 (recommended; add open-interpreter on Python 3.10-3.12)
# or minimal:
pip install -e ".[web]"     # dashboard + core (no vector DB / open-interpreter)
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

## Forwarding Home Assistant Logs (Addons, Core, Supervisor, Sensors)

RocketLogAI's deep HA integration pulls device info *from* HA and can push alerts *back* into HA. For the other direction — getting the logs that HA and its addons produce (sensor errors, addon crashes, zigbee/zwave/mqtt noise, supervisor events, update messages, etc.) — use this:

The best solution for Home Assistant OS / Supervised is the dedicated **Syslog addon**:

1. In your HA UI: **Settings → Add-ons → Add-on Store** → click the three dots (⋮) top-right → **Repositories**.
2. Add the repo: `https://github.com/mib1185/ha-addon-syslog`
3. Install the addon named **"Syslog"** (author mib1185).
4. Open its **Configuration** tab and set:

   ```yaml
   syslog_host: "192.168.20.138"   # ← the LAN IP of the host running RocketLogAI (where 5140 is reachable)
   syslog_port: 5140
   syslog_protocol: udp           # udp recommended for volume; tcp and tls also work
   syslog_ssl: false
   syslog_ssl_verify: false
   ```

5. **Start** the addon. (No protection mode toggle usually required.)

Once running, logs from:
- Home Assistant Core
- Supervisor
- All add-ons (including ones emitting sensor data, errors, state)
- Host system journal (docker, kernel, etc.)

...will be forwarded as standard syslog messages to RocketLogAI.

You will see them with:
- `hostname`: often `homeassistant`, `hassio`, or the addon container name
- `appname` / `tag`: `homeassistant`, `supervisor`, `addon_<slug>`, etc.

Create custom rules in `config.yaml` under `rules.custom_patterns` for things like addon update failures, frequent sensor errors, or auth problems coming out of specific addons.

**Note on your IP**: When RocketLogAI is running via `docker compose` (or native) on this host, use the machine's LAN IP (not localhost or docker bridge). On this volume's host it is typically `192.168.20.138:5140` (UDP). Adjust for your network. Make sure the port is published in docker-compose.yml. Make sure the port is published in docker-compose.yml.

For pure container (non-HAOS) installs of HA you can also use the Docker `log-driver: syslog` option pointing at the same address.

This + the existing `home_assistant:` block in config gives you full circle observability and response for your smart home.

**Quick verification after setup**: Run `python scripts/test_ha_forward.py --host YOUR-ROCKET-IP --port 5140` (it ships realistic addon/core logs with markers). Then check the web UI **/logs**, tail `data/logsentinel.log` for the marker or `homeassistant/addon_`, or (best) ask the AI Assistant "what recent Home Assistant addon logs or GROK test messages have you seen?". Real traffic also appears when you restart any HA addon. See docs/USAGE.md for the full HA section + verification steps. (We confirmed the mib1185 addon + your HA instance is already successfully delivering logs — e.g. `homeassistant/addon_a0d7b954_nut` UPS messages were parsed and LLM-analyzed live.)

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

## What's New in This Build (Phases 1-4 Complete)

**Phase 1-2 Quick Fixes + Conversational Operator**
- Fixed sidebar collapse (full slide-to-left, persists state, better arrows + topbar show button).
- Better device icons (OS-aware:  Windows 🪟 Linux 🐧 Router 📡 etc.) + fixed MAC vendor lookup (now reliably populates manufacturer + persists).
- Daily Briefing chat moved to top.
- AI Assistant transformed into safe natural-language operator (ping/nmap/SSH/deploy/etc. via plans + explicit confirmation).

**Phase 3 - Extremely Powerful Natural AI Assistant**
- Uses **Open Interpreter** as primary execution backend (wrapped in strict safety controller at `logsentinel/ai_assistant/controller.py`).
- Accepts high-level English like the examples in the query (HA control with token from chat, GitHub issues, PowerPoint generation, anomaly analysis, software deploy, etc.).
- Dynamic tool installation (proposes `ensure_tool python-pptx` etc. as plan steps).
- Credential ingestion from conversation → encrypted storage + reuse.
- Always shows detailed Action Plan first; confirmation required for risk; auto-backups + rollback notes; full audit.
- OS detection/adaptation, multi-step orchestration.

**Phase 4 - Advanced Authentication & RBAC (Enterprise Ready)**
- Full Active Directory / LDAPS with dedicated service account for group lookups (no more giving users broad search rights).
- Microsoft Entra ID (Azure AD) support via OAuth2 + Microsoft Graph (user + group membership).
- True 4-tier RBAC: **Viewer** (read-only) → **Analyst** → **Operator** (confirmed actions) → **Administrator**.
- Groups from AD/Entra are mapped in config (or UI) to roles. Highest match wins. Stored in session + audited.
- Secure encrypted storage for service account passwords and Entra client secrets.
- Dramatically improved "Test Domain Connectivity" (service bind + groups + optional full user auth + resolved role).
- RBAC enforcement on sensitive endpoints (Operator for assistant actions, Admin for config).
- Local admin fallback always available (with CLI escape hatch `logsentinel enable-local-login`).
- Proper session logout + login audit logging.

**Installers updated** to pull `open-interpreter` + `cryptography` (for full encryption).

**Quick full install:**
```bash
pip install -e ".[web,ai]"   # includes Open Interpreter for the conversational AI Operator + crypto for new auth
# or use the updated scripts/install.sh | install.ps1 | Docker
```

### What You Should Test in This Build
**High priority (new in Phase 4):**
- AD/LDAP: service account bind, group membership resolution, role mapping, LDAPS.
- Entra ID: token/Graph path + group-to-role.
- RBAC: log in as different group members and verify permissions (e.g. non-Operator can't confirm actions; non-Admin can't save config).
- The enhanced "Test Domain + Groups + Role" button on /config (with and without test user).
- Encryption of new secrets (check config.yaml after save via UI — should be fernet:... or similar).
- Login audit in /activity.

**High priority (Phase 3 AI Operator):**
- Natural commands in /assistant: "ping 8.8.8.8", "show devices using port 22", "create a PowerPoint summarizing recent threats", "use this token ghp_xxx for github and create an issue...".
- Full flow: see plan → review → Confirm & Execute (or Dry-run) → results + rollback hint + activity log entry.
- Credential from chat is stored and reusable.
- If open-interpreter not installed, it should gracefully fall back but still show plans.

**Regression / existing:**
- Sidebar toggle (collapse/expand, persist, mobile).
- Devices page icons + vendor names.
- Daily Briefing layout and chat.
- Basic domain login still works.
- Local admin + TOTP + API tokens.
- All previous Phase 1-2 fixes.

**Docker / Installers:**
- Fresh install on Linux/Windows should pull open-interpreter + cryptography when using the updated scripts.
- `pip install -e ".[web,ai]"` or ".[full]" should work.
- Docker image builds with the extras.

Run `python -m py_compile logsentinel/*.py logsentinel/ai_assistant/*.py` after any manual edits.

## Disclaimer

**Hobby / educational software — use at your own risk.**

This project is shared **for fun** under the [MIT License](LICENSE). It is provided **"AS IS"** with **no warranty** and **no liability** for AnythingIP or contributors, within applicable law. You are solely responsible for deployment, security, compliance, backups, and any damage or data loss.

This is **not** professional security, legal, or IT advice. AI and automation output may be wrong or unsafe. Never blindly trust detections or operator plans. Always keep a human in the loop — especially before enabling remediation, remote commands, or production use. Test in a lab first.

Full legal terms: **[DISCLAIMER.md](DISCLAIMER.md)** · Security reports: **[SECURITY.md](SECURITY.md)**
