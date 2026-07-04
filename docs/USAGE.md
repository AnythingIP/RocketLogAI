# RocketLogAI v2 Usage Guide

> **v2.0.0 (production ecosystem)** — see [INSTALL.md](../INSTALL.md) and [architecture.md](architecture.md) for the full picture.
>
> **New in v2:**
> - **Unified AI brain** — MCP server (`logsentinel mcp`), vector RAG, conversation memory
> - **RocketRemediate** — dry-run, approval workflow, backups, rollback (`/api/v2/remediate/*`)
> - **RocketShield** — WAF + AV + parental controls (`/api/v2/shield/*`)
> - **RocketAI Mobile** — QR pairing, sync, assistant API (`/api/v2/mobile/*`)
> - **UEBA** anomaly detection, structured audit logging, Prometheus metrics
> - Organization tasks, per-section config saves, Entra OAuth, Helm chart
>
> **Carried forward from v1.x:**
> - Threats grouped view with per-occurrence src/dst IPs, ports, protocol
> - Dashboard trusted devices + rich device intelligence
> - Monitors: credential profiles, English→AI script generator, probe on successful test
> - Multi-source geo (MaxMind + paid providers), M365 Copilot / Azure OpenAI
> - API tokens (`rla_...`), deep Home Assistant integration, white-label branding

## First Run Checklist

1. Start your local LLM server:
   - LM Studio: load model + start local server (default http://localhost:1234/v1)
   - Ollama: `ollama serve` (OpenAI compat at http://localhost:11434/v1 )
2. Verify the local server works:
   ```bash
   curl http://localhost:1234/v1/models   # or 11434 for Ollama
   ```
3. `logsentinel example-config`
4. Edit the ports if needed
5. `logsentinel run`
6. Send test logs (see below)
7. Watch `logsentinel threats` and `logsentinel status`

## Sending Logs (Testing)

### Using netcat

```bash
# UDP
echo '<34>Mar  5 14:23:01 myserver sshd[12345]: Failed password for admin from 203.0.113.77 port 22 ssh2' \
  | nc -u -w 1 127.0.0.1 5140
```

### Using Python (more realistic)

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = b'<13>Mar  5 12:34:56 prod-web-03 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/cat /etc/shadow'
sock.sendto(msg, ('127.0.0.1', 5140))
```

### From real devices

Configure your switches, firewalls, Linux servers, etc. to forward syslog to the IP:port where LogSentinel is listening.

Example rsyslog client config:
```
*.* @logsentinel-host:5140
```

### From Home Assistant (addons + sensors + core logs)

Most HA users run Home Assistant OS. There is no simple built-in "remote syslog" toggle for the full set of logs (core, supervisor, **all addons**, host journal). Use the excellent community addon:

**Install the Syslog forwarder addon (mib1185/ha-addon-syslog)**

- Settings → Add-ons → Add-on Store → ⋮ → Repositories → add `https://github.com/mib1185/ha-addon-syslog`
- Install **Syslog**
- Configure (example):

  ```yaml
  syslog_host: "192.168.20.138"   # RocketLogAI host LAN IP (this machine / docker host)
  syslog_port: 5140
  syslog_protocol: udp
  syslog_ssl: false
  ```

- Start it.

This will ship logs from addons (e.g. zigbee2mqtt, zwave_js, mosquitto, esphome, your custom sensors, etc.), HA core, supervisor, and system to RocketLogAI over the syslog protocol.

In the RocketLogAI UI / logs / threats you will see source hostnames and tags containing "homeassistant", "addon-...", "hassio", "supervisor" etc. Perfect for writing rules or letting the LLM spot anomalies in your IoT stack.

**Tip**: If you want *state change events* (e.g. "bedroom motion sensor changed to on") as syslog too, also add to your `configuration.yaml`:

```yaml
system_log:
  fire_event: true
```

Then pair with the custom component https://github.com/TheByteStuff/RemoteSyslog_Service (or the newer Remote Logger) + an automation that sends the `system_log_event` to the syslog target. The addon above already gives you the bulk of the useful operational logs.

Point the `syslog_host` at the same address you use for other devices (the IP where RocketLogAI's 5140/udp is listening).

**Verifying the HA syslog forwarder is working**

Once the addon is started in HA and pointed at your RocketLogAI IP:port:

- In the RocketLogAI web UI go to **/logs** (or the live logs view) and search for `homeassistant`, `addon_`, `hassio`, `supervisor`, or sensor names from your setup. You should see entries with appname/hostname like `homeassistant/addon_a0d7b954_nut` (or your own addon slugs).
- Tail the server log: `tail -f data/logsentinel.log | grep -E 'homeassistant|addon_|GROK'`
- The analyzer will periodically feed batches containing HA logs to the LLM. You will see lines like:
  ```
  ... Analysis complete: ... "appname": "homeassistant/addon_...", "description": "Multiple warnings... UPS driver for HA-UPS..."
  ```
  (This is exactly what we observed after you installed the addon — real HA addon output was received, parsed, and analyzed.)
- Use the **AI Assistant** (the gold feature!): ask things like
  - "show me recent logs from home assistant addons"
  - "what HA UPS or zigbee errors have you seen lately?"
  - "summarize logs containing 'addon_' from the last hour"
- Generate fresh traffic easily: in HA, go to the addons page and **restart** one (e.g. "Network UPS Tools", Mosquitto, Zigbee2MQTT, or ESPHome). This produces immediate log lines that should appear within a minute or two.
- For scripted/repeatable tests (great before next version or after changes):
  ```bash
  python scripts/test_ha_forward.py --host 192.168.20.138 --port 5140 --count 2
  ```
  It sends a mix of RFC3164 + RFC5424 messages with distinctive "GROK-HA-..." markers and HA-like appnames. Then check the UI /logs or ask the AI Assistant about the marker.

If nothing appears after a few minutes + restart of an addon:
- Double-check the addon config has the correct `syslog_host` (the IP that reaches RocketLogAI's 5140, not localhost).
- Confirm RocketLogAI is listening (`logsentinel status` or look for "Listening on ... 5140" in the app log).
- Check firewall / docker port publish (UDP 5140 must be reachable from the HA host).
- The in-memory ring + DB should have it even if the LLM summary doesn't always echo every appname.

This gives a very solid, observable loop for testing the full HA → syslog → parse → store → LLM analysis pipeline.

## Understanding Severity Levels

- `emergency` / `alert` / `critical` → always sent to LLM if analysis is on
- `error` / `warning` → sent when rule score is high or volume is interesting
- `notice` / `info` → only included for context

You can raise `min_severity_for_ai` in config to reduce LLM calls and noise.

## Working with the Local Model

The quality of detection is **heavily** dependent on the model you load.

Recommended prompt-friendly models (as of 2025-2026):
- Qwen2.5-14B-Instruct or Qwen2.5-32B (best JSON following)
- Llama-3.3-70B or Llama-3.1-70B
- Command-R+ (excellent long context)

If the model returns garbage JSON, lower temperature (already set low) or add more few-shot examples in `llm.py`.

## Production Deployment Tips

- **Linux/macOS**: Run under systemd or launchd
- **Windows**: Run as a proper Windows Service (see section below)
- Use a reverse proxy or rsyslog in front for TLS-wrapped syslog if crossing untrusted networks
- Increase `retention_days` and monitor DB size
- Point multiple hosts at one LogSentinel instance (it is designed for that)
- Back up the SQLite file periodically

### Running as a Windows Service (Recommended)

To make LogSentinel start automatically after reboots and run in the background on Windows, the easiest and most reliable way is using **NSSM** (Non-Sucking Service Manager).

#### Step-by-step (NSSM method)

1. **Download NSSM**
   - Go to https://nssm.cc/download
   - Download the latest version and extract it (you only need `nssm.exe` from the `win64` folder).

2. **Open an elevated Command Prompt** (Run as Administrator).

3. **Install the service** (adjust paths to match your setup):

```cmd
nssm install LogSentinel
```

This will open the NSSM GUI. Fill in:

- **Path**:  
  `C:\Users\YourName\AppData\Local\Programs\Python\Python313\Scripts\logsentinel.exe`

- **Startup directory**:  
  `D:\logsentinel`   ← wherever your `config.yaml` and `data\` folder live

- **Arguments**:  
  `run --web --web-host 0.0.0.0 -c "D:\logsentinel\config.yaml"`

4. Go to the **Details** tab:
   - **Display name**: `LogSentinel`
   - **Description**: `AI-powered syslog security analyzer`
   - **Startup type**: `Automatic (Delayed Start)` ← recommended

5. Go to the **Log on** tab:
   - **This account**: Create a dedicated Windows user (recommended) or use your normal account.
   - Do **not** run as Local System unless you really know what you're doing (it has fewer network rights).

6. Go to the **I/O** tab (very useful):
   - **Output (stdout)**: `D:\logsentinel\data\logsentinel-service.log`
   - **Error (stderr)**: `D:\logsentinel\data\logsentinel-service-error.log`

7. Go to the **Recovery** tab:
   - First failure → Restart the Service
   - Second failure → Restart the Service
   - Subsequent failures → Restart the Service
   - Reset fail count after: 1 day

8. Click **Install service**.

9. Start it:

```cmd
nssm start LogSentinel
```

Or open `services.msc` and start **LogSentinel**.

#### Useful NSSM commands

```cmd
# Edit the service later
nssm edit LogSentinel

# Stop / start / restart
nssm stop LogSentinel
nssm start LogSentinel
nssm restart LogSentinel

# Remove the service completely
nssm remove LogSentinel confirm
```

#### Alternative: WinSW (Single executable)

If you prefer a single-file solution without installing NSSM:

- Download WinSW from GitHub (https://github.com/winsw/winsw)
- Rename `WinSW.exe` to `LogSentinel.exe`
- Create `LogSentinel.xml` with service definition
- Run `LogSentinel.exe install`

This is cleaner for distribution but slightly more work to set up initially.

#### Tips for Windows Service

- Always use a full path to your `config.yaml` with the `-c` flag.
- Use `--web-host 0.0.0.0` if you want the web UI reachable from other machines.
- Give the service account read/write access to the `D:\logsentinel\data\` folder.
- The service will survive reboots and logouts.
- You can view real-time logs using the files you configured in the I/O tab.

## When the LLM is Down

The system degrades gracefully:
- Rule engine still runs at full speed
- High-scoring rule matches still create threat records
- You will see `"used_llm": false` in analysis results

This is actually a feature for air-gapped or high-reliability environments.

## Viewing Server Logs (new in this version)

- **Web UI**: Visit `/logs` (after logging into the dashboard at port 8787). It shows the live in-memory buffer with level filtering and search. Updates automatically.
- **Persistent on-disk log**: `data/logsentinel.log` (rotating, 5MB x 5 files) is always written during `logsentinel run` (and other commands). It captures everything including full tracebacks from crashes. Use `tail -f data/logsentinel.log` from the project directory for the complete history across restarts.
- The old manual `errors.txt` copying is no longer needed.

The web `/logs` page now also documents the on-disk location.

## Extending Rules

Add your own regexes in `config.yaml`:

```yaml
rules:
  custom_patterns:
    - "myapp.*(weird error|tamper detected)"
    - "CRITICAL: .* from 10\\.0\\.0\\."
```

These are evaluated with `re.IGNORECASE`.

## Roadmap Items You Can Influence

- Better multi-log correlation (same host over 5 minutes)
- Support for JSON logs (many modern apps)
- Native Windows Event Log ingestion
- Threat intel feed integration (offline only)
- TUI dashboard (Textual or Rich live view)

## Daily Briefing (the Operator Companion)

New in this version: `/daily` (also linked from the dashboard). 

Gives you an entertaining, grounded, Grok-style recap of everything the server saw in a calendar day, rolling 24h, your shift window, or any historical date ("last Tuesday", "my overnight", etc.). 

You can chat with it naturally ("why did the auth failures spike?", "who was the source?", "draft a fix script for the monitor that flapped", "what should we promote to a standing monitor?").

The crew proposes concrete scripts and moves. You can promote good ones directly into monitors + attached remediation scripts (reuses the existing safe flows).

Long historical windows warn you and show staged progress because they may take 30-90s+ while the model digests the full evidence.

Everything is persisted so you can go back and review previous shifts with their full conversation history. All generation and chat turns are also written to Server Activity for audit.
