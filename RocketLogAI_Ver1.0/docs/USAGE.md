# LogSentinel Usage Guide

## First Run Checklist

1. Start LM Studio and load a capable model (≥7B recommended)
2. Verify the local server works:
   ```bash
   curl http://localhost:1234/v1/models
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
