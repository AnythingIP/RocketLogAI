# RocketLogAI v2.0 Installation Guide

RocketLogAI v2 is a local-first security platform for homelabs and learning (see [DISCLAIMER.md](DISCLAIMER.md) — no warranty, use at your own risk). It ingests syslog, uses your own LLM for analysis, and ships a full ecosystem:

- **RocketLogAI** — Core monitoring, AI assistant, devices, daily briefing
- **RocketRemediate** — Safe remediation (dry-run, approval, backup, rollback)
- **RocketShield** — WAF + AV on decrypted traffic, parental controls
- **RocketAI Mobile** — API for iOS/Android/TV (QR pairing, sync, remote control)
- Unified AI brain (MCP server, vector RAG), UEBA, audit logging, Prometheus metrics
- Home Assistant integration, enterprise auth (AD/LDAP + Entra ID), Helm chart

This guide covers the easiest ways to get v2 running.

**One-click setup wizard (recommended):**

```bash
git clone https://github.com/AnythingIP/RocketLogAI.git
cd RocketLogAI
./scripts/setup.sh          # Linux / macOS
```

```powershell
git clone https://github.com/AnythingIP/RocketLogAI.git
cd RocketLogAI
.\scripts\setup.ps1         # Windows — install, Docker, upgrade, or repair
```

The wizard asks: **native Python**, **Docker**, **upgrade**, **health check**, or **restore from backup**.

**Python version:** Native installs default to **Python 3.12** when available (full AI Operator). Docker always uses Python 3.12 inside the image.

**Install folder hygiene:** Install and upgrade automatically remove junk (old `RocketLogAI_Ver1.0/` bundles, `.git/`, screenshots, duplicate DBs at root, stale code) and sync `logsentinel/` with the current release. Manual dry-run:

```bash
python scripts/rla_cleanup.py /path/to/install --source /path/to/RocketLogAI --dry-run
python scripts/rla_cleanup.py /path/to/install --source /path/to/RocketLogAI --fix
```

---

## 1. Easiest: Docker (one-click)

```bash
git clone https://github.com/AnythingIP/RocketLogAI.git
cd RocketLogAI
./scripts/install-docker.sh ~/logsentinel
```

```powershell
.\scripts\install-docker.ps1
```

Creates `config.yaml`, `./data` bind mount (easy backup), builds **Python 3.12** image, starts container.

Open http://localhost:8787 — default login `admin / admin` (change immediately).

---

## 2. One-Click Linux Install (No Docker)

```bash
# Download or copy the installer
cd /opt
tar -xzf RocketLogAI-v1.2-Installer.tar.gz
cd RocketLogAI-v1.2-Installer

# Run the installer (creates venv, installs deps, creates default config)
sudo ./scripts/install.sh

# Edit config (highly recommended before first run)
sudo nano /opt/rocketlogai/config.yaml

# Start it (systemd service is created automatically)
sudo systemctl enable --now rocketlogai

# View logs
sudo journalctl -u rocketlogai -f
```

Access at http://your-server:8787 (default admin/admin).

---

## 3. One-Click Windows Install (PowerShell)

Run as Administrator in PowerShell:

```powershell
# Extract the installer somewhere (e.g. C:\RocketLogAI)
cd C:\RocketLogAI-v1.2-Installer

# Run the installer
.\scripts\install.ps1

# Edit the config
notepad C:\RocketLogAI\config.yaml

# Start the service (or run manually)
# The script creates a scheduled task or you can run:
python -m logsentinel run
```

---

## 4. Manual Install (Python developers / advanced)

```bash
git clone <repo> RocketLogAI
cd RocketLogAI

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Create your config
cp example-config.yaml config.yaml
# Edit config.yaml - especially the llm: section for your model or Azure/M365 Copilot

# Run
python -m logsentinel run
```

---

## First-Run & Important Configuration

After starting:

1. Open the web UI (default http://localhost:8787 or your server IP)
2. Log in with `admin / admin`
3. **Immediately change the admin password** (Users page)
4. Go to **Config** and configure at least:
   - LLM section (critical)
     - For Microsoft 365 Copilot / Azure OpenAI: select the provider and fill `azure_endpoint`, `azure_deployment`, and your key.
   - Heartbeats / Monitors (add your important devices)
   - Geo (multi-source is supported)

### The New AI Assistant (Phases 2-3)
After install, go to **AI Assistant** in the sidebar (🤖).
- Natural language operator commands are now supported (e.g. "ping the core router", "create a PowerPoint from today's threats", "use this token for GitHub and create an issue...").
- Always shows a reviewable Action Plan first. Explicit confirmation required for changes.
- For full power: `pip install open-interpreter` (the installers now pull it).

### Advanced Authentication & RBAC (Phase 4)
See the expanded "Windows Domain Authentication" and new "Microsoft Entra ID" sections on the **Config** page.
- Use the "Test Domain + Groups + Role" button after filling service account + group mappings.
- Roles: Viewer / Analyst / Operator / Administrator mapped from your directory groups.
- Service account passwords and Entra secrets are encrypted on save.

**Full feature install (recommended):**
pip install -e ".[web,v2,ai]"

This page is the living documentation + feedback system.

---

## Key Features You Probably Want to Set Up

- **Microsoft 365 Copilot**: Use the dedicated fields on the Config page.
- **IBM i (AS/400)**: Create credentials of type `ibmi_ssh` or `ibmi_5250`, then monitors of that type. Use the English prompt box for legacy menu automation.
- **Multi-Geo**: Configure multiple providers (MaxMind + paid services) in the Geo section.
- **HA Integration**: Enable it and add your `notify.mobile_app_*` services.
- **API Tokens**: Create long-lived `rla_...` tokens under Config → API Tokens for scripts/agents.

---

## Troubleshooting

- **LLM not responding**: Make sure your local server (LM Studio/Ollama) is running and reachable, or that your Azure/M365 credentials are correct. Use the Test Connection button.
- **No logs appearing**: Check that your devices are sending syslog to the right port (default 5140 UDP/TCP).
- **Permission issues on Linux**: The install script tries to set up proper ownership. You can also run as a dedicated user.
- **Self-signed HTTPS warnings**: Expected on first run. Accept the cert in your browser.

---

## Updating / Upgrading

**Recommended:** Git clone the latest release, then run the upgrade script from the new source tree.

```bash
git clone https://github.com/AnythingIP/RocketLogAI.git
cd RocketLogAI
```

Linux / macOS:
```bash
./scripts/upgrade.sh /path/to/your/existing/install --native --fix
```

Windows (PowerShell):
```powershell
.\scripts\upgrade.ps1 -TargetDir "D:\logsentinel" -InstallType native -Fix
```

The upgrade script:
- Auto-detects **native** vs **Docker** (won't mistake a native install just because `docker-compose.yml` exists)
- Copies updated `logsentinel/`, `templates/`, `scripts/`, and v2 modules
- Creates a `.venv` if missing (prefers Python 3.12 via `py -3.12` when available)
- Installs core `pip install -e ".[web,v2]"` (required), then tries `open-interpreter` (optional)
- Preserves your `config.yaml` and `data/` (including the database)

**Python version:** Core RocketLogAI v2 works on Python 3.10–3.13. The optional **AI Operator** (`open-interpreter`) requires **Python 3.10–3.12** on Windows (Python 3.13 fails to build `tiktoken`). If you only have 3.13, the upgrade still completes — syslog, dashboard, remediation, and shield all work; only the Open Interpreter backend is skipped.

**Health check / repair** (run anytime):
```bash
python scripts/healthcheck.py /path/to/install --fix
# or wrappers:
./scripts/check.sh ~/logsentinel --fix          # Linux/macOS
.\scripts\check.ps1 -InstallDir D:\logsentinel -Fix   # Windows
```

**Important on Windows:** After upgrading, use `.\start-rocketlogai.ps1` from your install directory — not a globally installed `logsentinel` from another Python.

**Docker upgrades** (only when actually running in Docker):
```bash
./scripts/upgrade.sh /path/to/install --docker
```
Requires Docker Desktop/daemon to be running.

After upgrade, open http://localhost:8787 and verify the v2 dashboard.

---

## Support & Feedback

Use the built-in **AI Assistant** (/assistant) to ask questions.  
Submit feature ideas through the assistant — admins can review them in the same interface.

This tool was built to be self-documenting and self-improving. The more you use the Assistant and submit suggestions, the better it gets.

---

**You are now ready to move this to the new location and run it in production testing.**

If you run into any issues during the move, the most common fixes are:
- Correct LLM configuration (especially for Copilot)
- Network access for syslog/HA
- Proper file permissions on Linux

Good luck with the new deployment! RocketLogAI v2.0 includes the full ecosystem (RocketRemediate, RocketShield, mobile API, MCP brain), plus all v1.x features.