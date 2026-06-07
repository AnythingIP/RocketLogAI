# RocketLogAI Installation Guide (v1.3 - Daily Briefing / Operator Companion)

RocketLogAI is a local-first, AI-powered security monitoring platform. It ingests syslog (and other sources), uses your own LLM (local or Microsoft 365 Copilot / Azure OpenAI) for analysis, and includes powerful features like:

- IBM i (AS/400) conversational automation via English prompts
- Multi-source geolocation
- Deep service monitors + English-to-script generation
- Server Activity dashboard with AI suggestions
- AI Assistant (/assistant) for self-documenting help + admin-reviewed feature suggestions
- Home Assistant integration
- API tokens for external scripts

This guide covers the easiest ways to get it running so it "just works".

---

## 1. Easiest: Docker (Recommended for most people)

```bash
# 1. Clone or copy the installer files
git clone <your-repo>   # or extract the RocketLogAI-v1.2-Installer tarball

cd RocketLogAI-v1.2-Installer

# 2. Copy example config and edit it
cp example-config.yaml config.yaml
# Edit config.yaml - at minimum set your LLM base_url (or Azure/M365 Copilot details)

# 3. Start it
docker compose up -d

# 4. Open the UI
# http://your-server-ip:8787   (or the https port if you enabled SSL)
```

Default login: `admin / admin` (change this immediately in the UI under Users).

The container handles everything (Python, deps, SQLite, etc.).

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
pip install -e ".[web,ai]"

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

**Recommended:** Use the upgrade script included in every release tarball.

Linux / macOS (from the new installer dir):
```bash
./scripts/upgrade.sh /path/to/your/existing/logsentinel
```

Windows (Admin PowerShell):
```powershell
.\scripts\upgrade.ps1 -TargetDir "D:\logsentinel"
```

The script stops the service, copies the updated `logsentinel/`, `templates/`, and `scripts/`, reinstalls the Python package in your existing venv, updates launchers, and restarts. Your `config.yaml` and `data/` (including the DB) are left untouched.

**Manual alternative:**
Stop the service/container, replace the `logsentinel/` and `templates/` folders (and scripts/ if changed), keep your `config.yaml` and `logsentinel.db`, then restart. For Docker: `docker compose build --no-cache && docker compose up -d`.

After upgrade, visit the new **Daily Briefing** page (/daily) to see the Operator Companion in action.

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

Good luck with the new deployment! This version (1.2.0) includes the full iBMi conversational automation, multi-geo, M365 Copilot support, the new AI Assistant, and many usability improvements.