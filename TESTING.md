# RocketLogAI Build Testing Guide (Phases 1-4)

This build includes major new capabilities in the AI Assistant and enterprise authentication/RBAC. Use this as your test checklist.

## 1. Quick Smoke (after any install/restart)
- [ ] Web UI loads at http://localhost:8787 (or configured port)
- [ ] Login with default admin/admin (or your local creds)
- [ ] Change admin password immediately via /users
- [ ] Sidebar collapses/expands fully to the left, state persists on refresh, topbar show button appears when hidden
- [ ] /devices page shows proper icons ( / 🪟 / 🐧 / 📡 / ❔ gray) and real vendor names (MAC lookup now works and persists)
- [ ] /daily has chat at top, 24h summary below

## 2. AI Assistant / Operator (Phase 2 + 3) - /assistant
**Core flow (requires open-interpreter for full power, but plans work without it):**
- [ ] Type natural commands and get a rich "Proposed Action Plan" card:
  - `ping 1.1.1.1`
  - `nmap the local network`
  - `show devices using port 22`
  - `run 'uname -a' on the linux servers`
  - `create a PowerPoint summarizing recent network activity`
- [ ] Plan shows: explanation, numbered steps with exact commands, targets, risk, credentials needed, backup/rollback notes.
- [ ] "Confirm & Execute" and "Dry-run only" buttons work.
- [ ] Results appear in chat, including artifact paths (e.g. generated .pptx in data/generated_reports).
- [ ] Everything is logged in Server Activity (source_type `ai_assistant_powerful` or `assistant_operator`).

**Credential handling from conversation:**
- [ ] Say: `use this token ghp_xxx123 for github as work-github`
- [ ] It should be stored (encrypted) and appear in credential profiles / usable in later plans.
- [ ] Same for username/password style for HA or network devices.

**Advanced (with open-interpreter installed):**
- [ ] High-level requests like "Download latest Wireshark and deploy to these 3 computers" or "Connect to my Home Assistant with this token and turn on the lights in the office".
- [ ] Dynamic tool steps ("ensure_tool python-pptx") are proposed and can be confirmed.
- [ ] OS adaptation in generated commands.

**Fallbacks:**
- [ ] Works (with reduced execution power) when open-interpreter is not installed.
- [ ] Graceful degradation when cryptography is missing (secrets stored with lighter protection).

## 3. Advanced Auth & RBAC (Phase 4) - /config + Login
**Domain / LDAP:**
- [ ] Configure service account (low-priv), LDAPS options, and group mappings for the 4 roles.
- [ ] Use the **"Test Domain + Groups + Role"** button (with and without a test user).
  - Should report service bind success + sample groups + resolved role.
- [ ] Log in with a domain user that matches an Operator group → can use assistant confirm actions.
- [ ] Log in with Viewer-only group → read-only (actions should be blocked or 403 on API).
- [ ] Fallback to local when domain fails (configurable).
- [ ] Force domain-only + recovery via `logsentinel enable-local-login` (or equivalent CLI).

**Entra ID:**
- [ ] Configure tenant/client + group mappings.
- [ ] Test via the helper paths or token-based login (full redirect flow is prepared in docs).
- [ ] Group membership from Graph is used for role resolution.

**RBAC Enforcement:**
- [ ] Non-Administrator cannot save /config.
- [ ] Non-Operator cannot execute high-risk assistant plans.
- [ ] Role is visible in session and used for audit.

**Encryption & Secrets:**
- [ ] After saving service password or Entra secret via UI, check config.yaml — sensitive values should be encrypted (fernet:... prefix or similar).
- [ ] Restart and confirm logins still work (decryption happens at runtime).

**Audit:**
- [ ] All logins (success/fail) + role appear in /activity with source_type `auth`.
- [ ] Permission denials are logged where applicable.

**Fallbacks & Safety:**
- [ ] Local admin always works as escape hatch.
- [ ] TOTP still works on local accounts.
- [ ] API tokens (rla_*) continue to function.

## 4. Installers & Packaging
- [ ] Linux: `./scripts/install.sh` (or from dist) installs open-interpreter + cryptography.
- [ ] Windows: PowerShell installer does the same.
- [ ] Docker: `docker compose build` pulls the extras; container starts with full features.
- [ ] `pip install -e ".[web,ai]"` and `.[full]` work from source.
- [ ] `logsentinel` CLI entry point still works.
- [ ] ai_assistant package is importable after install.

## 5. Clean Sweep / Regressions
- [ ] No breakage to Phase 1 sidebar/devices/briefing.
- [ ] No breakage to Phase 2 basic operator flow.
- [ ] All py files compile: `python -m py_compile logsentinel/*.py logsentinel/ai_assistant/*.py`
- [ ] No circular import errors on startup.
- [ ] Config save/merge doesn't lose other sections.
- [ ] Existing credential_profiles for devices/monitors still work.

## Recommended Test Matrix for Release
1. Fresh Linux install + full AI + AD test.
2. Windows install + Entra test (if tenant available).
3. Docker compose up + basic operator commands.
4. RBAC matrix: 4 different AD/Entra test accounts.
5. "Locked out" recovery scenario.
6. Power user flow: credential from chat → complex multi-step plan (e.g. backup + deploy + report) → confirm → verify artifacts + audit.
7. Edge: no cryptography, no open-interpreter, LDAPS without CA, etc.

Report any issues with exact steps + config snippet (redact secrets) + server logs.

---

**Version note**: This is a development build incorporating Phases 1-4. Update version in pyproject.toml before tagging a release.

Happy testing! 🚀
