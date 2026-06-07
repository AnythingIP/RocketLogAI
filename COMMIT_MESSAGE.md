feat: Complete Phases 1-4 + installer + docs overhaul (AI Operator + Enterprise Auth/RBAC)

This is a major update bringing the AI Assistant to full conversational operator capability and adding proper enterprise authentication.

## Summary of Changes

### Phase 1 - Quick Fixes
- Fixed sidebar toggle: now fully slides off to the left on desktop with smooth animation, correct chevron icons that flip, state persisted in localStorage across refreshes, and a show button appears in the topbar when collapsed.
- Devices page: Replaced generic red ❓ icons with context-aware device icons ( for Apple, 🪟 for Windows, 🐧 for Linux, 📡 for routers/firewalls/switches, neutral ❔ for unknown). Fixed MAC vendor lookup so the Vendor field and category now reliably populate from the OUI/manuf databases and are persisted to the DB.
- Daily Briefing layout: Moved the AI Assistant chat panel to the top of the page; the 24h summary/readout now appears below it.

### Phase 2 - Smart AI Assistant (Conversational Operator)
- Transformed /assistant into a powerful, safe co-pilot that accepts natural English commands.
- Core flow: LLM generates a structured dry-run Action Plan (steps, OS-specific commands, affected devices, credential to use, risk, backup/rollback notes).
- Explicit user confirmation required before any execution.
- Supports ping, nmap, traceroute, SSH commands, basic software deployment, config backups, etc.
- OS detection and command adaptation.
- Secure credential management: user can say "use this token ... for github" in chat; creds are stored encrypted in the DB and reused.
- Full audit logging via server_activity (source_type=assistant_operator).
- Safety: always plan first, confirm gate, backups where relevant, easy rollback instructions.

### Phase 3 - Extremely Powerful & Natural
- Primary execution backend is now **Open Interpreter** (wrapped in a strict safety controller at `logsentinel/ai_assistant/controller.py`).
- High-level requests work: "Use this username/password to connect to my Home Assistant and turn on the lights", "Connect to my GitHub using this token and create a new issue summarizing today's logs", "Download the latest Wireshark and deploy it to these 3 computers", "Create a PowerPoint presentation summarizing network activity for the executives", "Analyze why the firewall admin logged in at 3am", etc.
- Dynamic tool use: the controller proposes and (on confirm) can install safe packages (python-pptx, etc.).
- Integrates with existing systems (HA client, credential_profiles, device registry, activity log, remediation scripts).
- Learning/anomaly hooks started; multi-turn conversational feel.

### Phase 4 - Advanced Authentication & RBAC
- **Full Active Directory / LDAP**: Proper service-account bind for group lookup (least privilege), LDAPS support with CA cert and verify options.
- **Entra ID (Azure AD)**: OAuth2 / client credentials + Microsoft Graph for user and transitive group membership.
- **RBAC**: Four roles — Viewer (read-only), Analyst, Operator (can run actions after confirmation), Administrator (full access).
- Group membership from AD/Entra is mapped in config (or the nice new UI section) to roles. Highest matching role wins.
- Secure storage: service account passwords and Entra client secrets are encrypted at rest (using the existing credential encryption helpers).
- Greatly improved "Test Domain Connectivity" button on /config that does real service bind + group fetch + optional full user auth + resolved role.
- Login flow now stores role + groups in the session and emits proper audit events.
- RBAC enforcement added to sensitive routes (e.g. config save requires Administrator, assistant execution requires Operator).
- Local admin fallback always works (with documented CLI escape hatch).
- Multiple domains/forests possible via config; everything audited.

### Installer & Packaging Updates
- All install paths (Linux `install.sh`, Windows `install.ps1`, root + dist Dockerfiles) now ensure `open-interpreter` and `cryptography` are installed so the new AI Operator and encrypted auth features work out of the box.
- `pyproject.toml` now has proper `[web,ai]` and `[full]` extras.
- `requirements.txt` updated with notes.
- `ai_assistant` subpackage is properly included.

### Documentation & GitHub Updates
- Comprehensive updates to README.md (feature highlights, install commands, testing checklist).
- New `TESTING.md` with detailed what-to-test matrix for this build (AI flows, RBAC matrix, domain tester, encryption, installers, etc.).
- Updated INSTALL.md, example-config.yaml with full new auth sections and examples.
- Updated CONVERSATIONAL_DEVICE_AUTOMATION.md.
- CLI now has a basic `logsentinel auth` helper.
- Version bumped.

## Files Changed (major ones)
- logsentinel/ai_assistant/{__init__.py,controller.py} (new)
- logsentinel/{auth.py,config.py,web.py,cli.py,storage.py}
- templates/{config.html,login.html,assistant.html,base.html,daily.html,devices.html}
- scripts/{install.sh,install.ps1}
- Dockerfile, docker-compose.yml, pyproject.toml, requirements.txt, example-config.yaml
- README.md, INSTALL.md, TESTING.md (new), docs/*.md
- Various dist/ installer copies kept in sync

## What We Should Be Testing
See TESTING.md for the full prioritized list. Key areas:
- AI Assistant natural language (with and without open-interpreter installed)
- Full plan → review → confirm → execute flow + audit
- Credential-from-chat storage/reuse
- AD/LDAP with service account + groups + role mapping (use the enhanced test button)
- Entra ID group lookup
- RBAC enforcement (different users see different capabilities)
- Encryption of new secrets
- Fresh installs on Linux/Windows/Docker
- No regression on sidebar, devices icons, daily briefing, etc.
- Graceful fallback when optional deps are missing

All changes follow existing patterns, keep safety rails, and are backward compatible with local auth.

Closes the Phase 1-4 roadmap items.
