# Conversational Device Automation (the "talk to devices like we talk here" pattern)

## Goal
The user wants RocketLogAI (and future tools in their ASP.NET environment) to interact with devices (especially legacy IBM i greenscreens, Windows, etc.) the same way the human operator talks to Grok:

- Human types plain English: "Block all outbound except 443 and 53 on this IoT camera" or "Run the old FINANCE menu option 12 close process and tell me if any jobs are stuck"
- System probes the device (using the credential profile's permissions)
- AI generates human-readable explanation + the exact low-level commands/CLs/scripts/F-key sequences
- Shows both the friendly version and the raw code
- Human reviews + clicks "Use / Confirm"
- Only then executes (with rollback options)
- Everything logged in the Server Activity view for humans + AI to see and learn from

This is **not** replacing the human — it complements and amplifies exactly like this chat session.

## Core Patterns (take these to ASP.NET)

1. **Credential Profiles as the single source of truth for "what this identity is allowed to do"**
   - Same table/model for web UI login, monitors, remediation, and now data sources.
   - Types: local, domain, ssh_key, ibmi_5250, ibmi_ssh, windows_wmi, token...
   - Never store plaintext. Hash or use OS keychain.

2. **English → Structured Action (the prompt engineering that works)**
   - Always send rich context: current device intelligence (vendor, category, port profile, recent threats, last probe result).
   - Ask LLM for:
     - human_explanation (markdown)
     - raw_code_or_cl (the actual command/script/CL)
     - safety_notes
     - suggested_monitor_or_prebuild
   - Never auto-execute. Always human gate + dry_run default.

3. **Unified Activity Log (what the server is actually doing)**
   - One table: server_activity (direction in/out, source_type, source, action, status, details_json, bytes, duration)
   - Powers the beautiful /activity dashboard.
   - AI can read the last N events and suggest "this source has been dead 14 days — dormant the monitor for 30 days?"
   - One-click apply (or at least clear suggested change).

4. **Pluggable Agent-less Sources + Active Monitors**
   - data_sources config section for "how do I get data from this thing?"
   - heartbeats/monitors for "is this thing healthy and what should I do about it?"
   - Both feed the same analyzer + activity log.

5. **IBM i Specific (the greenscreen automation you care about)**
   - Support both modern SSH (best) and classic 5250.
   - Prebuilts for common daily tasks + a "legacy_menu_task" pattern.
   - The `automate_legacy_menu_task(english_description)` method in ibmi.py is the starting point.
   - Goal: Old menu-driven programs from the 90s/2000s become scriptable via English.

## How to port the "Grok-style conversation" to ASP.NET

- Use the same LLM client pattern (Azure OpenAI / M365 Copilot is perfect here since you already have it).
- Have a "DeviceConversation" service that takes (device_id, credential_profile_id, user_english_prompt).
- It does:
  1. Load device intelligence + last activity.
  2. Call LLM with a strong system prompt that includes "You are a helpful co-pilot that talks to this exact device type the way Grok talks to the human operator."
  3. Return {explanation, proposed_commands[], safety, confidence}.
  4. Store the generation for audit (like we do with remediation generations).
  5. On user "Confirm", execute via the appropriate connector (SSH, 5250 library, WMI, etc.) and log to Activity table.
- Expose it through the same clean web UI pattern (HTMX or Blazor) so it feels as fluid as this chat.

The Python implementation here is the reference implementation and living spec for the .NET version.

## Phase 2 Status (implemented)
The AI Assistant (🤖) now accepts natural English device/network commands ("ping ...", "show devices using port 22", "run 'df -h' on the linux servers", etc.).

- Always returns a structured, reviewable Proposed Action Plan first.
- OS-aware command generation.
- Uses existing credential_profiles (now with reversible encryption for secrets that must be used at runtime).
- Explicit "Confirm & Execute" (or Dry-run only) gate.
- Automatic audit logging to server_activity with source_type=assistant_operator.
- Reuses the project's existing safe subprocess + ssh/sshpass execution patterns + remediation script infrastructure.
- Backups + rollback guidance encouraged in plans.

Full safety model from the original doc is respected: human in the loop, dry-run by default for dangerous actions, full visibility.

## Phase 3 Status (major foundation implemented)
The AI Assistant has been transformed into a full **natural-language co-pilot** that understands requests the way you talk to Grok Build or Open Interpreter.

**Core new architecture:**
- New `logsentinel/ai_assistant/controller.py` — the smart safety wrapper and orchestrator (this is the primary file for Phase 3 intelligence).
- **Open Interpreter is the primary execution backend** when installed (`pip install open-interpreter`). The controller sets it up with `safe_mode`, `auto_run=False`, and routes high-level natural language through it only after explicit user confirmation.
- The controller always generates a rich Action Plan first (using RocketLogAI's existing LLM client), presents it in the UI, and only executes after explicit confirmation.
- **Credential ingestion directly from conversation** ("use this token ghp_xxx for github", "connect to my Home Assistant with username X and password Y"). Credentials are stored securely (encrypted) using the Phase 2 credential_profiles system and can be reused.
- **Dynamic tool use**: Plans can include explicit "ensure_tool python-pptx" (or paramiko, etc.) steps. On confirmation the controller can safely pip-install approved packages.
- OS detection + command adaptation.
- Special high-value executors: Home Assistant service calls, GitHub issue creation, PowerPoint report generation (using python-pptx + data from storage/threats/activity), complex SSH/code tasks delegated to Open Interpreter.
- Automatic backups before changes + detailed rollback guidance surfaced in every plan.
- Full audit logging via `server_activity` (source_type=`ai_assistant_powerful`).
- Basic learning / anomaly recording hook (executions are recorded so future plans and the daily briefing can become smarter and flag unusual behavior, e.g. "firewall admin logged in at 3am").

**Example natural requests the system is now designed to handle:**
- "Use this username/password to connect to my Home Assistant and turn on the lights"
- "Connect to my GitHub using this token and create a new issue summarizing today's logs"
- "Ping 1.1.1.1 and nmap the local network"
- "Download the latest version of Wireshark and deploy it to these 3 computers"
- "Create a PowerPoint presentation summarizing network activity for the executives"
- "Analyze why the firewall admin logged in at 3am"

**Safety (non-negotiable):**
- Clear Action Plan is **always** shown first with numbered steps, exact commands/actions, targets, credentials, risk level, backup info, and rollback instructions.
- Explicit confirmation ("Confirm & Execute") required for any modifying or high-risk action. A "Dry-run only" option is always available.
- If the controller is unsure or the request is ambiguous/dangerous, it asks for clarification.
- All side effects are logged. Modifying actions attempt automatic backups.

The implementation builds directly on the Phase 2 foundation (the operator plan/confirm flow in web.py) while moving the heavy intelligence, Open Interpreter orchestration, credential conversation handling, and dynamic capabilities into the clean new `ai_assistant/controller.py` module.

To activate full power: `pip install open-interpreter` (and optionally python-pptx, paramiko, etc.), then restart the server. The controller degrades gracefully if Open Interpreter is missing.

## Next-level ideas
- After successful execution, feed the real output back to the LLM: "Here is what the device actually returned — was this what the operator wanted?"
- Let the AI suggest new monitors or data sources based on activity patterns.
- White-label the whole thing (instance name + logo) so it feels like your internal tool, not "RocketLogAI".

This is exactly why the activity dashboard + credential profiles + English generator were built the way they were.

Use this document when you move the concepts into ASP.NET.

## Phase 4 (side task completed alongside Phase 3 polish)
Advanced enterprise authentication & RBAC implemented on top of the existing local + basic domain system:

- Full LDAP/LDAPS with service account bind + group membership lookup for RBAC.
- Entra ID (OAuth + Microsoft Graph) support with group-to-role mapping.
- Proper 4-tier RBAC (Viewer / Analyst / Operator / Administrator) mapped from AD/Entra groups (or local is_admin).
- Secure encrypted storage for service account and Entra client secrets (reuses controller/storage crypto).
- Greatly improved "Test Domain Connectivity" that does service bind + user lookup + groups + optional full user auth + role resolution.
- Login now stores role + groups in session; RBAC dependencies protect sensitive routes (Operator for actions, Admin for config).
- Fallback to local admin always available (with CLI escape hatch).
- Audit of logins and role in server_activity.
- Config UI expanded with service accounts, LDAPS options, group mappings per role, and full Entra section.
- Existing local auth and basic flows untouched.

See updated WebConfig, auth.py helpers, web.py login + test + RBAC, and config.html for details.

All phases (1-4) foundations are now in the codebase. Ready for testing as requested.
