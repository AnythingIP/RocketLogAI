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

## Next-level ideas
- After successful execution, feed the real output back to the LLM: "Here is what the device actually returned — was this what the operator wanted?"
- Let the AI suggest new monitors or data sources based on activity patterns.
- White-label the whole thing (instance name + logo) so it feels like your internal tool, not "RocketLogAI".

This is exactly why the activity dashboard + credential profiles + English generator were built the way they were.

Use this document when you move the concepts into ASP.NET.
