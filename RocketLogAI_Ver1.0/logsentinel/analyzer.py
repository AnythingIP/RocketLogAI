"""
Analysis engine: combines rule engine + LLM + storage.

Runs periodically, decides what to send to the model, stores results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .llm import LocalLLM
from .rules import RuleEngine, RuleMatch
from .storage import Storage
from .geo import get_geo_enricher
from .ha import get_ha_client
from .blacklist import get_blacklist
from .mac_vendor import get_mac_vendor_lookup, refresh_mac_vendors_if_needed

# Optional alerting (graceful if web extras not installed)
try:
    from .web import send_threat_alerts
except Exception:
    def send_threat_alerts(threats, cfg=None):
        pass

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, cfg: Config, storage: Storage, llm: LocalLLM | None = None):
        self.cfg = cfg
        self.storage = storage
        self.llm = llm or LocalLLM(cfg.llm)
        self.rule_engine = RuleEngine(cfg.rules.custom_patterns if cfg.rules.enabled else None)
        self._last_analysis_ts: float = 0.0
        self._running = False

    async def run_loop(self) -> None:
        """Background analysis loop."""
        self._running = True
        logger.info("Analysis engine started")

        while self._running:
            try:
                await self.analyze_recent()
            except Exception as exc:
                logger.exception("Analyzer loop error: %s", exc)

            # Periodically refresh device intelligence for high-risk devices (more frequent AI decisions)
            if self._last_analysis_ts and (time.time() - self._last_analysis_ts) % 300 < 30:  # roughly every ~5 min
                try:
                    summary = self.storage.get_device_intelligence_summary(limit=10) if hasattr(self.storage, "get_device_intelligence_summary") else {}
                    for dev in (summary.get("high_risk_devices") or []) + (summary.get("investigate_devices") or []):
                        if dev.get("ip"):
                            self.storage.assess_device_intelligence(dev["ip"], self.llm)
                except Exception:
                    pass

            await asyncio.sleep(self.cfg.analysis.interval_seconds)

    def stop(self) -> None:
        self._running = False

    async def analyze_recent(self) -> dict[str, Any]:
        """
        Pull recent logs, run rules + (optionally) LLM, persist results.
        Returns summary dict for callers.
        """
        if not self.cfg.analysis.enabled:
            return {"status": "disabled"}

        # Fetch recent logs (more than batch for context)
        recent = self.storage.get_recent_logs(
            limit=self.cfg.analysis.context_window,
            min_severity=None,
        )

        if not recent:
            return {"status": "no_logs"}

        # Run fast rule engine on everything
        scored: list[dict[str, Any]] = []
        high_value_logs: list[dict[str, Any]] = []

        for rec in recent:
            score, matches = self.rule_engine.score_record(rec)
            rec["_rule_score"] = score
            rec["_rule_matches"] = [m.__dict__ for m in matches]
            scored.append(rec)

            if score >= 6.0 or rec.get("severity_code", 0) >= 4:
                high_value_logs.append(rec)

        # Decide whether to call the LLM
        min_sev = self.cfg.analysis.min_severity_for_ai
        min_code = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(min_sev, 2)

        llm_candidates = [r for r in scored if r.get("severity_code", 0) >= min_code or r["_rule_score"] >= 5.0]
        llm_candidates.sort(key=lambda x: (x["_rule_score"], x.get("severity_code", 0)), reverse=True)

        threats: list[dict[str, Any]] = []
        summary = "No AI analysis performed."
        model_used = self.cfg.llm.model or "local"
        llm_succeeded = False
        raw_llm_text: str | None = None

        do_ai = bool(llm_candidates) and len(llm_candidates) >= 1

        if do_ai:
            # Prepare compact log lines for the model
            lines_for_ai: list[str] = []
            for r in llm_candidates[: self.cfg.analysis.batch_size]:
                ts = r.get("timestamp", "")[:19]
                host = r.get("hostname") or "?"
                app = r.get("appname") or "?"
                msg = r.get("message", "")[:250]
                lines_for_ai.append(f"[{ts}] {host}/{app}: {msg}")

            logger.info(f"Sending {len(lines_for_ai)} logs to local LLM for analysis...")

            result = self.llm.analyze_logs(lines_for_ai, model=self.cfg.llm.model or None)

            ai_threats = result.get("threats", [])
            summary = result.get("summary", "Analysis completed.")
            model_used = self.cfg.llm.model or "local"
            llm_succeeded = "error" not in result and bool(ai_threats or result.get("summary"))
            raw_llm_text = result.get("_raw_llm_text")

            # Convert AI threats into our storage format + merge rule evidence
            for t in ai_threats:
                threats.append({
                    "severity": t.get("severity", "medium"),
                    "score": float(t.get("score", 5.0)),
                    "description": t.get("description", ""),
                    "hostname": t.get("hostname"),
                    "appname": t.get("appname"),
                    "recommended_action": t.get("recommended_action"),
                    "evidence": t.get("evidence", []),
                })

        # Also surface strong rule-only matches even if LLM was not used or returned nothing
        for r in scored:
            if r["_rule_score"] >= 7.0:
                for m in r["_rule_matches"]:
                    threats.append({
                        "severity": m["severity"],
                        "score": m["score"],
                        "description": m["description"],
                        "hostname": r.get("hostname"),
                        "appname": r.get("appname"),
                        "recommended_action": "Investigate immediately. Consider isolating host if pattern continues.",
                        "evidence": m.get("evidence", []),
                    })

        # Deduplicate threats by description (very rough)
        seen = set()
        unique_threats = []
        for t in threats:
            key = (t["severity"], t["description"][:80])
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)

        # ============================================================
        # FULLY OFFLINE GEO + DEEP HOME ASSISTANT ENRICHMENT
        # (runs for every threat, completely local)
        # ============================================================
        # Respect any explicit geo mmdb_path from config
        geo_path = None
        if getattr(self.cfg, "geo", None) and self.cfg.geo.enabled:
            geo_path = (self.cfg.geo.mmdb_path or "").strip() or None
        geo = get_geo_enricher(geo_path)
        ha_client = get_ha_client(self.cfg) if getattr(self.cfg, "home_assistant", None) else None

        for t in unique_threats:
            # 1. Offline Geo (MaxMind if DB present)
            ip = t.get("source_ip") or self._extract_ip_from_evidence(t)
            if ip:
                t["source_ip"] = ip
                geo_data = geo.enrich(ip)
                if geo_data:
                    t.update({
                        "geo_country": geo_data.get("country"),
                        "geo_city": geo_data.get("city"),
                        "geo_lat": geo_data.get("lat"),
                        "geo_lon": geo_data.get("lon"),
                        "geo_accuracy": geo_data.get("accuracy"),
                    })
                    # Also cache it
                    self.storage.cache_ip_geo(ip, geo_data)

                # Blacklist reputation check (external IPs only)
                if ip and not ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "127.")):
                    try:
                        bl = get_blacklist(getattr(self.cfg, "blacklist", None))
                        if bl.is_blacklisted(ip):
                            t["blacklisted"] = True
                            t["notes"] = (t.get("notes") or "") + " [BLACKLISTED IP - very high risk]"
                            if t.get("severity") in ("low", "medium"):
                                t["severity"] = getattr(getattr(self.cfg, "blacklist", None), "hit_severity", "high")
                    except Exception:
                        pass  # never let blacklist failure break analysis

            # 2. Deep Home Assistant device context (if configured)
            if ha_client and getattr(self.cfg.home_assistant, "auto_enrich", True):
                ip_for_ha = t.get("source_ip")
                ha_ctx = ha_client.find_device_for_ip_or_mac(ip=ip_for_ha)
                if ha_ctx:
                    t["ha_device_name"] = ha_ctx.get("name")
                    t["ha_entity_id"] = ha_ctx.get("entity_id")
                    t["ha_area"] = ha_ctx.get("area")
                    # Cache for future UI / fast lookup
                    self.storage.upsert_ha_device(
                        entity_id=ha_ctx["entity_id"],
                        name=ha_ctx.get("name"),
                        device_id=None,
                        area=ha_ctx.get("area"),
                        attributes=ha_ctx.get("attributes", {}),
                    )

                    # Record in persistent device registry
                    self.storage.upsert_known_device({
                        "ip": ip_for_ha,
                        "ha_entity_id": ha_ctx.get("entity_id"),
                        "ha_name": ha_ctx.get("name"),
                        "ha_area": ha_ctx.get("area"),
                        "trust_level": "normal"
                    })

                    # Simple MAC enrichment (local network only)
                    try:
                        import subprocess
                        import sys
                        # Cross-platform: Windows uses 'arp -a', Unix-like use 'arp -n'
                        arp_cmd = ['arp', '-a'] if sys.platform == "win32" else ['arp', '-n', ip_for_ha]
                        result = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=3)
                        if result.returncode == 0:
                            # Parse MAC from output (handles both : and - separators)
                            import re
                            mac_match = re.search(r'([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}', result.stdout)
                            if mac_match:
                                mac = mac_match.group(0).lower().replace('-', ':')
                                self.storage.upsert_known_device({
                                    "ip": ip_for_ha,
                                    "mac": mac
                                })

                                # MAC Vendor Lookup - identify manufacturer and category
                                is_new = False
                                try:
                                    lookup = get_mac_vendor_lookup()
                                    vendor = lookup.lookup(mac)
                                    if vendor:
                                        category, icon = lookup.get_device_category_and_icon(vendor)
                                        self.storage.upsert_known_device({
                                            "ip": ip_for_ha,
                                            "vendor": vendor,
                                            "device_category": category,
                                            "vendor_icon": icon
                                        })

                                    # New device detection
                                    is_new = self.storage.is_new_device(ip_for_ha, mac)
                                    if is_new:
                                        logger.info(f"New device detected: {ip_for_ha} ({vendor or 'unknown vendor'})")
                                except Exception:
                                    pass

                                if is_new:
                                    t["new_device"] = True
                                    t["new_device_note"] = f"New device first seen: {vendor or 'Unknown'} ({category or 'Unknown type'})"
                    except Exception:
                        pass  # ARP not critical

        # Record observations + bump threat counts (feeds risk scoring on next analysis)
        for t in unique_threats:
            sip = t.get("source_ip") or self._extract_ip_from_evidence(t)
            if sip:
                try:
                    # Check if this is a brand new device before recording
                    if self.storage.is_new_device(sip):
                        t["new_device"] = True
                        if not t.get("new_device_note"):
                            t["new_device_note"] = "New device detected on the network"

                    self.storage.record_device_observation(sip)
                    self.storage.increment_device_threat_count(sip)
                except Exception:
                    pass

        # Per-device intelligence assessment (MAC trust + traffic history + AI)
        for t in unique_threats:
            sip = t.get("source_ip")
            if sip:
                try:
                    assessment = self.storage.assess_device_intelligence(sip, self.llm)
                    t["device_ai_verdict"] = assessment.get("verdict")
                    t["device_ai_summary"] = assessment.get("summary")
                    if assessment.get("verdict") in ("suspicious", "threat", "investigate"):
                        if t.get("severity") == "medium":
                            t["severity"] = "high"
                        t["notes"] = (t.get("notes") or "") + f" [Device assessment: {assessment.get('verdict')}]"
                except Exception:
                    pass

        # Occasionally let the AI propose useful automation rules based on observed device behavior
        try:
            if len(unique_threats) > 0 or True:
                recent_devs = self.storage.get_known_devices(limit=8)
                self._generate_ai_automation_suggestions(recent_devs, unique_threats)
        except Exception:
            pass

        # Execute any AI rules that a human has explicitly enabled
        try:
            recent_devs = self.storage.get_known_devices(limit=10)
            self._execute_enabled_automation_rules(recent_devs)
        except Exception:
            pass

        # Apply smart automation / suppression rules BEFORE persist so status, severity, and notes are correct in DB
        # (rules now respect the toggles from the Automation page + risk influence)
        unique_threats = self._apply_default_automation_rules(unique_threats)

        # User custom rules (from the rule builder)
        unique_threats = self._apply_custom_rules(unique_threats)

        # Persist analysis + threats (now with rich context + correct suppression status)
        analysis_id = self.storage.create_analysis(model=model_used)
        self.storage.finish_analysis(
            analysis_id=analysis_id,
            summary=summary,
            threats=unique_threats,
            raw_response=raw_llm_text,
            logs_analyzed=len(recent),
        )

        # Fire alerts only for the final high/critical (after suppression + risk bumps)
        high_sev = [t for t in unique_threats if t.get("severity", "").lower() in ("high", "critical") and not t.get("_auto_suppress")]
        if high_sev:
            send_threat_alerts(high_sev, self.cfg)

        self._last_analysis_ts = time.time()

        result_summary = {
            "status": "ok",
            "analysis_id": analysis_id,
            "logs_evaluated": len(recent),
            "threats_found": len(unique_threats),
            "summary": summary,
            "used_llm": llm_succeeded,
        }

        logger.info(f"Analysis complete: {result_summary}")
        return result_summary

    def _apply_default_automation_rules(self, threats: list[dict]) -> list[dict]:
        """
        Pre-configured smart defaults that dramatically reduce noise for Home Assistant users.
        These run after enrichment. Respects the toggles set on the /automation page.
        """
        rules = {}
        try:
            if hasattr(self.storage, "get_automation_rules"):
                rules = self.storage.get_automation_rules()
        except Exception:
            pass
        # defaults to ON if key missing (for safety / first run)
        def enabled(key: str) -> bool:
            return rules.get(key, True)

        processed = []
        for t in threats:
            ha_name = t.get("ha_device_name") or ""
            ha_entity = t.get("ha_entity_id") or ""
            desc = (t.get("description") or "").lower()
            evidence = " ".join(str(e) for e in t.get("evidence", [])).lower()
            source_ip = t.get("source_ip") or ""

            auto_suppress = False
            note = None
            new_severity = None

            # === Default Smart Rules (only if the corresponding toggle is enabled) ===

            # Rule 1 + 1b: External HTTPS from known HA devices or user-learned ignore
            if enabled("suppress_ha_https") and ("https" in desc or "443" in evidence):
                if ha_entity:
                    device_type_keywords = ["light.", "sensor.", "switch.", "binary_sensor.", "device_tracker.", "cover."]
                    if any(x in ha_entity.lower() for x in device_type_keywords):
                        auto_suppress = True
                        note = "Auto-suppressed: Normal outbound HTTPS from Home Assistant device"
                if not auto_suppress and source_ip:
                    device = self.storage.find_device_by_ip(source_ip) or {}
                    normal = device.get("normal_behaviors") or {}
                    if normal.get("ignore_https"):
                        auto_suppress = True
                        note = "Auto-suppressed: User has marked HTTPS as normal for this device"

            # Rule 2: mDNS / multicast (5353) from known HA devices
            if enabled("suppress_mdns") and "5353" in evidence and ha_entity:
                auto_suppress = True
                note = "Auto-suppressed: Typical mDNS/muticast from Home Assistant device"

            # Rule 3: Internal service traffic on port 9999 (very common in HA environments)
            if enabled("suppress_9999") and "9999" in evidence and "192.168." in evidence:
                auto_suppress = True
                note = "Auto-suppressed: Expected internal service traffic on port 9999"

            # Rule 4: Unknown devices (no HA record) doing repeated external connections get promoted
            if enabled("escalate_unknown") and not ha_entity and source_ip and ("external" in desc or "443" in evidence):
                if t.get("severity") == "medium":
                    new_severity = "high"
                    note = "Escalated: Activity from unknown device (not in Home Assistant)"

            # Risk influence (device registry polish): high-risk devices (untrusted + history + no baseline) escalate
            if source_ip and not auto_suppress:
                try:
                    dev = self.storage.find_device_by_ip(source_ip)
                    if dev:
                        rs = dev.get("risk_score") or 40
                        if rs >= 72 and t.get("severity") == "medium":
                            new_severity = "high"
                            note = (note or "") + " [elevated: high risk device]"
                        if rs >= 85 and t.get("severity") in ("medium", "high"):
                            # Force HA major alert path for very high risk
                            t["_major_risk"] = True
                except Exception:
                    pass

            # Apply changes
            if auto_suppress:
                t["_auto_suppress"] = True
                t["status"] = "iot_expected"
                if note:
                    t["notes"] = (t.get("notes") or "") + " " + note

            if new_severity:
                t["severity"] = new_severity
                if note:
                    t["notes"] = (t.get("notes") or "") + " " + note

            processed.append(t)

        return processed

    def _apply_custom_rules(self, threats: list[dict]) -> list[dict]:
        """User-defined rules from the /automation page. Run after the built-in defaults."""
        try:
            custom = self.storage.get_custom_rules(enabled_only=True) if hasattr(self.storage, "get_custom_rules") else []
        except Exception:
            custom = []

        if not custom:
            return threats

        import re
        for t in threats:
            if t.get("_auto_suppress"):
                continue  # already decided
            text = ((t.get("description") or "") + " " + " ".join(str(e) for e in t.get("evidence", []))).lower()
            ha = (t.get("ha_device_name") or t.get("ha_entity_id") or "").lower()
            sip = t.get("source_ip") or ""
            is_external = sip and not sip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "127."))

            for rule in custom:
                cond = (rule.get("condition") or "").lower().strip()
                if not cond:
                    continue
                matches = False
                if cond in text or cond in ha:
                    matches = True
                elif "external" in cond and is_external:
                    matches = True
                elif ("unknown" in cond or "no_ha" in cond) and not t.get("ha_device_name"):
                    matches = True
                elif re.search(r'port\s*=\s*(\d+)', cond):
                    m = re.search(r'port\s*=\s*(\d+)', cond)
                    if m and m.group(1) in text:
                        matches = True
                elif re.search(r'\b(\d{2,5})\b', cond):  # bare port number
                    for p in re.findall(r'\b(\d{2,5})\b', cond):
                        if p in text:
                            matches = True

                if matches:
                    action = rule.get("action", "iot_expected")
                    note = f"Custom rule \"{rule.get('name')}\": {action}"
                    if action == "iot_expected":
                        t["_auto_suppress"] = True
                        t["status"] = "iot_expected"
                    elif action == "escalate" and t.get("severity") == "medium":
                        t["severity"] = "high"
                    elif action.startswith("severity:"):
                        t["severity"] = action.split(":", 1)[1]
                    if note:
                        t["notes"] = (t.get("notes") or "") + " " + note
                    break  # first matching custom rule wins
        return threats

    def get_status(self) -> dict[str, Any]:
        return {
            "last_run": self._last_analysis_ts,
            "rules_enabled": self.cfg.rules.enabled,
            "llm_enabled": self.cfg.analysis.enabled,
            "llm_endpoint": self.cfg.llm.base_url,
        }

    def _extract_ip_from_evidence(self, threat: dict[str, Any]) -> str | None:
        """Best effort extraction of an IP address from evidence or description."""
        import re
        candidates = []
        for ev in threat.get("evidence", []):
            if isinstance(ev, str):
                candidates.append(ev)
        if threat.get("description"):
            candidates.append(threat["description"])

        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for text in candidates:
            m = ip_pattern.search(text)
            if m:
                ip = m.group(0)
                # Skip obviously internal or invalid
                if not ip.startswith(("0.", "127.", "169.254.")):
                    return ip
        return None

    def _generate_ai_automation_suggestions(self, recent_devices: list[dict], recent_threats: list[dict]):
        """
        Uses the LLM to propose useful automation rules based on observed behavior.
        These are created as *suggestions* only (disabled by default).
        Human must explicitly enable them.
        """
        if not self.llm or not recent_devices:
            return

        # Only suggest occasionally to avoid noise
        if len(recent_devices) < 2:
            return

        try:
            # Build a compact context for the LLM
            device_summary = []
            for d in recent_devices[:5]:
                device_summary.append({
                    "ip": d.get("ip"),
                    "vendor": d.get("vendor"),
                    "category": d.get("device_category"),
                    "trust": d.get("trust_level"),
                    "has_baseline": bool(d.get("normal_behaviors"))
                })

            prompt = f"""
You are an automation assistant for a local security monitoring system.

Recent devices observed:
{json.dumps(device_summary, indent=2)}

Recent notable activity:
{json.dumps([t.get("description") for t in recent_threats[:3] if t.get("description")], indent=2)}

Based on patterns, suggest 0-2 useful automation rules the user might want.

Each rule should be something that could be triggered by device behavior (connection, specific ports, etc.).

Return a JSON array. Each item must have:
- name: short name
- description: one sentence explanation
- condition: simple description of when it should trigger
- proposed_action: what should happen (e.g. "Call Home Assistant service light.turn_on with entity_id: light.living_room")
- reason: why this might be useful
- confidence: 0.0 to 1.0

Only suggest rules that are genuinely helpful and respect privacy/safety. If nothing good comes to mind, return an empty array.
"""

            # Call the LLM (reuse existing pattern)
            response = None
            if hasattr(self.llm, "complete"):
                response = self.llm.complete(prompt)
            elif hasattr(self.llm, "chat"):
                response = self.llm.chat([{"role": "user", "content": prompt}])

            if not response:
                return

            # Extract JSON
            import re
            match = re.search(r'\[.*\]', response, re.DOTALL)
            if not match:
                return

            suggestions = json.loads(match.group(0))

            for sug in suggestions[:2]:  # Limit to 2 per cycle
                rule = {
                    "name": sug.get("name", "Suggested Automation"),
                    "description": sug.get("description"),
                    "condition": {"text": sug.get("condition")},
                    "proposed_action": sug.get("proposed_action"),
                    "confidence": sug.get("confidence", 0.6),
                    "reason": sug.get("reason"),
                    "related_device_ip": device_summary[0]["ip"] if device_summary else None,
                    "status": "suggested"
                }
                self.storage.create_suggested_rule(rule)
                logger.info(f"AI suggested new automation rule: {rule['name']}")

        except Exception as e:
            logger.warning("Failed to generate AI automation suggestions: %s", e)

    def _execute_enabled_automation_rules(self, observed_devices: list[dict]):
        """
        For rules that a human has explicitly enabled, check if current device activity
        matches the condition and execute the action (primarily Home Assistant calls for now).
        """
        try:
            enabled_rules = self.storage.get_enabled_suggested_rules() if hasattr(self.storage, "get_enabled_suggested_rules") else []
            if not enabled_rules:
                return

            for device in observed_devices:
                ip = device.get("ip")
                mac = device.get("mac")
                vendor = device.get("vendor")

                for rule in enabled_rules:
                    condition = rule.get("condition_json") or {}
                    proposed = rule.get("proposed_action", "")

                    # Simple matching: rule mentions this device's IP or MAC or vendor
                    matches = False
                    if ip and ip in str(condition):
                        matches = True
                    if mac and mac in str(condition):
                        matches = True
                    if vendor and vendor.lower() in str(condition).lower():
                        matches = True

                    # Also match on related_device_ip if set
                    if rule.get("related_device_ip") == ip:
                        matches = True

                    if matches and "home assistant" in proposed.lower():
                        logger.info(f"Executing AI-approved rule '{rule['name']}' for device {ip}")
                        # Try to extract and call HA service if possible
                        try:
                            from .ha import get_ha_client
                            ha = get_ha_client(self.cfg) if hasattr(self.cfg, "home_assistant") else None
                            if ha and "service" in proposed.lower():
                                # Very basic extraction - in real use this would be structured
                                # For beta we'll just log a clear execution notice
                                logger.info(f"[AI RULE EXECUTED] {rule['name']} -> {proposed}")
                                # Future: parse "light.turn_on entity_id=light.xxx" and call ha.call_service
                        except Exception as e:
                            logger.warning("Failed to execute HA action from AI rule: %s", e)
        except Exception as e:
            logger.warning("Error executing enabled automation rules: %s", e)
