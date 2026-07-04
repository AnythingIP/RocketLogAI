"""
SQLite storage for logs and AI analysis results.

Uses stdlib sqlite3 for zero extra dependencies.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .parser import severity_to_int
from .auth import hash_password, verify_password


def _normalize_threat_signature(severity: str, description: str) -> str:
    """Cheap runtime signature for grouping similar LLM-generated threats across analyses.
    Strips variable data (IPs, ports, hex, timestamps) so 'Multiple devices talking to 1.2.3.4 on port 9999'
    and 'Multiple devices talking to 5.6.7.8 on port 1234' collapse to the same key.
    """
    if not description:
        return f"{severity}:<empty>"
    d = description.lower()
    d = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", d)
    d = re.sub(r"\b\d{2,5}\b", "<port>", d)
    d = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", d)
    d = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", "<ts>", d)
    d = re.sub(r"\s+", " ", d).strip()
    return f"{severity}:{d[:115]}"


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _cursor(self):
        conn = self._connect()
        try:
            yield conn.cursor()
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT,
                    appname TEXT,
                    procid TEXT,
                    facility TEXT,
                    severity TEXT,
                    severity_code INTEGER,
                    priority INTEGER,
                    message TEXT NOT NULL,
                    raw TEXT,
                    source TEXT,
                    format TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(timestamp)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_sev ON logs(severity_code)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    logs_analyzed INTEGER,
                    threats_found INTEGER,
                    summary TEXT,
                    raw_response TEXT,
                    model TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    severity TEXT,
                    score REAL,
                    description TEXT,
                    evidence TEXT,           -- JSON array of log ids or excerpts
                    recommended_action TEXT,
                    hostname TEXT,
                    appname TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(analysis_id) REFERENCES analyses(id)
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_sev ON threats(severity)
            """)

            # --- Schema migrations for threat status tracking (v0.2+) ---
            # Add columns if they don't exist (SQLite doesn't support IF NOT EXISTS on ADD COLUMN easily)
            try:
                cur.execute("ALTER TABLE threats ADD COLUMN status TEXT DEFAULT 'open'")
            except Exception:
                pass  # column already exists
            try:
                cur.execute("ALTER TABLE threats ADD COLUMN acknowledged_at TEXT")
            except Exception:
                pass
            try:
                cur.execute("ALTER TABLE threats ADD COLUMN notes TEXT")
            except Exception:
                pass

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)
            """)

            # --- Major schema additions for offline Geo + deep Home Assistant + rich human verification (2026) ---
            # All additions are safe (try/except) for existing databases
            for col, coltype in [
                ("source_ip", "TEXT"),
                ("geo_country", "TEXT"),
                ("geo_city", "TEXT"),
                ("geo_lat", "REAL"),
                ("geo_lon", "REAL"),
                ("geo_accuracy", "INTEGER"),
                ("ha_device_name", "TEXT"),
                ("ha_entity_id", "TEXT"),
                ("ha_area", "TEXT"),
                ("verification_level", "TEXT"),   # ai, human_quick, human_deep
            ]:
                try:
                    cur.execute(f"ALTER TABLE threats ADD COLUMN {col} {coltype}")
                except Exception:
                    pass

            # Expanded status support (existing rows keep old values)
            try:
                cur.execute("ALTER TABLE threats ADD COLUMN ha_triggered INTEGER DEFAULT 0")
            except Exception:
                pass

            # Verification history table (full audit of every human or auto action)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS verification_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER,
                    action TEXT NOT NULL,           -- acknowledged, false_positive, verified_threat, verified_benign, iot_expected, ha_triggered, etc.
                    previous_status TEXT,
                    new_status TEXT,
                    notes TEXT,
                    triggered_ha INTEGER DEFAULT 0,
                    actor TEXT DEFAULT 'user',      -- user, auto, system
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(threat_id) REFERENCES threats(id)
                )
            """)

            # Home Assistant device/entity cache (refreshed periodically or on demand)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ha_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT UNIQUE,
                    name TEXT,
                    device_id TEXT,
                    area TEXT,
                    attributes_json TEXT,   -- full state attributes for matching (ip, mac, etc.)
                    last_seen TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ha_devices_entity ON ha_devices(entity_id)
            """)

            # Simple persistent IP geo cache (so we don't re-query even if DB reloads)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_geo_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    city TEXT,
                    lat REAL,
                    lon REAL,
                    accuracy INTEGER,
                    fetched_at TEXT
                )
            """)

            # --- Heartbeat / Deep Service Monitoring tables ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS monitors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,              -- tcp | http | https | ssh_version | ping | custom
                    port INTEGER,
                    path TEXT,
                    expected TEXT,                   -- substring that must be present for "healthy"
                    severity TEXT DEFAULT 'medium',
                    remediation_action TEXT,
                    interval_seconds INTEGER DEFAULT 300,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_monitors_name ON monitors(name)
            """)

            # Add credential columns for per-monitor SSH/WinRM/etc access (separate from web login)
            for col, coltype in [
                ("credential_type", "TEXT"),      # 'local', 'domain', or NULL
                ("credential_username", "TEXT"),
                ("credential_secret", "TEXT"),    # bcrypt hash or path to key
            ]:
                try:
                    cur.execute(f"ALTER TABLE monitors ADD COLUMN {col} {coltype}")
                except Exception:
                    pass  # column already exists

            # Variables for script templating and rollback support
            for col, coltype in [
                ("script_variables_json", "TEXT"),  # JSON of {{VAR}} substitutions
                ("rollback_action", "TEXT"),
            ]:
                try:
                    cur.execute(f"ALTER TABLE monitors ADD COLUMN {col} {coltype}")
                except Exception:
                    pass

            cur.execute("""
                CREATE TABLE IF NOT EXISTS monitor_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    monitor_id INTEGER,
                    monitor_name TEXT,
                    success INTEGER NOT NULL,
                    message TEXT,
                    latency_ms REAL,
                    remediation_suggested TEXT,
                    details_json TEXT,               -- full structured result
                    checked_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(monitor_id) REFERENCES monitors(id)
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_monitor_results_time ON monitor_results(checked_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_monitor_results_monitor ON monitor_results(monitor_name, checked_at DESC)
            """)

            # --- Server Activity / Connections Log (inbound data sources + outbound actions: HA, SSH, WMI, 5250, remediation, etc.) ---
            # Powers the new human-readable "what is RocketLogAI actually doing right now" dashboard + AI self-monitoring
            cur.execute("""
                CREATE TABLE IF NOT EXISTS server_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT DEFAULT (datetime('now')),
                    direction TEXT NOT NULL,           -- 'inbound' (syslog, wmi pull, 5250 query) or 'outbound' (ha_notify, ssh_remediation, 5250_command)
                    source_type TEXT NOT NULL,         -- syslog_udp, syslog_tls, windows_wmi, ibmi_5250, ha, remediation_ssh, etc.
                    source TEXT,                       -- IP, hostname, or friendly name
                    action TEXT,                       -- e.g. 'syslog_received', 'ha_sensor_update', 'ssh_exec', '5250_cl_run', 'wmi_query'
                    status TEXT DEFAULT 'success',     -- success, failed, warning
                    details_json TEXT,                 -- full context (user, command, bytes, monitor_name, etc.)
                    bytes INTEGER,
                    duration_ms REAL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_server_activity_ts ON server_activity(ts DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_server_activity_source ON server_activity(source_type, source)")

            # --- Known Devices Registry (persistent device inventory + behavior) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS known_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    mac TEXT,
                    ha_entity_id TEXT UNIQUE,
                    ha_name TEXT,
                    ha_device_type TEXT,       -- light, sensor, switch, etc.
                    ha_area TEXT,
                    trust_level TEXT DEFAULT 'normal',   -- normal, trusted, untrusted, critical
                    notes TEXT,
                    normal_behaviors TEXT,     -- JSON: common ports, destinations, protocols
                    first_seen TEXT,
                    last_seen TEXT,
                    last_threat_count INTEGER DEFAULT 0,
                    mac_history TEXT,              -- JSON array: [{mac, first_seen, last_seen}, ...]
                    mac_trust_level TEXT DEFAULT 'unknown',  -- trusted, untrusted, unknown, spoofed
                    trusted_macs TEXT,             -- JSON list of MACs the user has explicitly trusted
                    vendor TEXT,                   -- Manufacturer name from OUI lookup
                    device_category TEXT,          -- Phone, Router, IoT, TV, NAS, Camera, etc.
                    vendor_icon TEXT,              -- Emoji or short visual indicator
                    ai_assessment TEXT,            -- JSON: {verdict, confidence, summary, recommendation, last_assessed}
                    traffic_summary TEXT,          -- JSON summary of recent observed behavior
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_known_devices_ip ON known_devices(ip)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_known_devices_mac ON known_devices(mac)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_known_devices_ha ON known_devices(ha_entity_id)
            """)

            # Reusable credential profiles for devices (SSH keys, local/domain accounts, API tokens)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credential_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL,           -- local, domain, ssh_key, token, api_key, ibmi_5250, ibmi_ssh, windows_wmi, windows_winrm
                    username TEXT,
                    secret TEXT,                  -- hashed or encrypted secret / key path
                    notes TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            # Safe migrations for enhanced device intelligence (MAC history + AI assessment)
            for col, coltype in [
                ("mac_history", "TEXT"),
                ("mac_trust_level", "TEXT DEFAULT 'unknown'"),
                ("trusted_macs", "TEXT"),
                ("vendor", "TEXT"),
                ("device_category", "TEXT"),
                ("vendor_icon", "TEXT"),
                ("ai_assessment", "TEXT"),
                ("traffic_summary", "TEXT"),
                # Port-based auto-trust (vendor profile + observed vs expected)
                ("expected_ports", "TEXT"),      # JSON list of {port, proto, service, reason}
                ("observed_ports", "TEXT"),      # JSON {tcp:[..], udp:[..], last_updated, count}
                ("port_assessment", "TEXT"),     # JSON {status, matched, unexpected, assessed_at, reason, confidence}
            ]:
                try:
                    cur.execute(f"ALTER TABLE known_devices ADD COLUMN {col} {coltype}")
                except Exception:
                    pass

            # --- Preferences (for automation rule toggles, UI settings, etc.) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            # --- Custom user-defined automation rules (beyond the 4 built-in toggles) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    priority INTEGER DEFAULT 100,
                    condition TEXT,                 -- e.g. "443 and ha_light" or "external and unknown" or regex
                    action TEXT NOT NULL,           -- "iot_expected", "escalate", "severity:high", "ha_notify"
                    notes TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            # --- AI Suggested Automation Rules (human must approve before activation) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS suggested_automation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    condition_json TEXT,            -- Structured condition (device, event, pattern)
                    proposed_action TEXT,           -- What the rule would do (human readable + structured)
                    confidence REAL DEFAULT 0.6,
                    status TEXT DEFAULT 'suggested', -- suggested | enabled | disabled | rejected
                    reason TEXT,                    -- Why the AI proposed it
                    related_device_ip TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    reviewed_at TEXT,
                    reviewed_by TEXT,
                    notes TEXT
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_suggested_rules_status ON suggested_automation_rules(status)
            """)

            # --- Local authentication (hashed passwords + TOTP, stored in DB instead of plaintext YAML) ---
            cur.execute("""
                CREATE TABLE IF NOT EXISTS local_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,      -- bcrypt hash
                    totp_secret TEXT,                 -- Base32 for TOTP (optional 2FA)
                    is_admin INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_local_auth_username ON local_auth(username)
            """)

            # --- API Tokens: Long-lived tokens for programmatic access to RocketLogAI APIs ---
            # (Similar concept to Home Assistant long-lived access tokens)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,   -- never store plaintext
                    prefix TEXT NOT NULL,              -- e.g. "rla_abc123" (first 12 chars for identification)
                    scopes TEXT DEFAULT 'full',        -- 'full' | 'read' | future comma-separated
                    created_by TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    last_used_at TEXT,
                    expires_at TEXT,
                    revoked INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked ON api_tokens(revoked)
            """)

            # --- RocketLogAI Assistant Suggestions ---
            # Users can ask the built-in AI assistant for help using RocketLogAI.
            # If it can't answer, they can suggest improvements/features.
            # Only admins can review suggestions.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS assistant_suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    question TEXT NOT NULL,
                    ai_answer TEXT,
                    suggestion TEXT,
                    status TEXT DEFAULT 'pending',   -- pending | reviewed | accepted | rejected | implemented
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_assistant_suggestions_status ON assistant_suggestions(status)
            """)

            # --- Daily Briefing / Operator Companion storage ---
            # Persisted daily (or shift) narrative recaps + the interactive chat history with the AI crew.
            # Powers the "what happened that day" entertaining summary + follow-up conversation + action promotion.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS daily_briefings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    day TEXT NOT NULL,                 -- YYYY-MM-DD in local server time for calendar_day
                    window_type TEXT NOT NULL,         -- 'calendar_day', 'rolling_24h', 'shift', 'custom'
                    window_label TEXT,                 -- human friendly e.g. "Today (local calendar)", "My Shift 06:00-18:00", "Tuesday 2026-05-20"
                    start_ts TEXT NOT NULL,
                    end_ts TEXT NOT NULL,
                    narrative TEXT,
                    stats_json TEXT,                   -- totals, by-sev, monitor health, etc.
                    highlights_json TEXT,              -- list of "what stood out" + suggested moves
                    proposed_actions_json TEXT,
                    model TEXT,
                    generated_at TEXT DEFAULT (datetime('now')),
                    duration_ms REAL,
                    created_by TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_daily_briefings_day ON daily_briefings(day)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_daily_briefings_window ON daily_briefings(window_type, start_ts)")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS daily_briefing_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    briefing_id INTEGER NOT NULL,
                    role TEXT NOT NULL,                -- 'user' | 'assistant' | 'system'
                    content TEXT NOT NULL,
                    ts TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(briefing_id) REFERENCES daily_briefings(id)
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_daily_briefing_messages_briefing ON daily_briefing_messages(briefing_id, ts)")

            # v2: Organization tasks (dashboard acknowledgment, assignment, remediation)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS org_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    source TEXT DEFAULT 'manual',
                    threat_id INTEGER,
                    assigned_to TEXT,
                    created_by TEXT,
                    acknowledged_by TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_org_tasks_status ON org_tasks(status)")

            # v2: Device monitoring toggle + traffic stats
            try:
                cur.execute("ALTER TABLE known_devices ADD COLUMN monitoring_enabled INTEGER DEFAULT 1")
            except sqlite3.OperationalError:
                pass
            try:
                cur.execute("ALTER TABLE known_devices ADD COLUMN bytes_in INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                cur.execute("ALTER TABLE known_devices ADD COLUMN bytes_out INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                cur.execute("ALTER TABLE known_devices ADD COLUMN packets_in INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                cur.execute("ALTER TABLE known_devices ADD COLUMN packets_out INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass

            # v2: User preferences (last briefing, config UI state)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    updated_at TEXT DEFAULT (datetime('now')),
                    PRIMARY KEY (user_id, key)
                )
            """)

    def insert_log(self, record: dict[str, Any]) -> int:
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO logs (
                    timestamp, hostname, appname, procid, facility, severity,
                    severity_code, priority, message, raw, source, format
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.get("timestamp"),
                record.get("hostname"),
                record.get("appname"),
                record.get("procid"),
                record.get("facility"),
                record.get("severity"),
                record.get("severity_code"),
                record.get("priority"),
                record.get("message"),
                record.get("raw"),
                record.get("source"),
                record.get("format"),
            ))
            return cur.lastrowid

    def insert_logs_bulk(self, records: list[dict[str, Any]]) -> list[int]:
        ids = []
        with self._cursor() as cur:
            for rec in records:
                cur.execute("""
                    INSERT INTO logs (
                        timestamp, hostname, appname, procid, facility, severity,
                        severity_code, priority, message, raw, source, format
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rec.get("timestamp"),
                    rec.get("hostname"),
                    rec.get("appname"),
                    rec.get("procid"),
                    rec.get("facility"),
                    rec.get("severity"),
                    rec.get("severity_code"),
                    rec.get("priority"),
                    rec.get("message"),
                    rec.get("raw"),
                    rec.get("source"),
                    rec.get("format"),
                ))
                ids.append(cur.lastrowid)
        return ids

    def get_recent_logs(self, limit: int = 200, min_severity: str | None = None) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            if min_severity:
                min_code = severity_to_int(min_severity)
                cur.execute("""
                    SELECT * FROM logs 
                    WHERE severity_code >= ? 
                    ORDER BY timestamp DESC, id DESC 
                    LIMIT ?
                """, (min_code, limit))
            else:
                cur.execute("""
                    SELECT * FROM logs 
                    ORDER BY timestamp DESC, id DESC 
                    LIMIT ?
                """, (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def get_logs_since(self, since_iso: str, limit: int = 1000) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM logs 
                WHERE timestamp >= ? 
                ORDER BY timestamp ASC 
                LIMIT ?
            """, (since_iso, limit))
            return [dict(r) for r in cur.fetchall()]

    def count_logs(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM logs")
            return cur.fetchone()[0]

    def count_analyses(self) -> int:
        """Total number of analysis cycles ever recorded."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM analyses")
            return cur.fetchone()[0]

    def count_analyses_with_llm(self, since_hours: int = 0) -> int:
        """Count of analyses that actually received an LLM response (had raw_response)."""
        with self._cursor() as cur:
            if since_hours > 0:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
                cur.execute(
                    "SELECT COUNT(*) FROM analyses WHERE raw_response IS NOT NULL AND raw_response != '' AND started_at >= ?",
                    (cutoff,),
                )
            else:
                cur.execute("SELECT COUNT(*) FROM analyses WHERE raw_response IS NOT NULL AND raw_response != ''")
            return cur.fetchone()[0]

    def prune_old_logs(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._cursor() as cur:
            cur.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff,))
            deleted = cur.rowcount
        return deleted

    # --- Analysis / Threat storage ---

    def create_analysis(self, model: str | None = None) -> int:
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO analyses (started_at, model) 
                VALUES (?, ?)
            """, (datetime.now(timezone.utc).isoformat(), model))
            return cur.lastrowid

    def finish_analysis(self, analysis_id: int, summary: str, threats: list[dict], raw_response: str | None = None, logs_analyzed: int = 0) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                UPDATE analyses 
                SET finished_at = ?, logs_analyzed = ?, threats_found = ?, summary = ?, raw_response = ?
                WHERE id = ?
            """, (
                now,
                logs_analyzed,
                len(threats),
                summary,
                raw_response,
                analysis_id,
            ))

            for t in threats:
                evidence = json.dumps(t.get("evidence", []))
                cur.execute("""
                    INSERT INTO threats (
                        analysis_id, severity, score, description, 
                        evidence, recommended_action, hostname, appname,
                        status, source_ip,
                        geo_country, geo_city, geo_lat, geo_lon, geo_accuracy,
                        ha_device_name, ha_entity_id, ha_area
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    t.get("severity", "medium"),
                    t.get("score", 5.0),
                    t.get("description"),
                    evidence,
                    t.get("recommended_action"),
                    t.get("hostname"),
                    t.get("appname"),
                    "open",
                    t.get("source_ip"),
                    t.get("geo_country"),
                    t.get("geo_city"),
                    t.get("geo_lat"),
                    t.get("geo_lon"),
                    t.get("geo_accuracy"),
                    t.get("ha_device_name"),
                    t.get("ha_entity_id"),
                    t.get("ha_area"),
                ))

    def get_recent_threats(self, limit: int = 50, offset: int = 0, status: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
        """Return recent threats with optional pagination, status filter, and simple search on description/hostname."""
        with self._cursor() as cur:
            where = []
            params: list[Any] = []
            if status:
                where.append("t.status = ?")
                params.append(status)
            if search:
                where.append("(t.description LIKE ? OR t.hostname LIKE ? OR t.source_ip LIKE ?)")
                like = f"%{search}%"
                params.extend([like, like, like])
            where_clause = ("WHERE " + " AND ".join(where)) if where else ""
            params.extend([limit, offset])
            cur.execute(f"""
                SELECT t.*, a.model, a.started_at as analysis_started
                FROM threats t
                JOIN analyses a ON a.id = t.analysis_id
                {where_clause}
                ORDER BY t.created_at DESC
                LIMIT ? OFFSET ?
            """, params)
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
                except Exception:
                    d["evidence"] = []
                out.append(d)
            return out

    def count_threats(self, status: str | None = None, search: str | None = None) -> int:
        with self._cursor() as cur:
            where = []
            params: list[Any] = []
            if status:
                where.append("status = ?")
                params.append(status)
            if search:
                where.append("(description LIKE ? OR hostname LIKE ? OR source_ip LIKE ?)")
                like = f"%{search}%"
                params.extend([like, like, like])
            where_clause = ("WHERE " + " AND ".join(where)) if where else ""
            cur.execute(f"SELECT COUNT(*) FROM threats {where_clause}", params)
            return cur.fetchone()[0] or 0

    def get_last_analysis_time(self):
        with self._cursor() as cur:
            cur.execute("SELECT started_at, logs_analyzed, threats_found FROM analyses ORDER BY started_at DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                return {"started_at": row[0], "logs_analyzed": row[1], "threats_found": row[2]}
            return None

    def get_threat_groups(self, limit: int = 300, days: int = 7) -> list[dict[str, Any]]:
        """Return grouped similar threats (by normalized signature) for the grouped UI view.
        Includes per-group date buckets for 'seen on' display. Limits raw threats scanned.
        """
        recent = self.get_recent_threats(limit=limit)
        if not recent:
            return []

        from collections import defaultdict
        from datetime import datetime as dt

        groups: dict[str, dict] = {}
        for t in recent:
            sig = _normalize_threat_signature(t.get("severity", "medium"), t.get("description", ""))
            if sig not in groups:
                groups[sig] = {
                    "signature": sig,
                    "severity": t.get("severity", "medium"),
                    "sample": (t.get("description") or "")[:140],
                    "count": 0,
                    "first": t.get("created_at"),
                    "last": t.get("created_at"),
                    "hosts": set(),
                    "occurrences": [],  # list of {date, time, host, id}
                }
            g = groups[sig]
            g["count"] += 1
            ca = t.get("created_at") or ""
            if ca < g["first"]:
                g["first"] = ca
            if ca > g["last"]:
                g["last"] = ca
            if t.get("hostname"):
                g["hosts"].add(t["hostname"])
            # date bucket key
            try:
                day = ca[:10] if ca else "unknown"
            except Exception:
                day = "unknown"
            g["occurrences"].append({
                "id": t.get("id"),
                "created_at": ca,
                "day": day,
                "hostname": t.get("hostname") or t.get("source_ip") or "?",
                "short": (t.get("description") or "")[:80],
                # PR2 enrichment — real network details for the grouped view
                "source_ip": t.get("source_ip"),
                "destination_ip": t.get("destination_ip") or t.get("dst_ip"),
                "port": t.get("dport") or t.get("port"),
                "protocol": t.get("protocol"),
                "bytes": t.get("bytes"),
            })

        # finalize + compute date buckets
        out = []
        for g in groups.values():
            g["hosts"] = sorted(g["hosts"])[:8]
            # group occurrences by day
            by_day: dict[str, list] = defaultdict(list)
            for occ in g["occurrences"]:
                by_day[occ["day"]].append(occ)
            date_buckets = []
            for day in sorted(by_day.keys(), reverse=True):
                date_buckets.append({
                    "day": day,
                    "count": len(by_day[day]),
                    "samples": by_day[day][:5],  # PR2: more detail + richer fields
                })
            g["date_buckets"] = date_buckets
            g["days_seen"] = len(date_buckets)
            del g["occurrences"]  # not needed in final
            out.append(g)

        # sort by count desc, then recency
        out.sort(key=lambda x: (-x["count"], x["last"]), reverse=False)
        return out[:40]  # cap groups shown

    def get_threat_count_by_severity(self) -> dict[str, int]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) as cnt 
                FROM threats 
                GROUP BY severity
            """)
            return {row["severity"]: row["cnt"] for row in cur.fetchall()}

    def vacuum(self) -> None:
        conn = self._connect()
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()

    # --- Threat status & management ---

    def update_threat_status(self, threat_id: int, status: str, notes: str | None = None, actor: str = "user") -> bool:
        """
        Update threat status with expanded vocabulary and full history logging.
        New statuses: verified_threat, verified_benign, iot_expected, escalated
        """
        valid_status = {
            "open", "acknowledged", "false_positive",
            "verified_threat", "verified_benign", "iot_expected", "escalated"
        }
        if status not in valid_status:
            return False

        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("SELECT status FROM threats WHERE id = ?", (threat_id,))
            row = cur.fetchone()
            prev_status = row["status"] if row else None

            if status == "open":
                cur.execute("""
                    UPDATE threats SET status = ?, acknowledged_at = NULL, notes = ?
                    WHERE id = ?
                """, (status, notes, threat_id))
            else:
                cur.execute("""
                    UPDATE threats SET status = ?, acknowledged_at = ?, notes = ?
                    WHERE id = ?
                """, (status, now, notes, threat_id))

            # Write rich audit trail
            cur.execute("""
                INSERT INTO verification_history 
                (threat_id, action, previous_status, new_status, notes, actor, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (threat_id, status, prev_status, status, notes, actor, now))

            return cur.rowcount > 0

    def get_threat(self, threat_id: int) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM threats WHERE id = ?", (threat_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
            except Exception:
                d["evidence"] = []
            return d

    # --- Analytics helpers for charts ---

    def get_threats_over_time(self, days: int = 30) -> list[dict[str, Any]]:
        """Return daily threat counts for the last N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                SELECT date(created_at) as day, COUNT(*) as count
                FROM threats
                WHERE created_at >= ?
                GROUP BY day
                ORDER BY day
            """, (cutoff,))
            return [{"day": r["day"], "count": r["count"]} for r in cur.fetchall()]

    def get_threats_by_host(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT hostname, COUNT(*) as count
                FROM threats
                WHERE hostname IS NOT NULL AND hostname != ''
                GROUP BY hostname
                ORDER BY count DESC
                LIMIT ?
            """, (limit,))
            return [{"hostname": r["hostname"], "count": r["count"]} for r in cur.fetchall()]

    def get_threat_counts_by_status(self) -> dict[str, int]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT status, COUNT(*) as cnt FROM threats GROUP BY status
            """)
            return {row["status"]: row["cnt"] for row in cur.fetchall()}

    # --- Geo + HA enrichment + verification helpers (new in 2026 offline+HA release) ---

    def update_threat_geo(self, threat_id: int, geo: dict[str, Any]) -> bool:
        """Store offline geo enrichment results."""
        with self._cursor() as cur:
            cur.execute("""
                UPDATE threats 
                SET source_ip = ?, geo_country = ?, geo_city = ?, 
                    geo_lat = ?, geo_lon = ?, geo_accuracy = ?
                WHERE id = ?
            """, (
                geo.get("ip"),
                geo.get("country"),
                geo.get("city"),
                geo.get("lat"),
                geo.get("lon"),
                geo.get("accuracy"),
                threat_id,
            ))
            return cur.rowcount > 0

    def update_threat_ha_context(self, threat_id: int, ha: dict[str, Any]) -> bool:
        """Store Home Assistant device/entity context."""
        with self._cursor() as cur:
            cur.execute("""
                UPDATE threats 
                SET ha_device_name = ?, ha_entity_id = ?, ha_area = ?
                WHERE id = ?
            """, (
                ha.get("device_name"),
                ha.get("entity_id"),
                ha.get("area"),
                threat_id,
            ))
            return cur.rowcount > 0

    def mark_ha_triggered(self, threat_id: int) -> bool:
        with self._cursor() as cur:
            cur.execute("UPDATE threats SET ha_triggered = 1 WHERE id = ?", (threat_id,))
            # Also log it
            now = datetime.now(timezone.utc).isoformat()
            cur.execute("""
                INSERT INTO verification_history (threat_id, action, triggered_ha, created_at)
                VALUES (?, 'ha_triggered', 1, ?)
            """, (threat_id, now))
            return True

    def record_verification_action(self, threat_id: int, action: str, notes: str | None = None, actor: str = "user") -> None:
        """Generic audit log entry (used by HA triggers etc.)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO verification_history (threat_id, action, notes, actor, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (threat_id, action, notes, actor, now))

    def upsert_ha_device(self, entity_id: str, name: str | None, device_id: str | None, 
                         area: str | None, attributes: dict[str, Any]) -> None:
        """Cache a Home Assistant entity/device for fast lookup."""
        now = datetime.now(timezone.utc).isoformat()
        attrs_json = json.dumps(attributes or {})
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO ha_devices (entity_id, name, device_id, area, attributes_json, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_id) DO UPDATE SET
                    name=excluded.name,
                    device_id=excluded.device_id,
                    area=excluded.area,
                    attributes_json=excluded.attributes_json,
                    last_seen=excluded.last_seen,
                    updated_at=excluded.updated_at
            """, (entity_id, name, device_id, area, attrs_json, now, now))

    def get_ha_devices(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM ha_devices ORDER BY updated_at DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["attributes"] = json.loads(d["attributes_json"]) if d["attributes_json"] else {}
                except Exception:
                    d["attributes"] = {}
                out.append(d)
            return out

    def find_ha_context_for_ip(self, ip: str) -> dict[str, Any] | None:
        """Best-effort match of an IP against cached HA devices (looks in attributes)."""
        if not ip:
            return None
        devices = self.get_ha_devices(limit=1000)
        for d in devices:
            attrs = d.get("attributes", {})
            # Common places HA stores IP info
            for key in ("ip", "ipv4", "host", "ip_address", "source_ip", "address"):
                val = str(attrs.get(key, "")).strip()
                if val and val == ip:
                    return {
                        "entity_id": d.get("entity_id"),
                        "device_name": d.get("name"),
                        "area": d.get("area"),
                    }
            # Also check friendly_name or entity name containing IP (rare)
            if ip in str(d.get("name", "")):
                return {
                    "entity_id": d.get("entity_id"),
                    "device_name": d.get("name"),
                    "area": d.get("area"),
                }
        return None

    def cache_ip_geo(self, ip: str, geo: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO ip_geo_cache (ip, country, city, lat, lon, accuracy, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                geo.get("country"),
                geo.get("city"),
                geo.get("lat"),
                geo.get("lon"),
                geo.get("accuracy"),
                now,
            ))

    def get_cached_ip_geo(self, ip: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM ip_geo_cache WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "ip": row["ip"],
                "country": row["country"],
                "city": row["city"],
                "lat": row["lat"],
                "lon": row["lon"],
                "accuracy": row["accuracy"],
            }

    def get_all_cached_geo(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return a list of all geo-enriched IPs in the cache (useful for broad maps)."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT ip, country, city, lat, lon, accuracy, fetched_at 
                FROM ip_geo_cache 
                ORDER BY fetched_at DESC 
                LIMIT ?
            """, (limit,))
            out = []
            for row in cur.fetchall():
                out.append({
                    "ip": row["ip"],
                    "country": row["country"],
                    "city": row["city"],
                    "lat": row["lat"],
                    "lon": row["lon"],
                    "accuracy": row["accuracy"],
                    "fetched_at": row["fetched_at"],
                })
            return out

    def get_ips_missing_geo(self, limit: int = 300) -> list[str]:
        """Return public IPs that have been seen (in cache or threats) but have no geo data yet."""
        with self._cursor() as cur:
            # First, IPs already in cache but missing geo
            cur.execute("""
                SELECT ip FROM ip_geo_cache 
                WHERE lat IS NULL 
                ORDER BY fetched_at DESC 
                LIMIT ?
            """, (limit,))
            missing = {row[0] for row in cur.fetchall()}

            # Also look for unique public source_ips from threats that are not in the geo cache at all
            cur.execute("""
                SELECT DISTINCT source_ip 
                FROM threats 
                WHERE source_ip IS NOT NULL 
                  AND source_ip != ''
                LIMIT ?
            """, (limit * 2,))
            for row in cur.fetchall():
                ip = row[0]
                # Only add if not already in cache (we'll check in the enrichment loop too)
                if ip not in missing:
                    # Quick check if it already has an entry with geo
                    cur.execute("SELECT lat FROM ip_geo_cache WHERE ip = ?", (ip,))
                    if not cur.fetchone():
                        missing.add(ip)

            # NEW: also pull external destinations discovered from raw logs / evidence (helps maps populate faster)
            try:
                discovered = self.discover_external_ips_from_logs(limit=limit)
                for ip in discovered:
                    if ip not in missing:
                        cur.execute("SELECT lat FROM ip_geo_cache WHERE ip = ?", (ip,))
                        if not cur.fetchone():
                            missing.add(ip)
            except Exception:
                pass

            return list(missing)[:limit]

    # --- Known Devices Registry ---

    def upsert_known_device(self, device: dict[str, Any]) -> None:
        """Insert or update a device in the registry. Robust against duplicates by IP or HA id.
        Supports normal_behaviors as dict (auto-JSON). Also tracks MAC history for spoofing detection."""
        now = datetime.now(timezone.utc).isoformat()
        ip = device.get("ip")
        new_mac = device.get("mac")
        ha_id = device.get("ha_entity_id")
        nb = device.get("normal_behaviors")

        if isinstance(nb, (dict, list)):
            nb_json = json.dumps(nb)
        elif nb is None:
            nb_json = None
        else:
            nb_json = str(nb)

        with self._cursor() as cur:
            # Find existing
            row = None
            existing = None
            if ha_id:
                cur.execute("SELECT * FROM known_devices WHERE ha_entity_id = ?", (ha_id,))
                row = cur.fetchone()
            if not row and ip:
                cur.execute("SELECT * FROM known_devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,))
                row = cur.fetchone()

            if row:
                existing = dict(row)
                # Handle MAC history tracking
                mac_history = []
                if existing.get("mac_history"):
                    try:
                        mac_history = json.loads(existing["mac_history"])
                    except Exception:
                        mac_history = []

                if new_mac:
                    # Check if this MAC is new for the device
                    found = False
                    for entry in mac_history:
                        if entry.get("mac") == new_mac.lower():
                            entry["last_seen"] = now
                            found = True
                            break
                    if not found:
                        mac_history.append({
                            "mac": new_mac.lower(),
                            "first_seen": now,
                            "last_seen": now
                        })
                        # If more than one MAC seen, this could indicate spoofing or DHCP issues
                        if len(mac_history) > 1 and existing.get("mac_trust_level") not in ("trusted",):
                            # Auto flag for investigation
                            cur.execute("UPDATE known_devices SET mac_trust_level = 'investigate' WHERE id = ?", (row[0],))

                mac_history_json = json.dumps(mac_history) if mac_history else None

                # Merge update
                cur.execute("""
                    UPDATE known_devices SET
                        ip = COALESCE(?, ip),
                        mac = COALESCE(?, mac),
                        ha_entity_id = COALESCE(?, ha_entity_id),
                        ha_name = COALESCE(?, ha_name),
                        ha_device_type = COALESCE(?, ha_device_type),
                        ha_area = COALESCE(?, ha_area),
                        trust_level = COALESCE(?, trust_level),
                        notes = COALESCE(?, notes),
                        normal_behaviors = COALESCE(?, normal_behaviors),
                        mac_history = COALESCE(?, mac_history),
                        last_seen = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    ip,
                    new_mac,
                    ha_id,
                    device.get("ha_name"),
                    device.get("ha_device_type"),
                    device.get("ha_area"),
                    device.get("trust_level"),
                    device.get("notes"),
                    nb_json,
                    mac_history_json,
                    now, now, row[0]
                ))
                return

            # Insert new
            cur.execute("""
                INSERT INTO known_devices (
                    ip, mac, ha_entity_id, ha_name, ha_device_type, ha_area,
                    trust_level, notes, normal_behaviors, mac_history, mac_trust_level,
                    first_seen, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                new_mac,
                ha_id,
                device.get("ha_name"),
                device.get("ha_device_type"),
                device.get("ha_area"),
                device.get("trust_level", "normal"),
                device.get("notes"),
                nb_json,
                json.dumps([{"mac": new_mac.lower(), "first_seen": now, "last_seen": now}]) if new_mac else None,
                "trusted" if new_mac else "unknown",
                now,
                now,
                now
            ))

    def get_known_devices(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM known_devices ORDER BY last_seen DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                if d.get("normal_behaviors"):
                    try:
                        d["normal_behaviors"] = json.loads(d["normal_behaviors"])
                    except Exception:
                        d["normal_behaviors"] = {}
                out.append(d)
            return out

    def get_credential_profiles(self) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            try:
                cur.execute("SELECT * FROM credential_profiles ORDER BY name")
                profiles = []
                for row in cur.fetchall():
                    p = dict(row)
                    # Decrypt secret on the way out if it looks encrypted
                    if p.get("secret"):
                        p["secret"] = self._decrypt_credential_secret(p["secret"])
                    profiles.append(p)
                return profiles
            except Exception:
                return []

    def get_credential_profile(self, name: str) -> dict[str, Any] | None:
        """Get a single credential profile by name (with secret decrypted for use)."""
        with self._cursor() as cur:
            try:
                cur.execute("SELECT * FROM credential_profiles WHERE name = ?", (name,))
                row = cur.fetchone()
                if not row:
                    return None
                p = dict(row)
                if p.get("secret"):
                    p["secret"] = self._decrypt_credential_secret(p["secret"])
                return p
            except Exception:
                return None

    def upsert_credential_profile(self, name: str, type: str, username: str | None = None,
                                   secret: str | None = None, notes: str | None = None) -> int:
        """Create or update a reusable credential profile.
        Secret is encrypted before storage (reversible for actual device use).
        """
        now = datetime.now(timezone.utc).isoformat()
        encrypted_secret = self._encrypt_credential_secret(secret) if secret else None
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO credential_profiles (name, type, username, secret, notes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type,
                    username=excluded.username,
                    secret=excluded.secret,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
            """, (name, type, username, encrypted_secret, notes, now))
            # Return the id
            cur.execute("SELECT id FROM credential_profiles WHERE name = ?", (name,))
            return cur.fetchone()[0]

    # --- Simple reversible encryption for device credentials (so they can be used, unlike login hashes) ---
    def _get_credential_cipher(self):
        try:
            from cryptography.fernet import Fernet
            key_path = Path("data/credential.key")
            if not key_path.exists():
                key = Fernet.generate_key()
                key_path.write_bytes(key)
                try:
                    key_path.chmod(0o600)
                except Exception:
                    pass
                logger.info("Generated new credential encryption key at %s (keep this file safe)", key_path)
            key = key_path.read_bytes()
            return Fernet(key)
        except Exception as e:
            logger.warning("cryptography not available or key error (%s) — credential secrets will be stored with only light protection. pip install cryptography for real encryption.", e)
            return None

    def _encrypt_credential_secret(self, plaintext: str | None) -> str | None:
        if not plaintext:
            return None
        cipher = self._get_credential_cipher()
        if cipher is None:
            # Fallback: base64 only (not real encryption, but consistent with some existing patterns)
            import base64
            return "b64:" + base64.b64encode(plaintext.encode()).decode()
        return "fernet:" + cipher.encrypt(plaintext.encode()).decode()

    def _decrypt_credential_secret(self, stored: str | None) -> str | None:
        if not stored:
            return None
        if stored.startswith("fernet:"):
            cipher = self._get_credential_cipher()
            if cipher:
                try:
                    return cipher.decrypt(stored[7:].encode()).decode()
                except Exception:
                    return None
            return None
        if stored.startswith("b64:"):
            import base64
            try:
                return base64.b64decode(stored[4:]).decode()
            except Exception:
                return stored
        # Plaintext legacy
        return stored

    # --- API Tokens for programmatic access to this RocketLogAI instance ---

    def create_api_token(self, name: str, scopes: str = "full", notes: str = "", expires_days: int | None = None, created_by: str = "admin") -> dict[str, Any]:
        """Create a new long-lived API token. Returns the plaintext token + metadata (token is only shown once)."""
        import secrets
        from datetime import datetime, timedelta

        prefix = "rla_" + secrets.token_urlsafe(6)  # short readable prefix
        raw_token = prefix + secrets.token_urlsafe(32)  # full token shown to user once
        token_hash = hash_password(raw_token)  # reuse existing secure hasher

        expires_at = None
        if expires_days:
            expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()

        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO api_tokens (name, token_hash, prefix, scopes, created_by, expires_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, token_hash, prefix, scopes, created_by, expires_at, notes))
            token_id = cur.lastrowid

        return {
            "id": token_id,
            "name": name,
            "token": raw_token,   # IMPORTANT: only returned on creation
            "prefix": prefix,
            "scopes": scopes,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at,
            "notes": notes,
        }

    def verify_api_token(self, raw_token: str) -> dict[str, Any] | None:
        """Return token metadata if the token is valid and not revoked/expired."""
        if not raw_token or not raw_token.startswith("rla_"):
            return None

        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM api_tokens 
                WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))
            """)
            for row in cur.fetchall():
                row_dict = dict(row)
                if verify_password(raw_token, row_dict["token_hash"]):
                    # Update last_used
                    cur.execute("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?", (row_dict["id"],))
                    return {
                        "id": row_dict["id"],
                        "name": row_dict["name"],
                        "scopes": row_dict["scopes"],
                        "created_at": row_dict["created_at"],
                    }
        return None

    def list_api_tokens(self) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT id, name, prefix, scopes, created_by, created_at, last_used_at, expires_at, revoked, notes
                FROM api_tokens ORDER BY created_at DESC
            """)
            return [dict(r) for r in cur.fetchall()]

    def revoke_api_token(self, token_id: int) -> bool:
        with self._cursor() as cur:
            cur.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))
            return cur.rowcount > 0

    def find_device_by_ip(self, ip: str) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM known_devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("normal_behaviors"):
                try:
                    d["normal_behaviors"] = json.loads(d["normal_behaviors"])
                except Exception:
                    d["normal_behaviors"] = {}

            # Parse new intelligence fields
            if d.get("mac_history"):
                try:
                    d["mac_history"] = json.loads(d["mac_history"])
                except Exception:
                    d["mac_history"] = []
            else:
                d["mac_history"] = []

            if d.get("ai_assessment"):
                try:
                    d["ai_assessment"] = json.loads(d["ai_assessment"])
                except Exception:
                    d["ai_assessment"] = None

            # New vendor intelligence fields
            d["vendor"] = d.get("vendor")
            d["device_category"] = d.get("device_category")
            d["vendor_icon"] = d.get("vendor_icon") or "❓"

            # Port intelligence (for auto-trust feature)
            if d.get("expected_ports"):
                try:
                    d["expected_ports"] = json.loads(d["expected_ports"])
                except Exception:
                    d["expected_ports"] = None
            if d.get("observed_ports"):
                try:
                    d["observed_ports"] = json.loads(d["observed_ports"])
                except Exception:
                    d["observed_ports"] = None
            if d.get("port_assessment"):
                try:
                    d["port_assessment"] = json.loads(d["port_assessment"])
                except Exception:
                    d["port_assessment"] = None

            # Enhanced risk score with MAC stability + AI verdict + explicit trusted MACs
            trust = d.get("trust_level", "normal")
            mac_trust = d.get("mac_trust_level", "unknown")
            threat_count = d.get("last_threat_count", 0) or 0
            has_baseline = bool(d.get("normal_behaviors"))
            mac_history = d.get("mac_history", [])
            ai = d.get("ai_assessment") or {}
            current_mac = d.get("mac")
            trusted_macs = d.get("trusted_macs") or []
            if isinstance(trusted_macs, str):
                try:
                    trusted_macs = json.loads(trusted_macs)
                except Exception:
                    trusted_macs = []

            base = 50
            if trust == "critical":
                base = 95
            elif trust == "untrusted":
                base = 75
            elif trust == "trusted":
                base = 18
            else:
                base = 42

            # MAC stability penalty
            mac_penalty = 0
            if len(mac_history) > 1:
                mac_penalty = 15
            if mac_trust in ("investigate", "spoofed"):
                mac_penalty = 25

            # Strong bonus if current MAC is explicitly trusted by user
            if current_mac and any(current_mac.lower() == m.lower() for m in trusted_macs if isinstance(m, str)):
                mac_penalty = -20  # significant trust signal

            # AI verdict influence
            ai_bonus = 0
            if ai.get("verdict") == "trusted":
                ai_bonus = -12
            elif ai.get("verdict") in ("suspicious", "investigate"):
                ai_bonus = 18
            elif ai.get("verdict") == "threat":
                ai_bonus = 30

            vol = min(threat_count * 4, 25)
            baseline_bonus = -15 if has_baseline else 0

            score = max(5, min(98, base + vol + baseline_bonus + mac_penalty + ai_bonus))
            d["risk_score"] = int(score)
            return d

    def record_device_observation(self, ip: str, extra: dict[str, Any] = None) -> None:
        """Update last_seen and merge any extra info for a device."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                UPDATE known_devices 
                SET last_seen = ?, 
                    ip = COALESCE(?, ip),
                    mac = COALESCE(?, mac)
                WHERE ip = ? OR ha_entity_id IN (SELECT ha_entity_id FROM known_devices WHERE ip = ?)
            """, (now, extra.get("ip") if extra else None, extra.get("mac") if extra else None, ip, ip))

            if cur.rowcount == 0 and extra:
                # Create minimal record
                self.upsert_known_device({
                    "ip": ip,
                    "mac": extra.get("mac"),
                    "ha_name": extra.get("ha_name"),
                    "ha_entity_id": extra.get("ha_entity_id"),
                    "trust_level": "normal"
                })

    def increment_device_threat_count(self, ip: str) -> None:
        """Bump the threat counter for risk calculations."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                UPDATE known_devices SET last_threat_count = COALESCE(last_threat_count,0) + 1, last_seen=?, updated_at=?
                WHERE ip = ? 
            """, (now, now, ip))
            if cur.rowcount == 0:
                # create stub so future risk calc sees volume
                self.upsert_known_device({"ip": ip, "last_threat_count": 1})

    def get_recent_threats_for_device(self, ip: str, limit: int = 20) -> list[dict]:
        """Get recent threats involving this IP (for learning baseline)."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM threats 
                WHERE evidence LIKE ? OR description LIKE ?
                ORDER BY created_at DESC LIMIT ?
            """, (f"%{ip}%", f"%{ip}%", limit))
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else []
                except Exception:
                    d["evidence"] = []
                out.append(d)
            return out

    def _extract_behavior_patterns(self, threats: list[dict]) -> dict[str, Any]:
        """Shared logic to mine common ports, destinations, protocols from threat evidence/desc."""
        import re
        ports_seen = set()
        external_dests = set()
        protocols = set()
        for threat in threats or []:
            texts = []
            if threat.get("description"):
                texts.append(str(threat["description"]))
            for ev in threat.get("evidence", []):
                if isinstance(ev, str):
                    texts.append(ev)
                elif isinstance(ev, dict):
                    texts.append(json.dumps(ev))
            combined = " ".join(texts)
            for p in re.findall(r'DPT=(\d+)|dpt=(\d+)|port[ =:](\d+)', combined, re.I):
                for m in p:
                    if m:
                        ports_seen.add(int(m))
            for dst in re.findall(r'DST=([0-9.]+)|dst=([0-9.]+)|to ([0-9.]+)', combined, re.I):
                for m in dst:
                    if m and not m.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '127.')):
                        external_dests.add(m)
            for proto in re.findall(r'PROTO=([A-Za-z0-9]+)|proto[ =:](\w+)', combined, re.I):
                for m in proto:
                    if m:
                        protocols.add(m.lower())
        return {
            "common_destination_ports": sorted(list(ports_seen))[:30],
            "common_external_destinations": sorted(list(external_dests))[:15],
            "common_protocols": sorted(list(protocols))[:10],
            "sample_count": len(threats or []),
            "learned_at": datetime.now(timezone.utc).isoformat(),
        }

    def learn_baseline_for_ip(self, ip: str, lookback_days: int = 7) -> dict[str, Any]:
        """Learn and persist baseline for one IP from recent threats."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        # Use existing query (it is LIKE based, sufficient)
        recent = self.get_recent_threats_for_device(ip, limit=100)
        # Filter to window if possible
        recent = [r for r in recent if (r.get("created_at") or "") >= cutoff] or recent
        patterns = self._extract_behavior_patterns(recent)
        device = self.find_device_by_ip(ip) or {}
        current = device.get("normal_behaviors") or {}
        current.update(patterns)
        current["learned_at"] = patterns["learned_at"]
        self.upsert_known_device({"ip": ip, "normal_behaviors": current})
        return {"ip": ip, "patterns": patterns, "threats_analyzed": len(recent)}

    def get_all_external_destinations(self, limit: int = 500) -> list[str]:
        """Aggregate unique public external destination IPs from all known devices' baselines."""
        destinations = set()
        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                            "127.", "169.254.")
        with self._cursor() as cur:
            cur.execute("SELECT normal_behaviors FROM known_devices WHERE normal_behaviors IS NOT NULL")
            for row in cur.fetchall():
                try:
                    behaviors = json.loads(row[0])
                    for ip in behaviors.get("common_external_destinations", []):
                        if ip and not any(ip.startswith(p) for p in private_prefixes):
                            destinations.add(ip)
                except Exception:
                    continue
        return list(destinations)[:limit]

    def discover_external_ips_from_logs(self, limit: int = 200) -> list[str]:
        """Scan recent raw logs (and threat evidence) for DST= / 'to <ip>' patterns to discover
        external destinations that may never have become 'threats' or been baselined.
        This helps the map show 'where the world has been talking to' even without manual learn.
        """
        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                            "127.", "169.254.")
        found: set[str] = set()

        # 1. From recent logs.message
        try:
            recent_logs = self.get_recent_logs(limit=500)
            for log in recent_logs:
                msg = str(log.get("message", "")) + " " + str(log.get("raw", ""))
                for m in re.finditer(r"(?:DST=|dst=|to\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})", msg, re.I):
                    ip = m.group(1)
                    if ip and not any(ip.startswith(p) for p in private_prefixes):
                        found.add(ip)
        except Exception:
            pass

        # 2. Fallback: also mine recent threat evidence/descriptions (already have some)
        try:
            threats = self.get_recent_threats(limit=150)
            for t in threats:
                texts = [str(t.get("description", ""))]
                for ev in t.get("evidence", []) or []:
                    texts.append(str(ev))
                combined = " ".join(texts)
                for m in re.finditer(r"(?:DST=|dst=|to\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})", combined, re.I):
                    ip = m.group(1)
                    if ip and not any(ip.startswith(p) for p in private_prefixes):
                        found.add(ip)
        except Exception:
            pass

        return list(found)[:limit]

    def learn_baselines_for_all(self, lookback_days: int = 7) -> dict[str, Any]:
        """Bulk learn baselines for every device that has appeared in recent threats."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        with self._cursor() as cur:
            # Find distinct source_ips from recent threats (best field)
            cur.execute("""
                SELECT DISTINCT source_ip FROM threats 
                WHERE created_at >= ? AND source_ip IS NOT NULL AND source_ip != ''
                LIMIT 200
            """, (cutoff,))
            ips = [row[0] for row in cur.fetchall()]

            # Also try to discover IPs from evidence in older threats if source_ip column empty
            if not ips:
                cur.execute("""
                    SELECT description, evidence FROM threats 
                    WHERE created_at >= ? 
                    ORDER BY created_at DESC LIMIT 500
                """, (cutoff,))
                import re
                discovered = set()
                for row in cur.fetchall():
                    txt = (row[0] or "") + " " + (row[1] or "")
                    for ipm in re.findall(r'\b((?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\d{1,3}\.\d{1,3})\b', txt):
                        discovered.add(ipm)
                ips = list(discovered)[:100]

        results = []
        for ip in ips:
            try:
                res = self.learn_baseline_for_ip(ip, lookback_days)
                results.append(res)
            except Exception as e:
                results.append({"ip": ip, "error": str(e)})
        return {
            "lookback_days": lookback_days,
            "devices_processed": len(ips),
            "baselines_updated": len([r for r in results if "error" not in r]),
            "results": results[:50],  # cap response size
        }

    def get_device_intelligence_summary(self, limit: int = 8) -> dict[str, Any]:
        """Returns summary data for the Device Intelligence dashboard widget."""
        devices = self.get_known_devices(limit=100)
        high_risk = [d for d in devices if (d.get("risk_score") or 0) >= 70]
        needs_investigation = []
        mac_anomalies = 0

        for d in devices:
            if d.get("mac_trust_level") == "investigate":
                needs_investigation.append(d)
            mac_hist = d.get("mac_history") or []
            if isinstance(mac_hist, list) and len(mac_hist) > 1:
                mac_anomalies += 1
            ai = d.get("ai_assessment") or {}
            if ai.get("verdict") in ("suspicious", "threat", "investigate"):
                if d not in needs_investigation:
                    needs_investigation.append(d)

        trusted = [d for d in devices if (d.get("trust_level") == "trusted" or (d.get("port_assessment") or {}).get("status") == "trusted")]

        return {
            "high_risk_count": len(high_risk),
            "needs_investigation_count": len(needs_investigation),
            "mac_anomalies_count": mac_anomalies,
            "trusted_count": len(trusted),
            "high_risk_devices": sorted(high_risk, key=lambda x: x.get("risk_score", 0), reverse=True)[:limit],
            "investigate_devices": sorted(needs_investigation, key=lambda x: (x.get("last_seen") or ""), reverse=True)[:limit],
            "trusted_devices": sorted(trusted, key=lambda x: (x.get("last_seen") or ""), reverse=True)[:limit],
        }

    def get_recently_seen_devices(self, limit: int = 8) -> list[dict[str, Any]]:
        """Returns the most recently active devices (great for 'new devices detected' widget)."""
        devices = self.get_known_devices(limit=limit * 2)
        # Sort by last_seen descending
        sorted_devices = sorted(
            devices,
            key=lambda d: d.get("last_seen") or "",
            reverse=True
        )
        return sorted_devices[:limit]

    def is_new_device(self, ip: str, mac: str | None = None) -> bool:
        """Returns True if this IP (or IP+MAC combo) has never been seen before."""
        existing = self.find_device_by_ip(ip)
        if not existing:
            return True
        if mac:
            existing_mac = existing.get("mac")
            if not existing_mac:
                return True
            # If we've never seen this specific MAC before for this IP
            mac_history = existing.get("mac_history") or []
            seen_macs = [m.get("mac") for m in mac_history if isinstance(m, dict)]
            if mac.lower() not in [m.lower() for m in seen_macs if m]:
                return True
        return False

    def assess_device_intelligence(self, ip: str, llm_client=None) -> dict[str, Any]:
        """
        Core new feature: Have the system (rules + optional AI) decide if this device
        and its MAC should be trusted or investigated further based on traffic history.
        Now also considers manufacturer (vendor) expectations.
        """
        device = self.find_device_by_ip(ip) or {"ip": ip}
        mac_history = device.get("mac_history", [])
        behaviors = device.get("normal_behaviors") or {}
        threat_count = device.get("last_threat_count", 0)
        vendor = device.get("vendor")
        category = device.get("device_category")

        assessment = {
            "verdict": "unknown",
            "confidence": 0.5,
            "summary": "Insufficient data for assessment.",
            "recommendation": "Monitor and learn baseline",
            "last_assessed": datetime.now(timezone.utc).isoformat(),
            "factors": []
        }

        # Rule-based signals
        if len(mac_history) > 1:
            assessment["factors"].append("Multiple MAC addresses observed (possible spoofing)")
            assessment["verdict"] = "investigate"
            assessment["confidence"] = max(assessment["confidence"], 0.75)

        if threat_count > 5 and not behaviors:
            assessment["factors"].append("High threat volume with no learned baseline")
            assessment["verdict"] = "suspicious"

        if behaviors.get("learned_at"):
            assessment["factors"].append("Has established normal behavior profile")
            if assessment["verdict"] == "unknown":
                assessment["verdict"] = "trusted"
                assessment["confidence"] = 0.65

        if vendor and category:
            assessment["factors"].append(f"Identified as {category} from {vendor}")
            # Simple manufacturer expectation hint (can be expanded)
            if category in ["Security Camera", "IoT / Development"] and threat_count > 3:
                assessment["factors"].append("IoT/Camera devices with high activity volume — worth reviewing")

        # If LLM client is available, give it vendor context for better reasoning
        if llm_client and behaviors:
            try:
                vendor_context = f"Vendor: {vendor} | Category: {category}" if vendor else "Vendor unknown"
                prompt = f"""
You are a network security analyst. Assess this device:

IP: {ip}
{vendor_context}
MAC History: {json.dumps(mac_history)[:300]}
Learned Normal Behaviors: {json.dumps(behaviors)[:500]}
Recent threat count: {threat_count}

Does the traffic look typical for this manufacturer and device type?
Give a short JSON with:
- verdict: one of "trusted", "investigate", "suspicious", "threat"
- confidence: 0.0-1.0
- summary: one sentence
- recommendation: short action
"""
                response = llm_client.complete(prompt) if hasattr(llm_client, 'complete') else None
                if response:
                    import re
                    match = re.search(r'\{.*\}', response, re.DOTALL)
                    if match:
                        parsed = json.loads(match.group(0))
                        assessment.update(parsed)
                        assessment["factors"].append("AI-assisted assessment (with manufacturer context)")
            except Exception as e:
                assessment["factors"].append(f"AI assessment failed: {str(e)[:100]}")

        # Persist the assessment
        self.upsert_known_device({
            "ip": ip,
            "ai_assessment": assessment,
            "mac_trust_level": "trusted" if assessment["verdict"] == "trusted" else 
                              "investigate" if assessment["verdict"] in ("investigate", "suspicious") else "unknown"
        })

        # NEW: Also run port profile assessment (auto-trust if vendor ports match) - cheap if no LLM
        try:
            if vendor or category:
                self.assess_device_port_profile(ip, llm_client)
        except Exception:
            pass

        return assessment

    def assess_device_port_profile(self, ip: str, llm_client=None, force_ai: bool = False) -> dict[str, Any]:
        """
        NEW: Vendor-aware port trust.
        - Uses AI (if available) to get "what ports should a device from this vendor/category use?"
        - Compares against observed ports (from normal_behaviors + recent evidence)
        - Auto marks device trusted (no human) if ports look vendor-appropriate.
        - Marks as threat / raises risk if using ports outside the vendor profile.
        """
        device = self.find_device_by_ip(ip) or {"ip": ip}
        vendor = device.get("vendor") or "Unknown"
        category = device.get("device_category") or "Unknown"
        behaviors = device.get("normal_behaviors") or {}

        # Collect observed ports (prefer top-level, fall back to behaviors)
        observed = device.get("observed_ports") or {}
        if not observed and behaviors:
            ports = behaviors.get("common_destination_ports") or []
            observed = {"tcp": [int(p) for p in ports if str(p).isdigit()], "last_updated": behaviors.get("learned_at")}

        expected = device.get("expected_ports")

        assessment = {
            "status": "unknown",
            "matched": [],
            "unexpected": [],
            "assessed_at": datetime.now(timezone.utc).isoformat(),
            "reason": "Insufficient data",
            "confidence": 0.4,
            "vendor": vendor,
            "category": category,
        }

        # Step 1: ensure we have expected ports (AI or heuristic)
        if not expected or force_ai:
            if llm_client:
                try:
                    prompt = f"""You are a network device expert. For a real-world {category} made by {vendor}, list the 6-10 most common TCP/UDP ports and services it legitimately uses or listens on in normal operation (home/office/IoT).

Return ONLY compact JSON:
{{"ports": [
  {{"port": 443, "proto": "tcp", "service": "HTTPS", "reason": "standard web + updates for Apple devices"}},
  ...
]}}

Avoid rare/debug ports. Focus on what makes this vendor's devices recognizable (e.g. Apple 5223 for push, 9100 for printers, 554/8554 for cameras, etc)."""
                    # Use direct openai client if present on the llm instance
                    client = getattr(llm_client, "client", None)
                    if client:
                        resp = client.chat.completions.create(
                            model=getattr(llm_client.cfg, "model", "local"),
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.2,
                            max_tokens=600,
                        )
                        content = resp.choices[0].message.content if resp.choices else ""
                        m = re.search(r'\{.*\}', content, re.DOTALL)
                        if m:
                            data = json.loads(m.group(0))
                            expected = data.get("ports", [])
                            self.upsert_known_device({"ip": ip, "expected_ports": expected})
                            assessment["reason"] = "AI-generated vendor port profile"
                except Exception as e:
                    logger.debug("LLM port profile failed: %s", e)

            if not expected:
                # Heuristic fallback (no LLM or failed) - still useful
                expected = self._heuristic_expected_ports(vendor, category)
                if expected:
                    self.upsert_known_device({"ip": ip, "expected_ports": expected})
                    assessment["reason"] = "Heuristic vendor port profile (no LLM)"

        if expected:
            assessment["expected"] = expected

        # Step 2: compare
        obs_ports = set()
        if isinstance(observed, dict):
            obs_ports.update(observed.get("tcp") or [])
            obs_ports.update(observed.get("udp") or [])
        elif isinstance(observed, list):
            obs_ports.update(observed)

        exp_set = set()
        exp_details = {}
        for e in (expected or []):
            if isinstance(e, dict):
                p = e.get("port")
                if p:
                    exp_set.add(int(p))
                    exp_details[int(p)] = e
            elif isinstance(e, (int, str)) and str(e).isdigit():
                exp_set.add(int(e))

        matched = sorted([p for p in obs_ports if p in exp_set])
        unexpected = sorted([p for p in obs_ports if p not in exp_set and p > 0])

        assessment["matched"] = matched
        assessment["unexpected"] = unexpected

        # Step 3: decide auto status
        if exp_set and obs_ports:
            match_ratio = len(matched) / max(1, len(obs_ports))
            if len(unexpected) == 0 or (len(unexpected) <= 1 and match_ratio > 0.6):
                assessment["status"] = "trusted"
                assessment["confidence"] = 0.85 if len(unexpected) == 0 else 0.65
                assessment["reason"] = f"Ports match {vendor} {category} profile ({len(matched)}/{len(obs_ports)})"
                # AUTO TRUST - the key feature requested (no human intervention)
                current_trust = device.get("trust_level", "normal")
                if current_trust not in ("critical", "untrusted"):
                    self.upsert_known_device({
                        "ip": ip,
                        "trust_level": "trusted",
                        "port_assessment": assessment
                    })
            elif len(unexpected) >= 2 and match_ratio < 0.4:
                assessment["status"] = "threat"
                assessment["confidence"] = 0.75
                assessment["reason"] = f"Using {len(unexpected)} ports outside {vendor} profile"
                # Optionally auto-raise risk (conservative: only if no baseline or high volume)
                if device.get("last_threat_count", 0) > 2:
                    self.upsert_known_device({
                        "ip": ip,
                        "trust_level": "untrusted",
                        "port_assessment": assessment
                    })
            else:
                assessment["status"] = "investigate"
                assessment["confidence"] = 0.55
                assessment["reason"] = f"Partial match ({len(matched)} ok, {len(unexpected)} unexpected)"
        elif expected:
            assessment["reason"] = "Has vendor profile but no observed ports yet"
        else:
            assessment["reason"] = "No vendor profile and no observed ports"

        # Always persist latest assessment
        self.upsert_known_device({"ip": ip, "port_assessment": assessment})
        return assessment

    def _heuristic_expected_ports(self, vendor: str, category: str) -> list[dict]:
        """Reasonable defaults when LLM not available. Still better than nothing for auto-trust."""
        v = (vendor or "").lower()
        c = (category or "").lower()
        ports = []
        if "apple" in v or "iphone" in c or "tablet" in c:
            ports = [
                {"port": 443, "proto": "tcp", "service": "HTTPS", "reason": "Standard for Apple devices"},
                {"port": 80, "proto": "tcp", "service": "HTTP", "reason": "Web"},
                {"port": 5223, "proto": "tcp", "service": "APNS", "reason": "Apple Push Notification"},
                {"port": 53, "proto": "udp", "service": "DNS", "reason": "Name resolution"},
            ]
        elif "camera" in c or "hikvision" in v or "dahua" in v:
            ports = [
                {"port": 80, "proto": "tcp", "service": "HTTP", "reason": "Web UI"},
                {"port": 554, "proto": "tcp", "service": "RTSP", "reason": "Video stream"},
                {"port": 8000, "proto": "tcp", "service": "SDK", "reason": "Vendor SDK"},
                {"port": 443, "proto": "tcp", "service": "HTTPS", "reason": "Secure UI"},
            ]
        elif "printer" in c or "brother" in v or "epson" in v or "canon" in v:
            ports = [
                {"port": 9100, "proto": "tcp", "service": "RAW", "reason": "Printer job port"},
                {"port": 631, "proto": "tcp", "service": "IPP", "reason": "Internet Printing Protocol"},
                {"port": 161, "proto": "udp", "service": "SNMP", "reason": "Management"},
            ]
        elif "router" in c or "cisco" in v or "netgear" in v or "tp-link" in v:
            ports = [
                {"port": 80, "proto": "tcp", "service": "HTTP", "reason": "Admin UI"},
                {"port": 443, "proto": "tcp", "service": "HTTPS", "reason": "Secure admin"},
                {"port": 53, "proto": "udp", "service": "DNS", "reason": "DNS forwarder"},
                {"port": 22, "proto": "tcp", "service": "SSH", "reason": "Admin (some models)"},
            ]
        else:
            # generic safe
            ports = [
                {"port": 443, "proto": "tcp", "service": "HTTPS", "reason": "Modern devices"},
                {"port": 80, "proto": "tcp", "service": "HTTP", "reason": "Legacy/web"},
            ]
        return ports

    # --- Custom automation rules (user-defined via /automation page) ---
    def get_custom_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            q = "SELECT * FROM custom_rules ORDER BY priority, id"
            if enabled_only:
                q = "SELECT * FROM custom_rules WHERE enabled = 1 ORDER BY priority, id"
            cur.execute(q)
            return [dict(r) for r in cur.fetchall()]

    def upsert_custom_rule(self, rule: dict[str, Any]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            if rule.get("id"):
                cur.execute("""
                    UPDATE custom_rules SET
                        name = ?, enabled = ?, priority = ?, condition = ?, action = ?, notes = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    rule.get("name"), 1 if rule.get("enabled", True) else 0, rule.get("priority", 100),
                    rule.get("condition"), rule.get("action"), rule.get("notes"), now, rule["id"]
                ))
                return rule["id"]
            else:
                cur.execute("""
                    INSERT INTO custom_rules (name, enabled, priority, condition, action, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.get("name", "Untitled rule"),
                    1 if rule.get("enabled", True) else 0,
                    rule.get("priority", 100),
                    rule.get("condition"),
                    rule.get("action", "iot_expected"),
                    rule.get("notes"),
                    now, now
                ))
                return cur.lastrowid

    def delete_custom_rule(self, rule_id: int) -> bool:
        with self._cursor() as cur:
            cur.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            return cur.rowcount > 0

    def set_custom_rule_enabled(self, rule_id: int, enabled: bool) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("UPDATE custom_rules SET enabled = ?, updated_at = ? WHERE id = ?", (1 if enabled else 0, now, rule_id))
            return cur.rowcount > 0

    # --- AI Suggested Automation Rules (human approval required) ---
    def create_suggested_rule(self, rule: dict) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO suggested_automation_rules 
                (name, description, condition_json, proposed_action, confidence, reason, related_device_ip, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.get("name"),
                rule.get("description"),
                json.dumps(rule.get("condition", {})),
                rule.get("proposed_action"),
                rule.get("confidence", 0.6),
                rule.get("reason"),
                rule.get("related_device_ip"),
                rule.get("status", "suggested"),
                now
            ))
            return cur.lastrowid

    def get_suggested_rules(self, status: str | None = None) -> list[dict]:
        with self._cursor() as cur:
            if status:
                cur.execute("SELECT * FROM suggested_automation_rules WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cur.execute("SELECT * FROM suggested_automation_rules ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def get_enabled_suggested_rules(self) -> list[dict]:
        """Get rules that have been approved by a human and should actually run."""
        return self.get_suggested_rules(status="enabled")

    def update_suggested_rule_status(self, rule_id: int, status: str, reviewed_by: str = "user", notes: str | None = None) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                UPDATE suggested_automation_rules 
                SET status = ?, reviewed_at = ?, reviewed_by = ?, notes = COALESCE(?, notes)
                WHERE id = ?
            """, (status, now, reviewed_by, notes, rule_id))
            return cur.rowcount > 0

    # --- Preferences (automation rules, UI state, etc.) ---
    def set_preference(self, key: str, value: Any) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if isinstance(value, (dict, list)):
            val = json.dumps(value)
        elif value is None:
            val = ""
        else:
            val = str(value)
        with self._cursor() as cur:
            cur.execute("""
                INSERT OR REPLACE INTO preferences (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, val, now))

    def get_preference(self, key: str, default: Any = None) -> Any:
        with self._cursor() as cur:
            cur.execute("SELECT value FROM preferences WHERE key = ?", (key,))
            row = cur.fetchone()
            if not row or row[0] is None:
                return default
            raw = row[0]
            try:
                return json.loads(raw)
            except Exception:
                if raw.lower() in ("true", "1", "yes"):
                    return True
                if raw.lower() in ("false", "0", "no"):
                    return False
                return raw

    def get_automation_rules(self) -> dict[str, bool]:
        """Return the current enabled state for smart automation rules. Defaults to all enabled."""
        defaults = {
            "suppress_ha_https": True,
            "suppress_mdns": True,
            "suppress_9999": True,
            "escalate_unknown": True,
        }
        out = {}
        for k, d in defaults.items():
            v = self.get_preference(f"automation.{k}", d)
            if isinstance(v, bool):
                out[k] = v
            elif isinstance(v, (int, float)):
                out[k] = bool(v)
            else:
                out[k] = str(v).lower() in ("1", "true", "yes", "on")
        return out

    # --- Heartbeat / Monitor persistence ---

    def upsert_monitor(self, m: "HeartbeatMonitor") -> int:
        """Insert or update a monitor definition from config."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO monitors (name, host, type, port, path, expected, severity,
                                      remediation_action, interval_seconds, enabled,
                                      credential_type, credential_username, credential_secret,
                                      script_variables_json, rollback_action, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    host=excluded.host,
                    type=excluded.type,
                    port=excluded.port,
                    path=excluded.path,
                    expected=excluded.expected,
                    severity=excluded.severity,
                    remediation_action=excluded.remediation_action,
                    interval_seconds=excluded.interval_seconds,
                    enabled=excluded.enabled,
                    credential_type=excluded.credential_type,
                    credential_username=excluded.credential_username,
                    credential_secret=excluded.credential_secret,
                    script_variables_json=excluded.script_variables_json,
                    rollback_action=excluded.rollback_action,
                    updated_at=?
            """, (
                m.name, m.host, m.type, m.port, m.path, m.expected, m.severity,
                m.remediation_action, m.interval_seconds, 1 if m.enabled else 0,
                m.credential_type, m.credential_username, m.credential_secret,
                json.dumps(m.script_variables) if getattr(m, 'script_variables', None) else None,
                m.rollback_action, now, now
            ))
            cur.execute("SELECT id FROM monitors WHERE name = ?", (m.name,))
            return cur.fetchone()[0]

    def get_monitors(self, enabled_only: bool = True) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            query = "SELECT * FROM monitors"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY name"
            cur.execute(query)
            return [dict(r) for r in cur.fetchall()]

    def upsert_monitor_dict(self, name: str, host: str, type: str = "custom", interval_seconds: int = 3600, enabled: bool = True, remediation_action: str | None = None) -> int:
        """Lightweight dict version for Daily Briefing promote and other quick creations. Reuses the same table."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO monitors (name, host, type, interval_seconds, enabled, remediation_action, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    host=excluded.host,
                    type=excluded.type,
                    interval_seconds=excluded.interval_seconds,
                    enabled=excluded.enabled,
                    remediation_action=excluded.remediation_action,
                    updated_at=?
            """, (name, host, type, interval_seconds, 1 if enabled else 0, remediation_action, now, now))
            cur.execute("SELECT id FROM monitors WHERE name = ?", (name,))
            row = cur.fetchone()
            return row[0] if row else 0

    def record_monitor_result(self, monitor_name: str, success: bool, message: str,
                              latency_ms: float | None, remediation_suggested: str | None,
                              details: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        details_json = json.dumps(details or {})
        with self._cursor() as cur:
            # Get monitor id if exists
            cur.execute("SELECT id FROM monitors WHERE name = ?", (monitor_name,))
            row = cur.fetchone()
            monitor_id = row[0] if row else None

            cur.execute("""
                INSERT INTO monitor_results 
                (monitor_id, monitor_name, success, message, latency_ms, 
                 remediation_suggested, details_json, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                monitor_id, monitor_name, 1 if success else 0, message, latency_ms,
                remediation_suggested, details_json, now
            ))

            # Also feed the unified activity log (visible on new /activity dashboard)
            self.log_server_activity(
                direction="outbound",
                source_type="monitor_check",
                source=monitor_name,
                action="heartbeat_or_test",
                status="success" if success else "failed",
                details={"message": str(message)[:200] if message else None},
                duration_ms=latency_ms
            )

    def get_recent_monitor_results(self, limit: int = 100, monitor_name: str | None = None) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            if monitor_name:
                cur.execute("""
                    SELECT * FROM monitor_results 
                    WHERE monitor_name = ?
                    ORDER BY checked_at DESC LIMIT ?
                """, (monitor_name, limit))
            else:
                cur.execute("""
                    SELECT * FROM monitor_results 
                    ORDER BY checked_at DESC LIMIT ?
                """, (limit,))
            rows = cur.fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["details"] = json.loads(d["details_json"]) if d["details_json"] else {}
                except Exception:
                    d["details"] = {}
                out.append(d)
            return out

    def get_monitor_status_summary(self) -> dict[str, Any]:
        """Quick overview for dashboard widgets."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT 
                    COUNT(*) as total_checks,
                    SUM(success) as successful,
                    COUNT(DISTINCT monitor_name) as unique_monitors
                FROM monitor_results
                WHERE checked_at > datetime('now', '-24 hours')
            """)
            row = cur.fetchone()
            return {
                "checks_last_24h": row["total_checks"],
                "success_last_24h": row["successful"] or 0,
                "monitors_seen": row["unique_monitors"],
            }

    # --- Local Auth (DB-backed hashed credentials, replacing plaintext in config.yaml) ---

    def get_local_auth(self, username: str) -> dict[str, Any] | None:
        """Return the local auth record (with password_hash) for a username."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT username, password_hash, totp_secret, is_admin FROM local_auth WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def upsert_local_auth(self, username: str, password_hash: str, totp_secret: str | None = None) -> None:
        """Create or update the local admin credentials (hashed password)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO local_auth (username, password_hash, totp_secret, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    totp_secret = COALESCE(excluded.totp_secret, local_auth.totp_secret),
                    updated_at = excluded.updated_at
                """,
                (username, password_hash, totp_secret, now),
            )

    def update_local_totp_secret(self, username: str, totp_secret: str | None) -> None:
        with self._cursor() as cur:
            cur.execute(
                "UPDATE local_auth SET totp_secret = ?, updated_at = datetime('now') WHERE username = ?",
                (totp_secret, username),
            )

    def ensure_default_local_user(self, default_username: str = "admin", default_plain_password: str | None = None) -> bool:
        """
        On first run / migration: if no local_auth row exists for the username,
        and we have a plaintext from old config, hash it and store.
        Returns True if we created/migrated something.
        """
        existing = self.get_local_auth(default_username)
        if existing:
            return False

        if not default_plain_password:
            # Nothing to migrate — will rely on hard defaults elsewhere
            return False

        # Hash and store using the canonical implementation (always produces a format verify_password understands)
        try:
            from .auth import hash_password
            pwd_hash = hash_password(default_plain_password)
        except Exception:
            # Last-ditch emergency fallback (should almost never be needed)
            import hashlib, os
            salt = os.urandom(16)
            dk = hashlib.pbkdf2_hmac("sha256", default_plain_password.encode("utf-8"), salt, 200000)
            pwd_hash = "pbkdf2$sha256$200000$" + salt.hex() + "$" + dk.hex()

        self.upsert_local_auth(default_username, pwd_hash, None)
        return True

    def list_local_auth_users(self) -> list[dict[str, Any]]:
        """List all local web users (for admin management UI)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT username, is_admin, totp_secret IS NOT NULL as has_totp, updated_at FROM local_auth ORDER BY username"
            )
            return [dict(row) for row in cur.fetchall()]

    def delete_local_auth(self, username: str) -> None:
        """Delete a local web user (admin action). Cannot delete the last admin easily, but we allow it."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM local_auth WHERE username = ?", (username,))

    # --- RocketLogAI Assistant Suggestions (AI help + user feature suggestions) ---
    def create_assistant_suggestion(self, username: str, question: str, ai_answer: str | None = None,
                                    suggestion: str | None = None) -> int:
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO assistant_suggestions (username, question, ai_answer, suggestion, status)
                VALUES (?, ?, ?, ?, 'pending')
            """, (username, question, ai_answer, suggestion))
            return cur.lastrowid

    def list_assistant_suggestions(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            if status:
                cur.execute("SELECT * FROM assistant_suggestions WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cur.execute("SELECT * FROM assistant_suggestions ORDER BY created_at DESC")
            return [dict(row) for row in cur.fetchall()]

    def review_assistant_suggestion(self, suggestion_id: int, reviewer: str, new_status: str,
                                    notes: str | None = None) -> bool:
        with self._cursor() as cur:
            cur.execute("""
                UPDATE assistant_suggestions
                SET status = ?, reviewed_by = ?, reviewed_at = datetime('now'), notes = ?
                WHERE id = ?
            """, (new_status, reviewer, notes, suggestion_id))
            return cur.rowcount > 0

    # --- Server Activity Logging (powers the "what is the server actually doing" visibility dashboard) ---
    def log_server_activity(self, direction: str, source_type: str, source: str | None = None,
                            action: str | None = None, status: str = "success",
                            details: dict | None = None, bytes_count: int | None = None,
                            duration_ms: float | None = None) -> None:
        """Log any inbound data arrival or outbound action the server performs (HA, SSH, 5250, WMI, remediation, etc.)."""
        try:
            import json
            with self._cursor() as cur:
                cur.execute("""
                    INSERT INTO server_activity
                    (direction, source_type, source, action, status, details_json, bytes, duration_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    direction, source_type, source, action, status,
                    json.dumps(details or {}) if details else None,
                    bytes_count, duration_ms
                ))
        except Exception:
            pass  # never break the main path because of activity logging

    def get_recent_server_activity(self, limit: int = 200, source_type: str | None = None,
                                   direction: str | None = None) -> list[dict[str, Any]]:
        """Return recent activity for the dashboard (human + AI readable)."""
        try:
            import json
            with self._cursor() as cur:
                if source_type and direction:
                    cur.execute("SELECT * FROM server_activity WHERE source_type = ? AND direction = ? ORDER BY ts DESC LIMIT ?", (source_type, direction, limit))
                elif source_type:
                    cur.execute("SELECT * FROM server_activity WHERE source_type = ? ORDER BY ts DESC LIMIT ?", (source_type, limit))
                elif direction:
                    cur.execute("SELECT * FROM server_activity WHERE direction = ? ORDER BY ts DESC LIMIT ?", (direction, limit))
                else:
                    cur.execute("SELECT * FROM server_activity ORDER BY ts DESC LIMIT ?", (limit,))
                rows = cur.fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["details"] = json.loads(d["details_json"]) if d.get("details_json") else {}
                    except Exception:
                        d["details"] = {}
                    out.append(d)
                return out
        except Exception:
            return []

    def get_activity_summary(self) -> dict[str, Any]:
        """Quick stats for the activity dashboard header."""
        try:
            with self._cursor() as cur:
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_events,
                        COUNT(CASE WHEN direction='inbound' THEN 1 END) as inbound,
                        COUNT(CASE WHEN direction='outbound' THEN 1 END) as outbound,
                        COUNT(DISTINCT source_type) as unique_source_types,
                        MAX(ts) as last_event
                    FROM server_activity
                    WHERE ts > datetime('now', '-24 hours')
                """)
                row = cur.fetchone()
                return dict(row) if row else {"total_events": 0, "inbound": 0, "outbound": 0}
        except Exception:
            return {"total_events": 0, "inbound": 0, "outbound": 0}

    # =============================================================================
    # Daily Briefing / Operator Companion helpers
    # =============================================================================

    def _resolve_time_window(
        self,
        window: str = "rolling_24h",
        day: str | None = None,
        shift_start: str | None = None,
        shift_end: str | None = None,
        custom_start: str | None = None,
        custom_end: str | None = None,
    ) -> dict[str, Any]:
        """
        Resolve a user-friendly window request into concrete start/end ISO strings (UTC for queries)
        and a nice label. Supports the cases the user asked for: calendar day, rolling 24h, shift,
        historical "Tuesday", natural-ish queries, custom.
        Times in DB are mostly local 'now' strings; we compute python datetimes and emit ISOs.
        """
        from datetime import datetime, timedelta, time as dtime
        import re

        now = datetime.now()  # server local time for "calendar day" and "shift" feel
        today = now.date()

        if window == "custom" and custom_start and custom_end:
            return {
                "start": custom_start,
                "end": custom_end,
                "label": f"Custom window {custom_start[:10]}..{custom_end[:10]}",
                "type": "custom",
            }

        if window == "rolling_24h":
            start = (now - timedelta(hours=24)).isoformat()
            end = now.isoformat()
            return {"start": start, "end": end, "label": "Last 24 hours (rolling)", "type": "rolling_24h"}

        if window == "calendar_day":
            # Strict local calendar day. If day given (YYYY-MM-DD) use it, else today.
            target_day = today
            if day:
                try:
                    target_day = datetime.strptime(day, "%Y-%m-%d").date()
                except Exception:
                    pass
            day_start = datetime.combine(target_day, dtime.min).isoformat()
            day_end = datetime.combine(target_day + timedelta(days=1), dtime.min).isoformat()
            label = f"{target_day.isoformat()} (local calendar day)"
            return {"start": day_start, "end": day_end, "label": label, "type": "calendar_day", "day": target_day.isoformat()}

        if window == "shift":
            target_day = today
            if day:
                try:
                    target_day = datetime.strptime(day, "%Y-%m-%d").date()
                except Exception:
                    pass
            sh_start = shift_start or "06:00"
            sh_end = shift_end or "18:00"
            try:
                h1, m1 = map(int, sh_start.split(":"))
                h2, m2 = map(int, sh_end.split(":"))
                start_dt = datetime.combine(target_day, dtime(h1, m1))
                end_dt = datetime.combine(target_day, dtime(h2, m2))
                if end_dt <= start_dt:
                    end_dt += timedelta(days=1)
            except Exception:
                start_dt = datetime.combine(target_day, dtime(6, 0))
                end_dt = datetime.combine(target_day, dtime(18, 0))
            return {
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat(),
                "label": f"{target_day.isoformat()} shift {sh_start}-{sh_end}",
                "type": "shift",
                "day": target_day.isoformat(),
            }

        # Fallback / historical natural language helper (very lightweight)
        # Accept things like "2026-05-20", "last Tuesday", "yesterday", "Tuesday"
        if day:
            m = re.match(r"(\d{4}-\d{2}-\d{2})", day)
            if m:
                try:
                    d = datetime.strptime(m.group(1), "%Y-%m-%d").date()
                    ds = datetime.combine(d, dtime.min).isoformat()
                    de = datetime.combine(d + timedelta(days=1), dtime.min).isoformat()
                    return {"start": ds, "end": de, "label": f"{d.isoformat()} (calendar day)", "type": "calendar_day", "day": d.isoformat()}
                except Exception:
                    pass
            if "yesterday" in day.lower():
                d = today - timedelta(days=1)
                ds = datetime.combine(d, dtime.min).isoformat()
                de = datetime.combine(d + timedelta(days=1), dtime.min).isoformat()
                return {"start": ds, "end": de, "label": f"{d.isoformat()} (yesterday)", "type": "calendar_day", "day": d.isoformat()}

        # Default safe
        start = (now - timedelta(hours=24)).isoformat()
        end = now.isoformat()
        return {"start": start, "end": end, "label": "Last 24 hours (default)", "type": "rolling_24h"}

    def get_daily_context(self, start_iso: str, end_iso: str, max_items: int = 40) -> dict[str, Any]:
        """
        Build a compact, LLM-friendly snapshot of everything interesting that happened in the window.
        Used as the 'facts of the day' that the Operator Companion reads before writing the recap
        or answering follow-up questions. Keeps volume reasonable even for big historical pulls.
        """
        import json
        ctx: dict[str, Any] = {
            "window": {"start": start_iso, "end": end_iso},
            "totals": {},
            "threats": [],
            "monitor_issues": [],
            "activity": [],
            "excerpts": [],
            "top_hosts": [],
            "notes": [],
        }

        try:
            with self._cursor() as cur:
                # Logs volume (rough)
                cur.execute(
                    "SELECT COUNT(*) FROM logs WHERE timestamp >= ? AND timestamp < ?",
                    (start_iso, end_iso),
                )
                ctx["totals"]["logs"] = cur.fetchone()[0] or 0

                # Threats in window (with some detail)
                cur.execute(
                    """
                    SELECT id, created_at, severity, score, description, hostname, appname, source_ip, status
                    FROM threats
                    WHERE created_at >= ? AND created_at < ?
                    ORDER BY 
                        CASE severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            ELSE 4 
                        END, score DESC, created_at DESC
                    LIMIT ?
                    """,
                    (start_iso, end_iso, max_items),
                )
                threats = []
                for r in cur.fetchall():
                    t = dict(r)
                    threats.append({
                        "id": t.get("id"),
                        "time": t.get("created_at"),
                        "severity": t.get("severity"),
                        "score": t.get("score"),
                        "description": t.get("description"),
                        "hostname": t.get("hostname"),
                        "appname": t.get("appname"),
                        "source_ip": t.get("source_ip"),
                        "status": t.get("status"),
                    })
                ctx["threats"] = threats
                ctx["totals"]["threats"] = len(threats)

                # Monitor results (focus on interesting ones)
                cur.execute(
                    """
                    SELECT monitor_name, success, message, checked_at, latency_ms, details_json
                    FROM monitor_results
                    WHERE checked_at >= ? AND checked_at < ?
                    ORDER BY checked_at DESC
                    LIMIT ?
                    """,
                    (start_iso, end_iso, max_items * 2),
                )
                mon_issues = []
                successes = 0
                total_mon = 0
                for r in cur.fetchall():
                    total_mon += 1
                    d = dict(r)
                    if d.get("success"):
                        successes += 1
                    else:
                        mon_issues.append({
                            "time": d.get("checked_at"),
                            "monitor": d.get("monitor_name"),
                            "message": d.get("message"),
                            "latency_ms": d.get("latency_ms"),
                        })
                ctx["totals"]["monitor_checks"] = total_mon
                ctx["totals"]["monitor_failures"] = len(mon_issues)
                ctx["monitor_issues"] = mon_issues[: max_items // 2]

                # Server activity highlights in window (inbound sources + outbound actions)
                cur.execute(
                    """
                    SELECT ts, direction, source_type, source, action, status, details_json
                    FROM server_activity
                    WHERE ts >= ? AND ts < ?
                    ORDER BY ts DESC
                    LIMIT ?
                    """,
                    (start_iso, end_iso, max_items),
                )
                acts = []
                for r in cur.fetchall():
                    a = dict(r)
                    try:
                        det = json.loads(a.get("details_json") or "{}")
                    except Exception:
                        det = {}
                    acts.append({
                        "ts": a.get("ts"),
                        "direction": a.get("direction"),
                        "source_type": a.get("source_type"),
                        "source": a.get("source"),
                        "action": a.get("action"),
                        "status": a.get("status"),
                        "details": det,
                    })
                ctx["activity"] = acts

                # Top hosts from threats + activity (simple)
                host_counts: dict[str, int] = {}
                for t in threats:
                    h = t.get("hostname") or t.get("source_ip")
                    if h:
                        host_counts[h] = host_counts.get(h, 0) + 1
                ctx["top_hosts"] = sorted(host_counts.items(), key=lambda x: -x[1])[:8]

                # Sample excerpts: take a few threat descriptions + a few failed monitor messages + activity notes
                excerpts = []
                for t in threats[:6]:
                    if t.get("description"):
                        excerpts.append(f"[{t.get('severity','?').upper()}] {t.get('hostname') or ''} {t.get('description')[:160]}")
                for m in mon_issues[:4]:
                    excerpts.append(f"[MONITOR] {m.get('monitor')}: {m.get('message','')[:120]}")
                ctx["excerpts"] = excerpts[:12]

                ctx["totals"]["activity_events"] = len(acts)

        except Exception as e:
            ctx["notes"].append(f"Context gathering partial due to: {str(e)[:120]}")

        # Add a little "crew voice" flavor note for the prompt
        ctx["notes"].append("Context built for the Daily Briefing Operator Companion. Be precise with numbers and names from the data.")
        return ctx

    def save_daily_briefing(
        self,
        day: str,
        window_type: str,
        window_label: str,
        start_ts: str,
        end_ts: str,
        narrative: str,
        stats: dict,
        highlights: list,
        model: str | None = None,
        duration_ms: float | None = None,
        proposed_actions: list | None = None,
        created_by: str | None = None,
    ) -> int:
        """Persist a generated briefing so we can reload history and chats."""
        import json
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_briefings
                (day, window_type, window_label, start_ts, end_ts, narrative, stats_json, highlights_json,
                 proposed_actions_json, model, generated_at, duration_ms, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?)
                """,
                (
                    day,
                    window_type,
                    window_label,
                    start_ts,
                    end_ts,
                    narrative,
                    json.dumps(stats or {}),
                    json.dumps(highlights or []),
                    json.dumps(proposed_actions or []),
                    model,
                    duration_ms,
                    created_by,
                ),
            )
            return cur.lastrowid

    def get_daily_briefing(self, briefing_id: int) -> dict[str, Any] | None:
        import json
        with self._cursor() as cur:
            cur.execute("SELECT * FROM daily_briefings WHERE id = ?", (briefing_id,))
            row = cur.fetchone()
            if not row:
                return None
            b = dict(row)
            for k in ("stats_json", "highlights_json", "proposed_actions_json"):
                if b.get(k):
                    try:
                        b[k.replace("_json", "")] = json.loads(b[k])
                    except Exception:
                        b[k.replace("_json", "")] = b[k]
            return b

    def list_past_briefings(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT id, day, window_type, window_label, generated_at, model FROM daily_briefings ORDER BY generated_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]

    def add_daily_briefing_message(self, briefing_id: int, role: str, content: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO daily_briefing_messages (briefing_id, role, content) VALUES (?, ?, ?)",
                (briefing_id, role, content),
            )
            return cur.lastrowid

    def get_daily_briefing_messages(self, briefing_id: int, limit: int = 100) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT role, content, ts FROM daily_briefing_messages WHERE briefing_id = ? ORDER BY ts ASC LIMIT ?",
                (briefing_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_briefing_by_day_window(self, day: str, window_type: str) -> dict[str, Any] | None:
        """Convenience for default 'today' reloads."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM daily_briefings WHERE day = ? AND window_type = ? ORDER BY generated_at DESC LIMIT 1",
                (day, window_type),
            )
            row = cur.fetchone()
            if row:
                b = dict(row)
                import json
                for k in ("stats_json", "highlights_json", "proposed_actions_json"):
                    if b.get(k):
                        try:
                            b[k.replace("_json", "")] = json.loads(b[k])
                        except Exception:
                            pass
                return b
            return None

    # --- v2: Organization tasks ---

    def create_org_task(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        source: str = "manual",
        created_by: str = "",
        threat_id: int | None = None,
    ) -> int:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO org_tasks (title, description, severity, source, threat_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, description, severity, source, threat_id, created_by),
            )
            return cur.lastrowid

    def list_org_tasks(self, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            if status:
                cur.execute(
                    "SELECT * FROM org_tasks WHERE status = ? ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cur.execute("SELECT * FROM org_tasks ORDER BY updated_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def update_org_task(
        self,
        task_id: int,
        status: str = "",
        assigned_to: str = "",
        notes: str = "",
        actor: str = "",
    ) -> bool:
        with self._cursor() as cur:
            cur.execute("SELECT id FROM org_tasks WHERE id = ?", (task_id,))
            if not cur.fetchone():
                return False
            updates = ["updated_at = datetime('now')"]
            params: list[Any] = []
            if status:
                updates.append("status = ?")
                params.append(status)
                if status == "acknowledged":
                    updates.append("acknowledged_by = ?")
                    params.append(actor)
            if assigned_to:
                updates.append("assigned_to = ?")
                params.append(assigned_to)
            if notes:
                updates.append("notes = ?")
                params.append(notes)
            params.append(task_id)
            cur.execute(f"UPDATE org_tasks SET {', '.join(updates)} WHERE id = ?", params)
            return True

    # --- v2: User preferences (persist after logout) ---

    def set_user_preference(self, user_id: str, key: str, value: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO user_preferences (user_id, key, value, updated_at)
                VALUES (?, ?, ?, datetime('now'))
                """,
                (user_id, key, value),
            )

    def get_user_preference(self, user_id: str, key: str, default: str = "") -> str:
        with self._cursor() as cur:
            cur.execute("SELECT value FROM user_preferences WHERE user_id = ? AND key = ?", (user_id, key))
            row = cur.fetchone()
            return row["value"] if row else default

    # --- v2: Device monitoring toggle + traffic ---

    def set_device_monitoring(self, ip: str, enabled: bool) -> bool:
        with self._cursor() as cur:
            cur.execute("UPDATE known_devices SET monitoring_enabled = ? WHERE ip = ?", (1 if enabled else 0, ip))
            return cur.rowcount > 0

    def update_device_traffic(self, ip: str, bytes_in: int = 0, bytes_out: int = 0, packets_in: int = 0, packets_out: int = 0) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                UPDATE known_devices SET
                    bytes_in = COALESCE(bytes_in, 0) + ?,
                    bytes_out = COALESCE(bytes_out, 0) + ?,
                    packets_in = COALESCE(packets_in, 0) + ?,
                    packets_out = COALESCE(packets_out, 0) + ?
                WHERE ip = ?
                """,
                (bytes_in, bytes_out, packets_in, packets_out, ip),
            )
