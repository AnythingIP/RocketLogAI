"""
Configuration management for LogSentinel.

Loads YAML config with sensible defaults and validation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Literal

import yaml


@dataclass
class SyslogListen:
    protocol: Literal["udp", "tcp"] = "udp"
    host: str = "0.0.0.0"
    port: int = 5140  # non-privileged default (real syslog is 514)


@dataclass
class SyslogConfig:
    listen: list[SyslogListen] = field(default_factory=lambda: [
        SyslogListen(protocol="udp", host="0.0.0.0", port=5140),
        SyslogListen(protocol="tcp", host="0.0.0.0", port=5140),
    ])
    max_message_size: int = 8192
    buffer_size: int = 10000  # in-memory ring buffer


@dataclass
class StorageConfig:
    db_path: str = "./data/logsentinel.db"
    retention_days: int = 30
    vacuum_on_startup: bool = False


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:1234/v1"
    api_key: str = "lm-studio"  # LM Studio ignores this but OpenAI client requires something
    model: str = ""  # empty = let server decide / use loaded model
    timeout: int = 180
    max_tokens: int = 1200
    temperature: float = 0.1
    # Response format for structured output. "auto" tries json_schema then falls back gracefully.
    # Other values: "json_schema", "json_object", "text", "none" (omit the parameter)
    response_format: str = "auto"

    # LLM provider (future multi-provider support)
    # "local" (default, OpenAI-compatible like LM Studio/Ollama)
    # "openai", "grok", "anthropic" (via base_url + api_key)
    provider: str = "local"


@dataclass
class AnalysisConfig:
    enabled: bool = True
    interval_seconds: int = 45
    batch_size: int = 25
    min_severity_for_ai: Literal["low", "medium", "high", "critical"] = "medium"
    # How many recent logs to include as context even if not suspicious
    context_window: int = 80


@dataclass
class RuleConfig:
    enabled: bool = True
    # Custom regex patterns that immediately flag a log as suspicious
    custom_patterns: list[str] = field(default_factory=list)


@dataclass
class AlertingConfig:
    console: bool = True
    # Webhook URLs (POST JSON alert payload)
    webhooks: list[str] = field(default_factory=list)
    # Minimum severity to emit alert
    min_severity: Literal["low", "medium", "high", "critical"] = "medium"

    # Email (very basic SMTP)
    email_to: list[str] = field(default_factory=list)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "logsentinel@localhost"


@dataclass
class RemediationConfig:
    enabled: bool = False
    dry_run: bool = True
    # Explicit allow-list of action types (future use)
    allowed_actions: list[str] = field(default_factory=list)
    # Require human confirmation even if enabled
    require_confirmation: bool = True
    max_actions_per_hour: int = 5


@dataclass
class WebConfig:
    """Web UI settings (auth, domain login, web server, SSL, etc.)."""
    # Local fallback credentials
    local_user: str = "admin"
    local_password: str = "admin"
    totp_secret: str = ""  # Base32 secret for TOTP (Microsoft Authenticator etc.)

    # Domain / Active Directory authentication
    domain_enabled: bool = False
    domain_server: str = ""
    domain_base_dn: str = ""
    domain_user_domain: str = ""
    domain_fallback_local: bool = True

    # Web Server Listening
    web_host: str = "127.0.0.1"   # "127.0.0.1", "0.0.0.0", or specific IP
    web_port: int = 8787
    https_port: int = 8788        # Separate port for HTTPS when both http_enabled and ssl_enabled are true
    web_domain: str = ""          # Optional domain name (e.g. logsentinel.internal)

    # SSL/TLS - both HTTP and HTTPS enabled by default
    http_enabled: bool = True
    ssl_enabled: bool = True

    # Certificate files (can be paths or we auto-generate)
    ssl_certfile: str = ""
    ssl_keyfile: str = ""

    # Auto-generate a self-signed certificate on first run if none provided
    ssl_auto_generate: bool = True

    # Let's Encrypt support (requires public domain + port 80/443 access for validation)
    letsencrypt_enabled: bool = False
    letsencrypt_email: str = ""
    letsencrypt_staging: bool = False   # Use staging for testing (avoids rate limits)

    # Security behavior
    force_https_redirect: bool = True   # When SSL is on, redirect HTTP to HTTPS (when both enabled)


@dataclass
class HomeAssistantConfig:
    """Deep offline-first Home Assistant integration for context + rich alerting."""
    enabled: bool = False
    url: str = "http://homeassistant.local:8123"
    token: str = ""                    # Long-lived access token
    verify_ssl: bool = True

    # Automatically enrich threats with HA device names/entities when we see an IP
    auto_enrich: bool = True

    # Which statuses should automatically fire rich HA alerts
    trigger_on_statuses: list[str] = field(default_factory=lambda: ["verified_threat"])

    # Notify services to call (e.g. notify.mobile_app_pixel, notify.telegram)
    notify_services: list[str] = field(default_factory=list)

    # Custom event name fired into HA (listen in automations)
    custom_event: str = "logsentinel.major_threat"

    # Keep a running sensor of open threats etc.
    create_sensors: bool = True


@dataclass
class HeartbeatMonitor:
    """Definition of a single service/host to monitor deeply."""
    name: str
    host: str
    type: str = "tcp"                    # tcp | http | https | ssh_version | ping | custom
    port: int | None = None
    path: str = "/"                      # for http checks
    expected: str | None = None          # substring that must appear (http body/headers or SSH banner)
    severity: str = "medium"             # severity if this check fails or is outdated
    remediation_action: str | None = None  # e.g. "update_ssh" when version is behind
    interval_seconds: int = 300
    enabled: bool = True


@dataclass
class HeartbeatsConfig:
    """Active monitoring / heartbeat system for services and servers."""
    enabled: bool = False
    monitors: list[HeartbeatMonitor] = field(default_factory=list)

    # Global settings
    default_interval_seconds: int = 300


@dataclass
class GeoConfig:
    """Fully offline IP geolocation using MaxMind GeoLite2 City database."""
    enabled: bool = True
    # Explicit path to GeoLite2-City.mmdb. Empty string = auto-detect in common locations.
    # Common locations checked automatically (in order):
    #   ~/.logsentinel/GeoLite2-City.mmdb
    #   ./data/GeoLite2-City.mmdb
    #   /etc/logsentinel/GeoLite2-City.mmdb
    #   /usr/local/share/GeoIP/GeoLite2-City.mmdb
    mmdb_path: str = ""


@dataclass
class BlacklistProvider:
    name: str
    enabled: bool = True
    url: str = ""                    # Download URL for the list
    api_key: str = ""                # For providers that require one (AbuseIPDB, etc.)
    update_interval_hours: int = 24


@dataclass
class BlacklistConfig:
    """IP reputation / blacklist checking for external threats."""
    enabled: bool = True
    providers: list[BlacklistProvider] = field(default_factory=lambda: [
        BlacklistProvider(
            name="firehol_level1",
            url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        ),
        BlacklistProvider(
            name="blocklist_de",
            url="https://lists.blocklist.de/lists/all.txt",
        ),
    ])
    # When a hit is found on an external IP, treat as this severity
    hit_severity: str = "high"
    # Add note and mark as high risk
    escalate_on_hit: bool = True


@dataclass
class Config:
    syslog: SyslogConfig = field(default_factory=SyslogConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    web: WebConfig = field(default_factory=WebConfig)
    home_assistant: HomeAssistantConfig = field(default_factory=HomeAssistantConfig)
    heartbeats: HeartbeatsConfig = field(default_factory=HeartbeatsConfig)
    geo: GeoConfig = field(default_factory=GeoConfig)
    blacklist: BlacklistConfig = field(default_factory=BlacklistConfig)

    # Runtime
    config_path: str | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load config from YAML file. Falls back to defaults if missing."""
        if path is None:
            # Common locations
            candidates = [
                Path.cwd() / "config.yaml",
                Path.cwd() / "logsentinel.yaml",
                Path.home() / ".config" / "logsentinel" / "config.yaml",
                Path("/etc/logsentinel/config.yaml"),
            ]
            for c in candidates:
                if c.exists():
                    path = c
                    break

        if path is None or not Path(path).exists():
            cfg = cls()
            cfg.config_path = str(path) if path else None
            return cfg

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        # Merge with defaults (simple recursive update)
        cfg = cls()
        cfg.config_path = str(path)

        if "syslog" in raw:
            syslog = raw["syslog"]
            if "listen" in syslog:
                cfg.syslog.listen = []
                for item in syslog["listen"]:
                    cfg.syslog.listen.append(SyslogListen(
                        protocol=item.get("protocol", "udp"),
                        host=item.get("host", "0.0.0.0"),
                        port=int(item.get("port", 5140)),
                    ))
            cfg.syslog.max_message_size = syslog.get("max_message_size", cfg.syslog.max_message_size)
            cfg.syslog.buffer_size = syslog.get("buffer_size", cfg.syslog.buffer_size)

        if "storage" in raw:
            s = raw["storage"]
            cfg.storage.db_path = s.get("db_path", cfg.storage.db_path)
            cfg.storage.retention_days = s.get("retention_days", cfg.storage.retention_days)
            cfg.storage.vacuum_on_startup = s.get("vacuum_on_startup", cfg.storage.vacuum_on_startup)

        if "llm" in raw:
            l = raw["llm"]
            cfg.llm.base_url = l.get("base_url", cfg.llm.base_url)
            cfg.llm.api_key = l.get("api_key", cfg.llm.api_key)
            cfg.llm.model = l.get("model", cfg.llm.model)
            cfg.llm.timeout = l.get("timeout", cfg.llm.timeout)
            cfg.llm.max_tokens = l.get("max_tokens", cfg.llm.max_tokens)
            cfg.llm.temperature = l.get("temperature", cfg.llm.temperature)
            cfg.llm.response_format = l.get("response_format", cfg.llm.response_format)

        if "analysis" in raw:
            a = raw["analysis"]
            cfg.analysis.enabled = a.get("enabled", cfg.analysis.enabled)
            cfg.analysis.interval_seconds = a.get("interval_seconds", cfg.analysis.interval_seconds)
            cfg.analysis.batch_size = a.get("batch_size", cfg.analysis.batch_size)
            cfg.analysis.min_severity_for_ai = a.get("min_severity_for_ai", cfg.analysis.min_severity_for_ai)
            cfg.analysis.context_window = a.get("context_window", cfg.analysis.context_window)

        if "rules" in raw:
            r = raw["rules"]
            cfg.rules.enabled = r.get("enabled", cfg.rules.enabled)
            cfg.rules.custom_patterns = r.get("custom_patterns", cfg.rules.custom_patterns)

        if "alerting" in raw:
            al = raw["alerting"]
            cfg.alerting.console = al.get("console", cfg.alerting.console)
            cfg.alerting.webhooks = al.get("webhooks", cfg.alerting.webhooks)
            cfg.alerting.min_severity = al.get("min_severity", cfg.alerting.min_severity)

        if "remediation" in raw:
            rem = raw["remediation"]
            cfg.remediation.enabled = rem.get("enabled", cfg.remediation.enabled)
            cfg.remediation.dry_run = rem.get("dry_run", cfg.remediation.dry_run)
            cfg.remediation.allowed_actions = rem.get("allowed_actions", cfg.remediation.allowed_actions)
            cfg.remediation.require_confirmation = rem.get("require_confirmation", cfg.remediation.require_confirmation)
            cfg.remediation.max_actions_per_hour = rem.get("max_actions_per_hour", cfg.remediation.max_actions_per_hour)

        if "home_assistant" in raw:
            ha = raw["home_assistant"]
            cfg.home_assistant.enabled = ha.get("enabled", cfg.home_assistant.enabled)
            cfg.home_assistant.url = ha.get("url", cfg.home_assistant.url)
            cfg.home_assistant.token = ha.get("token", cfg.home_assistant.token)
            cfg.home_assistant.verify_ssl = ha.get("verify_ssl", cfg.home_assistant.verify_ssl)
            cfg.home_assistant.auto_enrich = ha.get("auto_enrich", cfg.home_assistant.auto_enrich)
            cfg.home_assistant.trigger_on_statuses = ha.get("trigger_on_statuses", cfg.home_assistant.trigger_on_statuses)
            cfg.home_assistant.notify_services = ha.get("notify_services", cfg.home_assistant.notify_services)
            cfg.home_assistant.custom_event = ha.get("custom_event", cfg.home_assistant.custom_event)
            cfg.home_assistant.create_sensors = ha.get("create_sensors", cfg.home_assistant.create_sensors)

        if "heartbeats" in raw:
            hb = raw.get("heartbeats", {})
            cfg.heartbeats.enabled = hb.get("enabled", cfg.heartbeats.enabled)
            cfg.heartbeats.default_interval_seconds = hb.get("default_interval_seconds", cfg.heartbeats.default_interval_seconds)

            monitors_raw = hb.get("monitors", [])
            cfg.heartbeats.monitors = []
            for m in monitors_raw:
                cfg.heartbeats.monitors.append(HeartbeatMonitor(
                    name=m.get("name", "unnamed"),
                    host=m.get("host", ""),
                    type=m.get("type", "tcp"),
                    port=m.get("port"),
                    path=m.get("path", "/"),
                    expected=m.get("expected"),
                    severity=m.get("severity", "medium"),
                    remediation_action=m.get("remediation_action"),
                    interval_seconds=m.get("interval_seconds", cfg.heartbeats.default_interval_seconds),
                    enabled=m.get("enabled", True),
                ))

        if "geo" in raw:
            g = raw["geo"]
            cfg.geo.enabled = g.get("enabled", cfg.geo.enabled)
            cfg.geo.mmdb_path = g.get("mmdb_path", cfg.geo.mmdb_path) or ""

        if "blacklist" in raw:
            b = raw["blacklist"]
            cfg.blacklist.enabled = b.get("enabled", cfg.blacklist.enabled)
            cfg.blacklist.hit_severity = b.get("hit_severity", cfg.blacklist.hit_severity)
            cfg.blacklist.escalate_on_hit = b.get("escalate_on_hit", cfg.blacklist.escalate_on_hit)
            # Providers can be extended in future

        if "web" in raw:
            w = raw["web"]
            cfg.web.local_user = w.get("local_user", cfg.web.local_user)
            cfg.web.local_password = w.get("local_password", cfg.web.local_password)
            cfg.web.domain_enabled = w.get("domain_enabled", cfg.web.domain_enabled)
            cfg.web.domain_server = w.get("domain_server", cfg.web.domain_server)
            cfg.web.domain_base_dn = w.get("domain_base_dn", cfg.web.domain_base_dn)
            cfg.web.domain_user_domain = w.get("domain_user_domain", cfg.web.domain_user_domain)
            cfg.web.domain_fallback_local = w.get("domain_fallback_local", cfg.web.domain_fallback_local)

            # New web server + SSL settings
            cfg.web.web_host = w.get("web_host", cfg.web.web_host)
            cfg.web.web_port = w.get("web_port", cfg.web.web_port)
            cfg.web.https_port = w.get("https_port", cfg.web.https_port)
            cfg.web.web_domain = w.get("web_domain", cfg.web.web_domain)

            cfg.web.http_enabled = w.get("http_enabled", cfg.web.http_enabled)
            cfg.web.ssl_enabled = w.get("ssl_enabled", cfg.web.ssl_enabled)
            cfg.web.ssl_certfile = w.get("ssl_certfile", cfg.web.ssl_certfile)
            cfg.web.ssl_keyfile = w.get("ssl_keyfile", cfg.web.ssl_keyfile)
            cfg.web.ssl_auto_generate = w.get("ssl_auto_generate", cfg.web.ssl_auto_generate)

            cfg.web.letsencrypt_enabled = w.get("letsencrypt_enabled", cfg.web.letsencrypt_enabled)
            cfg.web.letsencrypt_email = w.get("letsencrypt_email", cfg.web.letsencrypt_email)
            cfg.web.letsencrypt_staging = w.get("letsencrypt_staging", cfg.web.letsencrypt_staging)

            cfg.web.force_https_redirect = w.get("force_https_redirect", cfg.web.force_https_redirect)

        return cfg

    def save_example(self, path: str | Path) -> None:
        """Write a fully-commented example config to disk."""
        example = {
            "syslog": {
                "listen": [
                    {"protocol": "udp", "host": "0.0.0.0", "port": 5140},
                    {"protocol": "tcp", "host": "0.0.0.0", "port": 5140},
                ],
                "max_message_size": 8192,
                "buffer_size": 10000,
            },
            "storage": {
                "db_path": "./data/logsentinel.db",
                "retention_days": 30,
            },
            "llm": {
                "base_url": "http://localhost:1234/v1",
                "api_key": "lm-studio",
                "model": "",  # leave empty to use whatever is loaded in LM Studio
                "timeout": 180,
                "max_tokens": 1200,
                "temperature": 0.1,
                "response_format": "auto",  # "auto" | "json_schema" | "json_object" | "text" | "none"
            },
            "analysis": {
                "enabled": True,
                "interval_seconds": 45,
                "batch_size": 25,
                "min_severity_for_ai": "medium",
                "context_window": 80,
            },
            "rules": {
                "enabled": True,
                "custom_patterns": [
                    # Example: r"Failed password for .* from .* port",
                ],
            },
            "alerting": {
                "console": True,
                "webhooks": [],
                "min_severity": "medium",
            },
            "remediation": {
                "enabled": False,   # CRITICAL: keep false until you are ready
                "dry_run": True,
                "require_confirmation": True,
                "allowed_actions": [],
            },
            "geo": {
                "enabled": True,
                "mmdb_path": "",   # leave empty for auto-detect, or set explicit full path to GeoLite2-City.mmdb
            },
            "web": {
                "web_host": "0.0.0.0",
                "web_port": 8787,
                "https_port": 8788,
                "http_enabled": True,
                "ssl_enabled": True,
                "ssl_auto_generate": True,
                "force_https_redirect": True,
                "letsencrypt_enabled": False,
                "letsencrypt_email": "",
            },
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(example, f, sort_keys=False, default_flow_style=False, indent=2)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
