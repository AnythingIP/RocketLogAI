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
    # "local" (default for all local OpenAI-compatible servers: LM Studio, Ollama, vLLM, etc.)
    # "azure" or "azure_openai" for Microsoft Azure OpenAI
    # "microsoft_365_copilot" for Microsoft 365 Copilot / Graph
    # Cloud: "openai", "grok", "anthropic" (configured via base_url + key)
    provider: str = "local"

    # Azure OpenAI specific (only used when provider in ("azure", "azure_openai"))
    azure_endpoint: str = ""
    azure_deployment: str = ""
    azure_api_version: str = "2024-10-21"  # recent stable default

    # Microsoft 365 / Graph Copilot (skeleton for future)
    microsoft_graph_tenant: str = ""
    microsoft_auth_method: str = "key"  # key | managed_identity | delegated

    # Multi-LLM with priority and failover.
    # Order in the list determines priority (first = highest).
    # If a server errors, times out, or is "busy", we try the next enabled one.
    # Example entry: {"provider": "local", "base_url": "http://localhost:11434/v1", "api_key": "ollama", "model": "", "enabled": True}
    servers: list[dict] = field(default_factory=list)


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

    # Emergency local login toggle (can be disabled by admin to force domain-only, re-enabled via CLI if locked out)
    allow_local_login: bool = True

    # Web Server Listening
    web_host: str = "0.0.0.0"  # changed default for better first-run experience on servers   # "127.0.0.1", "0.0.0.0", or specific IP
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
class BrandingConfig:
    """White-label / instance branding settings."""
    instance_name: str = ""
    logo_path: str = ""
    show_powered_by: bool = True


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
    notify_services: list[str] = field(default_factory=list)  # must default to [] not None

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
    interval_seconds: int = 60  # pings/TCP fast (60s); override per-monitor for SSH (43200=12h, 1-2x/day) etc.
    enabled: bool = True

    # Secure credentials for this monitor (SSH, WinRM, etc.) - separate from web UI login
    credential_type: str | None = None   # 'local' | 'domain' | None
    credential_username: str | None = None
    credential_secret: str | None = None # hashed password (bcrypt) or path to private key

    # Script configuration
    script_variables: dict = field(default_factory=dict)  # e.g. {"SERVICE": "nginx", "PORT": "443"}
    rollback_action: str | None = None  # filename of rollback script or action


@dataclass
class HeartbeatsConfig:
    """Active monitoring / heartbeat system for services and servers."""
    enabled: bool = False
    monitors: list[HeartbeatMonitor] = field(default_factory=list)

    # Global settings
    default_interval_seconds: int = 60  # see per-monitor overrides; loop checks frequently (30s) and runs only due ones


@dataclass
class GeoProviderConfig:
    """Configuration for a single geo provider (supports multiple + paid services)."""
    type: str = "maxmind"          # maxmind, ipinfo, ipapi, ipstack, etc.
    enabled: bool = True
    path: str = ""                 # for offline dbs like maxmind
    token: str = ""                # for paid/online services (can use env vars)
    priority: int = 10             # lower = tried first


@dataclass
class GeoConfig:
    """Geolocation configuration supporting multiple sources working together."""
    enabled: bool = True

    # Legacy single MaxMind path (still supported for backward compat)
    mmdb_path: str = ""

    # New multi-provider support (recommended for paid + combined sources)
    providers: list[GeoProviderConfig] = field(default_factory=list)

    # How to combine results from multiple providers
    # "first_success": Use the first provider that returns data (current default behavior)
    # "best": Prefer providers with higher accuracy / more fields
    # "aggregate": Merge data from all successful providers (best effort)
    merge_strategy: str = "first_success"


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
class DataSourceConfig:
    """
    Agent-less data source / log ingestion method.
    Admins configure these to tell RocketLogAI how to receive or pull logs + events
    from devices (Windows, Linux, IBM i / AS/400, network gear, etc.).
    All auth uses reusable credential_profiles (never inline secrets).
    """
    name: str
    type: str = "syslog_udp"          # syslog_udp, syslog_tcp, syslog_tls, windows_wmi, windows_winrm, windows_eventlog, ibmi_5250, ibmi_ssh, generic_http_pull, etc.
    enabled: bool = True
    host: str = ""                    # target device IP/hostname (for pull methods) or bind address for listeners
    port: int | None = None
    params: dict = field(default_factory=dict)   # extra type-specific (e.g. tls_cert, wmi_namespace, ibmi_library, menu_path)
    credential_profile: str | None = None        # name from credential_profiles (the permissions this source gets)
    interval_seconds: int = 300                  # for pull-based sources (WMI poll, 5250 query, etc.)
    notes: str = ""


@dataclass
class DataSourcesConfig:
    """Container for all configured agent-less ingestion sources."""
    enabled: bool = True
    sources: list[DataSourceConfig] = field(default_factory=list)

    # Global defaults
    default_syslog_bind: str = "0.0.0.0"
    # Future: allow the main syslog server to also accept from these sources transparently


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
    branding: BrandingConfig = field(default_factory=BrandingConfig)

    # New: Pluggable agent-less data sources / log ingestion methods (syslog variants, Windows WMI/WinRM, IBM i 5250/SSH, etc.)
    # All methods are configured by admins; credentials come from credential_profiles for security.
    data_sources: "DataSourcesConfig" = field(default_factory=lambda: DataSourcesConfig())

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
            cfg.llm.provider = l.get("provider", cfg.llm.provider)

            # Multi-LLM servers list (priority order)
            if "servers" in l and isinstance(l["servers"], list):
                cfg.llm.servers = l["servers"]
            elif not cfg.llm.servers:
                # Backfill a single entry from the legacy fields so existing configs "just work" with multi-LLM logic
                cfg.llm.servers = [{
                    "provider": cfg.llm.provider or "local",
                    "base_url": cfg.llm.base_url,
                    "api_key": cfg.llm.api_key,
                    "model": cfg.llm.model,
                    "enabled": True,
                }]

            # Azure / Microsoft fields (additive, safe)
            cfg.llm.azure_endpoint = l.get("azure_endpoint", cfg.llm.azure_endpoint)
            cfg.llm.azure_deployment = l.get("azure_deployment", cfg.llm.azure_deployment)
            cfg.llm.azure_api_version = l.get("azure_api_version", cfg.llm.azure_api_version)
            cfg.llm.microsoft_graph_tenant = l.get("microsoft_graph_tenant", cfg.llm.microsoft_graph_tenant)
            cfg.llm.microsoft_auth_method = l.get("microsoft_auth_method", cfg.llm.microsoft_auth_method)

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
            cp = r.get("custom_patterns", cfg.rules.custom_patterns) or []
            cfg.rules.custom_patterns = cp if isinstance(cp, list) else []

        # Final safety net: ensure no list fields are None (prevents Jinja crashes on partial configs)
        for cfg_obj in (cfg.rules, cfg.alerting, cfg.home_assistant, cfg.blacklist):
            for attr in ('custom_patterns', 'webhooks', 'notify_services', 'providers'):
                if hasattr(cfg_obj, attr):
                    val = getattr(cfg_obj, attr)
                    if val is None:
                        setattr(cfg_obj, attr, [])

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
            ns = ha.get("notify_services", cfg.home_assistant.notify_services) or []
            cfg.home_assistant.notify_services = ns if isinstance(ns, list) else []
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
            cfg.geo.merge_strategy = g.get("merge_strategy", cfg.geo.merge_strategy)

            # Support new multi-provider config
            providers_raw = g.get("providers", [])
            if providers_raw:
                cfg.geo.providers = []
                for p in providers_raw:
                    if isinstance(p, dict):
                        cfg.geo.providers.append(GeoProviderConfig(
                            type=p.get("type", "maxmind"),
                            enabled=p.get("enabled", True),
                            path=p.get("path", ""),
                            token=p.get("token", ""),
                            priority=p.get("priority", 10),
                        ))
            elif cfg.geo.mmdb_path:
                # Legacy single mmdb_path → convert to providers list automatically
                cfg.geo.providers = [GeoProviderConfig(type="maxmind", path=cfg.geo.mmdb_path)]

        if "blacklist" in raw:
            b = raw["blacklist"]
            cfg.blacklist.enabled = b.get("enabled", cfg.blacklist.enabled)
            cfg.blacklist.hit_severity = b.get("hit_severity", cfg.blacklist.hit_severity)
            cfg.blacklist.escalate_on_hit = b.get("escalate_on_hit", cfg.blacklist.escalate_on_hit)
            # Providers can be extended in future

        if "branding" in raw:
            br = raw["branding"]
            cfg.branding.instance_name = br.get("instance_name", cfg.branding.instance_name)
            cfg.branding.logo_path = br.get("logo_path", cfg.branding.logo_path)
            cfg.branding.show_powered_by = br.get("show_powered_by", cfg.branding.show_powered_by)

        if "data_sources" in raw:
            ds = raw["data_sources"]
            cfg.data_sources.enabled = ds.get("enabled", True)
            sources_raw = ds.get("sources", [])
            cfg.data_sources.sources = []
            for s in sources_raw:
                if isinstance(s, dict):
                    cfg.data_sources.sources.append(DataSourceConfig(
                        name=s.get("name", "unnamed"),
                        type=s.get("type", "syslog_udp"),
                        enabled=s.get("enabled", True),
                        host=s.get("host", ""),
                        port=s.get("port"),
                        params=s.get("params", {}),
                        credential_profile=s.get("credential_profile"),
                        interval_seconds=s.get("interval_seconds", 300),
                        notes=s.get("notes", ""),
                    ))

        if "web" in raw:
            w = raw["web"]
            cfg.web.local_user = w.get("local_user", cfg.web.local_user)
            cfg.web.local_password = w.get("local_password", cfg.web.local_password)
            cfg.web.domain_enabled = w.get("domain_enabled", cfg.web.domain_enabled)
            cfg.web.domain_server = w.get("domain_server", cfg.web.domain_server)
            cfg.web.domain_base_dn = w.get("domain_base_dn", cfg.web.domain_base_dn)
            cfg.web.domain_user_domain = w.get("domain_user_domain", cfg.web.domain_user_domain)
            cfg.web.domain_fallback_local = w.get("domain_fallback_local", cfg.web.domain_fallback_local)
            cfg.web.allow_local_login = w.get("allow_local_login", cfg.web.allow_local_login)

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
                "provider": "local",  # "local" (default), "azure", "azure_openai", or "microsoft_365_copilot"
                "base_url": "http://localhost:1234/v1",
                "api_key": "lm-studio",
                "model": "",  # leave empty to use whatever is loaded in LM Studio
                "timeout": 180,
                "max_tokens": 1200,
                "temperature": 0.1,
                "response_format": "auto",  # "auto" | "json_schema" | "json_object" | "text" | "none"
                # For Azure OpenAI (when provider = "azure" or "azure_openai"):
                # "azure_endpoint": "https://YOUR-RESOURCE.openai.azure.com/",
                # "azure_deployment": "your-deployment-name",
                # "azure_api_version": "2024-10-21",
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
                "mmdb_path": "",   # legacy single MaxMind path (still works)
                "merge_strategy": "first_success",
                "providers": [
                    # Example multi-source setup (paid + free working together)
                    # {"type": "maxmind", "path": "", "priority": 10},
                    # {"type": "ipinfo", "token": "YOUR_IPINFO_TOKEN", "priority": 20},
                    # {"type": "ipapi", "priority": 30},
                ],
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
                "domain_enabled": False,
                "domain_server": "",
                "domain_base_dn": "",
                "domain_user_domain": "",
                "domain_fallback_local": True,
                "allow_local_login": True,
            },
            "branding": {
                "instance_name": "",
                "logo_path": "",
                "show_powered_by": True,
            },
            # === NEW: Pluggable agent-less data sources (multiple ways to feed logs/events to the AI) ===
            # All methods use credential_profiles for secure auth. No agents required.
            "data_sources": {
                "enabled": True,
                "sources": [
                    # Secure Syslog over TLS (recommended for production Windows/Linux/network gear)
                    # {
                    #   "name": "secure-syslog",
                    #   "type": "syslog_tls",
                    #   "host": "0.0.0.0",
                    #   "port": 6514,
                    #   "params": {"cert": "data/ssl/cert.pem", "key": "data/ssl/key.pem"},
                    #   "notes": "RFC 5425 TLS syslog from Windows Event Forwarding, rsyslog, etc."
                    # },
                    # Windows pull (WMI + PowerShell/WinRM) - agentless using domain or local creds
                    # {
                    #   "name": "win-dc01-events",
                    #   "type": "windows_wmi",
                    #   "host": "192.168.20.10",
                    #   "credential_profile": "Domain Admin Events",
                    #   "interval_seconds": 120,
                    #   "params": {"wmi_classes": ["Win32_NTLogEvent"], "log_files": ["Security", "System"]},
                    #   "notes": "Pulls Windows Event Log entries for AI analysis. Use a low-priv account with WMI permissions."
                    # },
                    # IBM i (AS/400) via 5250 telnet or modern SSH - full QSECOFR/SYSOPR power via your credential profile
                    # {
                    #   "name": "as400-prod",
                    #   "type": "ibmi_5250",   # or "ibmi_ssh" (preferred on modern iBMi)
                    #   "host": "10.0.0.50",
                    #   "port": 992,          # or 23 for classic telnet
                    #   "credential_profile": "QSECOFR Read-Only",
                    #   "interval_seconds": 300,
                    #   "params": {"libraries": ["QGPL", "PRODLIB"], "menu": "MAIN"},
                    #   "notes": "Connects to 5250 greenscreen, runs CLs, pulls job status, user profiles, security logs, etc."
                    # },
                ],
            },
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(example, f, sort_keys=False, default_flow_style=False, indent=2)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
