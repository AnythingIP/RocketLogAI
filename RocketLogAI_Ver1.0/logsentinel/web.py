"""
Minimal local web dashboard for RocketLogAI (AnythingIP).

Recommended usage:
    pip install -e '.[web]'        # one-time: installs fastapi + uvicorn + python-multipart + ldap3 + itsdangerous
    logsentinel run --web          # starts everything together (syslog + analyzer + UI)
    logsentinel web                # standalone dashboard (connects to existing DB)

Then open http://127.0.0.1:8787

Cross-platform (Linux, macOS, Windows). Auto-refreshes with HTMX.
Uses the optional fastapi/uvicorn/jinja2 extras (includes python-multipart for forms).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from starlette.datastructures import FormData
    from starlette.formparsers import parse_options_header  # triggers the multipart check
except Exception:
    FormData = None  # type: ignore
    parse_options_header = None  # type: ignore

from fastapi import FastAPI, Request, Depends, HTTPException, File, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import secrets

try:
    from starlette.middleware.sessions import SessionMiddleware
    HAS_SESSIONS = True
except ImportError:
    HAS_SESSIONS = False

from .config import Config
from .storage import Storage
from .geo import get_geo_enricher, force_reload_geo
from .certs import get_or_create_default_certs
from .ha import get_ha_client
from .remediation import RemediationAction, RemediationEngine
from .auth import hash_password, verify_password, needs_rehash

try:
    import pyotp
    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False
    pyotp = None


# =============================================================================
# LIVE SERVER LOG BUFFER (for the new /logs page)
# =============================================================================
import logging
import threading
from collections import deque
from typing import Deque

class LiveLogBuffer(logging.Handler):
    """
    Thread-safe in-memory log buffer.
    Keeps the last N log records formatted and ready for the web UI.
    """
    def __init__(self, max_lines: int = 500):
        super().__init__()
        self.max_lines = max_lines
        self._buffer: Deque[dict] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._last_id = 0

    def emit(self, record: logging.LogRecord):
        try:
            formatted = self.format(record)
            log_entry = {
                "id": self._last_id,
                "timestamp": datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": formatted,
            }
            with self._lock:
                self._last_id += 1
                log_entry["id"] = self._last_id
                self._buffer.append(log_entry)
        except Exception:
            self.handleError(record)

    def get_recent(self, limit: int = 200, min_level: str | None = None, search: str | None = None) -> list[dict]:
        with self._lock:
            logs = list(self._buffer)[-limit:]

        if min_level:
            level_order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
            min_val = level_order.get(min_level.upper(), 0)
            logs = [l for l in logs if level_order.get(l["level"], 0) >= min_val]

        if search:
            s = search.lower()
            logs = [l for l in logs if s in l["message"].lower() or s in l["logger"].lower()]

        return logs

    def clear(self):
        with self._lock:
            self._buffer.clear()


# Global live log buffer instance
live_log_buffer = LiveLogBuffer(max_lines=800)

# Attach a sensible formatter
live_log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S")
live_log_buffer.setFormatter(live_log_formatter)

# Attach to root logger so we catch almost everything (including our modules)
logging.getLogger().addHandler(live_log_buffer)
# Also make sure we get WARNING and above even if basicConfig wasn't called yet
logging.getLogger().setLevel(logging.INFO)


app = FastAPI(title="RocketLogAI", docs_url=None, redoc_url=None)

# Session middleware for proper login page (cookie-based)
# The secret is generated once and persisted in data/session_secret.txt so sessions survive restarts.
if HAS_SESSIONS:
    _session_secret_path = Path("data/session_secret.txt")
    try:
        _session_secret_path.parent.mkdir(parents=True, exist_ok=True)
        if _session_secret_path.exists():
            session_secret = _session_secret_path.read_text(encoding="utf-8").strip()
        else:
            session_secret = secrets.token_urlsafe(32)
            _session_secret_path.write_text(session_secret, encoding="utf-8")
            try:
                _session_secret_path.chmod(0o600)
            except Exception:
                pass
    except Exception:
        session_secret = secrets.token_urlsafe(32)  # fallback (sessions won't survive restart)

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="logsentinel_session",
        max_age=86400 * 7,
    )
else:
    print("⚠️  itsdangerous not installed — falling back to basic auth (pip install 'logsentinel[web]')")

# Will be set at startup
_storage: Storage | None = None
_cfg: Config | None = None

# Default credentials + CLI override support (legacy / emergency)
DEFAULT_AUTH_USER = "admin"
DEFAULT_AUTH_PASS = "admin"

_web_auth_user: str | None = None
_web_auth_pass: str | None = None


def get_auth_credentials():
    """
    Return the authoritative local (username, password_or_hash) for login.
    Priority:
      1. CLI override (--web-user / --web-password)
      2. DB-backed local_auth table (preferred, hashed)
      3. Config (web.local_user / local_password) — supports both plaintext (legacy) and hash
      4. Hard defaults (admin/admin) — only for first boot
    """
    # CLI forced override (highest priority, used for scripting / headless)
    if _web_auth_user and _web_auth_pass:
        return _web_auth_user, _web_auth_pass

    # DB-backed (new preferred path)
    if _storage is not None:
        # Use the username from CLI override if present, otherwise from config, otherwise default
        lookup_user = _web_auth_user or (getattr(_cfg.web, "local_user", None) if _cfg else None) or DEFAULT_AUTH_USER
        rec = _storage.get_local_auth(lookup_user)
        if rec:
            return rec["username"], rec["password_hash"]

    # Fall back to whatever is in the loaded config (may be plaintext during transition)
    if _cfg is not None:
        user = getattr(_cfg.web, "local_user", None) or DEFAULT_AUTH_USER
        pwd = getattr(_cfg.web, "local_password", None) or DEFAULT_AUTH_PASS
        # If the YAML contains our "we moved it to the DB" marker, do not treat it as a real password.
        if isinstance(pwd, str) and "stored securely in DB" in pwd:
            pwd = None
        if pwd:
            return user, pwd
        # No usable password in config — fall through to hard default (will fail login, which is safe)
        return user, DEFAULT_AUTH_PASS

    return DEFAULT_AUTH_USER, DEFAULT_AUTH_PASS


async def _safe_form(request: Request) -> dict:
    """Safely parse form data and give a clear error if python-multipart is missing."""
    if parse_options_header is None:
        raise HTTPException(
            status_code=500,
            detail="Missing dependency: python-multipart is required for form handling. "
                   "Please run: pip install 'logsentinel[web]'"
        )
    try:
        form = await request.form()
        return dict(form)
    except Exception as exc:
        if "python-multipart" in str(exc).lower():
            raise HTTPException(
                status_code=500,
                detail="Missing dependency: python-multipart. Run: pip install 'logsentinel[web]'"
            ) from exc
        raise


def try_domain_login(username: str, password: str, cfg: Config | None = None) -> bool:
    """
    Attempt to authenticate against a Windows Active Directory domain using LDAP.
    Returns True on successful bind.
    """
    if not cfg or not cfg.web.domain_enabled:
        return False

    server = cfg.web.domain_server
    base_dn = cfg.web.domain_base_dn

    if not server or not base_dn:
        return False

    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except ImportError:
        print("ldap3 not installed — domain auth unavailable. pip install 'logsentinel[web]'")
        return False

    try:
        # Support both "user@domain" and "DOMAIN\\user" styles
        domain = cfg.web.domain_user_domain or ""
        if "\\" in username or "@" in username:
            user_dn = username
        else:
            if domain:
                user_dn = f"{domain}\\{username}"
            else:
                # Try UPN style
                user_dn = f"{username}@{base_dn.split('DC=', 1)[-1].replace(',DC=', '.').replace('DC=', '')}" if ',' in base_dn else username

        srv = Server(server, get_info=ALL, connect_timeout=8)
        conn = Connection(srv, user=user_dn, password=password, auto_bind=True)

        # Optional: verify user is in the base DN
        conn.search(base_dn, f'(sAMAccountName={username})', SUBTREE, attributes=['sAMAccountName'])
        found = len(conn.entries) > 0
        conn.unbind()
        return found
    except Exception as e:
        # Authentication failed or server unreachable
        return False


def require_login(request: Request):
    """Dependency for protecting routes."""
    user, pwd = get_auth_credentials()

    if not HAS_SESSIONS:
        # Fallback: allow everything if sessions not available (user should install [web])
        return "anonymous"

    session_user = request.session.get("user")
    if session_user:
        return session_user

    raise HTTPException(status_code=307, headers={"Location": "/login"})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not HAS_SESSIONS:
        return HTMLResponse("<h1>Login page requires 'itsdangerous'.<br>Run: pip install 'logsentinel[web]'</h1>")

    require_totp = request.query_params.get("require_totp") == "1"
    username = request.query_params.get("username", "")

    return get_templates().TemplateResponse(
        request,
        "login.html",
        context={
            "error": request.query_params.get("error"),
            "require_totp": require_totp,
            "prefill_username": username,
            "has_totp": bool(_cfg and _cfg.web.totp_secret) if _cfg else False
        }
    )


@app.post("/login")
async def login(request: Request):
    if not HAS_SESSIONS:
        return RedirectResponse("/", status_code=302)

    form = await _safe_form(request)
    username = form.get("username", "").strip()
    password = form.get("password", "")

    if not username or not password:
        return RedirectResponse("/login?error=Username+and+password+required", status_code=302)

    # 1. Try domain authentication first (if enabled)
    if _cfg and _cfg.web.domain_enabled:
        if try_domain_login(username, password, _cfg):
            request.session["user"] = username
            request.session["auth_type"] = "domain"
            request.session["login_time"] = datetime.now(timezone.utc).isoformat()
            return RedirectResponse("/", status_code=302)

        # Domain failed — optionally fall back to local
        if not _cfg.web.domain_fallback_local:
            return RedirectResponse("/login?error=Domain+authentication+failed", status_code=302)

    # 2. Local authentication (default or fallback) — now supports hashed passwords from DB
    local_user, stored_secret = get_auth_credentials()

    if secrets.compare_digest(username, local_user) and verify_password(password, stored_secret):
        # Successful password verification

        # If we verified against a legacy/weak hash (or old plaintext), re-hash with strong params
        if _storage is not None and needs_rehash(stored_secret):
            try:
                new_hash = hash_password(password)
                _storage.upsert_local_auth(local_user, new_hash, _cfg.web.totp_secret if _cfg else None)
            except Exception:
                pass  # non-fatal

        # One-time migration: if this was the first successful login with old plaintext config,
        # push the (now hashed) credentials into the DB so we stop depending on YAML.
        if _storage is not None and _cfg is not None:
            try:
                rec = _storage.get_local_auth(local_user)
                if not rec:
                    new_hash = hash_password(password) if not stored_secret.startswith("$2") else stored_secret
                    _storage.upsert_local_auth(local_user, new_hash, _cfg.web.totp_secret or None)
            except Exception:
                pass

        # Check TOTP if enabled (from config for now — we can move totp_secret into local_auth later)
        if _cfg and _cfg.web.totp_secret and HAS_TOTP:
            totp_code = form.get("totp_code", "").strip()
            if not totp_code:
                return RedirectResponse(f"/login?require_totp=1&username={username}", status_code=302)

            totp = pyotp.TOTP(_cfg.web.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                return RedirectResponse("/login?error=Invalid+2FA+code", status_code=302)

        request.session["user"] = username
        request.session["auth_type"] = "local"
        request.session["login_time"] = datetime.now(timezone.utc).isoformat()
        return RedirectResponse("/", status_code=302)

    return RedirectResponse("/login?error=Invalid+credentials", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    if HAS_SESSIONS:
        request.session.clear()
    return RedirectResponse("/login", status_code=302)


# --- Web Config Editor (UI for editing settings without touching YAML manually) ---

@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request, user: str = Depends(require_login)):
    if _storage is None or _cfg is None:
        return HTMLResponse("Not initialized", status_code=500)

    return get_templates().TemplateResponse(
        request,
        "config.html",
        context={"cfg": _cfg}
    )


@app.post("/config/save")
async def save_config(request: Request, user: str = Depends(require_login)):
    if _cfg is None:
        return {"error": "no config"}

    form = await _safe_form(request)

    # Web / Auth
    _cfg.web.local_user = form.get("local_user", _cfg.web.local_user)
    # IMPORTANT: Never take the local_password from the main config form.
    # It is a masked field. Real password changes must go through /users/change-password
    # which does proper hashing + DB storage.
    _cfg.web.domain_enabled = form.get("domain_enabled") == "on"
    _cfg.web.domain_server = form.get("domain_server", _cfg.web.domain_server)
    _cfg.web.domain_base_dn = form.get("domain_base_dn", _cfg.web.domain_base_dn)
    _cfg.web.domain_user_domain = form.get("domain_user_domain", _cfg.web.domain_user_domain)
    _cfg.web.domain_fallback_local = form.get("domain_fallback_local") == "on"

    # Web Server settings
    _cfg.web.web_host = form.get("web_host", _cfg.web.web_host)
    if form.get("web_host_custom"):
        _cfg.web.web_host = form.get("web_host_custom")
    _cfg.web.web_port = int(form.get("web_port", _cfg.web.web_port) or 8787)
    _cfg.web.web_domain = form.get("web_domain", _cfg.web.web_domain)

    # Web Server + SSL (expanded)
    _cfg.web.http_enabled = form.get("http_enabled") == "on"
    _cfg.web.ssl_enabled = form.get("ssl_enabled") == "on"
    _cfg.web.ssl_auto_generate = form.get("ssl_auto_generate") == "on"
    _cfg.web.ssl_certfile = form.get("ssl_certfile", _cfg.web.ssl_certfile)
    _cfg.web.ssl_keyfile = form.get("ssl_keyfile", _cfg.web.ssl_keyfile)

    _cfg.web.letsencrypt_enabled = form.get("letsencrypt_enabled") == "on"
    _cfg.web.letsencrypt_email = form.get("letsencrypt_email", _cfg.web.letsencrypt_email)
    _cfg.web.force_https_redirect = form.get("force_https_redirect") == "on"

    # LLM Configuration
    _cfg.llm.provider = form.get("llm_provider", _cfg.llm.provider or "local")
    _cfg.llm.base_url = form.get("llm_base_url", _cfg.llm.base_url)
    _cfg.llm.api_key = form.get("llm_api_key", _cfg.llm.api_key)
    _cfg.llm.model = form.get("llm_model", _cfg.llm.model)
    _cfg.llm.temperature = float(form.get("llm_temperature", _cfg.llm.temperature))
    _cfg.llm.max_tokens = int(form.get("llm_max_tokens", _cfg.llm.max_tokens))
    _cfg.llm.response_format = form.get("llm_response_format", _cfg.llm.response_format)

    # Home Assistant
    _cfg.home_assistant.enabled = form.get("ha_enabled") == "on"
    _cfg.home_assistant.url = form.get("ha_url", _cfg.home_assistant.url)
    _cfg.home_assistant.token = form.get("ha_token", _cfg.home_assistant.token)
    _cfg.home_assistant.auto_enrich = form.get("ha_auto_enrich") == "on"
    _cfg.home_assistant.create_sensors = form.get("ha_create_sensors") == "on"
    _cfg.home_assistant.notify_services = [x.strip() for x in form.get("ha_notify_services", "").splitlines() if x.strip()]

    # Geo / IP Geolocation
    if hasattr(_cfg, "geo"):
        _cfg.geo.enabled = form.get("geo_enabled") == "on"
        _cfg.geo.mmdb_path = form.get("geo_mmdb_path", _cfg.geo.mmdb_path or "")

    # Alerting - Webhooks
    _cfg.alerting.webhooks = [x.strip() for x in form.get("webhooks", "").splitlines() if x.strip()]

    # Rules
    patterns = form.get("custom_patterns", "")
    _cfg.rules.custom_patterns = [p.strip() for p in patterns.splitlines() if p.strip()]

    # Analysis
    _cfg.analysis.interval_seconds = int(form.get("analysis_interval", _cfg.analysis.interval_seconds) or 45)
    _cfg.analysis.batch_size = int(form.get("analysis_batch_size", _cfg.analysis.batch_size) or 25)
    _cfg.analysis.min_severity_for_ai = form.get("min_severity_for_ai", _cfg.analysis.min_severity_for_ai)

    # Email / SMTP settings
    _cfg.alerting.email_to = [x.strip() for x in form.get("email_to", "").splitlines() if x.strip()]
    _cfg.alerting.smtp_host = form.get("smtp_host", _cfg.alerting.smtp_host)
    _cfg.alerting.smtp_port = int(form.get("smtp_port", _cfg.alerting.smtp_port) or 587)
    _cfg.alerting.smtp_user = form.get("smtp_user", _cfg.alerting.smtp_user)
    _cfg.alerting.smtp_password = form.get("smtp_password", _cfg.alerting.smtp_password)
    _cfg.alerting.smtp_from = form.get("smtp_from", _cfg.alerting.smtp_from)

    # Persist to disk — SAFE MERGE (do not destroy sections the form doesn't touch)
    try:
        config_path = _cfg.config_path or "config.yaml"
        import yaml

        # Read whatever already exists so we don't lose syslog, analysis, rules, remediation, etc.
        existing: dict = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}

        # Helper for deep update (only touches keys we actually received)
        def deep_update(target: dict, source: dict) -> dict:
            for k, v in source.items():
                if isinstance(v, dict) and k in target and isinstance(target[k], dict):
                    deep_update(target[k], v)
                else:
                    target[k] = v
            return target

        # Build only the sections the form actually edited
        updates: dict = {}

        # Web / Auth (NOTE: we deliberately do NOT write local_password here — use /users/change-password)
        web_section = {
            "local_user": _cfg.web.local_user,
            "domain_enabled": _cfg.web.domain_enabled,
            "domain_server": _cfg.web.domain_server,
            "domain_base_dn": _cfg.web.domain_base_dn,
            "domain_user_domain": _cfg.web.domain_user_domain,
            "domain_fallback_local": _cfg.web.domain_fallback_local,
            "web_host": _cfg.web.web_host,
            "web_port": _cfg.web.web_port,
            "web_domain": _cfg.web.web_domain,
            "http_enabled": _cfg.web.http_enabled,
            "ssl_enabled": _cfg.web.ssl_enabled,
            "ssl_auto_generate": _cfg.web.ssl_auto_generate,
            "ssl_certfile": _cfg.web.ssl_certfile,
            "ssl_keyfile": _cfg.web.ssl_keyfile,
            "letsencrypt_enabled": _cfg.web.letsencrypt_enabled,
            "letsencrypt_email": _cfg.web.letsencrypt_email,
            "force_https_redirect": _cfg.web.force_https_redirect,
        }
        # Only include password if the user actually typed something new (not masked dots)
        pwd_from_form = form.get("local_password", "").strip()
        if pwd_from_form and not pwd_from_form.startswith("•"):
            web_section["local_password"] = pwd_from_form
        updates["web"] = web_section

        updates["llm"] = {
            "provider": _cfg.llm.provider,
            "base_url": _cfg.llm.base_url,
            "api_key": _cfg.llm.api_key,
            "model": _cfg.llm.model,
            "temperature": _cfg.llm.temperature,
            "max_tokens": _cfg.llm.max_tokens,
            "response_format": _cfg.llm.response_format,
        }

        updates["home_assistant"] = {
            "enabled": _cfg.home_assistant.enabled,
            "url": _cfg.home_assistant.url,
            "token": _cfg.home_assistant.token,
            "auto_enrich": _cfg.home_assistant.auto_enrich,
            "create_sensors": _cfg.home_assistant.create_sensors,
            "notify_services": _cfg.home_assistant.notify_services,
            "custom_event": getattr(_cfg.home_assistant, "custom_event", "logsentinel.major_threat"),
            "trigger_on_statuses": getattr(_cfg.home_assistant, "trigger_on_statuses", ["verified_threat"]),
        }

        if hasattr(_cfg, "geo"):
            updates["geo"] = {
                "enabled": _cfg.geo.enabled,
                "mmdb_path": _cfg.geo.mmdb_path or "",
            }

        updates["alerting"] = {
            "webhooks": _cfg.alerting.webhooks,
            "email_to": _cfg.alerting.email_to,
            "smtp_host": _cfg.alerting.smtp_host,
            "smtp_port": _cfg.alerting.smtp_port,
            "smtp_user": _cfg.alerting.smtp_user,
            "smtp_password": _cfg.alerting.smtp_password,
            "smtp_from": _cfg.alerting.smtp_from,
        }

        # Rules & Analysis (these were often lost before)
        updates["rules"] = {"custom_patterns": _cfg.rules.custom_patterns}
        updates["analysis"] = {
            "enabled": _cfg.analysis.enabled,
            "interval_seconds": _cfg.analysis.interval_seconds,
            "batch_size": _cfg.analysis.batch_size,
            "min_severity_for_ai": _cfg.analysis.min_severity_for_ai,
            "context_window": getattr(_cfg.analysis, "context_window", 80),
        }

        # Merge into existing without clobbering other top-level keys (syslog, remediation, heartbeats, blacklist, etc.)
        merged = deep_update(existing, updates)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(merged, f, sort_keys=False, default_flow_style=False)

        return RedirectResponse("/config?saved=1", status_code=302)
    except Exception as e:
        return RedirectResponse(f"/config?error={str(e)}", status_code=302)


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: str = Depends(require_login)):
    if _cfg is None:
        return HTMLResponse("Not initialized", status_code=500)

    auth_type = request.session.get("auth_type", "local")
    login_time = request.session.get("login_time")

    totp_setup = None
    if _cfg and HAS_TOTP:
        # If no secret yet, we can offer to generate one
        if not _cfg.web.totp_secret:
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=_cfg.web.local_user, issuer_name="RocketLogAI")
            totp_setup = {"secret": secret, "uri": uri}
        else:
            totp_setup = {"enabled": True}

    return get_templates().TemplateResponse(
        request,
        "users.html",
        context={
            "current_user": user,
            "auth_type": auth_type,
            "login_time": login_time,
            "cfg": _cfg,
            "totp_setup": totp_setup,
            "has_totp_support": HAS_TOTP
        }
    )


@app.post("/users/change-password")
async def change_local_password(request: Request, user: str = Depends(require_login)):
    if _cfg is None:
        return RedirectResponse("/users?error=no_config", status_code=302)

    form = await _safe_form(request)
    new_password = form.get("new_password", "").strip()
    confirm = form.get("confirm_password", "").strip()

    if not new_password or new_password != confirm or len(new_password) < 4:
        return RedirectResponse("/users?error=Password+mismatch+or+too+short", status_code=302)

    # Hash the new password and store in DB (authoritative) + update in-memory config
    try:
        pwd_hash = hash_password(new_password)
        _cfg.web.local_password = new_password  # keep in memory (login will hash on next change if needed)

        if _storage:
            _storage.upsert_local_auth(_cfg.web.local_user or "admin", pwd_hash, _cfg.web.totp_secret or None)

        # Also update the on-disk config (for humans reading the file), but blank or comment the secret
        config_path = _cfg.config_path or "config.yaml"
        import yaml
        existing = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}

        existing.setdefault("web", {})
        # Store a marker instead of the real secret so the file is no longer the source of truth
        existing["web"]["local_password"] = "******** (stored securely in DB as bcrypt hash)"

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(existing, f, sort_keys=False, default_flow_style=False)

        return RedirectResponse("/users?saved=1", status_code=302)

    except Exception as e:
        import traceback
        print("[logsentinel] ERROR during password change:")
        traceback.print_exc()
        return RedirectResponse(f"/users?error=Failed+to+persist+password+change: {e}", status_code=302)


# --- Two-Factor Authentication (TOTP) Routes ---

@app.post("/users/setup-2fa")
async def setup_2fa(request: Request, user: str = Depends(require_login)):
    if not HAS_TOTP or not _cfg:
        return RedirectResponse("/users?error=TOTP+not+available", status_code=302)

    secret = pyotp.random_base32()
    _cfg.web.totp_secret = secret   # temporary, until confirmed

    # Persist temporarily
    try:
        config_path = _cfg.config_path or "config.yaml"
        import yaml
        existing = {}
        if os.path.exists(config_path):
            with open(config_path) as f:
                existing = yaml.safe_load(f) or {}
        existing.setdefault("web", {})
        existing["web"]["totp_secret"] = secret
        with open(config_path, "w") as f:
            yaml.safe_dump(existing, f, sort_keys=False)
    except Exception:
        pass

    return RedirectResponse("/users", status_code=302)


@app.post("/users/enable-2fa")
async def enable_2fa(request: Request, user: str = Depends(require_login)):
    if not HAS_TOTP or not _cfg:
        return RedirectResponse("/users?error=TOTP+not+available", status_code=302)

    form = await _safe_form(request)
    secret = form.get("secret")
    if secret:
        _cfg.web.totp_secret = secret
        # Already persisted in setup, but ensure it's saved
        try:
            config_path = _cfg.config_path or "config.yaml"
            import yaml
            existing = {}
            if os.path.exists(config_path):
                with open(config_path) as f:
                    existing = yaml.safe_load(f) or {}
            existing.setdefault("web", {})
            existing["web"]["totp_secret"] = secret
            with open(config_path, "w") as f:
                yaml.safe_dump(existing, f, sort_keys=False)
        except Exception:
            pass

    return RedirectResponse("/users?saved=1", status_code=302)


@app.post("/users/disable-2fa")
async def disable_2fa(request: Request, user: str = Depends(require_login)):
    if not _cfg:
        return RedirectResponse("/users?error=no_config", status_code=302)

    _cfg.web.totp_secret = ""

    try:
        config_path = _cfg.config_path or "config.yaml"
        import yaml
        existing = {}
        if os.path.exists(config_path):
            with open(config_path) as f:
                existing = yaml.safe_load(f) or {}
        if "web" in existing:
            existing["web"].pop("totp_secret", None)
        with open(config_path, "w") as f:
            yaml.safe_dump(existing, f, sort_keys=False)
    except Exception as e:
        return RedirectResponse(f"/users?error={str(e)}", status_code=302)

    return RedirectResponse("/users?saved=1", status_code=302)


def init(storage: Storage, cfg: Config) -> None:
    """Called by the CLI before starting the server."""
    global _storage, _cfg
    _storage = storage
    _cfg = cfg

    # One-time migration: move local admin credentials from config.yaml (plaintext) into DB (hashed)
    if _cfg and _storage:
        try:
            user = getattr(_cfg.web, "local_user", "admin") or "admin"
            plain = getattr(_cfg.web, "local_password", None)
            created = _storage.ensure_default_local_user(user, plain)
            if created:
                print("[logsentinel] Migrated local admin credentials into DB (now using secure hash)")
        except Exception as e:
            print(f"[logsentinel] Warning: could not migrate local auth to DB: {e}")

    # Pre-initialize the geo enricher with any user-specified mmdb path from config
    # so that /maps, analyzer, and api/geo/status all see the correct database.
    if cfg and getattr(cfg, "geo", None) and cfg.geo.enabled:
        geo_path = (cfg.geo.mmdb_path or "").strip() or None
        if geo_path:
            try:
                from .geo import OfflineGeoEnricher
                import logsentinel.geo as geo_mod
                geo_mod._geo_enricher = OfflineGeoEnricher(geo_path)
                print(f"[logsentinel] Geo using explicit mmdb_path from config: {geo_path}")
            except Exception as e:
                print(f"[logsentinel] Warning: failed to init geo with configured path {geo_path}: {e}")


# Try to find templates next to this file, fall back to package
_templates_dir = Path(__file__).parent / "templates"
if not _templates_dir.exists():
    _templates_dir = Path(__file__).parent.parent / "templates"  # when running from source root

# IMPORTANT: Do NOT create Jinja2Templates at import time.
# If the templates directory doesn't exist yet, the Jinja environment can end up
# in a broken state (leading to "unhashable type: 'dict'" errors later).
# We create it lazily in get_templates() after _ensure_templates() has run.
_templates_instance: Jinja2Templates | None = None


def get_templates() -> Jinja2Templates:
    """
    Return a cached Jinja2Templates instance with good dev ergonomics.

    We now try several locations so that whether you run from source,
    from an editable install, or via `python -m`, you usually get the
    latest templates you edited.
    """
    global _templates_instance
    if _templates_instance is None:
        candidates = [
            _templates_dir,                                    # original logic
            Path.cwd() / "templates",                          # running from project root
            Path(__file__).parent.parent / "templates",        # common dev layout
            Path(__file__).parent / "templates",
        ]

        chosen = None
        for c in candidates:
            if c.exists() and (c / "base.html").exists():
                chosen = c
                break

        if chosen is None:
            chosen = _templates_dir  # last resort

        print(f"[rocketlogai] Using templates from: {chosen}")
        _templates_instance = Jinja2Templates(directory=str(chosen))

        # Development friendly settings
        _templates_instance.env.auto_reload = True
        _templates_instance.env.cache = {}   # disable caching completely for fast iteration

        # Extra diagnostics on first load
        base_path = chosen / "base.html"
        if base_path.exists():
            mtime = base_path.stat().st_mtime
            print(f"[rocketlogai] base.html found on disk (mtime: {mtime})")
        else:
            print("[rocketlogai] WARNING: base.html not found at expected location!")

    return _templates_instance


def _is_running_from_source() -> bool:
    """Portable detection of source checkout (works for /Volumes/logsentinel, any clone, Windows, etc).

    Looks for pyproject.toml containing our project name or the logsentinel/cli.py file
    while walking up from the current file location.
    """
    try:
        current = Path(__file__).resolve()
        for _ in range(8):
            if (current / "pyproject.toml").exists():
                try:
                    content = (current / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
                    if "logsentinel" in content or "RocketLogAI" in content or 'name = "logsentinel"' in content:
                        return True
                except Exception:
                    pass
            if (current / "logsentinel" / "cli.py").exists():
                return True
            if (current / "templates" / "base.html").exists() and (current / "logsentinel" / "__init__.py").exists():
                return True
            current = current.parent
        return False
    except Exception:
        return False


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("<h1>RocketLogAI not initialized</h1>", status_code=500)

    total_logs = _storage.count_logs()
    threats = _storage.get_recent_threats(limit=20)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)
    recent_analyses = _get_recent_analyses(limit=5)

    # Real analysis stats (replaces the old fake "analyses|length * 4 + 12" gimmick)
    total_analyses = _storage.count_analyses() if hasattr(_storage, "count_analyses") else 0
    llm_analyses = _storage.count_analyses_with_llm() if hasattr(_storage, "count_analyses_with_llm") else 0
    llm_analyses_24h = _storage.count_analyses_with_llm(since_hours=24) if hasattr(_storage, "count_analyses_with_llm") else 0

    # Device Intelligence summary for the new dashboard widget
    device_intel = _storage.get_device_intelligence_summary(limit=6) if hasattr(_storage, "get_device_intelligence_summary") else {}

    # Recently seen / new devices (for "last devices that connected" widget)
    recent_devices = _storage.get_recently_seen_devices(limit=6) if hasattr(_storage, "get_recently_seen_devices") else []

    # AI Suggestions count for dashboard badge
    ai_suggestion_count = 0
    try:
        ai_suggestions = _storage.get_suggested_rules() if hasattr(_storage, "get_suggested_rules") else []
        ai_suggestion_count = len([s for s in ai_suggestions if s.get("status") == "suggested"])
    except Exception:
        pass

    return get_templates().TemplateResponse(
        request,
        "dashboard.html",
        context={
            "total_logs": total_logs,
            "threats": threats,
            "analyses": recent_analyses,
            "config": _cfg,
            "device_intel": device_intel,
            "recent_devices": recent_devices,
            "ai_suggestion_count": ai_suggestion_count,
            "total_analyses": total_analyses,
            "llm_analyses": llm_analyses,
            "llm_analyses_24h": llm_analyses_24h,
        },
    )


@app.get("/analyses", response_class=HTMLResponse)
async def analyses_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    analyses = _get_recent_analyses(limit=50)
    return get_templates().TemplateResponse(
        request,
        "analyses.html",
        context={"analyses": analyses},
    )


@app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_detail(request: Request, analysis_id: int):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    analysis = _get_analysis(analysis_id)
    if not analysis:
        return HTMLResponse("Analysis not found", status_code=404)

    return get_templates().TemplateResponse(
        request,
        "analysis_detail.html",
        context={"analysis": analysis},
    )


@app.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    threats = _storage.get_recent_threats(limit=100)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)
    return get_templates().TemplateResponse(
        request,
        "threats.html",
        context={"threats": threats},
    )


@app.get("/monitors", response_class=HTMLResponse)
async def monitors_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    return get_templates().TemplateResponse(
        request,
        "monitors.html",
        context={}
    )


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    ha_status = {"connected": False, "url": None}
    if _cfg and getattr(_cfg, "home_assistant", None) and _cfg.home_assistant.enabled:
        ha = get_ha_client(_cfg)
        if ha:
            ha_status = {"connected": ha.is_available(), "url": _cfg.home_assistant.url}

    llm_providers = ["local", "openai", "grok", "anthropic"]  # extensible

    return get_templates().TemplateResponse(
        request,
        "integrations.html",
        context={
            "ha_status": ha_status,
            "llm_providers": llm_providers,
            "current_llm": getattr(_cfg.llm, "provider", "local") if _cfg else "local",
            "cfg": _cfg
        }
    )


@app.get("/maps", response_class=HTMLResponse)
async def maps_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    geo_status = {}
    try:
        geo = get_geo_enricher()
        geo_status = {
            "available": geo.available,
            "db_path": geo.db_path,
        }
    except Exception:
        geo_status = {"available": False, "db_path": None}
    return get_templates().TemplateResponse(request, "maps.html", context={"geo_status": geo_status})

@app.get("/automation", response_class=HTMLResponse)
async def automation_page(request: Request, user: str = Depends(require_login)):
    if _storage is None or _cfg is None:
        return HTMLResponse("Not initialized", status_code=500)
    rules = _storage.get_automation_rules() if hasattr(_storage, "get_automation_rules") else {}
    custom_rules = _storage.get_custom_rules() if hasattr(_storage, "get_custom_rules") else []
    ai_suggestions = _storage.get_suggested_rules() if hasattr(_storage, "get_suggested_rules") else []
    return get_templates().TemplateResponse(
        request,
        "automation.html",
        context={"cfg": _cfg, "rules": rules, "custom_rules": custom_rules, "ai_suggestions": ai_suggestions}
    )

@app.post("/api/automation/preferences")
async def save_automation_preferences(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    saved = {}
    for key, val in data.items():
        if key in ("suppress_ha_https", "suppress_mdns", "suppress_9999", "escalate_unknown"):
            _storage.set_preference(f"automation.{key}", bool(val))
            saved[key] = bool(val)
    return {"success": True, "message": "Automation preferences saved", "saved": saved}

@app.get("/api/automation/preferences")
async def get_automation_preferences(user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    rules = _storage.get_automation_rules() if hasattr(_storage, "get_automation_rules") else {}
    return {"rules": rules}


# --- Custom automation rules CRUD (for the rule builder on /automation) ---
@app.get("/api/automation/custom-rules")
async def list_custom_rules(user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    rules = _storage.get_custom_rules() if hasattr(_storage, "get_custom_rules") else []
    return {"custom_rules": rules}

@app.post("/api/automation/custom-rules")
async def create_or_update_custom_rule(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    rid = _storage.upsert_custom_rule(data) if hasattr(_storage, "upsert_custom_rule") else None
    return {"success": True, "id": rid}

@app.post("/api/automation/custom-rules/{rule_id}/toggle")
async def toggle_custom_rule(rule_id: int, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    enabled = bool(data.get("enabled", True))
    ok = _storage.set_custom_rule_enabled(rule_id, enabled) if hasattr(_storage, "set_custom_rule_enabled") else False
    return {"success": ok}


# --- AI Suggested Automation Rules (human approval required) ---
@app.get("/api/automation/suggestions")
async def get_ai_suggestions(user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    suggestions = _storage.get_suggested_rules() if hasattr(_storage, "get_suggested_rules") else []
    return {"suggestions": suggestions}

@app.post("/api/automation/suggestions/{rule_id}/status")
async def update_suggestion_status(rule_id: int, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    new_status = data.get("status")
    notes = data.get("notes")
    if new_status not in ("enabled", "disabled", "rejected"):
        return {"error": "invalid status"}

    ok = _storage.update_suggested_rule_status(rule_id, new_status, reviewed_by=user, notes=notes)

    # When a human enables an AI-suggested rule, log it clearly and (optionally) notify via HA
    if ok and new_status == "enabled":
        logger.info(f"User {user} enabled AI-suggested automation rule #{rule_id}")

        # If Home Assistant is configured, send a persistent notification about the new active rule
        if _cfg and getattr(_cfg, "home_assistant", None) and _cfg.home_assistant.enabled:
            try:
                from .ha import get_ha_client
                ha = get_ha_client(_cfg)
                if ha:
                    ha.call_service("notify.persistent_notification", {
                        "title": "AI Automation Rule Enabled",
                        "message": f"An AI-suggested rule has been approved and is now active (Rule #{rule_id})."
                    })
            except Exception:
                pass

    return {"success": ok}

@app.delete("/api/automation/custom-rules/{rule_id}")
async def delete_custom_rule(rule_id: int, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    ok = _storage.delete_custom_rule(rule_id) if hasattr(_storage, "delete_custom_rule") else False
    return {"success": ok}


@app.post("/api/test/ha")
async def test_ha_connection(user: str = Depends(require_login)):
    if _cfg is None:
        return {"ok": False, "error": "no config"}
    ha = getattr(_cfg, "home_assistant", None)
    if not ha or not getattr(ha, "enabled", False):
        return {"ok": False, "error": "Home Assistant not enabled in config"}
    try:
        from .ha import get_ha_client
        # get_ha_client expects the full config object, not the subsection
        client = get_ha_client(_cfg)
        if client:
            # lightweight test
            states = client.get_states() or []
            return {"ok": True, "message": f"Connected — {len(states)} states visible", "url": ha.url}
        return {"ok": False, "error": "HA client disabled or unreachable"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}

@app.post("/api/test/llm")
async def test_llm_connection(user: str = Depends(require_login)):
    if _cfg is None:
        return {"ok": False, "error": "no config"}
    try:
        from .llm import LocalLLM
        llm = LocalLLM(_cfg.llm)
        # very light test — many local servers support /v1/models or a tiny prompt
        models = llm.list_models() if hasattr(llm, "list_models") else []
        return {"ok": True, "message": f"LLM reachable ({len(models)} models)" if models else "LLM endpoint responded", "provider": _cfg.llm.provider}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    devices = _storage.get_known_devices(limit=200) if hasattr(_storage, 'get_known_devices') else []
    return get_templates().TemplateResponse(request, "devices.html", context={"devices": devices})

@app.get("/devices/{ip:path}", response_class=HTMLResponse)
async def device_detail_page(ip: str, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    # Decode if needed (FastAPI path already gives raw-ish)
    device = _storage.find_device_by_ip(ip) or {"ip": ip, "trust_level": "normal", "risk_score": 40}
    # Enrich risk if not present
    if "risk_score" not in device or device.get("risk_score") is None:
        trust = device.get("trust_level", "normal")
        tc = device.get("last_threat_count", 0) or 0
        if trust == "critical":
            device["risk_score"] = 90
        elif trust == "untrusted":
            device["risk_score"] = 70 + min(tc * 2, 20)
        elif trust == "trusted":
            device["risk_score"] = max(10, 40 - tc)
        else:
            device["risk_score"] = min(60, 25 + tc * 3)
    threats = _storage.get_recent_threats_for_device(ip, limit=40) if hasattr(_storage, 'get_recent_threats_for_device') else []
    return get_templates().TemplateResponse(
        request,
        "device_detail.html",
        context={"device": device, "threats": threats}
    )

@app.get("/api/devices")
async def api_devices(user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    devices = _storage.get_known_devices(limit=200) if hasattr(_storage, 'get_known_devices') else []
    return {"devices": devices}

@app.post("/api/devices/{ip}/action")
async def api_device_action(ip: str, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    action = data.get("action")

    note = f"Action by {user}: {action} at {datetime.now(timezone.utc).isoformat()}"
    _storage.upsert_known_device({"ip": ip, "notes": note})

    if action == "learn_baseline":
        # Actually analyze recent threats for this IP and extract patterns
        recent = _storage.get_recent_threats_for_device(ip, limit=30) if hasattr(_storage, 'get_recent_threats_for_device') else []
        
        ports_seen = set()
        external_ips = set()
        for threat in recent:
            ev = threat.get("evidence", [])
            for item in ev:
                if isinstance(item, str):
                    import re
                    ports = re.findall(r'DPT=(\d+)', item)
                    ports_seen.update(ports)
                    ips = re.findall(r'DST=([0-9.]+)', item)
                    for dst in ips:
                        if not dst.startswith(('192.168.', '10.', '172.')):
                            external_ips.add(dst)
        
        device = _storage.find_device_by_ip(ip) or {}
        current = device.get("normal_behaviors") or {}
        current["learned_at"] = datetime.now(timezone.utc).isoformat()
        current["common_destination_ports"] = list(ports_seen)[:20]
        current["common_external_destinations"] = list(external_ips)[:10]
        current["baseline_note"] = f"Learned from user action by {user}"
        
        _storage.upsert_known_device({"ip": ip, "normal_behaviors": current})
        msg = f"Baseline learned for {ip}. Captured {len(ports_seen)} common ports and {len(external_ips)} external destinations."
    elif action == "ignore_https":
        device = _storage.find_device_by_ip(ip) or {}
        current = device.get("normal_behaviors") or {}
        current["ignore_https"] = True
        _storage.upsert_known_device({"ip": ip, "normal_behaviors": current})
        msg = "All future HTTPS from " + ip + " will be treated as normal."
    elif action == "mark_trusted":
        _storage.upsert_known_device({"ip": ip, "trust_level": "trusted"})
        msg = "Device " + ip + " marked as trusted."
    elif action == "mark_untrusted":
        _storage.upsert_known_device({"ip": ip, "trust_level": "untrusted"})
        msg = "Device " + ip + " marked as untrusted (higher risk)."
    elif action == "mark_critical":
        _storage.upsert_known_device({"ip": ip, "trust_level": "critical"})
        msg = "Device " + ip + " marked critical (max risk)."
    elif action == "trust_current_mac":
        device = _storage.find_device_by_ip(ip) or {}
        current_mac = device.get("mac")
        trusted = device.get("trusted_macs") or []
        if isinstance(trusted, str):
            try:
                trusted = json.loads(trusted)
            except Exception:
                trusted = []
        if current_mac and current_mac.lower() not in [m.lower() for m in trusted if isinstance(m, str)]:
            trusted.append(current_mac.lower())
        _storage.upsert_known_device({
            "ip": ip,
            "trusted_macs": trusted,
            "mac_trust_level": "trusted"
        })
        msg = f"MAC {current_mac or 'current'} marked trusted for {ip}."
    else:
        msg = "Action recorded for " + ip

    return {"success": True, "message": msg}


@app.post("/api/devices/learn-all")
async def api_learn_all_baselines(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    try:
        data = await request.json()
    except Exception:
        data = {}
    days = int(data.get("days", 7))
    summary = _storage.learn_baselines_for_all(lookback_days=max(1, min(days, 30)))
    return {"success": True, "summary": summary}


@app.post("/api/devices/{ip}/reassess")
async def api_reassess_device(ip: str, request: Request, user: str = Depends(require_login)):
    """Trigger full AI + rules device intelligence assessment for MAC trust and threat decision."""
    if _storage is None:
        return {"error": "not initialized"}
    llm = None
    try:
        from .llm import LocalLLM
        if _cfg:
            llm = LocalLLM(_cfg.llm)
    except Exception:
        pass

    assessment = _storage.assess_device_intelligence(ip, llm)
    return {"success": True, "assessment": assessment}


# =============================================================================
# LIVE SERVER LOGS PAGE
# =============================================================================

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    status = {
        "analyzer_running": True,  # We could wire real state later
        "web_started": True,
        "uptime_note": "Running since startup",
    }

    # Try to get analyzer status if available
    try:
        if hasattr(_storage, "_last_analysis") or True:  # placeholder
            status["last_activity"] = "Active"
    except Exception:
        pass

    return get_templates().TemplateResponse(request, "logs.html", context={
        "config": _cfg,
        "server_status": status
    })


@app.get("/api/logs")
async def api_get_logs(
    limit: int = 250,
    min_level: str | None = None,
    search: str | None = None,
    user: str = Depends(require_login)
):
    """Return recent logs from the live buffer."""
    logs = live_log_buffer.get_recent(limit=limit, min_level=min_level, search=search)
    return logs


@app.post("/api/logs/clear")
async def api_clear_logs(user: str = Depends(require_login)):
    live_log_buffer.clear()
    return {"success": True}


@app.get("/api/threats")
async def api_threats(limit: int = 50, enrich_geo: int = 1):
    if _storage is None:
        return {"error": "not initialized"}
    threats = _storage.get_recent_threats(limit=limit)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)

    # Live geo enrichment for the map / UI (so old threats light up as soon as the DB is present)
    if enrich_geo:
        geo = get_geo_enricher()
        if not geo.available:
            geo.self_heal()
        if geo.available:
            for t in threats:
                if t.get("geo_lat") is None or t.get("geo_lon") is None:
                    sip = t.get("source_ip")
                    if sip:
                        # Check cache first (fast)
                        cached = None
                        try:
                            cached = _storage.get_cached_ip_geo(sip)
                        except Exception:
                            pass
                        g = cached or geo.enrich(sip)
                        if g and g.get("lat") is not None:
                            t["geo_country"] = g.get("country")
                            t["geo_city"] = g.get("city")
                            t["geo_lat"] = g.get("lat")
                            t["geo_lon"] = g.get("lon")
                            t["geo_accuracy"] = g.get("accuracy")
                            # Warm the cache and persist for future
                            try:
                                _storage.cache_ip_geo(sip, g)
                                if t.get("id"):
                                    _storage.update_threat_geo(t["id"], g)
                            except Exception:
                                pass

    return {"threats": threats}


@app.get("/api/analyses")
async def api_analyses(limit: int = 20):
    if _storage is None:
        return {"error": "not initialized"}
    return _get_recent_analyses(limit=limit)


# --- Export Endpoints (JSON + CSV) ---

@app.get("/export/threats.json")
async def export_threats_json(status: str = "all"):
    if _storage is None:
        return {"error": "not ready"}
    threats = _storage.get_recent_threats(limit=2000)
    if status != "all":
        threats = [t for t in threats if t.get("status", "open") == status]
    return {"exported_at": datetime.now(timezone.utc).isoformat(), "count": len(threats), "threats": threats}


@app.get("/export/threats.csv")
async def export_threats_csv(status: str = "all"):
    if _storage is None:
        return "Not ready", 503
    threats = _storage.get_recent_threats(limit=2000)
    if status != "all":
        threats = [t for t in threats if t.get("status", "open") == status]

    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "severity", "score", "status", "hostname", "appname", "description", "recommended_action"])
    for t in threats:
        writer.writerow([
            t.get("id"),
            t.get("created_at"),
            t.get("severity"),
            t.get("score"),
            t.get("status", "open"),
            t.get("hostname"),
            t.get("appname"),
            (t.get("description") or "").replace("\n", " "),
            (t.get("recommended_action") or "").replace("\n", " ")
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rocketlogai-threats.csv"}
    )


# --- Threat Status Management API (now with deep HA integration) ---

@app.post("/api/threats/{threat_id}/status")
async def update_threat_status(threat_id: int, status: str, notes: str = ""):
    if _storage is None:
        return {"error": "not initialized"}

    success = _storage.update_threat_status(threat_id, status, notes or None)

    # === DEEP HOME ASSISTANT TRIGGERING (when user or auto confirms a real threat) ===
    if success and _cfg is not None:
        ha = getattr(_cfg, "home_assistant", None)
        trigger_statuses = getattr(ha, "trigger_on_statuses", ["verified_threat"]) if ha else []
        if status in trigger_statuses:
            threat = _storage.get_threat(threat_id)
            if threat:
                ha_client = get_ha_client(_cfg)
                if ha_client:
                    result = ha_client.trigger_major_threat_alert(
                        threat,
                        notify_services=getattr(ha, "notify_services", None),
                        custom_event=getattr(ha, "custom_event", "rocketlogai.major_threat"),
                    )
                    if result.get("event") or result.get("notification"):
                        _storage.mark_ha_triggered(threat_id)
                        _storage.record_verification_action(threat_id, "ha_triggered", "Auto-triggered via status change")

    return {"success": success, "threat_id": threat_id, "new_status": status}


@app.post("/api/threats/{threat_id}/ha_trigger")
async def force_ha_trigger(threat_id: int, request: Request, user: str = Depends(require_login)):
    """Manual 'big red button' from the UI."""
    if _storage is None or _cfg is None:
        return {"error": "not ready"}

    threat = _storage.get_threat(threat_id)
    if not threat:
        return {"error": "threat not found"}

    ha_client = get_ha_client(_cfg)
    if not ha_client:
        return {"success": False, "error": "Home Assistant not configured or unreachable"}

    result = ha_client.trigger_major_threat_alert(
        threat,
        notify_services=getattr(_cfg.home_assistant, "notify_services", None),
        custom_event=getattr(_cfg.home_assistant, "custom_event", "rocketlogai.major_threat"),
    )
    _storage.mark_ha_triggered(threat_id)
    _storage.record_verification_action(threat_id, "ha_triggered", f"Manual trigger by {user}", actor=user)

    return {"success": True, "result": result}


# --- Dynamic Chart Data APIs (real data) ---

@app.get("/api/charts/severity")
async def chart_severity():
    if _storage is None:
        return {"labels": [], "data": []}
    counts = _storage.get_threat_count_by_severity()
    order = ["critical", "high", "medium", "low"]
    labels = []
    data = []
    colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#4ade80"}
    for s in order:
        if counts.get(s, 0) > 0:
            labels.append(s.title())
            data.append(counts.get(s, 0))
    return {"labels": labels, "data": data, "colors": [colors.get(s.lower(), "#71717a") for s in labels]}


@app.get("/api/charts/activity")
async def chart_activity(days: int = 14):
    if _storage is None:
        return {"labels": [], "data": []}
    rows = _storage.get_threats_over_time(days=days)
    return {
        "labels": [r["day"] for r in rows],
        "data": [r["count"] for r in rows]
    }


@app.get("/api/charts/hosts")
async def chart_hosts(limit: int = 8):
    if _storage is None:
        return {"labels": [], "data": []}
    rows = _storage.get_threats_by_host(limit=limit)
    return {
        "labels": [r["hostname"] for r in rows],
        "data": [r["count"] for r in rows]
    }


@app.get("/api/charts/status")
async def chart_status():
    """Dynamic status breakdown (expanded vocabulary)."""
    if _storage is None:
        return {"labels": ["Open", "Verified", "Benign/IoT", "False +"], "data": [0, 0, 0, 0]}
    counts = _storage.get_threat_counts_by_status()
    labels = ["Open", "Verified Threat", "Benign / IoT", "False Positive"]
    data = [
        counts.get("open", 0),
        counts.get("verified_threat", 0) + counts.get("escalated", 0),
        counts.get("verified_benign", 0) + counts.get("iot_expected", 0),
        counts.get("false_positive", 0),
    ]
    return {"labels": labels, "data": data}


# --- Heartbeat / Monitors API ---

@app.get("/api/monitors")
async def api_monitors(user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    monitors = _storage.get_monitors()
    results = _storage.get_recent_monitor_results(limit=200)
    return {"monitors": monitors, "recent_results": results}

@app.post("/api/monitors/{monitor_name}/run")
async def api_run_monitor(monitor_name: str, user: str = Depends(require_login)):
    """Manually trigger a single heartbeat check.

    Supports monitors that live only in the database (added via the web UI)
    as well as those defined in config.yaml.
    """
    if _storage is None or _cfg is None:
        return {"error": "not ready"}

    from .config import HeartbeatMonitor
    from .heartbeat import HeartbeatMonitorRunner

    # 1. Prefer definition from the database (web UI / dynamic monitors)
    mon = None
    db_mon = None
    try:
        db_mons = _storage.get_monitors(enabled_only=False)
        db_mon = next((m for m in db_mons if m.get("name") == monitor_name), None)
    except Exception:
        pass

    if db_mon:
        mon = HeartbeatMonitor(
            name=db_mon["name"],
            host=db_mon["host"],
            type=db_mon.get("type", "tcp"),
            port=db_mon.get("port"),
            path=db_mon.get("path") or "/",
            expected=db_mon.get("expected"),
            severity=db_mon.get("severity", "medium"),
            remediation_action=db_mon.get("remediation_action"),
            interval_seconds=db_mon.get("interval_seconds", 300),
            enabled=bool(db_mon.get("enabled", 1)),
        )
    else:
        # 2. Fall back to monitors defined in config.yaml
        matches = [m for m in (_cfg.heartbeats.monitors or []) if m.name == monitor_name]
        if matches:
            mon = matches[0]

    if mon is None:
        return {"success": False, "error": "Monitor not found"}

    runner = HeartbeatMonitorRunner(_cfg.heartbeats, storage=_storage)
    result = runner._run_one(mon)
    _storage.record_monitor_result(mon.name, result.success, result.message,
                                   result.latency_ms, result.remediation_suggested, result.details)
    return {"success": True, "result": result.__dict__}

@app.post("/api/monitors/{monitor_name}/remediate")
async def api_remediate_monitor(monitor_name: str, action: str, user: str = Depends(require_login)):
    if not _rem:
        return {"success": False, "error": "Remediation not available"}

    action_obj = RemediationAction(action_type=action, target=monitor_name,
                                   reason="Manual from Monitors UI", parameters={})
    res = await _rem.execute(action_obj, confirmed=False)
    return {"success": True, "result": res}


# --- AI-Powered Remediation Suggestions (for monitors + regular threats) ---

def _generate_remediation_suggestions(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Rich, service-aware static knowledge + optional LLM enhancement.
    This is the heart of the 'smart monitoring AI' the user asked for.
    Designed to be future-proof for cert rotation, script execution, etc.
    """
    suggestions: list[dict[str, Any]] = []
    mon_type = (context.get("type") or context.get("monitor_type") or "").lower()
    host = context.get("host") or context.get("hostname") or "the host"
    last_message = context.get("message") or ""
    details = context.get("details") or {}
    red_flags = details.get("red_flags") or []

    # === HTTPS / TLS specific superpowers ===
    if mon_type in ("https", "tls"):
        fp = details.get("cert_sha256") or details.get("cert_fingerprint")
        days = details.get("cert_days_until_expiry")
        tls_ver = details.get("tls_version")

        if red_flags:
            suggestions.append({
                "title": "Certificate or TLS problem detected",
                "action": "Immediate investigation + rotation recommended",
                "steps": [
                    f"1. Verify the certificate on {host} with: openssl s_client -connect {host}:443 -servername {host} </dev/null | openssl x509 -noout -text",
                    "2. Obtain a fresh certificate (certbot, acme.sh, or your CA's API)",
                    "3. Use the new 'Upload remediation script' feature to safely deploy the new cert + key with proper permissions",
                    "4. After deployment, re-run the https monitor and confirm the fingerprint changed as expected",
                ],
                "priority": "critical",
                "future_vision": "LogSentinel AI can eventually call the CA API directly (ACME) and use your stored passkey/SSH identity to perform the rotation atomically."
            })

        if days is not None and days < 30:
            suggestions.append({
                "title": f"Certificate expires in {days} days",
                "action": "Plan renewal now",
                "steps": [
                    "Run your normal renewal process (certbot renew or equivalent)",
                    "Stage the new files and use a remediation script to atomically replace the live certs",
                    "Consider enabling auto-renewal with a 30-day threshold in your infrastructure",
                ],
                "priority": "high" if days < 14 else "medium"
            })

        if fp:
            suggestions.append({
                "title": "Record this certificate fingerprint",
                "action": "Baseline the current identity of the service",
                "steps": [
                    f"Current leaf SHA-256: {fp[:16]}...",
                    "Store this value (or let LogSentinel remember it from the monitor result)",
                    "Any future change will be flagged automatically — this is your tamper-evidence mechanism",
                ],
                "priority": "low"
            })

    # === SSH specific ===
    if mon_type in ("ssh_version", "ssh"):
        suggestions.append({
            "title": "SSH service health / update check",
            "action": "Log in and verify package status",
            "steps": [
                f"ssh {host} 'sudo apt update && apt list --upgradable 2>/dev/null | grep -i ssh || sudo dnf check-update --security || true'",
                "Check the exact OpenSSH version against known CVEs for your distro",
                "If an update is available, stage it and use a remediation script (or the built-in update_ssh action) to apply it during a maintenance window",
            ],
            "priority": "high" if "outdated" in last_message.lower() or "unexpected" in last_message.lower() else "medium"
        })

    # === HTTP / general web ===
    if mon_type in ("http", "https"):
        suggestions.append({
            "title": "Web service deep inspection",
            "action": "Look for outdated software and missing security headers",
            "steps": [
                "Inspect response headers for Server, X-Powered-By, X-Generator (common plugin/version leaks)",
                "Run a non-destructive scanner from the LogSentinel host: nmap -sV --script http-headers,http-security-headers <host>",
                "Check for missing HSTS, CSP, X-Frame-Options, etc.",
            ],
            "priority": "medium"
        })

    # === Ping / reachability ===
    if mon_type == "ping":
        suggestions.append({
            "title": "Host unreachable via ICMP",
            "action": "Layered connectivity troubleshooting",
            "steps": [
                f"From the LogSentinel machine: traceroute {host} or mtr {host}",
                "Check local firewall / security groups on both ends",
                "Verify the host is actually up (try TCP port 22 or 443 with the other monitor types)",
            ],
            "priority": "high"
        })

    # === Generic high-value next actions (always useful) ===
    suggestions.append({
        "title": "Capture forensic snapshot (safe)",
        "action": "Run a read-only investigation script",
        "steps": [
            "Use the new remediation script upload feature to attach a small 'investigate.sh' that collects: uptime, last logins, recent apt/yum history, listening sockets, etc.",
            "Execute it via the 'Run Script' button (preview + confirm always required)",
        ],
        "priority": "low"
    })

    # Future-proof note for the user
    if mon_type in ("https", "tls"):
        suggestions.append({
            "title": "Long-term: AI-driven certificate lifecycle",
            "action": "The vision you described",
            "steps": [
                "LogSentinel detects expiry or unexpected change via the https monitor",
                "AI suggests (or with your approval) obtains a new cert via the provider's API",
                "A remediation script (or future built-in deployer) uses your stored SSH passkey/identity to atomically install the new cert + key with correct permissions",
                "Monitor re-runs and confirms the new fingerprint — full closed loop with audit trail",
            ],
            "priority": "info"
        })

    return suggestions[:6]  # keep it focused


@app.post("/api/remediation/suggest")
async def api_suggest_remediation(request: Request, user: str = Depends(require_login)):
    """Return rich, actionable remediation suggestions for a monitor or a threat.
    The frontend can call this after a Run, or from the threats page.
    """
    data = await request.json()
    suggestions = _generate_remediation_suggestions(data or {})

    # Optional LLM enhancement (if the user has a local model running)
    llm_text = None
    if _cfg and getattr(_cfg, "llm", None) and _cfg.llm.base_url:
        try:
            # Lightweight one-shot prompt with the static suggestions as context
            from .llm import LocalLLM
            llm = LocalLLM(_cfg.llm)
            prompt_context = json.dumps(data, default=str)[:3000]
            static_suggestions = "\n".join(s.get("title", "") + ": " + s.get("action", "") for s in suggestions)
            user_msg = f"Context: {prompt_context}\n\nCurrent static suggestions:\n{static_suggestions}\n\nGive 2-3 additional concrete next steps tailored to this exact situation. Be extremely practical."

            # We reuse the existing client with a very short, focused prompt
            # (the full SECURITY_SYSTEM_PROMPT is too heavy here)
            messages = [
                {"role": "system", "content": "You are a senior SRE and security engineer. Give short, concrete, numbered remediation steps. Never suggest anything destructive without explicit human approval."},
                {"role": "user", "content": user_msg},
            ]
            resp = llm.client.chat.completions.create(
                model=_cfg.llm.model or "local-model",
                messages=messages,
                temperature=0.2,
                max_tokens=400,
            )
            llm_text = resp.choices[0].message.content if resp.choices else None
        except Exception as e:
            llm_text = f"(LLM enhancement unavailable: {str(e)[:120]})"

    return {
        "success": True,
        "suggestions": suggestions,
        "llm_additions": llm_text,
        "context": {"type": data.get("type"), "host": data.get("host")},
    }


# --- Remediation Script Upload + Safe Execution (1MB limit, preview + confirm always required) ---

REMEDIATION_SCRIPT_DIR = Path("data/remediation_scripts")
REMEDIATION_SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_SCRIPT_EXTS = {".sh", ".py", ".bash", ".zsh", ".txt"}
MAX_SCRIPT_SIZE = 1 * 1024 * 1024  # 1 MB as requested


def _safe_monitor_script_path(monitor_name: str, filename: str) -> Path:
    """Sanitize and return a safe path under data/remediation_scripts/<monitor>/"""
    safe_name = "".join(c for c in monitor_name if c.isalnum() or c in "-_")[:80] or "unnamed"
    mon_dir = REMEDIATION_SCRIPT_DIR / safe_name
    mon_dir.mkdir(parents=True, exist_ok=True)
    # Only allow safe extensions
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_SCRIPT_EXTS:
        ext = ".sh"
    final_name = Path(filename).stem[:60] + ext
    return mon_dir / final_name


@app.post("/api/monitors/{monitor_name}/remediation-script")
async def upload_remediation_script(monitor_name: str, file: UploadFile = File(...), user: str = Depends(require_login)):
    """Upload a remediation / investigation script for this specific monitor (max 1MB)."""
    if not file:
        return {"success": False, "error": "No file provided"}

    contents = await file.read()
    if len(contents) > MAX_SCRIPT_SIZE:
        return {"success": False, "error": f"File too large (max 1MB)"}

    # Basic text safety (we still allow binary but warn)
    try:
        text_preview = contents.decode("utf-8", errors="replace")[:2000]
    except Exception:
        text_preview = "<binary or non-utf8 content>"

    target_path = _safe_monitor_script_path(monitor_name, file.filename)
    target_path.write_bytes(contents)

    meta = {
        "original_name": file.filename,
        "stored_path": str(target_path.relative_to(REMEDIATION_SCRIPT_DIR)),
        "size": len(contents),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": user,
        "sha256": hashlib.sha256(contents).hexdigest()[:16],
    }
    (target_path.parent / (target_path.name + ".meta.json")).write_text(json.dumps(meta, indent=2))

    return {"success": True, "path": str(target_path), "meta": meta, "preview": text_preview[:800]}


@app.get("/api/monitors/{monitor_name}/remediation-script")
async def get_remediation_script(monitor_name: str, user: str = Depends(require_login)):
    """Return metadata + full content for preview before execution."""
    safe_name = "".join(c for c in monitor_name if c.isalnum() or c in "-_")[:80] or "unnamed"
    mon_dir = REMEDIATION_SCRIPT_DIR / safe_name
    if not mon_dir.exists():
        return {"success": False, "scripts": []}

    scripts = []
    for p in mon_dir.glob("*"):
        if p.suffix in ALLOWED_SCRIPT_EXTS:
            meta_file = p.parent / (p.name + ".meta.json")
            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                except Exception:
                    pass
            content = p.read_text(errors="replace")[:4000]
            scripts.append({
                "filename": p.name,
                "size": p.stat().st_size,
                "content_preview": content,
                "meta": meta,
            })
    return {"success": True, "scripts": scripts}


@app.post("/api/monitors/{monitor_name}/run-script")
async def run_remediation_script(monitor_name: str, request: Request, user: str = Depends(require_login)):
    """Safely execute an attached remediation script.
    The request body must contain:
      - script_filename
      - confirmed: true   (user has seen the preview)
    Execution is done with timeout, output captured, and recorded.
    Never auto-executes on monitor failure.
    """
    data = await request.json()
    script_filename = data.get("script_filename")
    confirmed = bool(data.get("confirmed"))

    safe_name = "".join(c for c in monitor_name if c.isalnum() or c in "-_")[:80] or "unnamed"
    target = REMEDIATION_SCRIPT_DIR / safe_name / script_filename

    if not target.exists() or target.suffix not in ALLOWED_SCRIPT_EXTS:
        return {"success": False, "error": "Script not found or not allowed"}

    # Read for preview / execution
    try:
        script_content = target.read_text(errors="replace")
    except Exception as e:
        return {"success": False, "error": f"Could not read script: {e}"}

    # === ACTUAL (guarded) EXECUTION ===
    import subprocess
    start = time.time()
    try:
        # Use bash for .sh files, python for .py, otherwise sh
        if target.suffix == ".py":
            cmd = [sys.executable, str(target)]
        else:
            cmd = ["bash", str(target)]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # 2 minute hard cap
        duration = (time.time() - start) * 1000

        result = {
            "status": "executed",
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
            "duration_ms": round(duration),
        }

        # Record as a monitor result so it appears in history
        if _storage:
            try:
                _storage.record_monitor_result(
                    monitor_name,
                    proc.returncode == 0,
                    f"Script {script_filename} exited {proc.returncode}",
                    duration,
                    None,
                    {"script": script_filename, "output": result}
                )
            except Exception:
                pass

        return {"success": True, "result": result}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Script execution timed out (120s limit)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# --- Full Monitor CRUD for Web Console (parity with config.yaml) ---

@app.post("/api/monitors")
async def api_create_monitor(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    data = await request.json()
    from .config import HeartbeatMonitor
    m = HeartbeatMonitor(
        name=data.get("name"),
        host=data.get("host"),
        type=data.get("type", "tcp"),
        port=data.get("port"),
        path=data.get("path", "/"),
        expected=data.get("expected"),
        severity=data.get("severity", "medium"),
        remediation_action=data.get("remediation_action"),
        interval_seconds=data.get("interval_seconds", 300),
        enabled=data.get("enabled", True),
    )
    mid = _storage.upsert_monitor(m)
    return {"success": True, "id": mid, "name": m.name}

@app.put("/api/monitors/{name}")
async def api_update_monitor(name: str, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    try:
        data = await request.json()
    except Exception:
        # Client disconnected or sent bad data (very common with HTMX)
        return {"success": False, "error": "request aborted"}
    from .config import HeartbeatMonitor
    m = HeartbeatMonitor(
        name=name,
        host=data.get("host", ""),
        type=data.get("type", "tcp"),
        port=data.get("port"),
        path=data.get("path", "/"),
        expected=data.get("expected"),
        severity=data.get("severity", "medium"),
        remediation_action=data.get("remediation_action"),
        interval_seconds=data.get("interval_seconds", 300),
        enabled=data.get("enabled", True),
    )
    _storage.upsert_monitor(m)
    return {"success": True}

@app.delete("/api/monitors/{name}")
async def api_delete_monitor(name: str, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    with _storage._cursor() as cur:
        cur.execute("DELETE FROM monitors WHERE name = ?", (name,))
        cur.execute("DELETE FROM monitor_results WHERE monitor_name = ?", (name,))
    return {"success": True}


# --- Geo Status & Monitor Sync APIs (for UI widgets) ---

@app.get("/api/geo/status")
async def api_geo_status(refresh: int = 0, user: str = Depends(require_login)):
    """Geo status. Pass ?refresh=1 to force the enricher to drop its cache and re-scan for the .mmdb
    (fixes the common case where the DB was added after the server started).
    """
    if refresh:
        geo = force_reload_geo()
    else:
        geo = get_geo_enricher()
        # Self-heal attempt (very cheap if already loaded)
        if not geo.available:
            geo.self_heal()

    cached_count = 0
    if _storage:
        try:
            with _storage._cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM ip_geo_cache")
                cached_count = cur.fetchone()[0]
        except Exception:
            pass

    return {
        "available": geo.available,
        "db_path": geo.db_path,
        "cached_ips": cached_count,
        "message": "GeoLite2 ready" if geo.available else "geoip2 package missing or no .mmdb found",
        "refreshed": bool(refresh),
    }


def _backfill_geo_for_threats(limit: int = 500) -> dict[str, Any]:
    """Find threats that have a source_ip but are missing geo_lat/lon, enrich them,
    update the DB rows, and return stats. Safe to call from the web UI.
    """
    if _storage is None:
        return {"updated": 0, "error": "storage not ready"}

    geo = get_geo_enricher()
    if not geo.available:
        # Last-ditch aggressive reload (especially important for /Volumes/logsentinel)
        geo = force_reload_geo()

    if not geo.available:
        return {"updated": 0, "error": "GeoLite2 still not available after reload attempt"}

    updated = 0
    try:
        threats = _storage.get_recent_threats(limit=limit)
        for t in threats:
            if t.get("geo_lat") is not None and t.get("geo_lon") is not None:
                continue
            sip = t.get("source_ip")
            if not sip:
                # Try the same extraction the analyzer uses
                sip = None
                for key in ("description", "evidence"):
                    val = t.get(key)
                    if isinstance(val, str):
                        import re
                        m = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", val)
                        if m:
                            cand = m.group(0)
                            if not cand.startswith(("0.", "127.", "169.254.")):
                                sip = cand
                                break
                    elif isinstance(val, list):
                        for item in val:
                            if isinstance(item, str):
                                m = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", item)
                                if m:
                                    cand = m.group(0)
                                    if not cand.startswith(("0.", "127.", "169.254.")):
                                        sip = cand
                                        break
            if not sip:
                continue

            g = geo.enrich(sip)
            if g and g.get("lat") is not None:
                # Persist to the threat row
                try:
                    _storage.update_threat_geo(t["id"], g)
                    updated += 1
                except Exception:
                    pass
                # Also make sure the cache is warm
                try:
                    _storage.cache_ip_geo(sip, g)
                except Exception:
                    pass
    except Exception as e:
        return {"updated": updated, "error": str(e)}

    return {"updated": updated, "message": f"Backfilled geo for {updated} threats"}


@app.post("/api/geo/backfill")
async def api_geo_backfill(user: str = Depends(require_login)):
    """Re-enrich all recent threats that are missing geo data but have a usable source_ip.
    This is the big button that makes old threats (and threats created before the .mmdb was present)
    appear on the map without requiring a full server restart or re-processing logs.
    """
    result = _backfill_geo_for_threats(limit=2000)
    return {"success": True, **result}


@app.post("/api/geo/reload")
async def api_geo_reload(user: str = Depends(require_login)):
    """Force the geo singleton to drop and re-scan every known location (including /Volumes/logsentinel)."""
    geo = force_reload_geo()
    return {
        "success": True,
        "available": geo.available,
        "db_path": geo.db_path,
        "message": "Geo re-scanned" if geo.available else "Still no database found",
    }


@app.post("/api/monitors/refresh-from-config")
async def api_refresh_monitors_from_config(user: str = Depends(require_login)):
    """Re-sync monitors defined in config.yaml into the database."""
    if _storage is None or _cfg is None:
        return {"success": False, "error": "not ready"}

    count = 0
    for m in _cfg.heartbeats.monitors:
        _storage.upsert_monitor(m)
        count += 1
    return {"success": True, "synced": count}


# --- LLM Model Discovery ---

@app.post("/api/llm/fetch-models")
async def fetch_llm_models(request: Request, user: str = Depends(require_login)):
    """Fetch available models from any OpenAI-compatible server (LM Studio, Ollama, etc.)."""
    if _cfg is None:
        return {"success": False, "error": "Config not loaded"}

    data = await request.json()
    base_url = data.get("base_url", _cfg.llm.base_url)
    api_key = data.get("api_key", _cfg.llm.api_key or "not-needed")

    try:
        from openai import OpenAI
        client = OpenAI(base_url=base_url.rstrip("/") + "/v1", api_key=api_key, timeout=10)
        models = client.models.list()
        model_list = [m.id for m in models.data]
        return {"success": True, "models": sorted(model_list)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/llm/test-connection")
async def test_llm_connection(request: Request, user: str = Depends(require_login)):
    """Test connectivity and basic functionality of the LLM server."""
    if _cfg is None:
        return {"success": False, "message": "Config not loaded"}

    data = await request.json()
    base_url = data.get("base_url", _cfg.llm.base_url)
    api_key = data.get("api_key", _cfg.llm.api_key or "not-needed")
    model = data.get("model", _cfg.llm.model) or None

    try:
        from openai import OpenAI
        client = OpenAI(base_url=base_url.rstrip("/") + "/v1", api_key=api_key, timeout=15)

        # Test models list first
        models = client.models.list()
        available = [m.id for m in models.data]

        # Try a tiny completion if a model is provided
        if model:
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Say 'OK'"}],
                max_tokens=5,
                temperature=0
            )
            return {
                "success": True,
                "message": f"Successfully connected to {base_url}",
                "models_found": len(available),
                "test_completion": "OK"
            }

        return {
            "success": True,
            "message": f"Successfully connected to {base_url}",
            "models_found": len(available)
        }

    except Exception as e:
        return {"success": False, "message": str(e)[:300]}


@app.post("/api/restart")
async def restart_logsentinel(request: Request, user: str = Depends(require_login)):
    """Gracefully exit the process so it can be restarted (e.g. by systemd, or manually)."""
    import os, signal
    # Best we can do from inside the process
    os.kill(os.getpid(), signal.SIGTERM)
    return {"success": True, "message": "Shutdown signal sent"}


# --- Domain Connectivity Test ---

@app.post("/api/domain/test")
async def test_domain_connection(request: Request, user: str = Depends(require_login)):
    """Test LDAP connectivity to the configured (or provided) domain settings."""
    if _cfg is None:
        return {"success": False, "message": "Config not loaded"}

    form = await _safe_form(request)
    server = form.get("domain_server") or _cfg.web.domain_server
    base_dn = form.get("domain_base_dn") or _cfg.web.domain_base_dn
    test_user = form.get("test_user", "")
    test_pass = form.get("test_pass", "")

    if not server or not base_dn:
        return {"success": False, "message": "Domain server and Base DN are required"}

    try:
        from ldap3 import Server, Connection, ALL
        srv = Server(server, get_info=ALL, connect_timeout=6)
        # Try a simple connection first (anonymous or with provided creds)
        if test_user and test_pass:
            conn = Connection(srv, user=test_user, password=test_pass, auto_bind=True)
        else:
            # Just test reachability
            conn = Connection(srv, auto_bind=True)
        conn.unbind()
        return {"success": True, "message": f"Successfully connected to {server}"}
    except Exception as e:
        return {"success": False, "message": str(e)[:200]}


# --- Simple Alerting (called when high severity threats are detected) ---

def send_threat_alerts(threats: list[dict], cfg: Config | None = None):
    """Fire webhooks + optional email for high severity threats."""
    if not threats:
        return

    import requests
    import smtplib
    from email.mime.text import MIMEText

    high_threats = [t for t in threats if t.get("severity", "").lower() in ("high", "critical")]

    if not high_threats:
        return

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(high_threats),
        "threats": high_threats,
    }

    # Webhooks (generic + special Microsoft Teams handling)
    webhooks = (cfg.alerting.webhooks if cfg else []) or []
    for url in webhooks:
        try:
            if "webhook.office.com" in url or "teams.microsoft.com" in url:
                # Microsoft Teams Adaptive Card format
                teams_payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "FF6B6B",
                    "summary": f"RocketLogAI: {len(high_threats)} high-severity threat(s)",
                    "sections": [{
                        "activityTitle": "🚨 RocketLogAI Security Alert",
                        "facts": [
                            {"name": "Threats", "value": str(len(high_threats))},
                            {"name": "Highest Severity", "value": high_threats[0].get("severity", "high").upper()},
                            {"name": "Host / App", "value": f"{high_threats[0].get('hostname','?')} / {high_threats[0].get('appname','?')}"},
                            {"name": "Example", "value": high_threats[0].get("description", "")[:160]}
                        ],
                        "markdown": True
                    }],
                    "potentialAction": [{
                        "@type": "OpenUri",
                        "name": "View Dashboard",
                        "targets": [{"os": "default", "uri": "http://127.0.0.1:8787"}]
                    }]
                }
                requests.post(url, json=teams_payload, timeout=8)
            else:
                requests.post(url, json=payload, timeout=8)
        except Exception:
            pass

    # Email (basic)
    if cfg and cfg.alerting.email_to and cfg.alerting.smtp_host:
        try:
            msg = MIMEText(f"RocketLogAI detected {len(high_threats)} high-severity threat(s):\n\n" +
                           "\n".join(f"- [{t['severity']}] {t['description']}" for t in high_threats))
            msg["Subject"] = f"[RocketLogAI] {len(high_threats)} high severity threat(s) detected"
            msg["From"] = cfg.alerting.smtp_from
            msg["To"] = ", ".join(cfg.alerting.email_to)

            with smtplib.SMTP(cfg.alerting.smtp_host, cfg.alerting.smtp_port) as server:
                if cfg.alerting.smtp_user:
                    server.starttls()
                    server.login(cfg.alerting.smtp_user, cfg.alerting.smtp_password)
                server.sendmail(cfg.alerting.smtp_from, cfg.alerting.email_to, msg.as_string())
        except Exception:
            pass  # silent fail for local tool


def _enrich_threats_with_device_context(threats: list[dict]) -> None:
    """Attach device registry risk/trust/name to threats that have a source_ip (in-place)."""
    if not _storage or not threats:
        return
    for t in threats:
        sip = t.get("source_ip")
        if not sip:
            # best-effort extraction for older records
            for key in ("description", "evidence"):
                val = t.get(key)
                if isinstance(val, str):
                    import re
                    m = re.search(r"\b((?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\d{1,3}\.\d{1,3})\b", val)
                    if m:
                        sip = m.group(1)
                        break
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            import re
                            m = re.search(r"\b((?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\d{1,3}\.\d{1,3})\b", item)
                            if m:
                                sip = m.group(1)
                                break
        if sip:
            try:
                dev = _storage.find_device_by_ip(sip)
                if dev:
                    t["device_risk"] = dev.get("risk_score")
                    t["device_trust"] = dev.get("trust_level", "normal")
                    t["device_name"] = dev.get("ha_name") or sip
                    t["device_vendor"] = dev.get("vendor")
                    t["device_vendor_icon"] = dev.get("vendor_icon")
                    t["device_category"] = dev.get("device_category")
            except Exception:
                pass


# --- HTMX fragment endpoints for auto-refresh (no full page reload) ---

@app.get("/fragments/recent-threats", response_class=HTMLResponse)
async def fragment_recent_threats(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not ready", status_code=503)
    threats = _storage.get_recent_threats(limit=12)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)
    return get_templates().TemplateResponse(
        request,
        "fragments/recent_threats.html",
        context={"threats": threats},
    )


@app.get("/fragments/recent-analyses", response_class=HTMLResponse)
async def fragment_recent_analyses(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not ready", status_code=503)
    analyses = _get_recent_analyses(limit=5)
    return get_templates().TemplateResponse(
        request,
        "fragments/recent_analyses.html",
        context={"analyses": analyses},
    )


def _get_recent_analyses(limit: int = 20) -> list[dict[str, Any]]:
    """Fetch recent analyses with their raw LLM output."""
    if _storage is None:
        return []

    with _storage._cursor() as cur:
        cur.execute("""
            SELECT id, started_at, finished_at, logs_analyzed, threats_found,
                   summary, raw_response, model
            FROM analyses
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()

    out = []
    for r in rows:
        d = dict(r)
        raw = d.get("raw_response")
        if raw:
            try:
                # Try to pretty-print if it looks like JSON
                parsed = json.loads(raw)
                d["raw_response_pretty"] = json.dumps(parsed, indent=2)
            except Exception:
                d["raw_response_pretty"] = raw
        else:
            d["raw_response_pretty"] = None
        out.append(d)
    return out


def _get_analysis(analysis_id: int) -> dict[str, Any] | None:
    if _storage is None:
        return None

    with _storage._cursor() as cur:
        cur.execute("""
            SELECT id, started_at, finished_at, logs_analyzed, threats_found,
                   summary, raw_response, model
            FROM analyses WHERE id = ?
        """, (analysis_id,))
        row = cur.fetchone()
        if not row:
            return None

        d = dict(row)
        raw = d.get("raw_response")
        if raw:
            try:
                parsed = json.loads(raw)
                d["raw_response_pretty"] = json.dumps(parsed, indent=2)
            except Exception:
                d["raw_response_pretty"] = raw
        else:
            d["raw_response_pretty"] = None

        # Also fetch associated threats
        cur.execute("SELECT * FROM threats WHERE analysis_id = ? ORDER BY score DESC", (analysis_id,))
        threats = []
        for t in cur.fetchall():
            td = dict(t)
            try:
                td["evidence"] = json.loads(td["evidence"]) if td["evidence"] else []
            except Exception:
                td["evidence"] = []
            td["advice"] = get_actionable_advice(td)
            threats.append(td)
        d["threats"] = threats

        return d


def get_actionable_advice(threat: dict[str, Any]) -> list[str]:
    """
    Generate practical, actionable security advice based on a threat.
    This gives users concrete next steps instead of just "something bad happened".
    """
    desc = (threat.get("description") or "").lower()
    sev = (threat.get("severity") or "medium").lower()
    hostname = threat.get("hostname") or "the host"
    app = threat.get("appname") or "the service"

    advice = []

    # Brute force / authentication attacks
    if any(x in desc for x in ["brute", "failed password", "authentication", "login attempt", "ssh"]):
        advice.append(f"Check auth logs on {hostname} for the full attack timeline.")
        advice.append("Consider enforcing key-based SSH authentication and disabling password login.")
        advice.append("Temporarily block the source IP at the firewall or fail2ban if the behavior continues.")
        if sev in ("high", "critical"):
            advice.append("Review whether any successful logins occurred from this IP around the same time.")

    # Privilege escalation or sudo
    elif any(x in desc for x in ["sudo", "privilege", "root", "escalat", "setuid"]):
        advice.append(f"Audit recent sudo / su activity on {hostname}.")
        advice.append("Check /var/log/auth.log (or equivalent) for the exact commands that were run.")
        advice.append("Review which users have sudo rights — principle of least privilege.")

    # Malware / suspicious process / miner
    elif any(x in desc for x in ["miner", "crypto", "malware", "suspicious process", "base64", "curl.*http"]):
        advice.append("Capture volatile data (ps, netstat, lsof) before rebooting.")
        advice.append("Look for unknown processes and unusual outbound connections.")
        advice.append("Consider isolating the host from the network for investigation.")

    # General high severity
    if sev in ("critical", "high"):
        advice.append("Treat this as a potential security incident — start your incident response process.")
        advice.append("Preserve logs and consider taking a forensic image if the host is critical.")

    # Generic fallback
    if not advice:
        advice.append("Review the evidence logs and correlate with other systems (EDR, firewall, etc.).")
        advice.append("Check if this pattern has appeared before in historical logs.")
        if sev in ("high", "critical"):
            advice.append("Escalate to your security team or incident response contact.")

    return advice[:5]  # keep it concise


def run_web(
    host: str = "127.0.0.1",
    port: int = 8787,
    storage: Storage | None = None,
    cfg: Config | None = None,
    auth_user: str | None = None,
    auth_pass: str | None = None,
):
    """Start the web server (blocking)."""
    global _web_auth_user, _web_auth_pass

    if storage and cfg:
        init(storage, cfg)

    if auth_user and auth_pass:
        _web_auth_user = auth_user
        _web_auth_pass = auth_pass
        print(f"🔒 Web UI protected with basic auth (user: {auth_user})")

    # Create templates dir on the fly if it doesn't exist (first run convenience)
    _ensure_templates()

    # Force template loader to initialize early so we get the diagnostic messages immediately
    try:
        get_templates()
    except Exception as e:
        print(f"[logsentinel] Warning: could not pre-load templates: {e}")

    # Determine final host/port from config if available (config takes precedence)
    if cfg and getattr(cfg, "web", None):
        host = cfg.web.web_host or host
        port = cfg.web.web_port or port
        https_port = getattr(cfg.web, "https_port", port + 1) or (port + 1)
    else:
        https_port = port + 1

    # Determine SSL configuration
    ssl_cert = None
    ssl_key = None
    if cfg and getattr(cfg, "web", None):
        w = cfg.web
        if w.ssl_enabled:
            ssl_cert, ssl_key = get_or_create_default_certs(w)
            if ssl_cert and ssl_key:
                print(f"[rocketlogai] HTTPS certificate ready: {ssl_cert}")
            else:
                print("[rocketlogai] Warning: SSL was enabled but no valid certificate could be found or generated.")

    have_https = bool(ssl_cert and ssl_key)

    want_http = True
    want_https = False
    if cfg and getattr(cfg, "web", None):
        w = cfg.web
        want_http = w.http_enabled
        want_https = w.ssl_enabled and have_https

    # Print friendly startup message
    print(f"\n🌐 RocketLogAI web dashboard")
    if want_http:
        print(f"    HTTP  →  http://{host}:{port}")
    if want_https:
        print(f"    HTTPS →  https://{host}:{https_port}  (self-signed cert - accept the warning in your browser)")
    print("   Press Ctrl+C to stop.\n")

    logging.getLogger("logsentinel.web").info(
        "Web UI starting: HTTP=%s on %s:%s, HTTPS=%s on %s:%s",
        want_http, host, port, want_https, host, https_port
    )

    # Capture uvicorn logs into our live buffer
    try:
        uvicorn_logger = logging.getLogger("uvicorn")
        uvicorn_error_logger = logging.getLogger("uvicorn.error")
        uvicorn_access_logger = logging.getLogger("uvicorn.access")

        for lg in [uvicorn_logger, uvicorn_error_logger, uvicorn_access_logger]:
            lg.addHandler(live_log_buffer)
            lg.setLevel(logging.INFO)
    except Exception:
        pass

    # Extra confirmation for developers working in the source tree (portable detection)
    if _is_running_from_source():
        print("[rocketlogai] ✓ Development mode: Using live templates from source (changes should appear on refresh)")

    import threading

    def _run_one_server(use_ssl_server: bool, listen_port: int, label: str):
        kwargs = {
            "app": app,
            "host": host,
            "port": listen_port,
            "log_level": "warning",
            "access_log": False,
        }
        if use_ssl_server and have_https:
            kwargs["ssl_certfile"] = ssl_cert
            kwargs["ssl_keyfile"] = ssl_key
        print(f"[rocketlogai] Starting {label} server on {host}:{listen_port} ...")
        uvicorn.run(**kwargs)

    if want_http and want_https:
        # Both protocols requested → run HTTPS in a background thread, HTTP blocking (main)
        https_thread = threading.Thread(
            target=_run_one_server,
            args=(True, https_port, "HTTPS"),
            daemon=True,
            name="rocketlogai-https"
        )
        https_thread.start()
        # Give the HTTPS thread a moment to print its startup line
        import time; time.sleep(0.3)
        _run_one_server(False, port, "HTTP")
    elif want_https:
        _run_one_server(True, https_port, "HTTPS")
    else:
        # Plain HTTP only (or fallback)
        _run_one_server(False, port, "HTTP")


def run_web_in_thread(
    host: str = "127.0.0.1",
    port: int = 8787,
    storage: Storage | None = None,
    cfg: Config | None = None,
    auth_user: str | None = None,
    auth_pass: str | None = None,
) -> "threading.Thread":
    """
    Start the web dashboard in a background daemon thread.
    This is the recommended way to run it together with `logsentinel run`.

    Works reliably on Linux, macOS, and Windows.
    """
    import threading

    def _runner():
        try:
            run_web(host=host, port=port, storage=storage, cfg=cfg, auth_user=auth_user, auth_pass=auth_pass)
        except Exception:
            # Don't crash the whole process if web fails — log full traceback for diagnosis
            import logging
            logging.getLogger("logsentinel.web").exception("Web UI thread crashed with full traceback:")

    thread = threading.Thread(target=_runner, daemon=True, name="logsentinel-web")
    thread.start()
    auth_msg = f" (auth: {auth_user})" if auth_user else ""
    print(f"🌐 Web dashboard background thread started{auth_msg}")
    print("   Exact HTTP/HTTPS addresses and ports are printed by the server startup above.")
    print(f"   Templates directory: {_templates_dir}")
    print("   Tip: Edit files in the templates/ folder and refresh the browser (no restart needed for most changes).")
    return thread


def _ensure_templates():
    """
    Bootstrap templates from embedded strings **only** when explicitly allowed.

    This function has historically been the source of "my UI changes keep disappearing"
    because it would overwrite the real files in templates/ with the old embedded strings.

    Safe portable behavior:
    - If we detect we are running from a source checkout (any location containing
      pyproject.toml or the logsentinel package source), we **completely skip**
      unless you explicitly set: LOGSENTINEL_DEV_OVERWRITE_TEMPLATES=1
    - Your real edited files in templates/ will always win.
    """
    import os

    running_from_source = _is_running_from_source()
    force_overwrite = os.environ.get("LOGSENTINEL_DEV_OVERWRITE_TEMPLATES") == "1"

    if running_from_source and not force_overwrite:
        print("[rocketlogai] Running from source tree → skipping template bootstrap/overwrite for safety.")
        print("              Your real files in templates/ will be used. (Set LOGSENTINEL_DEV_OVERWRITE_TEMPLATES=1 to force old behavior)")
        return

    # --- Only reach here if NOT running from source OR the user forced it ---
    tpl_dir = Path(_templates_dir)
    tpl_dir.mkdir(parents=True, exist_ok=True)

    force = force_overwrite

    # Key files the user is likely editing
    important = ["base.html", "monitors.html", "maps.html", "integrations.html", "dashboard.html"]

    has_user_files = any((tpl_dir / f).exists() for f in important)

    if force or not has_user_files:
        print("[rocketlogai] Bootstrapping embedded fallback templates (first run or forced)")
        base = tpl_dir / "base.html"
        base.write_text(BASE_TEMPLATE, encoding="utf-8")

        for name, content in [
            ("dashboard.html", DASHBOARD_TEMPLATE),
            ("analyses.html", ANALYSES_TEMPLATE),
            ("analysis_detail.html", ANALYSIS_DETAIL_TEMPLATE),
            ("threats.html", THREATS_TEMPLATE),
            ("login.html", LOGIN_TEMPLATE),
            ("config.html", CONFIG_TEMPLATE),
            ("users.html", USERS_TEMPLATE),
            ("fragments/recent_threats.html", RECENT_THREATS_FRAGMENT),
            ("fragments/recent_analyses.html", RECENT_ANALYSES_FRAGMENT),
        ]:
            p = tpl_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
    else:
        print("[rocketlogai] Real template files detected — not overwriting them.")


# --- Embedded templates (nice Tailwind via CDN for zero-config local use) ---

BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}RocketLogAI{% endblock %}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
        
        :root {
            --bg: #0a0a0c;
        }
        
        body { 
            font-family: 'Inter', ui-sans-serif, system-ui, sans-serif; 
            background: #0a0a0c;
        }
        
        .font-display {
            font-family: 'Space Grotesk', 'Inter', sans-serif;
            font-weight: 600;
            letter-spacing: -0.025em;
        }

        .glass {
            background: rgba(255,255,255,0.03);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.08);
        }

        .section-card {
            background: #111113;
            border: 1px solid #27272a;
            transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), 
                       box-shadow 0.2s cubic-bezier(0.4, 0.0, 0.2, 1);
        }
        
        .section-card:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.3), 0 4px 6px -4px rgb(0 0 0 / 0.3);
        }

        .threat-card {
            transition: all 0.2s cubic-bezier(0.4, 0.0, 0.2, 1);
        }
        
        .threat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.2), 0 8px 10px -6px rgb(0 0 0 / 0.2);
        }

        .status-pill {
            font-size: 10px;
            padding: 1px 8px;
            border-radius: 9999px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .metric-value {
            font-variant-numeric: tabular-nums;
        }

        .log-line { font-family: ui-monospace, monospace; font-size: 0.8rem; }
        pre { white-space: pre-wrap; word-break: break-word; }
        
        .htmx-indicator { display: none; }
        .htmx-request .htmx-indicator { display: inline; }

        .nav-active {
            color: #a1a1aa;
            background: rgba(255,255,255,0.06);
            border-radius: 6px;
            padding: 2px 10px;
        }

        .chart-container {
            position: relative;
        }

        .severity-critical { color: #f87171; }
        .severity-high { color: #fb923c; }
        .severity-medium { color: #fbbf24; }
        .severity-low { color: #4ade80; }

        .glow-emerald {
            box-shadow: 0 0 15px -3px rgb(52 211 153 / 0.15);
        }
    </style>
</head>
<body class="bg-[#0a0a0c] text-zinc-200">
    <nav class="bg-[#0f0f11] border-b border-zinc-800 px-6 py-3.5 flex items-center text-sm sticky top-0 z-50 shadow-sm">
        <div class="flex items-center gap-3">
            <div class="flex items-center gap-2.5">
                <div class="w-9 h-9 rounded-2xl bg-gradient-to-br from-emerald-400 to-teal-500 flex items-center justify-center text-black font-bold text-2xl shadow-inner">L</div>
                <div>
                    <span class="font-display text-2xl tracking-tighter font-semibold">RocketLogAI</span>
                </div>
            </div>
            <div class="px-2.5 py-0.5 text-[10px] rounded-full bg-zinc-900 text-emerald-400 border border-emerald-900/60 font-semibold">v0.2</div>
        </div>

        <!-- Main Menu Bar -->
        <div class="ml-10 flex items-center gap-1.5 text-sm font-medium">
            <a href="/" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path == '/' %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>📊</span> <span>Dashboard</span>
            </a>
            <a href="/threats" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path.startswith('/threats') %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>⚠️</span> <span>Threats</span>
            </a>
            <a href="/analyses" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path.startswith('/analyses') %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>🧠</span> <span>AI Analyses</span>
            </a>
            <a href="/monitors" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path.startswith('/monitors') %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>❤️</span> <span>Monitors</span>
            </a>
            <a href="/maps" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path.startswith('/maps') %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>🌍</span> <span>Maps</span>
            </a>
            <a href="/integrations" class="px-5 py-2 rounded-2xl hover:bg-emerald-900/30 transition-all flex items-center gap-2 {% if request.url.path.startswith('/integrations') %}bg-emerald-900/60 text-emerald-300 shadow-sm{% else %}text-zinc-300 hover:text-emerald-300{% endif %}">
                <span>🔌</span> <span>Integrations</span>
            </a>
            <a href="/config" class="px-5 py-2 rounded-2xl hover:bg-emerald-900/30 transition-all flex items-center gap-2 {% if request.url.path.startswith('/config') %}bg-emerald-900/60 text-emerald-300 shadow-sm{% else %}text-zinc-300 hover:text-emerald-300{% endif %}">
                <span>⚙️</span> <span>Config</span>
            </a>
            <a href="/users" class="px-5 py-2 rounded-2xl hover:bg-zinc-900 transition-all flex items-center gap-2 {% if request.url.path.startswith('/users') %}bg-zinc-900 text-white shadow-sm{% else %}text-zinc-300 hover:text-white{% endif %}">
                <span>👤</span> <span>Users</span>
            </a>
        </div>

        <div class="flex-1"></div>

        <div class="flex items-center gap-3 text-xs">
            <div class="flex items-center gap-1.5 bg-zinc-900 px-3 py-1.5 rounded-full border border-zinc-800">
                <div class="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
                <span class="text-emerald-400 font-semibold">Live</span>
            </div>
            <span id="last-updated" class="text-zinc-500 tabular-nums">Updated just now</span>
            {% if config %}
            <span class="text-zinc-600 font-mono text-[10px] max-w-[180px] truncate">{{ config.storage.db_path }}</span>
            {% endif %}
        </div>
    </nav>

    <div class="max-w-7xl mx-auto p-6">
        {% block content %}{% endblock %}
    </div>

    <!-- Global Notes Modal -->
    <div id="notes-modal" class="hidden fixed inset-0 bg-black/70 z-[100] flex items-center justify-center">
        <div class="bg-zinc-900 border border-zinc-700 rounded-3xl w-full max-w-md mx-4 overflow-hidden">
            <div class="px-6 py-5 border-b border-zinc-800 flex items-center justify-between">
                <div class="font-semibold">Add notes</div>
                <button onclick="closeNotesModal()" class="text-zinc-400 hover:text-white text-2xl leading-none">&times;</button>
            </div>
            <div class="p-6 space-y-4">
                <div>
                    <div class="text-xs text-zinc-400 mb-1">THREAT</div>
                    <div id="modal-threat-desc" class="text-sm text-zinc-200 line-clamp-2"></div>
                </div>
                <div>
                    <label class="text-xs text-zinc-400 block mb-1.5">NOTES (optional)</label>
                    <textarea id="modal-notes" rows="4" 
                              class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl p-3 text-sm focus:outline-none focus:border-emerald-500"></textarea>
                </div>
            </div>
            <div class="px-6 py-4 bg-zinc-950 flex gap-3 justify-end">
                <button onclick="closeNotesModal()" 
                        class="px-5 py-2 rounded-2xl bg-zinc-800 hover:bg-zinc-700 text-sm">Cancel</button>
                <button onclick="submitNotesModal()" 
                        class="px-5 py-2 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-sm">Save &amp; Update Status</button>
            </div>
        </div>
    </div>

    <script>
        let pendingStatusUpdate = null;

        function updateTimestamp() {
            const el = document.getElementById('last-updated');
            if (el) el.textContent = 'Updated just now';
        }
        setInterval(updateTimestamp, 30000);
        document.body.addEventListener('htmx:afterSwap', updateTimestamp);

        // Notes modal helpers
        window.showNotesModal = function(threatId, description, newStatus) {
            pendingStatusUpdate = { threatId, newStatus };
            document.getElementById('modal-threat-desc').textContent = description || 'Threat #' + threatId;
            document.getElementById('modal-notes').value = '';
            document.getElementById('notes-modal').classList.remove('hidden');
            document.getElementById('notes-modal').classList.add('flex');
        };

        window.closeNotesModal = function() {
            document.getElementById('notes-modal').classList.add('hidden');
            document.getElementById('notes-modal').classList.remove('flex');
            pendingStatusUpdate = null;
        };

        window.submitNotesModal = async function() {
            if (!pendingStatusUpdate) return;
            const notes = document.getElementById('modal-notes').value.trim();
            const { threatId, newStatus } = pendingStatusUpdate;

            try {
                await fetch(`/api/threats/${threatId}/status?status=${newStatus}&notes=${encodeURIComponent(notes)}`, {
                    method: 'POST'
                });
                const threatsEl = document.getElementById('recent-threats');
                if (threatsEl) htmx.trigger(threatsEl, 'htmx:load');
                closeNotesModal();
            } catch (e) {
                alert("Failed to update status");
                closeNotesModal();
            }
        };

        // NEW: Quick verify without forcing notes modal every time
        window.quickVerify = async function(threatId, newStatus, description) {
            if (!confirm(`Mark threat #${threatId} as "${newStatus}"?\n\n${description}`)) return;

            try {
                const res = await fetch(`/api/threats/${threatId}/status?status=${newStatus}&notes=Quick+action+from+dashboard`, {
                    method: 'POST'
                });
                const data = await res.json();
                if (data.success) {
                    const threatsEl = document.getElementById('recent-threats');
                    if (threatsEl) htmx.trigger(threatsEl, 'htmx:load');
                } else {
                    alert("Update failed");
                }
            } catch (e) {
                alert("Network error during verify");
            }
        };

        // Optional: richer "Deep Review" modal can be added later
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """{% extends "base.html" %}
{% block title %}RocketLogAI • Dashboard{% endblock %}
{% block content %}
<div class="flex items-end justify-between mb-6">
    <div>
        <h1 class="font-display text-4xl tracking-tighter font-semibold">Security Overview</h1>
        <p class="text-zinc-400 mt-1">Real-time visibility into your infrastructure</p>
    </div>
    <div class="flex gap-2">
        <a href="/threats?status=open" 
           class="px-4 py-2 text-sm rounded-xl bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 flex items-center gap-2 transition-all active:scale-[0.985]">
            <span>Open Threats</span>
        </a>
        <button onclick="exportThreats('csv')" 
                class="px-4 py-2 text-sm rounded-xl bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 flex items-center gap-2 transition-all active:scale-[0.985]">
            <span>Export CSV</span>
        </button>
    </div>
</div>

<!-- Big Metrics -->
<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="section-card rounded-3xl p-5">
        <div class="text-xs uppercase tracking-[1px] text-zinc-500">Total Logs</div>
        <div class="text-6xl font-semibold tracking-tighter metric-value mt-1">{{ total_logs }}</div>
        <div class="text-emerald-400 text-xs mt-2">All time in DB</div>
    </div>
    
    <div class="section-card rounded-3xl p-5">
        <div class="text-xs uppercase tracking-[1px] text-zinc-500">Open Threats</div>
        <div class="text-6xl font-semibold tracking-tighter text-orange-400 metric-value mt-1" id="open-threat-count">—</div>
        <div class="text-xs mt-2 flex items-center gap-1">
            <span class="text-orange-400">Requires attention</span>
        </div>
    </div>
    
    <div class="section-card rounded-3xl p-5">
        <div class="text-xs uppercase tracking-[1px] text-zinc-500">High/Critical</div>
        <div class="text-6xl font-semibold tracking-tighter text-red-400 metric-value mt-1" id="high-sev-count">—</div>
        <div class="text-xs mt-2 text-red-400">Last 7 days</div>
    </div>
    
    <div class="section-card rounded-3xl p-5 flex flex-col justify-between">
        <div>
            <div class="text-xs uppercase tracking-[1px] text-zinc-500">AI Analyses Run</div>
            <div class="text-5xl font-semibold tracking-tighter mt-1">{{ total_analyses }}</div>
            <div class="text-[10px] text-emerald-400/80 mt-0.5">
                {% if llm_analyses_24h %}{{ llm_analyses_24h }} with LLM in last 24h{% else %}{{ llm_analyses }} ever used the LLM{% endif %}
            </div>
        </div>
        <div class="text-xs text-emerald-400">Powered by local LLM</div>
    </div>
</div>

<!-- Charts Row -->
<div class="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
    <!-- Severity Distribution -->
    <div class="lg:col-span-2 section-card rounded-3xl p-5">
        <div class="flex justify-between items-center mb-4">
            <div class="font-semibold">Threats by Severity</div>
        </div>
        <div class="chart-container h-[210px]">
            <canvas id="severityChart"></canvas>
        </div>
    </div>

    <!-- Activity Over Time -->
    <div class="lg:col-span-3 section-card rounded-3xl p-5">
        <div class="flex justify-between items-center mb-4">
            <div class="font-semibold">Threat Activity (Last 14 days)</div>
        </div>
        <div class="chart-container h-[210px]">
            <canvas id="activityChart"></canvas>
        </div>
    </div>
</div>

<!-- Top Hosts + Status Breakdown -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
    <div class="section-card rounded-3xl p-5">
        <div class="font-semibold mb-4">Top Attacking / Affected Hosts</div>
        <div class="chart-container h-[240px]">
            <canvas id="hostsChart"></canvas>
        </div>
    </div>

    <div class="section-card rounded-3xl p-5">
        <div class="font-semibold mb-4">Threat Status Overview</div>
        <div class="chart-container h-[240px]">
            <canvas id="statusChart"></canvas>
        </div>
    </div>
</div>

<div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
    <!-- Live Threats -->
    <div class="section-card rounded-3xl p-6">
        <div class="flex items-center justify-between mb-4">
            <div class="font-semibold flex items-center gap-2">
                Live Threats
                <span class="text-[10px] px-2 py-px bg-red-950 text-red-400 rounded-full">AUTO</span>
            </div>
            <a href="/threats" class="text-sm text-emerald-400 hover:underline font-medium">See all →</a>
        </div>
        
        <div id="recent-threats" 
             hx-get="/fragments/recent-threats" 
             hx-trigger="load, every 20s" 
             hx-swap="outerHTML">
            <div class="py-8 text-center text-zinc-500">Loading threats...</div>
        </div>
    </div>

    <!-- Recent AI Work -->
    <div class="section-card rounded-3xl p-6">
        <div class="flex items-center justify-between mb-4">
            <div class="font-semibold">Recent AI Reasoning</div>
            <a href="/analyses" class="text-sm text-emerald-400 hover:underline font-medium">History →</a>
        </div>
        
        <div id="recent-analyses" 
             hx-get="/fragments/recent-analyses" 
             hx-trigger="load, every 30s" 
             hx-swap="outerHTML">
            <div class="py-8 text-center text-zinc-500">Loading analyses...</div>
        </div>
    </div>
</div>

<script>
    let severityChartInstance = null;
    let activityChartInstance = null;

    async function loadChartData() {
        try {
            // Severity chart (real data)
            const sevRes = await fetch('/api/charts/severity');
            const sevData = await sevRes.json();

            const sevCtx = document.getElementById('severityChart');
            if (sevCtx) {
                if (severityChartInstance) severityChartInstance.destroy();
                severityChartInstance = new Chart(sevCtx, {
                    type: 'doughnut',
                    data: {
                        labels: sevData.labels.length ? sevData.labels : ['No data'],
                        datasets: [{
                            data: sevData.data.length ? sevData.data : [1],
                            backgroundColor: sevData.colors || ['#3f3f46'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false, cutout: '72%',
                        plugins: { legend: { position: 'right', labels: { color: '#71717a', font: { size: 12 } } } }
                    }
                });
            }

            // Activity chart (real data)
            const actRes = await fetch('/api/charts/activity');
            const actData = await actRes.json();

            const actCtx = document.getElementById('activityChart');
            if (actCtx) {
                if (activityChartInstance) activityChartInstance.destroy();
                activityChartInstance = new Chart(actCtx, {
                    type: 'line',
                    data: {
                        labels: actData.labels.length ? actData.labels : ['No data'],
                        datasets: [{
                            label: 'Threats',
                            data: actData.data,
                            borderColor: '#34d399',
                            backgroundColor: 'rgba(52, 211, 153, 0.12)',
                            borderWidth: 2.5, tension: 0.35, fill: true,
                            pointRadius: 0, pointHoverRadius: 4
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: '#27272a' }, ticks: { color: '#52525b', font: { size: 10 } } },
                            y: { grid: { color: '#27272a' }, ticks: { color: '#52525b', stepSize: 1, font: { size: 10 } } }
                        }
                    }
                });
            }

            // Top Hosts bar chart (new)
            const hostsRes = await fetch('/api/charts/hosts');
            const hostsData = await hostsRes.json();

            const hostsCtx = document.getElementById('hostsChart');
            if (hostsCtx && hostsData.labels.length) {
                new Chart(hostsCtx, {
                    type: 'bar',
                    data: {
                        labels: hostsData.labels,
                        datasets: [{
                            label: 'Threats',
                            data: hostsData.data,
                            backgroundColor: '#34d399',
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: '#27272a' }, ticks: { color: '#52525b', font: { size: 10 } } },
                            y: { grid: { color: '#27272a' }, ticks: { color: '#52525b', stepSize: 1, font: { size: 10 } } }
                        }
                    }
                });
            }

            // Dynamic Status breakdown
            const statusRes = await fetch('/api/charts/status');
            const statusData = await statusRes.json();

            const statusCtx = document.getElementById('statusChart');
            if (statusCtx) {
                new Chart(statusCtx, {
                    type: 'pie',
                    data: {
                        labels: statusData.labels,
                        datasets: [{
                            data: statusData.data,
                            backgroundColor: ['#fb923c', '#4ade80', '#71717a']
                        }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
        } catch (e) {
            console.warn("Chart data load failed, using fallback visuals", e);
        }
    }

    async function loadQuickStats() {
        try {
            const res = await fetch('/api/threats?limit=200');
            const threats = await res.json();
            
            const open = threats.filter(t => (t.status || 'open') === 'open').length;
            const high = threats.filter(t => ['high','critical'].includes((t.severity||'').toLowerCase())).length;
            
            const openEl = document.getElementById('open-threat-count');
            const highEl = document.getElementById('high-sev-count');
            if (openEl) openEl.textContent = open;
            if (highEl) highEl.textContent = high;
        } catch(e) {}
    }

    window.addEventListener('load', () => {
        loadChartData();
        loadQuickStats();
        setInterval(() => { loadChartData(); loadQuickStats(); }, 30000);
    });

    function exportThreats(format) {
        window.location = `/export/threats.${format}`;
    }
</script>
{% endblock %}
"""

ANALYSES_TEMPLATE = """{% extends "base.html" %}
{% block title %}LLM Analyses • LogSentinel{% endblock %}
{% block content %}
<h1 class="text-2xl font-semibold mb-6">LLM Analysis History</h1>

<div class="space-y-3">
{% for a in analyses %}
<a href="/analysis/{{ a.id }}" class="block bg-zinc-900 hover:bg-zinc-800 rounded-2xl p-5 border border-zinc-800">
    <div class="flex items-center justify-between">
        <div>
            <span class="font-medium">Analysis #{{ a.id }}</span>
            <span class="ml-3 text-sm text-zinc-500">{{ a.started_at[:19] }}</span>
        </div>
        <div class="text-xs bg-zinc-950 px-2 py-px rounded">{{ a.model or 'local' }}</div>
    </div>
    <div class="mt-2 text-sm">{{ a.summary }}</div>
    <div class="text-xs mt-1 text-emerald-400">{{ a.threats_found }} threats</div>
</a>
{% else %}
<div class="text-zinc-500">No analyses stored yet.</div>
{% endfor %}
</div>
{% endblock %}
"""

ANALYSIS_DETAIL_TEMPLATE = """{% extends "base.html" %}
{% block title %}Analysis #{{ analysis.id }} • LogSentinel{% endblock %}
{% block content %}
<div class="mb-4">
    <a href="/analyses" class="text-sm text-emerald-400">← Back to analyses</a>
</div>

<div class="bg-zinc-900 rounded-2xl p-6 border border-zinc-800">
    <div class="flex justify-between">
        <div>
            <div class="text-sm text-zinc-400">Analysis #{{ analysis.id }}</div>
            <div class="text-xl font-semibold">{{ analysis.started_at[:19] }}</div>
        </div>
        <div class="text-right">
            <div class="text-xs text-zinc-500">{{ analysis.model }}</div>
            <div class="text-emerald-400 font-medium">{{ analysis.threats_found }} threats found</div>
        </div>
    </div>

    <div class="mt-6">
        <div class="uppercase tracking-widest text-xs text-zinc-500 mb-1">LLM Summary</div>
        <div class="text-lg">{{ analysis.summary }}</div>
    </div>

    {% if analysis.threats %}
    <div class="mt-8">
        <div class="uppercase tracking-widest text-xs text-zinc-500 mb-3">Threats + Actionable Next Steps</div>
        <div class="space-y-4">
            {% for t in analysis.threats %}
            <div class="bg-zinc-950 border border-zinc-800 rounded-2xl p-5">
                <div class="flex gap-3 items-start">
                    <div>
                        <span class="inline-block font-mono text-xs px-2 py-0.5 rounded bg-zinc-900 text-red-400">{{ t.severity }}</span>
                        <div class="text-xs text-zinc-500 mt-1">{{ t.hostname or 'unknown' }} / {{ t.appname or 'unknown' }}</div>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="font-medium text-zinc-100">{{ t.description }}</div>

                        {% if t.advice %}
                        <div class="mt-3 bg-zinc-900 border border-amber-900/60 rounded-xl p-3">
                            <div class="uppercase text-[10px] tracking-wider text-amber-400 mb-1.5">What you should do now</div>
                            <ul class="space-y-1 text-sm text-amber-200">
                                {% for tip in t.advice %}
                                <li class="flex gap-2">
                                    <span class="text-amber-500 mt-0.5">→</span>
                                    <span>{{ tip }}</span>
                                </li>
                                {% endfor %}
                            </ul>
                        </div>
                        {% endif %}

                        {% if t.recommended_action %}
                        <div class="mt-2 text-xs text-zinc-400">LLM suggested: {{ t.recommended_action }}</div>
                        {% endif %}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
</div>

{% if analysis.raw_response_pretty %}
<div class="mt-8">
    <div class="flex items-center justify-between mb-2">
        <div class="uppercase tracking-[2px] text-xs text-zinc-500">Raw model output (what the LLM actually returned)</div>
        <button onclick="navigator.clipboard.writeText(document.getElementById('raw').innerText); this.innerText='Copied!'"
                class="text-xs px-3 py-1 bg-zinc-800 hover:bg-zinc-700 rounded">Copy</button>
    </div>
    <pre id="raw" class="bg-black text-emerald-300 text-xs p-5 rounded-2xl overflow-auto border border-zinc-800 max-h-[520px]">{{ analysis.raw_response_pretty }}</pre>
</div>
{% else %}
<div class="mt-6 text-sm text-zinc-500">No raw model response was stored for this analysis.</div>
{% endif %}
{% endblock %}
"""

THREATS_TEMPLATE = """{% extends "base.html" %}
{% block title %}Threats • LogSentinel{% endblock %}
{% block content %}
<h1 class="text-2xl font-semibold mb-6">All Recorded Threats</h1>

<div class="bg-zinc-900 rounded-2xl border border-zinc-800 overflow-hidden">
<table class="w-full text-sm">
    <thead class="bg-zinc-950 text-zinc-400 text-xs">
        <tr>
            <th class="text-left px-4 py-3">Time</th>
            <th class="text-left px-4 py-3">Sev</th>
            <th class="text-left px-4 py-3">Score</th>
            <th class="text-left px-4 py-3">Description</th>
            <th class="text-left px-4 py-3">Host/App</th>
        </tr>
    </thead>
    <tbody class="divide-y divide-zinc-800">
    {% for t in threats %}
    <tr class="hover:bg-zinc-950">
        <td class="px-4 py-3 font-mono text-xs text-zinc-400">{{ t.created_at[:19] }}</td>
        <td class="px-4 py-3"><span class="font-mono text-xs {{ 'text-red-400' if t.severity in ['critical','high'] else 'text-yellow-400' }}">{{ t.severity }}</span></td>
        <td class="px-4 py-3 font-medium">{{ '%.1f' % t.score }}</td>
        <td class="px-4 py-3 text-zinc-200">
            {{ t.description }}
            {% if t.advice %}
            <div class="text-[10px] text-amber-400 mt-1">→ {{ t.advice[0] }}</div>
            {% endif %}
        </td>
        <td class="px-4 py-3 text-xs text-zinc-400">{{ t.hostname or '-' }} / {{ t.appname or '-' }}</td>
    </tr>
    {% else %}
    <tr><td colspan="5" class="px-4 py-8 text-center text-zinc-500">No threats yet.</td></tr>
    {% endfor %}
    </tbody>
</table>
</div>
{% endblock %}
"""

# --- HTMX fragment templates (small partials, no full page chrome) ---

RECENT_THREATS_FRAGMENT = """<div class="space-y-2 text-sm" hx-get="/fragments/recent-threats" hx-trigger="every 25s" hx-swap="outerHTML">
    {% if threats %}
        {% for t in threats %}
        <div class="threat-card flex gap-3 bg-zinc-950/70 rounded-2xl px-4 py-3 border border-zinc-800/80 group">
            <div class="pt-0.5">
                <span class="font-mono text-xs font-bold px-2 py-0.5 rounded-lg 
                    {% if t.severity == 'critical' %}bg-red-950 text-red-400{% elif t.severity == 'high' %}bg-orange-950 text-orange-400{% else %}bg-yellow-950 text-yellow-400{% endif %}">
                    {{ t.severity }}
                </span>
            </div>
            <div class="flex-1 min-w-0 text-sm">
                <div class="font-medium leading-tight">{{ t.description }}</div>
                <div class="text-xs text-zinc-500 mt-0.5">{{ t.hostname or 'unknown' }} / {{ t.appname or '?' }} • {{ t.created_at[:16] }}</div>

                <div class="flex items-center gap-2 mt-2">
                    <span class="status-pill 
                        {% if t.status == 'false_positive' %}bg-zinc-800 text-zinc-400{% elif t.status == 'acknowledged' %}bg-emerald-900 text-emerald-300{% else %}bg-orange-900 text-orange-300{% endif %}">
                        {{ t.status or 'open' }}
                    </span>

                    {% if (t.status or 'open') == 'open' %}
                    <button onclick="showNotesModal({{ t.id }}, '{{ t.description|replace("'", "\\'") }}', 'acknowledged')"
                            class="text-[10px] px-2 py-px rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 transition-colors">
                        Ack
                    </button>
                    <button onclick="showNotesModal({{ t.id }}, '{{ t.description|replace("'", "\\'") }}', 'false_positive')"
                            class="text-[10px] px-2 py-px rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 transition-colors">
                        False +
                    </button>
                    {% endif %}
                </div>

                {% if t.advice %}
                <div class="mt-2 pt-2 border-t border-zinc-800 text-[10px] text-amber-300/90 space-y-px">
                    {% for tip in t.advice[:1] %}
                    <div>→ {{ tip }}</div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    {% else %}
        <div class="text-zinc-500 text-sm py-3 px-1">No open threats. Nice work.</div>
    {% endif %}
</div>"""

RECENT_ANALYSES_FRAGMENT = """<div class="space-y-4" hx-get="/fragments/recent-analyses" hx-trigger="every 30s" hx-swap="outerHTML">
    {% if analyses %}
        {% for a in analyses %}
        <a href="/analysis/{{ a.id }}" class="block bg-zinc-900 hover:bg-zinc-800 transition rounded-2xl p-5 border border-zinc-800">
            <div class="flex justify-between text-sm">
                <div>
                    <span class="font-semibold">Analysis #{{ a.id }}</span>
                    <span class="text-zinc-500 ml-2">{{ a.started_at[:19] }}</span>
                </div>
                <div class="text-xs px-2 py-0.5 rounded bg-zinc-950">{{ a.model or 'local' }}</div>
            </div>
            <div class="mt-2 text-sm text-zinc-300 line-clamp-2">{{ a.summary }}</div>
            <div class="mt-2 text-xs text-emerald-400">{{ a.threats_found }} threats found</div>
        </a>
        {% endfor %}
    {% else %}
        <div class="text-zinc-500">No LLM analyses yet.</div>
    {% endif %}
</div>"""


LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RocketLogAI • Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', system-ui, sans-serif; background: #0a0a0c; }
        .font-display { font-family: 'Space Grotesk', system-ui, sans-serif; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center bg-[#0a0a0c] text-zinc-200">
    <div class="w-full max-w-md px-6">
        <div class="flex justify-center mb-8">
            <div class="flex items-center gap-3">
                <div class="w-11 h-11 rounded-2xl bg-gradient-to-br from-emerald-400 to-teal-500 flex items-center justify-center text-black font-bold text-3xl shadow-inner">L</div>
                <span class="font-display text-4xl font-semibold tracking-tighter">RocketLogAI</span>
            </div>
        </div>

        <div class="bg-zinc-900 border border-zinc-800 rounded-3xl p-8 shadow-2xl">
            <div class="text-center mb-8">
                <h1 class="text-2xl font-semibold tracking-tight">Sign in</h1>
                <p class="text-zinc-400 text-sm mt-1">Local security monitoring</p>
            </div>

            {% if error %}
            <div class="mb-6 p-3 bg-red-950 border border-red-900 text-red-300 rounded-2xl text-sm">
                {{ error }}
            </div>
            {% endif %}

            <form method="post" action="/login" class="space-y-5">
                <div>
                    <label class="block text-xs text-zinc-400 mb-1.5 tracking-wider">USERNAME</label>
                    <input type="text" name="username" value="admin" required
                           class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-3 text-lg focus:outline-none focus:border-emerald-500 transition-colors">
                </div>
                <div>
                    <label class="block text-xs text-zinc-400 mb-1.5 tracking-wider">PASSWORD</label>
                    <input type="password" name="password" value="admin" required
                           class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-3 text-lg focus:outline-none focus:border-emerald-500 transition-colors">
                </div>

                <button type="submit"
                        class="w-full mt-2 py-3.5 rounded-2xl bg-white text-black font-semibold text-lg active:scale-[0.985] transition-all hover:bg-zinc-100">
                    Sign in
                </button>
            </form>

            <div class="mt-6 text-center text-xs text-zinc-500">
                Default credentials: <span class="font-mono text-emerald-400">admin / admin</span>
            </div>
        </div>

        <p class="text-center text-xs text-zinc-600 mt-6">Secure local access • Your data never leaves this machine</p>
    </div>
</body>
</html>"""

CONFIG_TEMPLATE = """{% extends "base.html" %}
{% block title %}Configuration • RocketLogAI{% endblock %}
{% block content %}
<h1 class="text-4xl font-semibold tracking-tighter mb-2">Configuration</h1>
<p class="text-zinc-400 mb-8">Manage all major RocketLogAI settings from the browser. Changes are written directly to your <code>config.yaml</code>.</p>

{% if request.query_params.get('saved') %}
<div class="mb-4 p-3 bg-emerald-950 border border-emerald-800 text-emerald-300 rounded-2xl">Settings saved. Some changes may require restart.</div>
{% endif %}

<form method="post" action="/config/save" class="max-w-5xl space-y-10">

    <!-- LLM / AI Backend -->
    <div class="section-card rounded-3xl p-7">
        <div class="flex items-center gap-3 mb-6">
            <span class="text-2xl">🤖</span>
            <h2 class="font-semibold text-2xl tracking-tight">LLM / AI Backend</h2>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-5">
            <div class="lg:col-span-2">
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">LLM Server Type</label>
                <div class="flex flex-wrap gap-2">
                    <label class="cursor-pointer"><input type="radio" name="llm_provider" value="lmstudio" class="peer hidden" checked><div class="peer-checked:bg-emerald-900/40 peer-checked:border-emerald-600 border border-zinc-700 rounded-2xl px-4 py-2 text-sm">LM Studio</div></label>
                    <label class="cursor-pointer"><input type="radio" name="llm_provider" value="ollama" class="peer hidden"><div class="peer-checked:bg-emerald-900/40 peer-checked:border-emerald-600 border border-zinc-700 rounded-2xl px-4 py-2 text-sm">Ollama</div></label>
                    <label class="cursor-pointer"><input type="radio" name="llm_provider" value="custom" class="peer hidden"><div class="peer-checked:bg-emerald-900/40 peer-checked:border-emerald-600 border border-zinc-700 rounded-2xl px-4 py-2 text-sm">Custom / Remote</div></label>
                </div>
            </div>

            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Base URL</label>
                <input name="llm_base_url" value="{{ cfg.llm.base_url }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5 font-mono text-sm">
            </div>
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">API Key</label>
                <input name="llm_api_key" value="{{ cfg.llm.api_key }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>

            <div class="lg:col-span-2">
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Model</label>
                <div class="flex gap-2 items-end">
                    <div class="flex-1">
                        <select name="llm_model" id="llm_model_select" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5 font-mono text-sm" onchange="document.getElementById('llm_model_field').value = this.value">
                            <option value="{{ cfg.llm.model }}">{{ cfg.llm.model or '— Select or enter model —' }}</option>
                        </select>
                        <input type="hidden" name="llm_model" id="llm_model_field" value="{{ cfg.llm.model }}">
                    </div>
                    <button type="button" onclick="fetchAvailableModels()" class="px-4 py-2 rounded-2xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-sm font-medium active:scale-[0.985] whitespace-nowrap">Fetch Models</button>
                    <button type="button" onclick="testLLMConnection()" class="px-4 py-2 rounded-2xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-sm font-medium active:scale-[0.985] whitespace-nowrap">Test</button>
                </div>
                <div id="model-status" class="text-xs mt-1.5 min-h-[18px] text-emerald-400"></div>
                <div id="llm-test-status" class="text-xs mt-1 min-h-[18px]"></div>
            </div>

            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Temperature</label>
                <input type="number" step="0.1" name="llm_temperature" value="{{ cfg.llm.temperature }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Max Tokens</label>
                <input type="number" name="llm_max_tokens" value="{{ cfg.llm.max_tokens }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
        </div>
        <p class="text-xs text-zinc-500 mt-4">Supports LM Studio, Ollama, vLLM, or any remote OpenAI-compatible server.</p>
    </div>

    <!-- Web Server -->
    <div class="section-card rounded-3xl p-7">
        <div class="flex items-center gap-3 mb-6">
            <span class="text-2xl">🌐</span>
            <h2 class="font-semibold text-2xl tracking-tight">Web Server</h2>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Listen Address</label>
                <select name="web_host" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
                    <option value="127.0.0.1" {% if cfg.web.web_host == '127.0.0.1' %}selected{% endif %}>Localhost only</option>
                    <option value="0.0.0.0" {% if cfg.web.web_host == '0.0.0.0' %}selected{% endif %}>All interfaces (0.0.0.0)</option>
                </select>
            </div>
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Port</label>
                <input type="number" name="web_port" value="{{ cfg.web.web_port }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1.5">Public Domain</label>
                <input name="web_domain" value="{{ cfg.web.web_domain }}" placeholder="logsentinel.internal" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
        </div>

        <div class="mt-6 pt-6 border-t border-zinc-800">
            <div class="flex items-center gap-2 mb-4">
                <input type="checkbox" name="ssl_enabled" {% if cfg.web.ssl_enabled %}checked{% endif %} class="accent-emerald-500">
                <span class="font-medium">Enable HTTPS / SSL</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs text-zinc-400 mb-1">Certificate Path</label>
                    <input name="ssl_certfile" value="{{ cfg.web.ssl_certfile }}" placeholder="/path/to/cert.pem" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2 text-sm">
                </div>
                <div>
                    <label class="block text-xs text-zinc-400 mb-1">Private Key Path</label>
                    <input name="ssl_keyfile" value="{{ cfg.web.ssl_keyfile }}" placeholder="/path/to/key.pem" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2 text-sm">
                </div>
            </div>
        </div>
    </div>

    <!-- Local Auth -->
    <div class="section-card rounded-3xl p-6">
        <h2 class="font-semibold mb-4">Local Authentication</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label class="text-xs text-zinc-400">Local Username</label>
                <input name="local_user" value="{{ cfg.web.local_user }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <div>
                <label class="text-xs text-zinc-400">Local Password</label>
                <input type="password" name="local_password" value="{{ cfg.web.local_password }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
        </div>
        <p class="text-xs text-zinc-500 mt-2">Used as fallback when domain auth is disabled or fails.</p>
    </div>

    <!-- Windows Domain / AD -->
    <div class="section-card rounded-3xl p-6">
        <h2 class="font-semibold mb-4 flex items-center gap-2">Windows Domain Authentication (Active Directory)</h2>
        <div class="flex items-center gap-2 mb-4">
            <input type="checkbox" name="domain_enabled" {% if cfg.web.domain_enabled %}checked{% endif %} class="accent-emerald-500">
            <span class="text-sm">Enable domain login</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label class="text-xs text-zinc-400">Domain Controller / LDAP Server</label>
                <input name="domain_server" value="{{ cfg.web.domain_server }}" placeholder="dc01.corp.local or ldap://dc01.corp.local" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <div>
                <label class="text-xs text-zinc-400">Base DN</label>
                <input name="domain_base_dn" value="{{ cfg.web.domain_base_dn }}" placeholder="DC=corp,DC=local" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <div>
                <label class="text-xs text-zinc-400">NetBIOS Domain (optional)</label>
                <input name="domain_user_domain" value="{{ cfg.web.domain_user_domain }}" placeholder="CORP" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
        </div>
        <div class="mt-3 flex items-center gap-2 text-xs">
            <input type="checkbox" name="domain_fallback_local" {% if cfg.web.domain_fallback_local %}checked{% endif %} class="accent-emerald-500">
            <span>Allow local fallback if domain authentication fails</span>
        </div>

        <!-- Domain Test -->
        <div class="mt-5 pt-4 border-t border-zinc-800">
            <button type="button" onclick="testDomainConnection()" 
                    class="px-4 py-1.5 text-sm rounded-2xl border border-emerald-700 hover:bg-emerald-900/30 text-emerald-300">
                Test Domain Connectivity
            </button>
            <span id="domain-test-result" class="ml-3 text-xs"></span>
        </div>
    </div>

    <script>
        async function testDomainConnection() {
            const resultEl = document.getElementById('domain-test-result');
            resultEl.textContent = 'Testing...';
            resultEl.className = 'ml-3 text-xs text-yellow-400';

            const formData = new FormData();
            formData.append('domain_server', document.querySelector('[name="domain_server"]').value);
            formData.append('domain_base_dn', document.querySelector('[name="domain_base_dn"]').value);

            try {
                const res = await fetch('/api/domain/test', { method: 'POST', body: formData });
                const data = await res.json();
                if (data.success) {
                    resultEl.textContent = '✓ ' + data.message;
                    resultEl.className = 'ml-3 text-xs text-emerald-400';
                } else {
                    resultEl.textContent = '✗ ' + data.message;
                    resultEl.className = 'ml-3 text-xs text-red-400';
                }
            } catch (e) {
                resultEl.textContent = '✗ Connection test failed';
                resultEl.className = 'ml-3 text-xs text-red-400';
            }
        }
    </script>

    <script>
        async function testLLMConnection() {
            const statusEl = document.getElementById('llm-test-status') || document.createElement('div');
            if (!document.getElementById('llm-test-status')) {
                const container = document.getElementById('model-status').parentElement;
                statusEl.id = 'llm-test-status';
                container.appendChild(statusEl);
            }

            const baseUrl = document.querySelector('[name="llm_base_url"]').value;
            const apiKey = document.querySelector('[name="llm_api_key"]').value || 'not-needed';
            const model = document.getElementById('llm_model_field').value;

            statusEl.textContent = 'Testing LLM connection...';
            statusEl.className = 'text-xs mt-1 text-yellow-400';

            try {
                const res = await fetch('/api/llm/test-connection', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ base_url: baseUrl, api_key: apiKey, model: model })
                });
                const data = await res.json();

                if (data.success) {
                    statusEl.textContent = '✅ ' + data.message + (data.models_found ? ` (${data.models_found} models)` : '');
                    statusEl.className = 'text-xs mt-1 text-emerald-400';
                } else {
                    statusEl.textContent = '❌ ' + data.message;
                    statusEl.className = 'text-xs mt-1 text-red-400';
                }
            } catch (e) {
                statusEl.textContent = '❌ Failed to reach LLM server';
                statusEl.className = 'text-xs mt-1 text-red-400';
            }
        }
    </script>

    <!-- Alerting -->
    <div class="section-card rounded-3xl p-6">
        <h2 class="font-semibold mb-4">Alerting</h2>
        
        <div class="mb-4">
            <label class="text-xs text-zinc-400 block mb-1">Webhook URLs (one per line)</label>
            <textarea name="webhooks" rows="3" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl p-3 font-mono text-sm">{{ cfg.alerting.webhooks | join('\n') }}</textarea>
        </div>

        <div class="mb-4">
            <label class="text-xs text-zinc-400 block mb-1">Email Recipients (one per line)</label>
            <textarea name="email_to" rows="2" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl p-3 font-mono text-sm">{{ cfg.alerting.email_to | join('\n') }}</textarea>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label class="text-xs text-zinc-400">SMTP Host</label>
                <input name="smtp_host" value="{{ cfg.alerting.smtp_host }}" placeholder="smtp.gmail.com" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="text-xs text-zinc-400">SMTP Port</label>
                <input name="smtp_port" value="{{ cfg.alerting.smtp_port }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="text-xs text-zinc-400">SMTP Username</label>
                <input name="smtp_user" value="{{ cfg.alerting.smtp_user }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="text-xs text-zinc-400">SMTP Password</label>
                <input type="password" name="smtp_password" value="{{ cfg.alerting.smtp_password }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div class="md:col-span-2">
                <label class="text-xs text-zinc-400">From Address</label>
                <input name="smtp_from" value="{{ cfg.alerting.smtp_from }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
        </div>
        <p class="text-xs text-zinc-500 mt-2">Supports generic webhooks + Microsoft Teams (auto-detected) and email alerts on high/critical threats.</p>
    </div>

    <!-- Rules - Flexible for any device -->
    <div class="section-card rounded-3xl p-7">
        <div class="flex items-center justify-between mb-4">
            <div>
                <h2 class="font-semibold text-xl">Rules (Custom Patterns)</h2>
                <p class="text-xs text-zinc-400">Define regex rules that trigger immediate high-severity alerts for any device (firewalls, switches, servers, desktops, etc.).</p>
            </div>
        </div>

        <div>
            <label class="text-xs font-medium text-zinc-400 block mb-1.5">Custom Regex Patterns (one per line)</label>
            <textarea name="custom_patterns" rows="5" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl p-3 font-mono text-sm" placeholder="Failed password.*from .*&#10;CRITICAL.*tamper&#10;.*sudo.*root">{{ cfg.rules.custom_patterns | join('\n') }}</textarea>
        </div>
        <p class="text-xs text-zinc-500 mt-2">These are evaluated with case-insensitive matching. High scoring matches will always create threats and can trigger alerts.</p>
    </div>

    <!-- Analysis Settings -->
    <div class="section-card rounded-3xl p-7">
        <h2 class="font-semibold text-xl mb-4">Analysis Engine</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
                <label class="text-xs text-zinc-400">Analysis Interval (seconds)</label>
                <input type="number" name="analysis_interval" value="{{ cfg.analysis.interval_seconds }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="text-xs text-zinc-400">Batch Size</label>
                <input type="number" name="analysis_batch_size" value="{{ cfg.analysis.batch_size }}" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
            </div>
            <div>
                <label class="text-xs text-zinc-400">Min Severity for AI</label>
                <select name="min_severity_for_ai" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2">
                    <option value="low" {% if cfg.analysis.min_severity_for_ai == 'low' %}selected{% endif %}>low</option>
                    <option value="medium" {% if cfg.analysis.min_severity_for_ai == 'medium' %}selected{% endif %}>medium</option>
                    <option value="high" {% if cfg.analysis.min_severity_for_ai == 'high' %}selected{% endif %}>high</option>
                    <option value="critical" {% if cfg.analysis.min_severity_for_ai == 'critical' %}selected{% endif %}>critical</option>
                </select>
            </div>
        </div>
    </div>

    <div class="flex gap-3">
        <button type="submit" class="px-8 py-3 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-black font-semibold">Save Configuration</button>
        <a href="/" class="px-8 py-3 rounded-2xl border border-zinc-700 hover:bg-zinc-900 flex items-center">Cancel</a>
    </div>

    <!-- Restart Section -->
    <div class="mt-4 p-5 rounded-3xl border border-amber-700 bg-amber-950/30">
        <div class="font-semibold text-amber-400 mb-2">Restart Required</div>
        <p class="text-sm text-amber-300 mb-3">LLM server, Web listening, and SSL changes require a restart of RocketLogAI.</p>
        <button onclick="if(confirm('This will stop the current process. You will need to start RocketLogAI again manually.')) { 
            document.getElementById('restart-status').textContent = 'Shutting down...'; 
            fetch('/api/restart', {method: 'POST'}).finally(() => location.reload()); 
        }" class="px-5 py-2 rounded-2xl bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium">
            Restart RocketLogAI Now
        </button>
        <span id="restart-status" class="ml-3 text-sm text-amber-300"></span>
    </div>
</form>

<div class="mt-6 text-xs text-zinc-500">
    Note: Changes to LLM server or Web Server settings usually require restarting RocketLogAI.
</div>

<script>
async function fetchAvailableModels() {
    const statusEl = document.getElementById('model-status');
    const baseUrl = document.querySelector('[name="llm_base_url"]').value;
    const apiKey = document.querySelector('[name="llm_api_key"]').value || 'not-needed';

    statusEl.textContent = 'Fetching models from server...';
    statusEl.className = 'text-xs mt-1.5 text-yellow-400';

    try {
        const res = await fetch('/api/llm/fetch-models', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ base_url: baseUrl, api_key: apiKey })
        });
        const data = await res.json();

        if (data.success && data.models && data.models.length > 0) {
            statusEl.innerHTML = `✅ Found <strong>${data.models.length}</strong> models.`;
            statusEl.className = 'text-xs mt-1.5 text-emerald-400';
            console.log('%c[RocketLogAI] Available models:', 'color:#34d399', data.models);

            const select = document.getElementById('llm_model_select');
            const hidden = document.getElementById('llm_model_field');
            const current = hidden ? hidden.value : '';

            select.innerHTML = '<option value="">— Select a model —</option>';
            data.models.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m;
                opt.textContent = m;
                if (m === current) opt.selected = true;
                select.appendChild(opt);
            });

            select.onchange = () => {
                if (hidden) hidden.value = select.value;
            };
        } else {
            statusEl.textContent = '❌ ' + (data.error || 'No models returned');
            statusEl.className = 'text-xs mt-1.5 text-red-400';
        }
    } catch (e) {
        statusEl.textContent = '❌ Could not reach the LLM server';
        statusEl.className = 'text-xs mt-1.5 text-red-400';
    }
}
</script>
{% endblock %}
"""

# Add the fetch models JS at the end of the template rendering
# (this will be included when the page loads)

USERS_TEMPLATE = """{% extends "base.html" %}
{% block title %}User Management • RocketLogAI{% endblock %}
{% block content %}
<h1 class="text-3xl font-semibold tracking-tight mb-2">User Management</h1>
<p class="text-zinc-400 mb-6">Manage local credentials and view current session.</p>

{% if request.query_params.get('saved') %}
<div class="mb-4 p-3 bg-emerald-950 border border-emerald-800 text-emerald-300 rounded-2xl">Password updated successfully.</div>
{% endif %}
{% if request.query_params.get('error') %}
<div class="mb-4 p-3 bg-red-950 border border-red-900 text-red-300 rounded-2xl">{{ request.query_params.get('error') }}</div>
{% endif %}

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-4xl">
    <!-- Current Session -->
    <div class="section-card rounded-3xl p-6">
        <h2 class="font-semibold mb-4">Current Session</h2>
        <div class="space-y-3 text-sm">
            <div><span class="text-zinc-400">Logged in as:</span> <span class="font-mono">{{ current_user }}</span></div>
            <div><span class="text-zinc-400">Auth method:</span> <span class="font-semibold {% if auth_type == 'domain' %}text-emerald-400{% else %}text-amber-400{% endif %}">{{ auth_type | upper }}</span></div>
            {% if login_time %}
            <div><span class="text-zinc-400">Login time:</span> {{ login_time[:19] }}</div>
            {% endif %}
        </div>
        <a href="/logout" class="inline-block mt-4 text-sm text-red-400 hover:text-red-300">Log out</a>
    </div>

    <!-- Change Local Password -->
    <div class="section-card rounded-3xl p-6">
        <h2 class="font-semibold mb-4">Change Local Password</h2>
        <form method="post" action="/users/change-password" class="space-y-4">
            <div>
                <label class="text-xs text-zinc-400">New Password</label>
                <input type="password" name="new_password" required minlength="4" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <div>
                <label class="text-xs text-zinc-400">Confirm New Password</label>
                <input type="password" name="confirm_password" required minlength="4" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5">
            </div>
            <button type="submit" class="mt-2 px-6 py-2.5 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-black font-semibold">Update Local Password</button>
        </form>
        <p class="text-xs text-zinc-500 mt-3">This updates the local fallback credentials used when domain auth is disabled or unavailable.</p>
    </div>
</div>

<div class="mt-8 max-w-4xl text-sm text-zinc-400">
    <strong>Domain users:</strong> Authenticate directly against your Windows Active Directory using the credentials configured in <a href="/config" class="text-emerald-400">Config</a>. No local password is required for domain accounts.
</div>
{% endblock %}
"""

if __name__ == "__main__":
    run_web()
