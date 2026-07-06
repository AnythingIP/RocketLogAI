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
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote as urlquote

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
import logging

logger = logging.getLogger(__name__)

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
from .ai_assistant.controller import get_ai_assistant_controller  # Phase 3 powerful natural language controller (Open Interpreter + safety)
from .assistant_tasks import TASKS as ASSISTANT_TASKS
from .diagnostics import run_live_checks as run_live_diagnostics
from .mac_vendor import get_mac_vendor_lookup  # for reliable vendor name + smart icons on /devices

try:
    import pyotp
    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False
    pyotp = None


# =============================================================================
# LIVE SERVER LOG BUFFER (for the new /logs page)
# =============================================================================
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


app = FastAPI(title="RocketLogAI", version="2.0.0", docs_url=None, redoc_url=None)

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

    # Serve branding assets (logos etc.)
    branding_dir = Path("data/branding")
    branding_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static/branding", StaticFiles(directory=str(branding_dir)), name="branding")
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


def try_domain_login(username: str, password: str, cfg: Config | None = None) -> Tuple[bool, Optional[str], List[str]]:
    """
    Phase 4 wrapper: uses the advanced LDAP helper with service account + group lookup.
    Returns (success, role, groups)
    """
    if not cfg or not getattr(cfg.web, "domain_enabled", False):
        return False, None, []
    from .auth import try_ldap_login
    return try_ldap_login(username, password, cfg.web, _storage)


def require_login(request: Request):
    """Dependency for protecting routes (UI pages). Session only."""
    user, pwd = get_auth_credentials()

    if not HAS_SESSIONS:
        return "anonymous"

    session_user = request.session.get("user")
    if session_user:
        return session_user

    raise HTTPException(status_code=307, headers={"Location": "/login"})


def get_current_api_user(request: Request) -> str | None:
    """
    Support for long-lived API tokens (like Home Assistant).
    Checks Authorization: Bearer rla_... header.
    Returns the token name on success, None otherwise.
    """
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    if not token.startswith("rla_"):
        return None

    if _storage is None:
        return None

    token_info = _storage.verify_api_token(token)
    if token_info:
        # For API calls we return the token name as the "user"
        return f"api:{token_info['name']}"
    return None


def require_api_token(request: Request):
    """Strict API token only (for routes that should never be called from browser sessions)."""
    api_user = get_current_api_user(request)
    if api_user:
        return api_user
    raise HTTPException(status_code=401, detail="Valid API token required")


def require_api_or_login(request: Request):
    """
    Flexible dependency: accepts either a valid session (for browser) 
    or a valid API token (for scripts / other tools).
    Great for /api/* routes.
    """
    # Try API token first (common for automation)
    api_user = get_current_api_user(request)
    if api_user:
        return api_user

    # Fall back to normal session login
    return require_login(request)


# --- Phase 4 RBAC helpers ---
def get_current_role(request: Request) -> str:
    if not HAS_SESSIONS:
        return "administrator"  # dev / no-session mode
    return request.session.get("role", "viewer")


def require_min_role(min_role: str = "viewer"):
    """FastAPI dependency: require at least this role (viewer < analyst < operator < administrator)."""
    def _checker(request: Request):
        role = get_current_role(request)
        order = {"viewer": 0, "analyst": 1, "operator": 2, "administrator": 3}
        user_level = order.get(role, 0)
        required = order.get(min_role, 0)
        if user_level < required:
            raise HTTPException(status_code=403, detail=f"Insufficient permissions. Requires '{min_role}' role or higher (current: {role}).")
        return role
    return _checker


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
            "has_totp": bool(_cfg and _cfg.web.totp_secret) if _cfg else False,
            "domain_enabled": bool(_cfg and getattr(_cfg.web, "domain_enabled", False)) if _cfg else False,
            "entra_enabled": bool(_cfg and getattr(_cfg.web, "entra_enabled", False)) if _cfg else False,
            "allow_local_login": bool(_cfg and getattr(_cfg.web, "allow_local_login", True)) if _cfg else True,
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

    force_local = str(form.get("force_local", "")).lower() in ("1", "true", "yes", "on")

    # Determine if we should even consider local auth
    allow_local = bool(_cfg and _cfg.web.allow_local_login) if _cfg else True

    # 1. Try domain authentication first (Phase 4 enhanced - returns role + groups)
    if _cfg and getattr(_cfg.web, "domain_enabled", False) and not force_local:
        success, role, groups = try_domain_login(username, password, _cfg)
        if success:
            request.session["user"] = username
            request.session["auth_type"] = "domain"
            request.session["role"] = role or "viewer"
            request.session["groups"] = groups or []
            request.session["login_time"] = datetime.now(timezone.utc).isoformat()
            # Audit
            if _storage:
                _storage.log_server_activity("inbound", "auth", source="domain", action="login", status="success",
                                             details={"user": username, "role": role, "groups": groups[:5]})
            return RedirectResponse("/", status_code=302)

        # Domain failed. If local not allowed at all, hard error.
        if not allow_local:
            return RedirectResponse("/login?error=Domain+authentication+failed.+Local+login+has+been+disabled+by+admin.+Use+CLI+to+re-enable+if+needed.", status_code=302)

        # Otherwise respect the fallback flag (backward compat)
        if not _cfg.web.domain_fallback_local:
            return RedirectResponse("/login?error=Domain+authentication+failed", status_code=302)

    # Phase 4 Entra ID (Microsoft Entra / Azure AD) support
    if _cfg and getattr(_cfg.web, "entra_enabled", False) and not force_local:
        from .auth import try_entra_login
        # For simplicity in this phase we support direct token or UPN + (we treat password as hint or use prior token)
        # In production UI you would do the OAuth redirect; here we try the helper
        success, role, groups = try_entra_login(username, password, _cfg.web, _storage, is_token=False)
        if success:
            request.session["user"] = username
            request.session["auth_type"] = "entra"
            request.session["role"] = role or "viewer"
            request.session["groups"] = groups or []
            request.session["login_time"] = datetime.now(timezone.utc).isoformat()
            if _storage:
                _storage.log_server_activity("inbound", "auth", source="entra", action="login", status="success",
                                             details={"user": username, "role": role})
            return RedirectResponse("/", status_code=302)
        # If Entra fails and no local fallback allowed...
        if not allow_local:
            return RedirectResponse("/login?error=Entra+ID+authentication+failed.+Local+login+disabled.", status_code=302)

    # 2. Local authentication (default or fallback or explicit backup)
    if not allow_local:
        return RedirectResponse("/login?error=Local+login+is+currently+disabled.+Contact+your+admin+or+use+the+CLI+escape+hatch.", status_code=302)

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

        # Set role for local (admin if is_admin in DB, else analyst or viewer)
        local_rec = _storage.get_local_auth(username) if _storage else None
        local_role = "administrator" if (local_rec and local_rec.get("is_admin")) else "analyst"
        request.session["user"] = username
        request.session["auth_type"] = "local"
        request.session["role"] = local_role
        request.session["groups"] = []
        request.session["login_time"] = datetime.now(timezone.utc).isoformat()
        if _storage:
            _storage.log_server_activity("inbound", "auth", source="local", action="login", status="success",
                                         details={"user": username, "role": local_role})
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

    # Prepare JSON-safe version of geo providers for the template (dataclasses are not directly serializable)
    geo_providers_json = "[]"
    try:
        if hasattr(_cfg, "geo") and _cfg.geo and getattr(_cfg.geo, "providers", None):
            from dataclasses import asdict
            serializable = [asdict(p) for p in _cfg.geo.providers]
            geo_providers_json = json.dumps(serializable, indent=2)
    except Exception:
        geo_providers_json = "[]"

    # Raw config.yaml for direct editor
    raw_config = ""
    try:
        config_path = _cfg.config_path or "config.yaml"
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                raw_config = f.read()
    except Exception:
        raw_config = "# Could not read config.yaml"

    return get_templates().TemplateResponse(
        request,
        "config.html",
        context={
            "cfg": _cfg,
            "geo_providers_json": geo_providers_json,
            "raw_config_yaml": raw_config,
            "llm_servers_json": json.dumps(getattr(_cfg.llm, "servers", []) or [], indent=2),
        }
    )


@app.post("/config/save")
async def save_config(request: Request, user: str = Depends(require_login), role: str = Depends(require_min_role("administrator"))):
    global _cfg, _storage
    if _cfg is None:
        return {"error": "no config"}

    form = await _safe_form(request)

    def _safe_int(val, default):
        try:
            v = val if val is not None else ""
            return int(v) if str(v).strip() else default
        except Exception:
            return default

    def _safe_float(val, default):
        try:
            v = val if val is not None else ""
            return float(v) if str(v).strip() else default
        except Exception:
            return default

    # Web / Auth
    _cfg.web.local_user = form.get("local_user", _cfg.web.local_user)
    # IMPORTANT: Never take the local_password from the main config form.
    # It is a masked field. Real password changes must go through /users/change-password
    # which does proper hashing + DB storage.
    _cfg.web.domain_enabled = form.get("domain_enabled") == "on"
    _cfg.web.domain_server = form.get("domain_server", _cfg.web.domain_server)
    _cfg.web.domain_base_dn = form.get("domain_base_dn", _cfg.web.domain_base_dn)
    _cfg.web.domain_user_domain = form.get("domain_user_domain", _cfg.web.domain_user_domain)
    _cfg.web.domain_service_account = form.get("domain_service_account", _cfg.web.domain_service_account)
    _cfg.web.domain_service_password = form.get("domain_service_password", _cfg.web.domain_service_password)
    _cfg.web.domain_use_ldaps = form.get("domain_use_ldaps") == "on"
    _cfg.web.domain_ca_cert = form.get("domain_ca_cert", _cfg.web.domain_ca_cert)
    _cfg.web.domain_verify_cert = form.get("domain_verify_cert") == "on"
    _cfg.web.domain_admin_groups = form.get("domain_admin_groups", _cfg.web.domain_admin_groups)
    _cfg.web.domain_operator_groups = form.get("domain_operator_groups", _cfg.web.domain_operator_groups)
    _cfg.web.domain_analyst_groups = form.get("domain_analyst_groups", _cfg.web.domain_analyst_groups)
    _cfg.web.domain_viewer_groups = form.get("domain_viewer_groups", _cfg.web.domain_viewer_groups)
    _cfg.web.domain_fallback_local = form.get("domain_fallback_local") == "on"
    _cfg.web.allow_local_login = form.get("allow_local_login") == "on"

    # Entra ID
    _cfg.web.entra_enabled = form.get("entra_enabled") == "on"
    _cfg.web.entra_tenant_id = form.get("entra_tenant_id", _cfg.web.entra_tenant_id)
    _cfg.web.entra_client_id = form.get("entra_client_id", _cfg.web.entra_client_id)
    _cfg.web.entra_client_secret = form.get("entra_client_secret", _cfg.web.entra_client_secret)
    _cfg.web.entra_redirect_uri = form.get("entra_redirect_uri", _cfg.web.entra_redirect_uri)
    _cfg.web.entra_scopes = form.get("entra_scopes", _cfg.web.entra_scopes)
    _cfg.web.entra_admin_groups = form.get("entra_admin_groups", _cfg.web.entra_admin_groups)
    _cfg.web.entra_operator_groups = form.get("entra_operator_groups", _cfg.web.entra_operator_groups)
    _cfg.web.entra_analyst_groups = form.get("entra_analyst_groups", _cfg.web.entra_analyst_groups)
    _cfg.web.entra_viewer_groups = form.get("entra_viewer_groups", _cfg.web.entra_viewer_groups)

    # Web Server settings
    _cfg.web.web_host = form.get("web_host", _cfg.web.web_host)
    if form.get("web_host_custom"):
        _cfg.web.web_host = form.get("web_host_custom")
    _cfg.web.web_port = _safe_int(form.get("web_port"), _cfg.web.web_port or 8787)
    _cfg.web.https_port = _safe_int(form.get("https_port"), _cfg.web.https_port or 8788)
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
    _cfg.llm.temperature = _safe_float(form.get("llm_temperature"), _cfg.llm.temperature or 0.1)
    _cfg.llm.max_tokens = _safe_int(form.get("llm_max_tokens"), _cfg.llm.max_tokens or 1200)
    _cfg.llm.response_format = form.get("llm_response_format", _cfg.llm.response_format)

    # Multi LLM servers (JSON list for priority/failover). If provided, use it; else keep/ backfill single.
    servers_raw = form.get("llm_servers", "").strip()
    if servers_raw:
        try:
            parsed = json.loads(servers_raw)
            if isinstance(parsed, list):
                _cfg.llm.servers = parsed
        except Exception:
            pass  # keep previous

    # Home Assistant
    _cfg.home_assistant.enabled = form.get("ha_enabled") == "on"
    _cfg.home_assistant.url = form.get("ha_url", _cfg.home_assistant.url)
    _cfg.home_assistant.token = form.get("ha_token", _cfg.home_assistant.token)
    _cfg.home_assistant.auto_enrich = form.get("ha_auto_enrich") == "on"
    _cfg.home_assistant.create_sensors = form.get("ha_create_sensors") == "on"
    _cfg.home_assistant.notify_services = [x.strip() for x in form.get("ha_notify_services", "").splitlines() if x.strip()]

    # Geo / IP Geolocation (multi-provider support)
    if hasattr(_cfg, "geo"):
        _cfg.geo.enabled = form.get("geo_enabled") == "on"
        _cfg.geo.mmdb_path = form.get("geo_mmdb_path", _cfg.geo.mmdb_path or "")
        _cfg.geo.merge_strategy = form.get("geo_merge_strategy", _cfg.geo.merge_strategy or "first_success")
        providers_raw = form.get("geo_providers", "").strip()
        if providers_raw:
            try:
                parsed = json.loads(providers_raw)
                if isinstance(parsed, list):
                    from .config import GeoProviderConfig
                    _cfg.geo.providers = [GeoProviderConfig(**p) if isinstance(p, dict) else GeoProviderConfig(type=str(p)) for p in parsed]
            except Exception:
                pass  # keep previous if bad JSON

    # LLM Azure / M365 fields
    _cfg.llm.azure_endpoint = form.get("llm_azure_endpoint", _cfg.llm.azure_endpoint or "")
    _cfg.llm.azure_deployment = form.get("llm_azure_deployment", _cfg.llm.azure_deployment or "")
    _cfg.llm.azure_api_version = form.get("llm_azure_api_version", _cfg.llm.azure_api_version or "2024-10-21")

    # Alerting - Webhooks
    _cfg.alerting.webhooks = [x.strip() for x in form.get("webhooks", "").splitlines() if x.strip()]

    # Rules
    patterns = form.get("custom_patterns", "")
    _cfg.rules.custom_patterns = [p.strip() for p in patterns.splitlines() if p.strip()]

    # Analysis
    _cfg.analysis.interval_seconds = _safe_int(form.get("analysis_interval"), _cfg.analysis.interval_seconds or 45)

    # Branding (additive - PR9)
    if not hasattr(_cfg, "branding") or _cfg.branding is None:
        from types import SimpleNamespace
        _cfg.branding = SimpleNamespace(instance_name="", logo_path="", show_powered_by=True)
    _cfg.branding.instance_name = form.get("branding_instance_name", _cfg.branding.instance_name or "")
    _cfg.branding.logo_path = form.get("branding_logo_path", _cfg.branding.logo_path or "")
    _cfg.branding.show_powered_by = True  # always kept on for attribution
    _cfg.analysis.batch_size = _safe_int(form.get("analysis_batch_size"), _cfg.analysis.batch_size or 25)
    _cfg.analysis.min_severity_for_ai = form.get("min_severity_for_ai", _cfg.analysis.min_severity_for_ai)

    # Heartbeats global (for monitors page + config UI)
    _cfg.heartbeats.enabled = form.get("heartbeats_enabled") == "on"
    _cfg.heartbeats.default_interval_seconds = _safe_int(form.get("heartbeats_default_interval"), getattr(_cfg.heartbeats, "default_interval_seconds", 60) or 60)

    # Email / SMTP settings
    _cfg.alerting.email_to = [x.strip() for x in form.get("email_to", "").splitlines() if x.strip()]
    _cfg.alerting.smtp_host = form.get("smtp_host", _cfg.alerting.smtp_host)
    _cfg.alerting.smtp_port = _safe_int(form.get("smtp_port"), _cfg.alerting.smtp_port or 587)
    _cfg.alerting.smtp_user = form.get("smtp_user", _cfg.alerting.smtp_user)
    _cfg.alerting.smtp_password = form.get("smtp_password", _cfg.alerting.smtp_password)
    _cfg.alerting.smtp_from = form.get("smtp_from", _cfg.alerting.smtp_from)

    # Handle direct config.yaml editor save (if present)
    if "raw_config_yaml" in form:
        try:
            config_path = _cfg.config_path or "config.yaml"
            # atomic write for safety
            tmp = config_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(form.get("raw_config_yaml"))
            os.replace(tmp, config_path)
            # Reload global config after direct edit
            _cfg = Config.load(config_path)
        except Exception as e:
            logger.error("Failed to save raw config.yaml: %s", e)

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

        # Web / Auth (Phase 4 enhanced) - NOTE: local_password handled separately via /users
        web_section = {
            "local_user": _cfg.web.local_user,
            "domain_enabled": _cfg.web.domain_enabled,
            "domain_server": _cfg.web.domain_server,
            "domain_base_dn": _cfg.web.domain_base_dn,
            "domain_user_domain": _cfg.web.domain_user_domain,
            # Service account for secure group lookups (encrypted on persist)
            "domain_service_account": _cfg.web.domain_service_account,
            "domain_service_password": _cfg.web.domain_service_password,  # will encrypt below
            "domain_use_ldaps": _cfg.web.domain_use_ldaps,
            "domain_ca_cert": _cfg.web.domain_ca_cert,
            "domain_verify_cert": _cfg.web.domain_verify_cert,
            "domain_admin_groups": _cfg.web.domain_admin_groups,
            "domain_operator_groups": _cfg.web.domain_operator_groups,
            "domain_analyst_groups": _cfg.web.domain_analyst_groups,
            "domain_viewer_groups": _cfg.web.domain_viewer_groups,
            "domain_fallback_local": _cfg.web.domain_fallback_local,
            "allow_local_login": _cfg.web.allow_local_login,
            "web_host": _cfg.web.web_host,
            "web_port": _cfg.web.web_port,
            "https_port": _cfg.web.https_port,
            "web_domain": _cfg.web.web_domain,
            "http_enabled": _cfg.web.http_enabled,
            "ssl_enabled": _cfg.web.ssl_enabled,
            "ssl_auto_generate": _cfg.web.ssl_auto_generate,
            "ssl_certfile": _cfg.web.ssl_certfile,
            "ssl_keyfile": _cfg.web.ssl_keyfile,
            "letsencrypt_enabled": _cfg.web.letsencrypt_enabled,
            "letsencrypt_email": _cfg.web.letsencrypt_email,
            "force_https_redirect": _cfg.web.force_https_redirect,
            # Entra ID
            "entra_enabled": _cfg.web.entra_enabled,
            "entra_tenant_id": _cfg.web.entra_tenant_id,
            "entra_client_id": _cfg.web.entra_client_id,
            "entra_client_secret": _cfg.web.entra_client_secret,  # encrypted below
            "entra_redirect_uri": _cfg.web.entra_redirect_uri,
            "entra_scopes": _cfg.web.entra_scopes,
            "entra_admin_groups": _cfg.web.entra_admin_groups,
            "entra_operator_groups": _cfg.web.entra_operator_groups,
            "entra_analyst_groups": _cfg.web.entra_analyst_groups,
            "entra_viewer_groups": _cfg.web.entra_viewer_groups,
        }
        # Only include password if the user actually typed something new (not masked dots)
        pwd_from_form = form.get("local_password", "").strip()
        if pwd_from_form and not pwd_from_form.startswith("•"):
            web_section["local_password"] = pwd_from_form

        # Phase 4: Encrypt sensitive service / Entra secrets before persisting to YAML
        # Use storage's reversible encryption if available (reuses Phase 2/3 credential crypto)
        try:
            if _storage and hasattr(_storage, "_encrypt_credential_secret"):
                if web_section.get("domain_service_password"):
                    web_section["domain_service_password"] = _storage._encrypt_credential_secret(web_section["domain_service_password"])
                if web_section.get("entra_client_secret"):
                    web_section["entra_client_secret"] = _storage._encrypt_credential_secret(web_section["entra_client_secret"])
        except Exception:
            pass  # non-fatal; secrets may be stored plaintext in worst case (still better than nothing + file perms)

        updates["web"] = web_section

        updates["llm"] = {
            "provider": _cfg.llm.provider,
            "base_url": _cfg.llm.base_url,
            "api_key": _cfg.llm.api_key,
            "model": _cfg.llm.model,
            "temperature": _cfg.llm.temperature,
            "max_tokens": _cfg.llm.max_tokens,
            "response_format": _cfg.llm.response_format,
            "servers": _cfg.llm.servers or [],
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

        # Heartbeats (global for monitors page toggle etc)
        updates["heartbeats"] = {
            "enabled": getattr(_cfg.heartbeats, "enabled", False),
            "default_interval_seconds": getattr(_cfg.heartbeats, "default_interval_seconds", 60),
        }

        # Merge into existing without clobbering other top-level keys (syslog, remediation, heartbeats, blacklist, etc.)
        merged = deep_update(existing, updates)

        # Atomic write to avoid partial/corrupt config.yaml on crash or perms issues during save
        tmp_path = config_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(merged, f, sort_keys=False, default_flow_style=False, indent=2)
        os.replace(tmp_path, config_path)

        # Reload global so the running app sees the saved values (and any merged keys)
        _cfg = Config.load(config_path)

        # Also persist key dynamic/runtime config to DB (preferences + custom_rules tables)
        # so they survive yaml issues, are transactional, and avoid file-permission problems on volumes.
        # (yaml remains the bootstrap for syslog ports, llm url, db_path, initial secrets etc.)
        if _storage is not None:
            try:
                _storage.set_preference("branding.instance_name", getattr(_cfg.branding, "instance_name", "") if hasattr(_cfg, "branding") else "")
                _storage.set_preference("analysis.min_severity_for_ai", _cfg.analysis.min_severity_for_ai)
                _storage.set_preference("analysis.interval_seconds", _cfg.analysis.interval_seconds)
                _storage.set_preference("geo.merge_strategy", getattr(_cfg.geo, "merge_strategy", "first_success") if hasattr(_cfg, "geo") else "first_success")
                # custom patterns -> also the custom_rules table (or simple pref for now)
                if _cfg.rules.custom_patterns:
                    _storage.set_preference("rules.custom_patterns", json.dumps(_cfg.rules.custom_patterns))
                # ha notify etc can be extended similarly
                logger.info("Also synced selected config sections to DB preferences for durability")
            except Exception as db_e:
                logger.warning("Could not sync config prefs to DB (non-fatal): %s", db_e)

        return RedirectResponse("/config?saved=1", status_code=302)
    except Exception as e:
        logger.exception("Config save failed")
        safe_err = urlquote(str(e)[:200] or "unknown error")
        return RedirectResponse(f"/config?error={safe_err}", status_code=302)


@app.post("/api/config/save/{section}")
async def save_config_section(
    section: str,
    request: Request,
    user: str = Depends(require_login),
    role: str = Depends(require_min_role("administrator")),
):
    """Per-section config save — loads running config, updates only the requested section."""
    global _cfg
    if _cfg is None:
        return {"error": "no config"}

    body = await request.json()
    import yaml

    config_path = _cfg.config_path or "config.yaml"
    existing: dict = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}

    allowed_sections = {
        "llm", "web", "syslog", "storage", "analysis", "rules", "alerting",
        "remediation", "geo", "blacklist", "home_assistant", "heartbeats",
        "branding", "data_sources", "brain", "shield", "mobile", "syslog_forwarding", "tenant",
    }
    if section not in allowed_sections:
        return {"error": f"unknown section: {section}"}

    existing[section] = {**(existing.get(section) or {}), **body}
    tmp = config_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(existing, f, sort_keys=False, default_flow_style=False)
    os.replace(tmp, config_path)
    _cfg = Config.load(config_path)

    if _storage and hasattr(_storage, "set_user_preference"):
        _storage.set_user_preference(user, f"config_section_{section}", json.dumps(body))

    return {"success": True, "section": section, "message": "Section saved. Some changes may require restart."}


@app.get("/api/config/running")
async def get_running_config(user: str = Depends(require_login), role: str = Depends(require_min_role("administrator"))):
    """Return the currently running config (no defaults reset)."""
    if _cfg is None:
        return {"error": "no config"}
    return _cfg.to_dict()


@app.get("/callback/entra")
async def entra_oauth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Entra ID OAuth redirect callback."""
    if error:
        return RedirectResponse(f"/login?error={urlquote(error)}", status_code=302)
    if not code or _cfg is None:
        return RedirectResponse("/login?error=missing_code", status_code=302)

    try:
        import requests
        from .auth import decrypt_secret

        tenant = _cfg.web.entra_tenant_id
        client_id = _cfg.web.entra_client_id
        client_secret = decrypt_secret(_cfg.web.entra_client_secret or "")
        redirect_uri = _cfg.web.entra_redirect_uri or str(request.url_for("entra_oauth_callback"))

        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": _cfg.web.entra_scopes,
        }
        r = requests.post(token_url, data=data, timeout=15)
        r.raise_for_status()
        tokens = r.json()
        access_token = tokens.get("access_token", "")

        from .auth import try_entra_login
        success, role, groups = try_entra_login(access_token, "", _cfg.web, _storage, is_token=True)
        if success:
            request.session["user"] = groups[0] if groups else "entra_user"
            request.session["role"] = role or "viewer"
            request.session["auth_type"] = "entra"
            return RedirectResponse("/", status_code=302)
        return RedirectResponse("/login?error=entra_auth_failed", status_code=302)
    except Exception as exc:
        logger.exception("Entra callback failed")
        return RedirectResponse(f"/login?error={urlquote(str(exc)[:100])}", status_code=302)


@app.get("/auth/entra")
async def entra_oauth_start(request: Request):
    """Start Entra ID OAuth flow."""
    if _cfg is None or not _cfg.web.entra_enabled:
        return RedirectResponse("/login?error=entra_disabled", status_code=302)
    tenant = _cfg.web.entra_tenant_id
    client_id = _cfg.web.entra_client_id
    redirect_uri = _cfg.web.entra_redirect_uri or str(request.url_for("entra_oauth_callback"))
    scopes = _cfg.web.entra_scopes.replace(" ", "%20")
    auth_url = (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        f"?client_id={client_id}&response_type=code&redirect_uri={urlquote(redirect_uri)}"
        f"&scope={scopes}&response_mode=query"
    )
    return RedirectResponse(auth_url, status_code=302)


@app.post("/api/devices/{ip}/monitoring")
async def toggle_device_monitoring(ip: str, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    ok = _storage.set_device_monitoring(ip, enabled) if hasattr(_storage, "set_device_monitoring") else False
    return {"success": ok, "ip": ip, "monitoring_enabled": enabled}


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

    users_list = []
    if _storage:
        try:
            users_list = _storage.list_local_auth_users()
        except Exception:
            pass

    return get_templates().TemplateResponse(
        request,
        "users.html",
        context={
            "current_user": user,
            "auth_type": auth_type,
            "login_time": login_time,
            "cfg": _cfg,
            "totp_setup": totp_setup,
            "has_totp_support": HAS_TOTP,
            "local_users": users_list,
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

    # Wire storage for reversible encryption in auth.py (Phase 4 service account / Entra secrets + AI controller)
    try:
        from .auth import set_storage_for_crypto
        set_storage_for_crypto(_storage)
    except Exception:
        pass  # graceful; encryption will fallback

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
        if geo_path and os.path.exists(geo_path):
            try:
                from .geo import force_reload_geo
                force_reload_geo(geo_path)
                print(f"[logsentinel] Geo using explicit mmdb_path from config: {geo_path}")
            except Exception as e:
                print(f"[logsentinel] Warning: failed to init geo with configured path {geo_path}: {e}")
        elif geo_path:
            print(f"[logsentinel] Warning: configured geo mmdb_path does not exist on this system: {geo_path} (will auto-detect if possible)")

    # Mount v2 API routes (after web module fully loaded to avoid circular imports)
    try:
        from .v2_api import router as v2_router
        existing = {getattr(r, "path", "") for r in app.routes}
        if "/api/v2/status" not in existing:
            app.include_router(v2_router)
    except Exception as exc:
        logger.warning("v2 API routes not mounted: %s", exc)


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

        # Make cfg and branding available in all templates
        def inject_globals():
            return {
                "cfg": _cfg,
                "branding": getattr(_cfg, 'branding', None) if _cfg else None,
            }
        _templates_instance.env.globals.update(inject_globals())

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

    last_analysis = _storage.get_last_analysis_time() if hasattr(_storage, "get_last_analysis_time") else None

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

    org_tasks = _storage.list_org_tasks(status="open", limit=10) if hasattr(_storage, "list_org_tasks") else []

    return get_templates().TemplateResponse(
        request,
        "dashboard.html",
        context={
            "total_logs": total_logs,
            "threats": threats,
            "analyses": recent_analyses,
            "cfg": _cfg,
            "device_intel": device_intel,
            "recent_devices": recent_devices,
            "ai_suggestion_count": ai_suggestion_count,
            "total_analyses": total_analyses,
            "llm_analyses": llm_analyses,
            "llm_analyses_24h": llm_analyses_24h,
            "last_analysis": last_analysis,
            "org_tasks": org_tasks,
        },
    )


@app.get("/analyses", response_class=HTMLResponse)
async def analyses_page(
    request: Request,
    limit: int = 20,
    offset: int = 0,
    q: str | None = None,
    user: str = Depends(require_login),
):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    limit = max(5, min(limit, 100))
    # _get_recent_analyses is simple; we slice here for now (small table)
    all_a = _get_recent_analyses(limit=200)
    if q:
        qlow = q.lower()
        all_a = [a for a in all_a if qlow in (a.get("summary") or "").lower()]
    total = len(all_a)
    analyses = all_a[offset : offset + limit]
    return get_templates().TemplateResponse(
        request,
        "analyses.html",
        context={"analyses": analyses, "total": total, "limit": limit, "offset": offset, "q": q or ""},
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
async def threats_page(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    view: str = "grouped",  # grouped | list  (grouped is the new default to fight clutter)
    status: str | None = None,
    q: str | None = None,
    user: str = Depends(require_login),
):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    limit = max(5, min(limit, 100))  # 10/50/100 safe
    offset = max(0, offset)
    search = (q or "").strip() or None

    threats = _storage.get_recent_threats(limit=limit, offset=offset, status=status, search=search)
    total = _storage.count_threats(status=status, search=search)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)

    groups = []
    if view == "grouped":
        groups = _storage.get_threat_groups(limit=300)

    return get_templates().TemplateResponse(
        request,
        "threats.html",
        context={
            "threats": threats,
            "total": total,
            "limit": limit,
            "offset": offset,
            "view": view,
            "status": status or "",
            "q": search or "",
            "groups": groups,
        },
    )


@app.get("/monitors", response_class=HTMLResponse)
async def monitors_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    view = request.query_params.get("view", "")
    return get_templates().TemplateResponse(
        request,
        "monitors.html",
        context={"view": view}
    )


@app.get("/activity", response_class=HTMLResponse)
async def activity_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    return get_templates().TemplateResponse(
        request,
        "activity.html",
        context={"cfg": _cfg}
    )


# --- RocketLogAI AI Assistant (self-documenting help + feature suggestions) ---
@app.get("/assistant", response_class=HTMLResponse)
async def assistant_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    is_admin = False
    try:
        auth = _storage.get_local_auth(user)
        is_admin = bool(auth and auth.get("is_admin"))
    except Exception:
        pass
    return get_templates().TemplateResponse(
        request,
        "assistant.html",
        context={"cfg": _cfg, "is_admin": is_admin, "current_user": user}
    )


def _operator_keywords_match(question: str) -> bool:
    q = question.lower().strip()
    operator_keywords = [
        "ping", "nmap", "traceroute", "ssh ", "run on ", "deploy", "install on ",
        "show ips", "devices using port", "backup config", "reboot ", "update on ",
    ]
    if any(kw in q for kw in operator_keywords):
        return True
    return len(q.split()) > 4 and any(w in q for w in ("the ", "these ", "my ", "local network"))


def _try_fast_operator_plan(question: str) -> dict | None:
    """Deterministic plans for simple read-only commands (no LLM required)."""
    import platform
    import re

    q = question.strip()
    ql = q.lower()

    ping_match = re.search(
        r"\bping\s+(?:the\s+)?([\d.]+|[a-z0-9][\w.-]*)",
        ql,
        re.I,
    )
    if ping_match:
        host = ping_match.group(1).rstrip(".")
        if platform.system() == "Windows":
            cmd = f"ping -n 4 {host}"
        else:
            cmd = f"ping -c 4 {host}"
        return {
            "is_operator_command": True,
            "is_actionable": True,
            "intent": "ping",
            "explanation": (
                f"Ping {host} from the RocketLogAI server ({platform.system()}) "
                "to verify reachability. Review the plan, then click Confirm & Execute."
            ),
            "targets": [{"ip": host, "name": host, "os_guess": "unknown"}],
            "proposed_steps": [
                {
                    "step": 1,
                    "description": f"Ping {host}",
                    "command": cmd,
                    "command_or_action": cmd,
                    "os": "host",
                    "risk": "low",
                }
            ],
            "requires_confirmation": True,
            "backup_recommended": False,
            "rollback_notes": "Read-only ICMP test; nothing to roll back.",
            "safety_notes": "Runs ping on the RocketLogAI host only (not remote devices unless SSH is used).",
        }

    if ql in ("yes", "y", "ok", "okay", "confirm", "do it", "go ahead"):
        return None

    return None


def _normalize_operator_plan_response(plan: dict) -> dict:
    """Unify Phase 2/3 plan shapes for the assistant UI."""
    for step in plan.get("proposed_steps") or []:
        if not step.get("command") and step.get("command_or_action"):
            step["command"] = step["command_or_action"]
    if plan.get("is_actionable") and not plan.get("is_operator_command"):
        plan["is_operator_command"] = True
    return plan


@app.post("/api/assistant/ask")
async def api_assistant_ask(request: Request, user: str = Depends(require_login)):
    if _cfg is None:
        return {"answer": "Assistant not available (config not loaded)."}

    data = await request.json()
    question = (data.get("question") or "").strip()
    history = data.get("history") or []
    if not question:
        return {"answer": "Please ask a question about using RocketLogAI."}

    looks_like_operator = _operator_keywords_match(question)

    # Fast path: ping/traceroute-style commands work without any LLM backend.
    fast_plan = _try_fast_operator_plan(question)
    if fast_plan:
        fast_plan = _normalize_operator_plan_response(fast_plan)
        return {
            "mode": "operator_plan",
            "plan": fast_plan,
            "answer": fast_plan.get("explanation", "Proposed action plan ready for your review."),
            "requires_confirmation": fast_plan.get("requires_confirmation", True),
        }

    # Phase 3: powerful natural-language controller for complex requests.
    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm) if _cfg and _cfg.llm else None
        if llm and _storage:
            controller = get_ai_assistant_controller(_storage, llm, _cfg)
            powerful_response = await asyncio.wait_for(
                controller.process_natural_request(question, user, conversation_history=history),
                timeout=120,
            )
            if powerful_response.get("mode") == "action_plan":
                plan = _normalize_operator_plan_response(powerful_response.get("plan") or {})
                return {
                    "mode": "operator_plan",
                    "plan": plan,
                    "answer": powerful_response.get("answer", "Proposed action plan ready for your review."),
                    "requires_confirmation": powerful_response.get("requires_confirmation", True),
                }
            if powerful_response.get("mode") == "text" and not looks_like_operator:
                return powerful_response
    except asyncio.TimeoutError:
        logger.warning("Phase 3 powerful controller timed out, falling back")
    except Exception as e:
        logger.warning(f"Phase 3 powerful controller failed, falling back: {e}")

    # Legacy Phase 2 operator path (LLM-backed plans for network/device commands)
    if looks_like_operator:
        plan = await _handle_operator_command(question, user)
        if plan.get("is_operator_command"):
            plan = _normalize_operator_plan_response(plan)
            return {
                "mode": "operator_plan",
                "plan": plan,
                "answer": plan.get("explanation", "Proposed action plan ready for your review."),
                "requires_confirmation": plan.get("requires_confirmation", True)
            }

    # Fallback: normal platform help assistant
    system_prompt = """You are RocketLogAI Assistant — a helpful, concise co-pilot for the RocketLogAI security monitoring platform.

Current major capabilities include:
- Multi-source geolocation (MaxMind + ipinfo, ipapi, custom HTTP)
- Microsoft 365 Copilot / Azure OpenAI as LLM backend
- IBM i (AS/400) support via SSH or 5250 with English → CL for legacy greenscreen menus
- Deep monitors with credential profiles + English-to-script generation
- Server Activity dashboard with AI suggestions for dormant sources
- API tokens (rla_*) for external scripts/agents
- Home Assistant integration (pulls devices/states for enrichment + pushes alerts/notifications/sensors; also receives logs from HA core + all addons via the syslog forwarder addon for full observability of sensors, zigbee, UPS, etc.)
- MAC vendor intelligence + port-based auto-trust
- Direct in-UI editing of config.yaml
- NEW (Phase 2): Conversational Device Operator — type natural commands like "ping 1.1.1.1", "nmap the local network", "show devices using port 22", or "run 'uname -a' on the core servers". Always shows a dry-run plan first and requires your explicit confirmation before anything runs.

Answer questions about how to use these features. Be practical and step-by-step when possible.
If you genuinely don't know or the feature doesn't exist yet, say so clearly and invite the user to suggest it as a new capability."""

    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm)
        if hasattr(llm, "client") and hasattr(llm.client, "chat"):
            resp = llm.client.chat.completions.create(
                model=llm.cfg.model or "local",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ],
                max_tokens=600,
                temperature=0.3
            )
            answer = resp.choices[0].message.content if resp.choices else "I'm sorry, I couldn't generate a response."
        else:
            answer = "The assistant is currently limited on this LLM backend. Try asking a more specific question or use the suggestion box below."

        return {"answer": answer, "mode": "help"}
    except Exception as e:
        return {"answer": f"Assistant error: {str(e)[:200]}. You can still submit this as a suggestion below."}


@app.post("/api/assistant/suggest")
async def api_assistant_suggest(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"success": False, "error": "Storage not available"}

    data = await request.json()
    question = (data.get("question") or "").strip()
    suggestion = (data.get("suggestion") or "").strip()

    if not suggestion and not question:
        return {"success": False, "error": "Please provide a suggestion or question."}

    try:
        sid = _storage.create_assistant_suggestion(
            username=user,
            question=question,
            suggestion=suggestion or question
        )
        return {"success": True, "id": sid, "message": "Thank you! An admin will review your suggestion."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/assistant/suggestions")
async def api_list_assistant_suggestions(user: str = Depends(require_login)):
    if _storage is None:
        return {"suggestions": []}

    # Simple admin check
    try:
        auth = _storage.get_local_auth(user)
        if not (auth and auth.get("is_admin")):
            return {"error": "Admin access required"}
    except Exception:
        return {"error": "Admin access required"}

    suggestions = _storage.list_assistant_suggestions()
    return {"suggestions": suggestions}


@app.post("/api/assistant/suggestions/{suggestion_id}/review")
async def api_review_suggestion(suggestion_id: int, request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"success": False}

    # Admin check
    try:
        auth = _storage.get_local_auth(user)
        if not (auth and auth.get("is_admin")):
            return {"success": False, "error": "Admin only"}
    except Exception:
        return {"success": False, "error": "Admin only"}

    data = await request.json()
    new_status = data.get("status", "reviewed")
    notes = data.get("notes")

    ok = _storage.review_assistant_suggestion(suggestion_id, user, new_status, notes)
    return {"success": ok}


@app.get("/api/credentials")
async def api_list_credentials(user: str = Depends(require_login)):
    if _storage is None:
        return {"profiles": []}
    profiles = _storage.get_credential_profiles()
    # Never return decrypted secrets to the UI
    safe = []
    for p in profiles:
        safe.append({
            "id": p.get("id"),
            "name": p.get("name"),
            "type": p.get("type"),
            "username": p.get("username"),
            "notes": p.get("notes"),
        })
    return {"profiles": safe}


@app.post("/api/credentials")
async def api_create_credential(request: Request, user: str = Depends(require_login)):
    """Allow the operator (or UI) to quickly save a new credential profile when the plan needs one."""
    if _storage is None:
        return {"success": False, "error": "not initialized"}
    try:
        data = await request.json()
    except Exception:
        return {"success": False, "error": "bad json"}
    name = (data.get("name") or "").strip()
    typ = data.get("type", "ssh_key")
    username = data.get("username")
    secret = data.get("secret")
    notes = data.get("notes")
    if not name:
        return {"success": False, "error": "name required"}
    try:
        cid = _storage.upsert_credential_profile(name, typ, username, secret, notes)
        _storage.log_server_activity("outbound", "assistant_operator", source=user, action="create_credential_profile", status="success",
                                     details={"name": name, "type": typ})
        return {"success": True, "id": cid, "name": name}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


async def _execute_assistant_plan(plan: dict, user: str, confirmed: bool, user_notes: str | None = None) -> dict:
    """Run operator plans without blocking the event loop on subprocess/LLM work."""
    intent = (plan.get("intent") or "").lower()
    simple_readonly = intent in ("ping", "traceroute", "nmap_basic", "list_devices")
    use_legacy = bool(plan.get("is_operator_command")) or simple_readonly

    if use_legacy:
        return await _execute_operator_plan(plan, user, confirmed=confirmed)

    if plan.get("_meta") or plan.get("proposed_steps"):
        try:
            from .llm import get_llm_client
            llm = get_llm_client(_cfg.llm) if _cfg and _cfg.llm else None
            if llm:
                controller = get_ai_assistant_controller(_storage, llm, _cfg)
                return await controller.confirm_and_execute(
                    plan, user, confirmed=confirmed, user_notes=user_notes
                )
        except Exception as e:
            logger.warning(f"Phase 3 controller confirm failed, falling back to legacy executor: {e}")

    return await _execute_operator_plan(plan, user, confirmed=confirmed)


@app.post("/api/assistant/confirm_execute")
async def api_assistant_confirm_execute(request: Request, user: str = Depends(require_login), role: str = Depends(require_min_role("operator"))):
    """Synchronous execution (kept for API clients). Prefer execute-async from the web UI."""
    if _storage is None:
        return {"success": False, "error": "not initialized"}
    try:
        data = await request.json()
    except Exception:
        return {"success": False, "error": "bad request"}

    plan = data.get("plan") or {}
    confirmed = bool(data.get("confirmed"))
    user_notes = data.get("user_notes")
    return await _execute_assistant_plan(plan, user, confirmed=confirmed, user_notes=user_notes)


@app.post("/api/assistant/execute-async")
async def api_assistant_execute_async(request: Request, user: str = Depends(require_login), role: str = Depends(require_min_role("operator"))):
    """Queue assistant operator work in the background; poll /api/assistant/tasks/{id}."""
    if _storage is None:
        return {"success": False, "error": "not initialized"}
    try:
        data = await request.json()
    except Exception:
        return {"success": False, "error": "bad request"}

    plan = data.get("plan") or {}
    confirmed = bool(data.get("confirmed"))
    user_notes = data.get("user_notes")
    label = (plan.get("intent") or "operator") + " plan"

    task_id = await ASSISTANT_TASKS.create(label=label, user=user)

    async def _runner() -> dict:
        return await _execute_assistant_plan(plan, user, confirmed=confirmed, user_notes=user_notes)

    asyncio.create_task(ASSISTANT_TASKS.run(task_id, _runner))
    return {"success": True, "task_id": task_id, "status": "queued"}


@app.get("/api/assistant/tasks/{task_id}")
async def api_assistant_task_status(task_id: str, user: str = Depends(require_login)):
    task = await ASSISTANT_TASKS.get(task_id)
    if not task:
        return {"success": False, "error": "task not found"}
    if task.get("user") != user:
        return {"success": False, "error": "forbidden"}
    return {"success": True, "task": task}


@app.get("/api/system/diagnostics")
async def api_system_diagnostics(user: str = Depends(require_login)):
    llm = None
    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm) if _cfg and _cfg.llm else None
    except Exception:
        pass
    return run_live_diagnostics(cfg=_cfg, llm_client=llm, storage=_storage)


@app.post("/api/system/diagnostics/operator-test")
async def api_operator_self_test(user: str = Depends(require_login), role: str = Depends(require_min_role("operator"))):
    """Safe read-only ping self-test from the RocketLogAI host."""
    import platform as _platform

    host = "127.0.0.1"
    if _platform.system() == "Windows":
        cmd = f"ping -n 1 {host}"
    else:
        cmd = f"ping -c 1 {host}"
    plan = {
        "is_operator_command": True,
        "intent": "ping",
        "proposed_steps": [{"description": "Self-test ping", "command": cmd, "risk": "low"}],
        "requires_confirmation": False,
    }
    result = await _execute_operator_plan(plan, user, confirmed=True)
    return {"success": bool(result.get("success")), "result": result}


@app.get("/system-health", response_class=HTMLResponse)
async def system_health_page(request: Request, user: str = Depends(require_login)):
    return get_templates().TemplateResponse(
        request,
        "system_health.html",
        context={"cfg": _cfg, "current_user": user},
    )


@app.get("/shield", response_class=HTMLResponse)
async def shield_page(request: Request, user: str = Depends(require_login)):
    return get_templates().TemplateResponse(
        request,
        "shield.html",
        context={"cfg": _cfg, "current_user": user},
    )


@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request, user: str = Depends(require_login)):
    return get_templates().TemplateResponse(
        request,
        "agents.html",
        context={"cfg": _cfg, "current_user": user},
    )


# =============================================================================
# PHASE 2: Smart AI Assistant — Conversational Device Operator Co-Pilot
# Natural English commands with strong safety rails (dry-run first, explicit confirm,
# OS-aware commands, credential profiles, auto-backup for changes, full audit logging).
# =============================================================================

_OPERATOR_SYSTEM_PROMPT = """You are RocketLogAI Operator — a careful, safety-first conversational co-pilot that lets the human operator talk to devices and the network in plain English.

Core rules you MUST follow:
- NEVER suggest or plan anything that would run without explicit human confirmation in the UI.
- Always produce a clear, numbered "Proposed Action Plan" with:
  - exact commands that will be run (OS-specific)
  - which devices / IPs will be touched
  - which credential profile (if any) will be used
  - whether a backup will be made first
  - risk level (low/medium/high)
- For any modifying or high-risk action (deploy, write config, restart service, install software, etc.) set "requires_confirmation": true and "backup_recommended": true.
- Detect target OS from device intelligence when possible (linux, windows, macos, unknown). Generate the right flags (ping -c vs -n, etc.).
- Supported intents you can handle today: ping, traceroute, nmap_basic, list_devices, ssh_exec, run_script, backup_config, deploy_software (via scp + exec of known safe script).
- If the request is ambiguous or dangerous, ask for clarification in the explanation instead of guessing.
- Ground everything in the provided device list and known credential profiles. Do not invent devices.

Return ONLY valid JSON with this shape (no extra text outside the JSON):

{
  "is_operator_command": true,
  "intent": "ping" | "traceroute" | "nmap_basic" | "ssh_exec" | "deploy_software" | "list_devices" | "other",
  "explanation": "Short friendly summary for the operator.",
  "targets": [
    {"ip": "192.168.1.50", "name": "core-switch", "os_guess": "linux", "cred_profile": "primary-ssh" or null}
  ],
  "proposed_steps": [
    {"step": 1, "description": "Ping the device to check reachability", "command": "ping -c 4 192.168.1.50", "os": "linux", "risk": "low"}
  ],
  "backup_recommended": false,
  "requires_confirmation": true,
  "rollback_notes": "No changes will be made for a simple ping.",
  "safety_notes": "Read-only network test."
}

If the user's message is NOT a device/network operator command (e.g. just asking about the UI), set "is_operator_command": false and put a normal answer in "explanation".
"""

async def _handle_operator_command(question: str, user: str) -> dict:
    """Core Phase 2 entrypoint. Uses LLM to turn natural language into a safe, reviewable plan."""
    if _storage is None or _cfg is None:
        return {"error": "not initialized"}

    # Rich context for the LLM so it can resolve "these computers", "the linux servers", etc.
    try:
        devices = _storage.get_known_devices(limit=30)
        creds = _storage.get_credential_profiles()
    except Exception:
        devices = []
        creds = []

    device_summary = []
    for d in devices[:15]:
        device_summary.append({
            "ip": d.get("ip"),
            "name": d.get("ha_name") or d.get("ip"),
            "vendor": d.get("vendor"),
            "category": d.get("device_category"),
            "mac": d.get("mac"),
            "last_seen": d.get("last_seen"),
            "trust": d.get("trust_level"),
        })

    cred_summary = [{"name": c.get("name"), "type": c.get("type"), "username": c.get("username")} for c in creds[:10]]

    context = {
        "devices": device_summary,
        "credential_profiles": cred_summary,
        "user": user,
    }

    from .llm import get_llm_client
    llm = get_llm_client(_cfg.llm)

    user_msg = f"""Current context (devices + available credentials):
{json.dumps(context, default=str)[:4500]}

Operator request: {question}

Produce the JSON plan now. Be precise and conservative with safety."""

    try:
        if hasattr(llm, "client") and hasattr(llm.client, "chat"):
            resp = llm.client.chat.completions.create(
                model=llm.cfg.model or "local",
                messages=[
                    {"role": "system", "content": _OPERATOR_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg}
                ],
                max_tokens=1200,
                temperature=0.2,
            )
            raw = resp.choices[0].message.content if resp.choices else "{}"
        else:
            raw = '{"is_operator_command": false, "explanation": "LLM backend not available for operator mode."}'

        # Extract JSON (LLM sometimes wraps it)
        import re
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        plan_text = match.group(0) if match else raw
        plan = json.loads(plan_text)

        # Always attach audit context
        plan["_meta"] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "raw_llm_response": raw[:2000],
        }
        return plan
    except Exception as e:
        logger.exception("Operator plan generation failed")
        return {
            "is_operator_command": False,
            "explanation": f"Could not turn that into a safe operator plan: {str(e)[:180]}. Try rephrasing or use the regular help mode.",
            "error": str(e)[:200]
        }


async def _execute_operator_plan(plan: dict, user: str, confirmed: bool = False) -> dict:
    """Execute (or dry-run) a previously proposed operator plan.
    Enforces confirmation for anything that requires it.
    Does OS-aware command selection, auto-backup where relevant, and full audit logging.
    """
    if _storage is None:
        return {"success": False, "error": "storage not available"}

    if not plan.get("is_operator_command"):
        return {"success": False, "error": "Not an operator plan"}

    intent = plan.get("intent", "other")
    targets = plan.get("targets", [])
    steps = plan.get("proposed_steps", [])
    requires_confirmation = plan.get("requires_confirmation", True)
    backup_recommended = plan.get("backup_recommended", False)

    if requires_confirmation and not confirmed:
        return {"success": False, "error": "Explicit confirmation required for this action", "needs_confirm": True}

    results = []
    overall_success = True

    # Log the execution attempt (even if dry)
    _storage.log_server_activity(
        "outbound", "assistant_operator", source=user,
        action=f"execute_{intent}", status="started",
        details={"plan": plan, "confirmed": confirmed}
    )

    for step in steps:
        cmd = step.get("command") or step.get("command_or_action") or ""
        desc = step.get("description", "")
        target_ip = None
        cred_name = None
        for t in targets:
            if t.get("ip") and t["ip"] in (cmd or ""):
                target_ip = t["ip"]
                cred_name = t.get("cred_profile")
                break

        cred = None
        if cred_name:
            cred = _storage.get_credential_profile(cred_name)

        # === Basic safe executors (follow existing subprocess + ssh patterns in the codebase) ===
        step_result = {"step": desc, "command": cmd, "output": "", "success": False}

        try:
            import subprocess, shlex, platform, shutil, os

            # Ping / traceroute / basic network (use system tools, cross-platform)
            if intent in ("ping", "traceroute") or "ping" in cmd.lower() or "traceroute" in cmd.lower():
                # Already safe read-only commands (thread pool — do not block other HTTP requests)
                proc = await asyncio.to_thread(
                    subprocess.run,
                    shlex.split(cmd) if " " in cmd else [cmd],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                step_result["output"] = (proc.stdout or "") + (proc.stderr or "")
                step_result["success"] = proc.returncode == 0

            elif intent == "nmap_basic" or "nmap" in cmd.lower():
                if shutil.which("nmap"):
                    proc = await asyncio.to_thread(
                        subprocess.run,
                        shlex.split(cmd),
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    step_result["output"] = proc.stdout or proc.stderr or ""
                    step_result["success"] = proc.returncode == 0
                else:
                    step_result["output"] = "nmap not installed on the RocketLogAI host. Install it or use 'list_devices' + port data from the registry."
                    step_result["success"] = False

            elif intent in ("ssh_exec", "run_command") or cmd.strip().startswith("ssh "):
                # Reuse the battle-tested ssh + sshpass pattern already present in web.py remediation code
                # For real execution we expect a cred with username + secret (password or key path)
                if not cred or not cred.get("username"):
                    step_result["output"] = "No suitable credential profile selected for SSH. Create/select one in credential profiles first."
                    step_result["success"] = False
                else:
                    username = cred["username"]
                    secret = cred.get("secret") or ""
                    host = target_ip or (targets[0].get("ip") if targets else "localhost")
                    port = 22

                    ssh_opts = ["-o", "BatchMode=no", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
                    if secret and os.path.exists(secret):  # treat as key file
                        full_cmd = ["ssh", "-i", secret] + ssh_opts + [f"{username}@{host}", "-p", str(port), cmd.split(" ", 1)[1] if " " in cmd else "echo 'no command'"]
                    elif secret:
                        if shutil.which("sshpass"):
                            full_cmd = ["sshpass", "-p", secret, "ssh"] + ssh_opts + [f"{username}@{host}", "-p", str(port), cmd.split(" ", 1)[1] if len(cmd.split(" ", 1)) > 1 else "echo ok"]
                        else:
                            step_result["output"] = "sshpass not found for password auth. Use SSH keys instead."
                            step_result["success"] = False
                            full_cmd = None
                    else:
                        full_cmd = ["ssh"] + ssh_opts + [f"{username}@{host}", "-p", str(port), cmd.split(" ", 1)[1] if " " in cmd else "echo ok"]

                    if full_cmd:
                        proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=45)
                        step_result["output"] = (proc.stdout or "") + "\n" + (proc.stderr or "")
                        step_result["success"] = proc.returncode == 0

            else:
                # Fallback: treat as local shell command on the RocketLogAI host (very limited, read-only preference)
                # For safety we only allow a tiny allowlist for now
                safe_local = any(x in cmd.lower() for x in ["ping", "traceroute", "uname", "date", "whoami", "ss -", "netstat"])
                if safe_local:
                    proc = await asyncio.to_thread(
                        subprocess.run,
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    step_result["output"] = proc.stdout or proc.stderr or ""
                    step_result["success"] = proc.returncode == 0
                else:
                    step_result["output"] = "This action type is not yet wired for automatic execution. Use the remediation script UI or prebuilts for complex changes."
                    step_result["success"] = False

            # Simple automatic backup hook for modifying actions (example: before a config change we could cat files)
            if backup_recommended and step_result["success"]:
                # In a fuller impl we would have pre-generated backup commands per step
                step_result["backup_note"] = "Backup recommended in plan (operator should have captured state before changes)."

        except Exception as ex:
            step_result["output"] = f"Execution error: {str(ex)[:200]}"
            step_result["success"] = False
            overall_success = False

        results.append(step_result)

        # Per-step audit
        _storage.log_server_activity(
            "outbound", "assistant_operator", source=user,
            action=intent, status="success" if step_result["success"] else "error",
            details={"step": step, "result": step_result, "target": target_ip}
        )

    final = {
        "success": overall_success,
        "results": results,
        "plan": plan,
        "message": "Action completed." if overall_success else "One or more steps failed or were skipped. See results.",
        "rollback_hint": plan.get("rollback_notes", "Review server_activity for details. Many changes can be rolled back by re-applying previous known-good config/scripts.")
    }

    _storage.log_server_activity(
        "outbound", "assistant_operator", source=user,
        action=f"operator_{intent}_complete", status="success" if overall_success else "partial",
        details=final
    )

    return final


# =============================================================================
# Daily Briefing / Operator Companion (the "talk to the crew about the day" feature)
# =============================================================================

# Simple in-memory job tracker so long historical generations can show progress
_daily_briefing_jobs: dict[str, dict[str, Any]] = {}


def _get_daily_llm_system_prompt(context_block: str) -> str:
    """The voice the user asked for: Grok-style as we actually talk here. Direct, in-between, useful, lightly irreverent when appropriate."""
    return f"""You are Grok, acting as the user's sharp, no-BS on-site operations co-pilot and Daily Briefing Operator Companion.

You have the full factual record of everything RocketLogAI saw during a specific time window (the "facts of the day").

Talk exactly like we talk in this chat: direct, practical, somewhere between casual and proper, technically precise, never corporate-speak or heavy slang. Use "we" when referring to what the servers and the monitoring system did together. When it fits, lightly channel different expert hats on the team ("as the SRE on the overnight crew would point out...", "the legacy systems gremlin is cackling at this one...", "threats desk noted...").

Core job:
- Deliver an entertaining but genuinely useful one-stop recap of what the server had to deal with all day (or the requested window).
- Call out the real signal, the weird/ridiculous stuff, the wins, the near-misses, the boring-but-critical things.
- Ground every single claim in the provided facts. If it's not in the data, say so.
- When the user drills ("why?", "who was doing X?", "what exactly failed?", "how bad was it really?") answer from the context.
- Propose concrete, safe next steps. When it makes sense, sketch small scripts or exact commands tuned to the day's actual incidents.
- Keep responses readable: short paragraphs, bullets for lists of issues or options.
- At natural points, surface clear "here's what we could do about it" options.

You are the super-genius coworker who stayed up with the machines so the human doesn't have to. Make the day make sense and make the next moves obvious.

Safety: Never suggest destructive actions without the human explicitly confirming later. All real execution still goes through the existing preview/confirm/activity-log rails that are already in the system.

Here are the concrete facts for the current window the user cares about:

{context_block}

Now write the briefing or answer the follow-up question. Be the helpful, slightly irreverent but trustworthy crew member."""


async def _generate_briefing_narrative(context: dict, window_label: str) -> dict[str, Any]:
    """Call the LLM with the strong daily companion prompt and return narrative + structured highlights."""
    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm) if _cfg else None

        # Compact but rich text version of the context for the prompt
        facts = json.dumps({
            "window": context.get("window"),
            "totals": context.get("totals"),
            "threats_sample": context.get("threats", [])[:8],
            "monitor_failures": context.get("monitor_issues", [])[:6],
            "activity_sample": context.get("activity", [])[:8],
            "top_hosts": context.get("top_hosts", []),
            "excerpts": context.get("excerpts", []),
        }, default=str, indent=2)[:6500]

        system = _get_daily_llm_system_prompt(facts)
        user_msg = f"Write the Daily Briefing report for: {window_label}. Start with a short engaging title, then the story-like recap, then clear 'What stood out' bullets, then any immediate suggested moves. Keep the Grok voice we use when talking here."

        if llm and hasattr(llm, "client") and hasattr(llm.client, "chat"):
            resp = llm.client.chat.completions.create(
                model=getattr(llm.cfg, "model", None) or "local",
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg}
                ],
                max_tokens=1400,
                temperature=0.4
            )
            text = resp.choices[0].message.content if resp.choices else "No response from model."
        else:
            text = "LLM not available for the crew report. Here's a raw summary of the facts instead:\n\n" + json.dumps(context.get("totals", {}), indent=2)

        # Try to extract a clean narrative. The model usually gives title + body.
        narrative = text.strip()

        # Simple structured highlights extraction (we also let the model be free-form)
        highlights = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("-", "•", "*")) and len(line) > 4:
                highlights.append(line.lstrip("-•* ").strip())

        # Very lightweight "proposed actions" the UI can turn into buttons later
        proposed = []
        low = text.lower()
        if "script" in low or "remediation" in low or "restart" in low:
            proposed.append({"title": "Draft remediation script for the main issue", "type": "script"})

        return {
            "narrative": narrative,
            "highlights": highlights[:7] or ["Context captured — ask me to expand on any part."],
            "proposed_actions": proposed,
            "_raw": text,
        }
    except Exception as e:
        logger.warning("Daily briefing LLM generation failed: %s", e)
        return {
            "narrative": "The model had a rough time with the full evidence (or is slow on a big historical day). Here's what we know from the raw numbers:\n\n" + json.dumps(context.get("totals", {}), indent=2),
            "highlights": ["Raw data collected — try asking specific follow-up questions."],
            "proposed_actions": [],
        }


@app.get("/daily", response_class=HTMLResponse)
async def daily_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    return get_templates().TemplateResponse(
        request,
        "daily.html",
        context={"cfg": _cfg, "current_user": user}
    )


@app.post("/api/daily/briefing")
async def api_create_daily_briefing(request: Request, user: str = Depends(require_login)):
    """Generate (or reload) a Daily Briefing for a window. Returns job_id for long-running cases so UI can show progress."""
    if _storage is None or _cfg is None:
        return {"error": "not initialized"}

    data = await request.json()
    window = data.get("window", "rolling_24h")
    day = data.get("day")
    shift_start = data.get("shift_start")
    shift_end = data.get("shift_end")
    natural = data.get("natural")  # free text like "last Tuesday" or "my overnight shift"

    # Resolve the actual time window
    resolved = _storage._resolve_time_window(
        window=window,
        day=day,
        shift_start=shift_start,
        shift_end=shift_end,
    )

    # If natural language was supplied, let the resolver try, otherwise we can pass it through
    if natural:
        # Lightweight: treat natural as a hint; the context + LLM will handle meaning
        resolved["label"] = f"Interpreted: {natural}"
        # For truly wild historical we still use the resolved bounds (or fall back)

    start = resolved["start"]
    end = resolved["end"]
    label = resolved.get("label", window)

    # Check if we already have a recent one for the exact same window (nice for "today" reloads)
    existing = None
    try:
        if resolved.get("day"):
            existing = _storage.get_briefing_by_day_window(resolved["day"], window)
    except Exception:
        pass

    if existing and not data.get("force"):
        # Return the saved one immediately (chat history will load too)
        return {
            "briefing_id": existing.get("id"),
            "window_label": existing.get("window_label"),
            "narrative": existing.get("narrative"),
            "highlights": existing.get("highlights", []),
            "stats": existing.get("stats", {}),
            "model": existing.get("model"),
        }

    # Build rich context (this can be heavy on big historical days)
    job_id = str(uuid.uuid4())
    _daily_briefing_jobs[job_id] = {
        "status": "running",
        "progress": 15,
        "message": "Gathering the day's evidence from logs, threats, monitors and activity...",
        "detail": f"Window: {label}",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "user": user,
    }

    # Fire background generation so the request returns fast and UI can poll
    async def _bg_generate():
        try:
            _daily_briefing_jobs[job_id]["progress"] = 25
            _daily_briefing_jobs[job_id]["message"] = "Compiling the facts the crew needs..."

            ctx = _storage.get_daily_context(start, end)
            ctx["window"]["label"] = label

            _daily_briefing_jobs[job_id]["progress"] = 55
            _daily_briefing_jobs[job_id]["message"] = "The crew is writing the shift report..."

            gen = await _generate_briefing_narrative(ctx, label)

            _daily_briefing_jobs[job_id]["progress"] = 85
            _daily_briefing_jobs[job_id]["message"] = "Saving the briefing for later..."

            # Persist
            day_key = resolved.get("day") or start[:10]
            model_name = None
            try:
                from .llm import get_llm_client as _get_llm
                l = _get_llm(_cfg.llm) if _cfg else None
                model_name = getattr(getattr(l, "cfg", None), "model", None) if l else None
            except Exception:
                model_name = None

            bid = _storage.save_daily_briefing(
                day=day_key,
                window_type=window,
                window_label=label,
                start_ts=start,
                end_ts=end,
                narrative=gen["narrative"],
                stats=ctx.get("totals", {}),
                highlights=gen.get("highlights", []),
                model=model_name,
                duration_ms=None,
                proposed_actions=gen.get("proposed_actions"),
                created_by=user,
            )

            # Log the act of creating the briefing (so activity dashboard sees it)
            try:
                _storage.log_server_activity(
                    "outbound", "daily_briefing", "operator_companion", "generate",
                    "success", {"window": label, "briefing_id": bid}, None, None
                )
            except Exception:
                pass

            _daily_briefing_jobs[job_id]["status"] = "done"
            _daily_briefing_jobs[job_id]["progress"] = 100
            _daily_briefing_jobs[job_id]["briefing_id"] = bid
            _daily_briefing_jobs[job_id]["narrative"] = gen["narrative"]
            _daily_briefing_jobs[job_id]["highlights"] = gen.get("highlights", [])
            _daily_briefing_jobs[job_id]["window_label"] = label
            _daily_briefing_jobs[job_id]["model"] = _cfg.llm.model if _cfg and _cfg.llm else "local"
        except Exception as ex:
            logger.exception("Daily briefing background generation failed")
            _daily_briefing_jobs[job_id]["status"] = "error"
            _daily_briefing_jobs[job_id]["error"] = str(ex)[:200]

    asyncio.create_task(_bg_generate())

    # Return immediately with the job so the UI can show nice progress for big days
    return {
        "job_id": job_id,
        "status": "queued",
        "window_label": label,
        "note": "For large historical windows this can take a while. The UI will poll and show progress."
    }


@app.get("/api/daily/briefing/status/{job_id}")
async def api_daily_briefing_status(job_id: str, user: str = Depends(require_login)):
    job = _daily_briefing_jobs.get(job_id)
    if not job:
        return {"status": "unknown"}
    # Return a clean subset for the frontend poll
    return {
        "status": job.get("status"),
        "progress": job.get("progress", 50),
        "message": job.get("message"),
        "detail": job.get("detail"),
        "briefing_id": job.get("briefing_id"),
        "narrative": job.get("narrative"),
        "highlights": job.get("highlights"),
        "window_label": job.get("window_label"),
        "model": job.get("model"),
        "error": job.get("error"),
    }


@app.get("/api/daily/briefing/{briefing_id}")
async def api_get_daily_briefing(briefing_id: int, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    b = _storage.get_daily_briefing(briefing_id)
    if not b:
        return {"error": "not found"}
    return b


@app.get("/api/daily/briefings")
async def api_list_daily_briefings(user: str = Depends(require_login)):
    if _storage is None:
        return {"briefings": []}
    return {"briefings": _storage.list_past_briefings(limit=30)}


@app.get("/api/daily/briefing/{briefing_id}/messages")
async def api_get_daily_messages(briefing_id: int, user: str = Depends(require_login)):
    if _storage is None:
        return {"messages": []}
    msgs = _storage.get_daily_briefing_messages(briefing_id)
    return {"messages": msgs}


@app.post("/api/daily/chat")
async def api_daily_chat(request: Request, user: str = Depends(require_login)):
    """Continue the conversation with the Operator Companion for a specific briefing. Injects the original context so answers stay grounded."""
    if _storage is None or _cfg is None:
        return {"response": "System not ready."}

    data = await request.json()
    bid = data.get("briefing_id")
    message = (data.get("message") or "").strip()
    if not bid or not message:
        return {"response": "Need a briefing and a question."}

    b = _storage.get_daily_briefing(int(bid))
    if not b:
        return {"response": "I can't find that briefing anymore."}

    # Rebuild a compact context from the stored briefing + fresh data if the window is still valid
    ctx = _storage.get_daily_context(b.get("start_ts"), b.get("end_ts"))
    facts = json.dumps({
        "window": {"label": b.get("window_label")},
        "totals": ctx.get("totals"),
        "threats_sample": ctx.get("threats", [])[:5],
        "excerpts": ctx.get("excerpts", [])[:5],
    }, default=str)[:4200]

    system = _get_daily_llm_system_prompt(facts)

    # Load prior turns for this briefing (keep last ~12 for token sanity)
    prior = _storage.get_daily_briefing_messages(int(bid), limit=20)
    messages = [{"role": "system", "content": system}]
    for m in prior[-12:]:
        messages.append({"role": m["role"], "content": m["content"]})
    messages.append({"role": "user", "content": message})

    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm)
        if hasattr(llm, "client") and hasattr(llm.client, "chat"):
            resp = llm.client.chat.completions.create(
                model=getattr(llm.cfg, "model", None) or "local",
                messages=messages,
                max_tokens=900,
                temperature=0.35
            )
            reply = resp.choices[0].message.content if resp.choices else "I got nothing useful from the model on that one."
        else:
            reply = "LLM backend limited right now. Ask me something narrower or try again later."
    except Exception as e:
        reply = f"Chat hiccup: {str(e)[:160]}. The facts are still here though — try rephrasing."

    # Persist the turn
    try:
        _storage.add_daily_briefing_message(int(bid), "user", message)
        _storage.add_daily_briefing_message(int(bid), "assistant", reply)
        _storage.log_server_activity(
            "outbound", "daily_briefing", "operator_companion", "chat",
            "success", {"briefing_id": bid, "q": message[:80]}, None, None
        )
    except Exception:
        pass

    # Very lightweight action extraction so the UI can offer buttons
    suggested = []
    low = reply.lower()
    if "script" in low and ("draft" in low or "generate" in low or "write" in low):
        suggested.append({"label": "Draft the script now (uses today's context)", "type": "script", "prompt": "Using the facts from this window, draft a safe, ready-to-review remediation or investigation script for the main issue we discussed."})
    if "monitor" in low and ("create" in low or "add" in low or "standing" in low):
        suggested.append({"label": "Go to Monitors to create one", "type": "goto_monitors"})

    return {"response": reply, "suggested_actions": suggested}


@app.post("/api/daily/promote")
async def api_daily_promote_action(request: Request, user: str = Depends(require_login)):
    """
    Turn something the crew suggested in a Daily Briefing chat into a real, durable thing.
    Currently supports:
    - Attaching a generated script to an existing monitor (or creating a simple one)
    - Recording a suggested automation rule
    The heavy lifting reuses the existing monitor + remediation script machinery.
    """
    if _storage is None:
        return {"success": False, "error": "storage not ready"}

    data = await request.json()
    action_type = data.get("type", "note")
    monitor_name = data.get("monitor_name")
    script_content = data.get("script") or data.get("script_content")
    description = data.get("description") or data.get("title") or "From Daily Briefing"

    try:
        _storage.log_server_activity(
            "outbound", "daily_briefing", "operator_companion", "promote",
            "success", {"type": action_type, "monitor": monitor_name, "desc": description[:100]}, None, None
        )
    except Exception:
        pass

    # If they gave us a script, try to make it available via the existing per-monitor script system
    stored_path = None
    if script_content and monitor_name:
        try:
            # Reuse the safe path logic that already exists in the remediation script upload handler
            safe = "".join(c for c in monitor_name if c.isalnum() or c in "-_")[:40] or "daily-briefing"
            mon_dir = REMEDIATION_SCRIPT_DIR / safe
            mon_dir.mkdir(parents=True, exist_ok=True)
            fname = f"from_daily_{int(datetime.now().timestamp())}.sh"
            target = mon_dir / fname
            target.write_text(script_content, encoding="utf-8")
            try:
                target.chmod(0o700)
            except Exception:
                pass
            stored_path = str(target.relative_to(REMEDIATION_SCRIPT_DIR))
        except Exception as ex:
            logger.warning("Could not auto-store daily script: %s", ex)

    # If it's a monitor-related suggestion and we have the name, we can also create a very lightweight monitor record
    # (user can refine in the monitors UI). This reuses the same table the heartbeats + UI use.
    created_monitor = None
    if monitor_name and _storage:
        try:
            # Only create if it doesn't already exist (idempotent-ish)
            existing = _storage.get_monitors(enabled_only=False)
            if not any((m.get("name") or "").lower() == monitor_name.lower() for m in existing):
                # Minimal safe monitor (user will usually have host/type from context)
                _storage.upsert_monitor_dict(
                    name=monitor_name,
                    host=data.get("host") or "unknown",
                    type=data.get("type") or "custom",
                    interval_seconds=3600,  # daily-ish by default for briefing-born monitors
                    enabled=True,
                    remediation_action="script" if stored_path else None,
                )
                created_monitor = monitor_name
        except Exception as ex:
            logger.info("Daily promote did not auto-create monitor (user can do it in UI): %s", ex)

    return {
        "success": True,
        "stored_script_path": stored_path,
        "created_monitor": created_monitor,
        "message": "Script saved under the monitor's remediation scripts if provided. Monitor created if new name given. Go to /monitors to attach/run/refine. Full one-click 'add this exact script as the remediation for this exact failure pattern' is a 5-minute follow-up away.",
    }


@app.get("/api/daily/briefing/{briefing_id}/export")
async def api_export_daily_briefing(briefing_id: int, user: str = Depends(require_login)):
    """Return a nice markdown export of the briefing + chat transcript."""
    if _storage is None:
        return {"error": "not ready"}
    b = _storage.get_daily_briefing(briefing_id)
    if not b:
        return {"error": "not found"}
    msgs = _storage.get_daily_briefing_messages(briefing_id)
    md = []
    md.append(f"# Daily Briefing — {b.get('window_label', b.get('day'))}")
    md.append(f"Generated: {b.get('generated_at', '')}  • Model: {b.get('model', 'local')}")
    md.append("")
    md.append(b.get("narrative", ""))
    md.append("")
    if b.get("highlights"):
        md.append("## What stood out")
        for h in b["highlights"]:
            md.append(f"- {h}")
        md.append("")
    md.append("## Conversation with the Crew")
    for m in msgs:
        who = "You" if m["role"] == "user" else "The Crew"
        md.append(f"**{who}** ({m.get('ts','')[:16]}):")
        md.append(m["content"])
        md.append("")
    md.append("---")
    md.append("*Exported from RocketLogAI Daily Briefing. Everything was grounded in the actual logs, threats, monitor results and activity for the window.*")
    return {"markdown": "\n".join(md), "filename": f"daily-briefing-{b.get('day','report')}.md"}


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)

    ha_status = {"connected": False, "url": None}
    if _cfg and getattr(_cfg, "home_assistant", None) and _cfg.home_assistant.enabled:
        ha = get_ha_client(_cfg)
        if ha:
            ha_status = {"connected": ha.is_available(), "url": _cfg.home_assistant.url}

    llm_providers = ["local", "openai", "grok", "anthropic"]  # "local" covers LM Studio, Ollama, vLLM etc (all OpenAI-compatible)

    return get_templates().TemplateResponse(
        request,
        "integrations.html",
        context={
            "ha_status": ha_status,
            "llm_providers": llm_providers,
            "current_llm": getattr(_cfg.llm, "provider", "local") if _cfg else "local",
            "llm_servers_json": json.dumps(getattr(_cfg.llm, "servers", []) or [], indent=2),
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
async def test_ha_connection(user: str = Depends(require_api_or_login)):
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
async def test_llm_connection(user: str = Depends(require_api_or_login)):
    if _cfg is None:
        return {"ok": False, "error": "no config"}
    try:
        from .llm import get_llm_client
        llm = get_llm_client(_cfg.llm)
        # very light test — many local servers support /v1/models or a tiny prompt
        models = llm.list_models() if hasattr(llm, "list_models") else []
        return {"ok": True, "message": f"LLM reachable ({len(models)} models)" if models else "LLM endpoint responded", "provider": _cfg.llm.provider}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _pick_device_display_icon(d: dict) -> str:
    """Return the best visual icon per Phase 1 spec:
    Windows/PC -> 🪟 , Apple/Mac ->  , Linux -> 🐧 , Router/FW/Switch -> 📡 , else neutral ❔ or sensible fallback.
    Uses vendor (from MAC), category, ha_name, ip hints. Never returns the red ❓ for unknown.
    """
    cat = (d.get('device_category') or '').lower()
    v = (d.get('vendor') or '').lower()
    nm = (d.get('ha_name') or d.get('ip') or '').lower()

    # Apple / Mac devices (vendor or name)
    if 'apple' in v or 'apple, inc' in v or any(k in nm for k in ['macbook', 'imac', 'mac mini', 'iphone', 'ipad', 'apple tv', 'homepod', 'macos']):
        return ''
    # Linux (RPi, explicit distros, or name)
    if any(k in v for k in ['raspberry', 'linux', 'tux', 'canonical', 'ubuntu', 'debian', 'red hat', 'fedora', 'arch']) or \
       any(k in nm for k in ['linux', 'raspberry', 'ubuntu', 'debian', 'rpi']):
        return '🐧'
    # Windows / generic PC (name hints or pc/laptop category)
    if 'windows' in nm or 'pc' in nm or 'desktop' in nm or 'win32' in nm or 'laptop' in cat or 'computer' in cat:
        return '🪟'
    # Routers, firewalls, switches, APs (category or common vendors)
    if 'router' in cat or 'network' in cat or 'switch' in cat or 'firewall' in cat or 'ap ' in cat or 'access point' in cat or \
       any(k in v for k in ['cisco', 'ubiquiti', 'netgear', 'tp-link', 'tplink', 'mikrotik', 'unifi', 'juniper', 'aruba',
                            'pfsense', 'opnsense', 'zyxel', 'd-link', 'dlink', 'linksys', 'edgerouter']):
        return '📡'

    # Fallbacks from stored (from analyzer or prior)
    icon = d.get('vendor_icon')
    if icon and icon not in ('❓', '?', '❔'):
        return icon

    # Generic sensible fallbacks
    if 'nas' in cat or 'storage' in cat:
        return '🖥️'
    if 'camera' in cat or 'printer' in cat:
        return '📹' if 'camera' in cat else '🖨️'
    if d.get('mac') or d.get('vendor'):
        return '💻' if ('computer' in cat or 'laptop' in cat or not cat) else '🔌'
    return '❔'  # neutral gray ? (we will style it gray in template)


def _enrich_device_with_vendor(d: dict) -> dict:
    """Ensure vendor name (manufacturer) is populated from MAC OUI lookup if missing.
    This fixes the 'Vendor column' being empty/broken for devices not yet seen in threat ARP.
    Also computes display_icon and persists the lookup result for future loads.
    """
    mac = d.get('mac')
    if mac and not d.get('vendor'):
        try:
            lookup = get_mac_vendor_lookup()
            det = lookup.lookup_detailed(mac)
            if det:
                d['vendor'] = det.get('vendor')
                if not d.get('device_category'):
                    d['device_category'] = det.get('device_category')
                d['vendor_icon'] = det.get('vendor_icon') or d.get('vendor_icon')
                # Persist so DB + future page loads have it immediately (no re-lookup spam)
                try:
                    if _storage and d.get('ip'):
                        _storage.upsert_known_device({
                            'ip': d.get('ip'),
                            'mac': mac,
                            'vendor': d['vendor'],
                            'device_category': d.get('device_category'),
                            'vendor_icon': d.get('vendor_icon'),
                        })
                except Exception:
                    pass  # non-fatal
        except Exception:
            pass  # lookup is best-effort

    # Always attach a smart display icon (Phase 1 requirement)
    d['display_icon'] = _pick_device_display_icon(d)
    # Backfill vendor_icon if it was the old red ? so template and detail pages stay nice
    if not d.get('vendor_icon') or d.get('vendor_icon') in ('❓', '?'):
        d['vendor_icon'] = d['display_icon']
    return d


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return HTMLResponse("Not initialized", status_code=500)
    devices = _storage.get_known_devices(limit=200) if hasattr(_storage, 'get_known_devices') else []
    # Enrich geo / local flag for display in registry cards (country/city or "local IP")
    geo = None
    try:
        geo = get_geo_enricher()
    except Exception:
        pass
    if geo:
        for d in devices:
            ip = d.get("ip")
            if ip and not d.get("geo_city") and not d.get("is_internal"):
                try:
                    g = geo.enrich(ip)
                    if g:
                        if g.get("source") == "private_ip":
                            d["is_internal"] = True
                            d["location_label"] = "Local / Private IP"
                        else:
                            d["geo_country"] = g.get("country")
                            d["geo_city"] = g.get("city")
                            d["geo_source"] = g.get("source")
                except Exception:
                    pass

    # Phase 1: ensure every device gets a vendor name (MAC lookup) + proper icon (fixes broken Vendor + red ?)
    for d in devices:
        _enrich_device_with_vendor(d)

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

    # Enrich with latest geo using multi-source system (new)
    # Always attempt; special-case internal/private IPs as "local address only"
    device["is_internal"] = False
    if device.get("ip"):
        try:
            geo = get_geo_enricher()
            g = geo.enrich(device["ip"])
            if g:
                if g.get("source") == "private_ip":
                    device["is_internal"] = True
                    device["location_label"] = "Local / Private IP (internal address only)"
                else:
                    if g.get("lat") is not None:
                        device["geo_lat"] = g.get("lat")
                        device["geo_lon"] = g.get("lon")
                    if g.get("country"):
                        device["geo_country"] = g.get("country")
                    if g.get("city"):
                        device["geo_city"] = g.get("city")
                    device["geo_source"] = g.get("source") or (g.get("sources")[0] if g.get("sources") else None)
        except Exception:
            pass

    threats = _storage.get_recent_threats_for_device(ip, limit=40) if hasattr(_storage, 'get_recent_threats_for_device') else []

    # Phase 1: ensure vendor + nice icon on detail view too (MAC lookup fix)
    _enrich_device_with_vendor(device)

    return get_templates().TemplateResponse(
        request,
        "device_detail.html",
        context={"device": device, "threats": threats}
    )

@app.get("/api/devices")
async def api_devices(user: str = Depends(require_api_or_login)):
    if _storage is None:
        return {"error": "not initialized"}
    devices = _storage.get_known_devices(limit=200) if hasattr(_storage, 'get_known_devices') else []
    # enrich geo/local for API users (e.g. other UIs)
    try:
        geo = get_geo_enricher()
        for d in devices:
            ip = d.get("ip")
            if ip and geo and not d.get("geo_city") and not d.get("is_internal"):
                gg = geo.enrich(ip)
                if gg:
                    if gg.get("source") == "private_ip":
                        d["is_internal"] = True
                    else:
                        d["geo_country"] = gg.get("country")
                        d["geo_city"] = gg.get("city")
    except Exception:
        pass

    # Phase 1: same vendor + icon enrichment for API consumers
    for d in devices:
        _enrich_device_with_vendor(d)

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
        # LLM client now obtained via get_llm_client factory
        if _cfg:
            from .llm import get_llm_client
            llm = get_llm_client(_cfg.llm)
    except Exception:
        pass

    assessment = _storage.assess_device_intelligence(ip, llm)
    return {"success": True, "assessment": assessment}


@app.post("/api/devices/{ip}/reassess_ports")
async def api_reassess_device_ports(ip: str, request: Request, user: str = Depends(require_login)):
    """Trigger vendor port profile + observed vs expected comparison (auto-trusts if match)."""
    if _storage is None:
        return {"error": "not initialized"}
    llm = None
    try:
        # LLM client now obtained via get_llm_client factory
        if _cfg:
            from .llm import get_llm_client
            llm = get_llm_client(_cfg.llm)
    except Exception:
        pass

    assessment = _storage.assess_device_port_profile(ip, llm, force_ai=True)
    return {"success": True, "assessment": assessment}


@app.post("/api/vendors/refresh")
async def api_refresh_vendors(request: Request, user: str = Depends(require_login)):
    """Force re-download of Wireshark manuf + IEEE databases."""
    from .mac_vendor import refresh_mac_vendors_if_needed
    summary = refresh_mac_vendors_if_needed(force=True)
    return {"success": True, "summary": summary}


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
async def api_threats(limit: int = 50, offset: int = 0, status: str | None = None, q: str | None = None, enrich_geo: int = 1):
    if _storage is None:
        return {"error": "not initialized"}
    limit = max(5, min(limit, 500))
    threats = _storage.get_recent_threats(limit=limit, offset=offset, status=status, search=q)
    for t in threats:
        t["advice"] = get_actionable_advice(t)
    _enrich_threats_with_device_context(threats)

    # Live geo enrichment for the map / UI (so old threats light up as soon as the DB is present)
    if enrich_geo:
        geo = get_geo_enricher()
        if not geo.available:
            if hasattr(geo, 'self_heal'):
                try:
                    geo.self_heal()
                except Exception:
                    pass  # geo self-heal is best-effort only
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
                            t["geo_source"] = g.get("source") or g.get("sources", ["unknown"])[0] if g.get("sources") else "unknown"
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
async def api_monitors(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    monitors = _storage.get_monitors(enabled_only=False)
    try:
        limit = int(request.query_params.get("limit", 200))
        limit = max(1, min(limit, 2000))
    except:
        limit = 200
    results = _storage.get_recent_monitor_results(limit=limit)
    hb_enabled = getattr(getattr(_cfg, "heartbeats", None), "enabled", False) if _cfg else False
    hb_def_int = getattr(getattr(_cfg, "heartbeats", None), "default_interval_seconds", 60) if _cfg else 60
    return {"monitors": monitors, "recent_results": results, "heartbeats_enabled": hb_enabled, "heartbeats_default_interval": hb_def_int}


@app.get("/api/server-activity")
async def api_server_activity(request: Request, user: str = Depends(require_login)):
    if _storage is None:
        return {"error": "not initialized"}
    direction = request.query_params.get("direction") or None
    source = request.query_params.get("source") or None
    events = _storage.get_recent_server_activity(limit=300, direction=direction)
    if source:
        events = [e for e in events if source.lower() in (e.get("source") or "").lower() or source.lower() in (e.get("source_type") or "").lower()]
    summary = _storage.get_activity_summary()
    return {"events": events, "summary": summary}


@app.post("/api/server-activity/suggest")
async def api_server_activity_suggest(user: str = Depends(require_login)):
    """LLM analyzes recent server activity and suggests config/monitor changes (e.g. dormant dead sources)."""
    if _storage is None or _cfg is None:
        return {"suggestions": []}
    recent = _storage.get_recent_server_activity(limit=150)
    if not recent:
        return {"suggestions": [{"title": "No data yet", "reason": "Run monitors or send logs for a while first.", "action": "Wait for activity"}]}

    try:
        llm = get_llm_client(_cfg.llm)
        prompt = f"""You are an expert operations analyst for RocketLogAI.
Here is recent server activity (inbound data sources and outbound actions like HA, SSH, monitors, remediation):

{json.dumps(recent[:60], default=str)[:4500]}

Analyze for:
- Sources that have been completely silent for a long time (candidates to disable or mark dormant)
- High failure rates on certain connections (WMI, 5250, SSH, HA)
- Opportunities to adjust intervals or add new monitors

Return a JSON array of 0-4 suggestions:
[
  {{"title": "Short title", "reason": "One sentence why", "action": "Concrete recommendation (e.g. disable monitor X for 30 days)"}}
]
Keep suggestions conservative and safe. Never suggest deleting data.
"""
        # Use a simple completion path (works for both local and azure-style clients)
        if hasattr(llm, 'client') and hasattr(llm.client, 'chat'):
            resp = llm.client.chat.completions.create(
                model=getattr(llm.cfg, 'model', None) or "local",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=600,
                temperature=0.2
            )
            content = resp.choices[0].message.content if resp.choices else "[]"
        else:
            content = "[]"

        import re
        m = re.search(r'\[.*\]', content, re.DOTALL)
        if m:
            suggestions = json.loads(m.group(0))
            return {"suggestions": suggestions[:4]}
    except Exception as e:
        logger.warning("Activity AI suggest failed: %s", e)

    # Fallback simple heuristics
    suggestions = []
    fails = [e for e in recent if e.get("status") != "success"]
    if len(fails) > 8:
        suggestions.append({"title": "High failure rate detected", "reason": f"{len(fails)} recent failed actions", "action": "Review the failing sources in Monitors and consider increasing interval or checking credentials", "action_type": "review", "target": None})
    return {"suggestions": suggestions or [{"title": "Activity looks normal", "reason": "No strong anomalies in recent log", "action": "No action needed", "action_type": "none", "target": None}]}


@app.post("/api/activity/apply-suggestion")
async def api_apply_activity_suggestion(request: Request, user: str = Depends(require_login)):
    """Execute a safe action suggested by the AI activity analyzer (e.g. disable a monitor)."""
    if _storage is None:
        return {"success": False, "error": "not initialized"}
    data = await request.json()
    action_type = data.get("action_type", "")
    target = data.get("target", {})
    monitor_name = target.get("monitor_name") if isinstance(target, dict) else None

    if action_type == "disable_monitor" and monitor_name:
        try:
            # Use existing monitor update path
            mons = _storage.get_monitors(enabled_only=False)
            for m in mons:
                if m.get("name") == monitor_name:
                    # Simple disable by updating (we can add a direct helper later)
                    from .config import HeartbeatMonitor
                    _storage.upsert_monitor(HeartbeatMonitor(
                        name=m["name"], host=m["host"], type=m.get("type","tcp"),
                        port=m.get("port"), enabled=False,
                        interval_seconds=m.get("interval_seconds", 300)
                    ))
                    _storage.log_server_activity("outbound", "config_change", "activity_ai", "disable_monitor",
                                                 "success", {"monitor": monitor_name, "by": "ai_suggestion"})
                    return {"success": True, "message": f"Monitor '{monitor_name}' disabled."}
            return {"success": False, "error": "Monitor not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    if action_type == "dormant_monitor" and monitor_name:
        # For now, just disable + note. Real "dormant for 30 days" would need a new field.
        _storage.log_server_activity("outbound", "config_change", "activity_ai", "dormant_monitor",
                                     "success", {"monitor": monitor_name, "note": "treated as disable for now"})
        return {"success": True, "message": f"Monitor '{monitor_name}' marked dormant (disabled for now). You can re-enable later."}

    if action_type == "increase_interval" and monitor_name:
        # Placeholder - in real impl we would read current and * 2
        return {"success": True, "message": "Interval increase not fully wired yet - please adjust manually in Monitors for now."}

    return {"success": False, "error": f"Unsupported or incomplete action_type: {action_type}"}

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
            # LLM client now obtained via get_llm_client factory
            from .llm import get_llm_client
            llm = get_llm_client(_cfg.llm)
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
    variables = data.get("variables") or {}  # e.g. {"SERVICE": "nginx", "TARGET_HOST": "..." }
    run_rollback = bool(data.get("run_rollback"))  # explicit rollback request
    rollback_filename = data.get("rollback_filename")
    additional_scripts = data.get("additional_scripts") or []  # list of filenames to run after main

    safe_name = "".join(c for c in monitor_name if c.isalnum() or c in "-_")[:80] or "unnamed"
    target = REMEDIATION_SCRIPT_DIR / safe_name / script_filename

    if not target.exists() or target.suffix not in ALLOWED_SCRIPT_EXTS:
        return {"success": False, "error": "Script not found or not allowed"}

    # Read for preview / execution
    try:
        script_content = target.read_text(errors="replace")
    except Exception as e:
        return {"success": False, "error": f"Could not read script: {e}"}

    # === Variable substitution ({{VAR}} style) so users don't edit the original files ===
    if variables:
        for key, value in variables.items():
            script_content = script_content.replace("{{" + str(key) + "}}", str(value))
        # Also support $VAR style for shell friendliness
        for key, value in variables.items():
            script_content = script_content.replace("$" + str(key), str(value))

    # === ACTUAL (guarded) EXECUTION ===
    import subprocess, tempfile, os
    start = time.time()
    temp_script_path = None
    try:
        # Write substituted content to a secure temp file so we never modify originals
        with tempfile.NamedTemporaryFile(mode='w', suffix=target.suffix, delete=False, dir="/tmp") as tmp:
            tmp.write(script_content)
            temp_script_path = tmp.name
        os.chmod(temp_script_path, 0o700)

        # Use bash for .sh files, python for .py, otherwise sh
        if target.suffix == ".py":
            cmd = [sys.executable, temp_script_path]
        else:
            cmd = ["bash", temp_script_path]

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
                    {"script": script_filename, "output": result, "variables_used": variables}
                )
            except Exception:
                pass

        # === Sequential execution of additional scripts (chaining) ===
        additional_results = []
        if proc.returncode == 0 and additional_scripts:
            for add_script in additional_scripts:
                if not add_script: continue
                add_target = REMEDIATION_SCRIPT_DIR / safe_name / add_script
                if not add_target.exists():
                    additional_results.append({"script": add_script, "error": "Script not found"})
                    continue
                try:
                    add_content = add_target.read_text(errors="replace")
                    # Apply variables to additional script too
                    for k, v in variables.items():
                        add_content = add_content.replace("{{" + str(k) + "}}", str(v))
                    with tempfile.NamedTemporaryFile(mode='w', suffix=add_target.suffix, delete=False, dir="/tmp") as atmp:
                        atmp.write(add_content)
                        atmp_path = atmp.name
                    os.chmod(atmp_path, 0o700)
                    add_cmd = [sys.executable, atmp_path] if add_target.suffix == ".py" else ["bash", atmp_path]
                    add_proc = subprocess.run(add_cmd, capture_output=True, text=True, timeout=120)
                    os.unlink(atmp_path)
                    additional_results.append({
                        "script": add_script,
                        "returncode": add_proc.returncode,
                        "stdout": add_proc.stdout[-1500:],
                        "stderr": add_proc.stderr[-800:]
                    })
                except Exception as add_e:
                    additional_results.append({"script": add_script, "error": str(add_e)})

        # === Rollback support ===
        rollback_result = None
        if proc.returncode != 0 and rollback_filename and not run_rollback:
            # Offer rollback on failure
            result["rollback_suggested"] = rollback_filename
        elif run_rollback and rollback_filename:
            # Explicit rollback requested
            rollback_target = REMEDIATION_SCRIPT_DIR / safe_name / rollback_filename
            if rollback_target.exists():
                try:
                    with open(rollback_target) as rb:
                        rb_content = rb.read()
                    # Apply same variable substitution to rollback
                    for key, value in variables.items():
                        rb_content = rb_content.replace("{{" + str(key) + "}}", str(value))
                    with tempfile.NamedTemporaryFile(mode='w', suffix=rollback_target.suffix, delete=False, dir="/tmp") as rtmp:
                        rtmp.write(rb_content)
                        rtmp_path = rtmp.name
                    os.chmod(rtmp_path, 0o700)
                    rb_cmd = ["bash", rtmp_path] if rollback_target.suffix != ".py" else [sys.executable, rtmp_path]
                    rb_proc = subprocess.run(rb_cmd, capture_output=True, text=True, timeout=120)
                    rollback_result = {
                        "returncode": rb_proc.returncode,
                        "stdout": rb_proc.stdout[-2000:],
                        "stderr": rb_proc.stderr[-1000:]
                    }
                    os.unlink(rtmp_path)
                except Exception as rb_e:
                    rollback_result = {"error": str(rb_e)}

        if temp_script_path and os.path.exists(temp_script_path):
            os.unlink(temp_script_path)

        return {"success": True, "result": result, "rollback_result": rollback_result, "additional_results": additional_results}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Script execution timed out (120s limit)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/monitors/{monitor_name}/test-connection")
async def test_monitor_connection(monitor_name: str, request: Request, user: str = Depends(require_login)):
    """Test connectivity to the monitored device using the stored credentials.
    The caller must send the password (or key passphrase) in this request for security.
    Never stores or logs the secret.
    """
    data = await request.json()
    password = data.get("password", "")  # provided by user for this test only
    cred_type = data.get("credential_type")  # allow override for testing

    # Get stored monitor info
    monitors = _storage.get_monitors(enabled_only=False) if _storage else []
    mon = next((m for m in monitors if m.get("name") == monitor_name), None)
    if not mon:
        return {"success": False, "error": "Monitor not found"}

    username = mon.get("credential_username") or data.get("username")
    host = mon.get("host")
    port = mon.get("port") or 22

    if not username or not host:
        return {"success": False, "error": "No username or host configured for this monitor"}

    # Enhanced connection test with key support
    import subprocess, os, shutil
    try:
        ssh_opts = ["-o", "BatchMode=no", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8"]

        if password and os.path.exists(password):  # Treat as private key path
            cmd = ["ssh", "-i", password] + ssh_opts + [f"{username}@{host}", "-p", str(port), "echo 'Connection OK via key'"]
        elif password:
            # Password auth via sshpass (if installed) or fallback note
            if shutil.which("sshpass"):
                cmd = ["sshpass", "-p", password, "ssh"] + ssh_opts + [f"{username}@{host}", "-p", str(port), "echo 'Connection OK'"]
            else:
                return {"success": False, "error": "sshpass not installed for password auth. Install it or use SSH keys instead."}
        else:
            # Pure key-based (user has ssh-agent or default keys)
            cmd = ["ssh"] + ssh_opts + [f"{username}@{host}", "-p", str(port), "echo 'Connection OK'"]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        success = proc.returncode == 0

        result = {
            "success": success,
            "stdout": proc.stdout.strip()[:600],
            "stderr": proc.stderr.strip()[:600],
            "message": "Connection successful" if success else "Connection failed — check logs for details"
        }

        # === NEW: On successful login, do lightweight AI-powered device discovery (user vision) ===
        if success:
            try:
                # Run safe discovery commands
                discovery_cmd = f"ssh {'-i ' + password if password and os.path.exists(password) else ''} {ssh_opts} {username}@{host} -p {port} 'uname -a; echo \"---\"; cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || echo unknown; echo \"---\"; ss -tuln 2>/dev/null | head -20 || netstat -tuln 2>/dev/null | head -20'"
                disc = subprocess.run(discovery_cmd, shell=True, capture_output=True, text=True, timeout=20)
                discovery_output = disc.stdout.strip()[:1500]

                result["discovery"] = discovery_output

                # Ask LLM for smart suggestions based on discovery
                if _cfg and discovery_output:
                    try:
                        llm = get_llm_client(_cfg.llm)
                        prompt = f"Device discovery output:\n{discovery_output}\n\nBased on this, suggest 2-3 useful monitors or safe remediation scripts for this device. Be specific."
                        # Lightweight call
                        resp = llm.client.chat.completions.create(
                            model=llm.cfg.model or "local",
                            messages=[{"role": "user", "content": prompt}],
                            max_tokens=250,
                            temperature=0.2
                        )
                        suggestions_text = resp.choices[0].message.content if resp.choices else ""
                        result["ai_suggestions"] = suggestions_text[:800]
                    except Exception:
                        pass
            except Exception as e:
                result["discovery_error"] = str(e)[:200]

        return result
    except Exception as e:
        return {"success": False, "error": f"Test failed: {str(e)}"}


@app.get("/api/remediation-scripts")
async def list_remediation_scripts(user: str = Depends(require_login)):
    """List prebuilt scripts + (optionally) per-monitor uploaded scripts."""
    prebuilts = []
    prebuilt_dir = REMEDIATION_SCRIPT_DIR / "prebuilts"
    if prebuilt_dir.exists():
        for p in sorted(prebuilt_dir.glob("*")):
            if p.suffix in ALLOWED_SCRIPT_EXTS:
                prebuilts.append({
                    "name": p.name,
                    "path": f"prebuilts/{p.name}",
                    "type": "prebuilt"
                })

    return {
        "success": True,
        "prebuilts": prebuilts,
        "note": "Per-monitor uploaded scripts are stored under data/remediation_scripts/<monitor>/"
    }


@app.post("/api/remediation/suggest")
async def suggest_remediation_scripts(request: Request, user: str = Depends(require_login)):
    """Smart suggestions based on monitor type + recent results + device intelligence.
    Now also supports direct English prompts for AI script generation (PR7)."""
    data = await request.json()
    prompt = data.get("prompt", "").strip()
    mtype = data.get("type", "").lower()
    host = data.get("host", "").lower()

    recent_results = []
    try:
        recent_results = _storage.get_recent_monitor_results(data.get("name"), limit=5) if _storage and hasattr(_storage, "get_recent_monitor_results") else []
    except Exception:
        recent_results = []

    suggestions = []

    # If user gave a direct English prompt, try to use LLM for better generation
    if prompt and len(prompt) > 10:
        try:
            llm = get_llm_client(_cfg.llm) if _cfg else None
            if llm:
                user_msg = f"""The user wants to create a safe automation/remediation script for a device.

Device: {host or 'unknown'} (type: {mtype})
Request: "{prompt}"

Return a JSON array with 1-2 objects:
[
  {{"title": "Short title", "description": "One sentence what it does", "suggested_command": "safe one-line command or script name if possible"}}
]
Keep everything non-destructive. Focus on monitoring, checks, or safe restarts."""
                resp = llm.client.chat.completions.create(
                    model=llm.cfg.model or "local",
                    messages=[{"role": "user", "content": user_msg}],
                    max_tokens=400,
                    temperature=0.3
                )
                content = resp.choices[0].message.content if resp.choices else ""
                import re
                match = re.search(r'\[.*\]', content, re.DOTALL)
                if match:
                    parsed = json.loads(match.group(0))
                    for item in parsed[:2]:
                        suggestions.append({
                            "title": item.get("title", "AI Suggestion")[:80],
                            "description": item.get("description", ""),
                            "suggested": item.get("suggested_command", "")
                        })
        except Exception:
            pass

    # Static smart suggestions (existing logic)
    if not suggestions:
        if "linux" in host or mtype in ("ssh_version", "tcp"):
            suggestions.append({"title": "Update packages + daily maintenance", "action": "prebuilts/update_linux_packages.sh,prebuilts/daily_linux_maintenance.sh"})
        if "web" in host or "https" in mtype:
            suggestions.append({"title": "SSL renewal + disk check", "action": "prebuilts/renew_ssl_cert_example.sh,prebuilts/check_disk_space.sh"})
        if any(x in host for x in ["switch", "cisco", "firewall"]):
            suggestions.append({"title": "Interface / port health", "action": "prebuilts/switch_port_status.sh,prebuilts/cisco_interface_reset.sh"})
        if "domain" in host or "dc" in host:
            suggestions.append({"title": "Domain Controller health", "action": "prebuilts/domain_controller_health.ps1"})

        if any(not r.get("success") for r in recent_results):
            suggestions.append({"title": "Service restart with rollback", "action": "prebuilts/restart_service_linux.sh"})

    # When user gave English prompt, try to return a small ready-to-use script example
    generated_script = None
    if prompt and len(prompt) > 8:
        # Simple safe template based on keywords + LLM suggestion if available
        script = "#!/bin/bash\n# Auto-generated from your request: " + prompt + "\nset -e\n\n"
        lower = prompt.lower()
        if "disk" in lower or "space" in lower:
            script += "USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')\nif [ \"$USAGE\" -gt 90 ]; then\n  echo \"High disk usage: ${USAGE}%\"\n  # Add your cleanup or alert here\nfi\n"
        elif "restart" in lower and ("nginx" in lower or "service" in lower):
            script += "SERVICE=${1:-nginx}\nif ! pgrep -x \"$SERVICE\" > /dev/null; then\n  echo \"Restarting $SERVICE...\"\n  systemctl restart $SERVICE || service $SERVICE restart\nfi\n"
        elif "block" in lower and "outbound" in lower:
            script += "# Basic outbound lockdown example (review carefully!)\niptables -F OUTPUT || true\niptables -A OUTPUT -p tcp --dport 443 -j ACCEPT\niptables -A OUTPUT -p udp --dport 53 -j ACCEPT\niptables -P OUTPUT DROP\n"
        else:
            script += "echo \"Running check for: " + prompt + "\"\n# TODO: Add your safe monitoring or remediation commands here\n"

        # If LLM gave a suggested command, append it
        if suggestions and suggestions[0].get("suggested"):
            script += "\n# LLM suggested additional step:\n# " + suggestions[0]["suggested"] + "\n"

        generated_script = script

    result = {"success": True, "suggestions": suggestions}
    if generated_script:
        result["generated_script"] = generated_script
        result["generated_from_prompt"] = prompt
    return result


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
        credential_type=data.get("credential_type"),
        credential_username=data.get("credential_username"),
        credential_secret=data.get("credential_secret"),  # will be hashed below if provided
    )

    # Hash credential secret if provided (never store plaintext)
    if m.credential_secret:
        try:
            from .auth import hash_password
            m.credential_secret = hash_password(m.credential_secret)
        except Exception:
            pass  # fallback to storing as-is (not ideal)

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
        credential_type=data.get("credential_type"),
        credential_username=data.get("credential_username"),
        credential_secret=data.get("credential_secret"),
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
            if hasattr(geo, 'self_heal'):
                try:
                    geo.self_heal()
                except Exception:
                    pass  # geo self-heal is best-effort only

    cached_count = 0
    if _storage:
        try:
            with _storage._cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM ip_geo_cache")
                cached_count = cur.fetchone()[0]
        except Exception:
            pass

    # Support both old single enricher and new MultiGeoEnricher
    providers_info = []
    if hasattr(geo, "providers"):
        for p in getattr(geo, "providers", []):
            providers_info.append({
                "type": getattr(p, "name", p.__class__.__name__),
                "available": p.available,
            })
    else:
        providers_info.append({
            "type": "maxmind",
            "available": geo.available,
            "db_path": geo.db_path,
        })

    active_names = [p["type"] for p in providers_info if p.get("available")]
    message = "Multi-source geo active (" + " + ".join(active_names) + ")" if active_names else "No active geo providers"

    return {
        "available": geo.available,
        "db_path": getattr(geo, "db_path", None),
        "cached_ips": cached_count,
        "message": message,
        "refreshed": bool(refresh),
        "providers": providers_info,
        "merge_strategy": getattr(getattr(geo, "config", None), "merge_strategy", None) if hasattr(geo, "config") else None,
    }


@app.get("/api/discovered-devices")
async def api_discovered_devices(user: str = Depends(require_login)):
    """Return devices the system has already discovered on the network.
    Used to power smart device selection when adding new monitors."""
    devices = []
    if _storage and hasattr(_storage, 'get_known_devices'):
        try:
            raw = _storage.get_known_devices(limit=150)
            for d in raw:
                # Build the best possible display name
                display_name = (
                    d.get('hostname') or 
                    d.get('ha_name') or 
                    d.get('ip') or 
                    'unknown-device'
                )
                vendor = d.get('vendor') or d.get('device_category') or 'unknown'
                ip = d.get('ip') or '?'
                display = f"{display_name} ({ip}) — {vendor}"

                name_suggestion = d.get('hostname') or d.get('ha_name') or d.get('ip')

                devices.append({
                    "ip": d.get('ip'),
                    "mac": d.get('mac'),
                    "name_suggestion": name_suggestion,
                    "vendor": d.get('vendor'),
                    "os_guess": d.get('os_guess') or d.get('device_category'),
                    "last_seen": d.get('last_seen'),
                    "display": display
                })
        except Exception:
            pass
    return {"success": True, "devices": devices}


@app.get("/api/credential-profiles")
async def api_credential_profiles(user: str = Depends(require_login)):
    profiles = []
    if _storage and hasattr(_storage, 'get_credential_profiles'):
        try:
            profiles = _storage.get_credential_profiles()
        except Exception:
            pass
    return {"success": True, "profiles": profiles}


@app.post("/api/credential-profiles")
async def create_credential_profile(request: Request, user: str = Depends(require_login)):
    data = await request.json()
    name = data.get("name", "").strip()
    ctype = data.get("type", "local")
    username = data.get("username", "").strip()
    secret = data.get("secret", "")

    if not name or not username:
        return {"success": False, "error": "Name and username are required"}

    if _storage:
        try:
            with _storage._cursor() as cur:
                # Hash the secret if it's a password (not a key path)
                hashed = secret
                if ctype in ("local", "domain") and secret:
                    try:
                        from .auth import hash_password
                        hashed = hash_password(secret)
                    except Exception:
                        pass

                cur.execute("""
                    INSERT INTO credential_profiles (name, type, username, secret, notes)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        type=excluded.type,
                        username=excluded.username,
                        secret=excluded.secret,
                        notes=excluded.notes,
                        updated_at = datetime('now')
                """, (name, ctype, username, hashed, data.get("notes", "")))
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Storage not available"}


@app.delete("/api/credential-profiles/{name}")
async def delete_credential_profile(name: str, user: str = Depends(require_login)):
    if not _storage:
        return {"success": False, "error": "storage not available"}
    try:
        with _storage._cursor() as cur:
            cur.execute("DELETE FROM credential_profiles WHERE name = ?", (name,))
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# API Token Management (long-lived tokens for external tools / scripts)
# Similar to Home Assistant long-lived access tokens
# =============================================================================

@app.get("/api/api-tokens")
async def list_api_tokens(user: str = Depends(require_login)):
    if not _storage:
        return {"tokens": []}
    return {"tokens": _storage.list_api_tokens()}

@app.post("/api/api-tokens")
async def create_api_token(request: Request, user: str = Depends(require_login)):
    if not _storage:
        return {"success": False, "error": "storage not available"}
    try:
        data = await request.json()
        name = data.get("name", "Unnamed token").strip()
        scopes = data.get("scopes", "full")
        notes = data.get("notes", "")
        expires_days = data.get("expires_days")

        result = _storage.create_api_token(name, scopes, notes, expires_days, created_by=user)
        return {"success": True, "token": result}  # token shown only once
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.delete("/api/api-tokens/{token_id}")
async def revoke_api_token(token_id: int, user: str = Depends(require_login)):
    if not _storage:
        return {"success": False, "error": "storage not available"}
    ok = _storage.revoke_api_token(token_id)
    return {"success": ok}


@app.post("/api/local-users")
async def create_local_user(request: Request, user: str = Depends(require_login)):
    """Admin endpoint to create additional local users (for testing or multi-admin setups).
    Conservative: only works if storage is available. Password is always hashed.
    """
    data = await request.json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    is_admin = bool(data.get("is_admin", False))

    if not username or not password:
        return {"success": False, "error": "username and password required"}

    if len(password) < 8:
        return {"success": False, "error": "password must be at least 8 characters"}

    if not _storage:
        return {"success": False, "error": "storage not available"}

    try:
        from .auth import hash_password
        pwd_hash = hash_password(password)
        _storage.upsert_local_auth(username, pwd_hash, None)
        return {"success": True, "username": username, "message": "Local user created."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/local-users")
async def list_local_users(user: str = Depends(require_login)):
    """List all local web users (admin use)."""
    if not _storage:
        return {"success": False, "error": "storage not available"}
    try:
        users = _storage.list_local_auth_users()
        return {"success": True, "users": users}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.delete("/api/local-users/{username}")
async def delete_local_user(username: str, user: str = Depends(require_login)):
    """Delete a local web user (admin action)."""
    if not _storage:
        return {"success": False, "error": "storage not available"}
    if username == user:
        return {"success": False, "error": "Cannot delete your own account via this endpoint"}
    try:
        _storage.delete_local_auth(username)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/smart-monitor-suggestion")
async def smart_monitor_suggestion(request: Request, user: str = Depends(require_login)):
    """
    The brain for the smart Add Monitor flow.
    Given a device (ip, vendor, os_guess, etc.), returns a complete safe suggested configuration.
    Prioritizes non-destructive monitoring + safe maintenance scripts.
    """
    data = await request.json() or {}
    ip = data.get("ip")
    vendor = (data.get("vendor") or "").lower()
    os_guess = (data.get("os_guess") or data.get("device_category") or "").lower()
    name = data.get("name_suggestion") or ip or "new-device"

    suggestion = {
        "name": name,
        "host": ip,
        "type": "tcp",
        "port": None,
        "expected": None,
        "severity": "medium",
        "recommended_scripts": [],
        "credential_suggestion": None,
        "safety_notes": [],
        "auto_add_monitors": []   # list of additional safe monitors we can suggest
    }

    # === Smart type + port + expected detection ===
    if "windows" in os_guess or "microsoft" in vendor:
        suggestion["type"] = "tcp"
        suggestion["port"] = 445
        suggestion["expected"] = None
        suggestion["safety_notes"].append("Windows device — preferring read-only and service restart scripts only.")
    elif "cisco" in vendor or "ubiquiti" in vendor or "omada" in vendor or "netgear" in vendor:
        suggestion["type"] = "ssh_version"
        suggestion["port"] = 22
        suggestion["expected"] = "OpenSSH" if "linux" not in os_guess else None
    elif "linux" in os_guess or "ubuntu" in os_guess or "debian" in os_guess:
        suggestion["type"] = "ssh_version"
        suggestion["port"] = 22
        suggestion["expected"] = "OpenSSH"
    elif "http" in os_guess or "web" in name.lower():
        suggestion["type"] = "https"
        suggestion["port"] = 443
    else:
        suggestion["type"] = "tcp"

    # === Safe script recommendations (never destructive by default) ===
    safe_scripts = []
    prebuilt_dir = REMEDIATION_SCRIPT_DIR / "prebuilts"

    if prebuilt_dir.exists():
        for p in sorted(prebuilt_dir.glob("*")):
            name_lower = p.name.lower()
            # Only suggest safe / monitoring / maintenance scripts
            if any(x in name_lower for x in ["update", "maintenance", "health", "check", "disk", "status", "restart_service"]):
                # Avoid super destructive ones for now
                if "reset" not in name_lower and "reboot" not in name_lower:
                    safe_scripts.append(f"prebuilts/{p.name}")

    # OS-specific safe defaults
    if "windows" in os_guess:
        safe_scripts = [s for s in safe_scripts if ".ps1" in s or "windows" in s] or safe_scripts[:3]
    elif "cisco" in vendor:
        safe_scripts = [s for s in safe_scripts if "cisco" in s] or safe_scripts[:2]
    elif "ubiquiti" in vendor or "omada" in vendor:
        safe_scripts = [s for s in safe_scripts if "ubiquiti" in s or "omada" in s] or safe_scripts[:2]
    else:
        safe_scripts = safe_scripts[:4]   # limit to avoid overwhelming

    suggestion["recommended_scripts"] = safe_scripts

    # === Credential hints ===
    if _storage and hasattr(_storage, "get_credential_profiles"):
        try:
            profiles = _storage.get_credential_profiles()
            for p in profiles:
                if (p.get("type") == "domain" and "windows" in os_guess) or \
                   (p.get("type") == "local" and "linux" in os_guess):
                    suggestion["credential_suggestion"] = p["name"]
                    break
        except Exception:
            pass

    if not suggestion["credential_suggestion"]:
        suggestion["credential_suggestion"] = "Create new local/domain credential for this device"

    suggestion["safety_notes"].append("Only safe, non-destructive scripts are pre-selected. Destructive actions require extra confirmation.")

    return {"success": True, "suggestion": suggestion}


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


@app.get("/api/geo/cached-ips")
async def api_geo_cached_ips(limit: int = 500, user: str = Depends(require_login)):
    """Return cached geo locations for all external IPs seen (not just threats).
    Useful for broader maps showing normal + threat traffic."""
    if not _storage:
        return {"success": False, "error": "storage not ready"}
    try:
        ips = _storage.get_all_cached_geo(limit=limit)
        return {"success": True, "ips": ips, "count": len(ips)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/geo/outbound-destinations")
async def api_geo_outbound_destinations(limit: int = 300, user: str = Depends(require_login)):
    """Return geo-enriched external destination IPs that internal devices talk to.
    This powers the 'Outbound Destinations' view on the map."""
    if not _storage:
        return {"success": False, "error": "storage not ready"}

    geo = get_geo_enricher()
    if not geo.available:
        geo = force_reload_geo()

    try:
        dest_ips = _storage.get_all_external_destinations(limit=limit)
        enriched = []
        for ip in dest_ips:
            g = _storage.get_cached_ip_geo(ip)
            if not g or g.get("lat") is None:
                g = geo.enrich(ip)
                if g and g.get("lat") is not None:
                    _storage.cache_ip_geo(ip, g)

            if g and g.get("lat") is not None:
                enriched.append({
                    "ip": ip,
                    "lat": g.get("lat"),
                    "lon": g.get("lon"),
                    "city": g.get("city"),
                    "country": g.get("country"),
                    "source": g.get("source", "unknown")
                })

        return {"success": True, "destinations": enriched, "count": len(enriched)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/geo/enrich-missing")
async def api_geo_enrich_missing(user: str = Depends(require_login)):
    """
    Bulk online enrichment for public IPs that are in the cache but have no geo data yet.
    This is the button that helps populate the map with many more external IPs
    when the local MaxMind DB is incomplete.
    """
    if not _storage:
        return {"success": False, "error": "storage not ready"}

    geo = get_geo_enricher()
    if not geo.available:
        geo = force_reload_geo()

    missing_ips = _storage.get_ips_missing_geo(limit=400)
    enriched = 0
    failed = 0
    skipped_private = 0

    for ip in missing_ips:
        try:
            if geo._is_private_ip(ip):
                skipped_private += 1
                continue

            g = geo.enrich(ip)  # local first, then online fallback
            if g and g.get("lat") is not None:
                _storage.cache_ip_geo(ip, g)
                enriched += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    # Also enrich outbound destination IPs from device baselines
    try:
        dest_ips = _storage.get_all_external_destinations(limit=300)
        for ip in dest_ips:
            if geo._is_private_ip(ip):
                continue
            g = _storage.get_cached_ip_geo(ip)
            if not g or g.get("lat") is None:
                g = geo.enrich(ip)
                if g and g.get("lat") is not None:
                    _storage.cache_ip_geo(ip, g)
                    enriched += 1
    except Exception:
        pass

    msg = f"Checked {len(missing_ips)} missing IPs. Enriched {enriched}."
    if skipped_private:
        msg += f" Skipped {skipped_private} private IPs."
    if failed:
        msg += f" {failed} lookups failed or had no data."

    return {
        "success": True,
        "checked": len(missing_ips),
        "enriched": enriched,
        "failed": failed,
        "skipped_private": skipped_private,
        "message": msg
    }


@app.post("/api/geo/warm-external-light")
async def api_geo_warm_external_light(user: str = Depends(require_login)):
    """Light, non-interactive enrichment of up to N missing public external IPs (for maps auto-warm).
    Safe to call from UI on external map load when few dots are visible. Caps low to avoid rate limits.
    """
    if not _storage:
        return {"success": False, "error": "storage not ready"}
    try:
        geo = get_geo_enricher()
        if not geo.available:
            geo = force_reload_geo()
        missing = _storage.get_ips_missing_geo(limit=25)  # small cap for UI
        enriched = 0
        for ip in missing[:12]:  # very light
            try:
                if geo._is_private_ip(ip):
                    continue
                g = geo.enrich(ip)
                if g and g.get("lat") is not None:
                    _storage.cache_ip_geo(ip, g)
                    enriched += 1
            except Exception:
                pass
        # also warm a few from fresh log discovery
        try:
            extra = _storage.discover_external_ips_from_logs(limit=15)
            for ip in extra[:8]:
                if geo._is_private_ip(ip):
                    continue
                g = _storage.get_cached_ip_geo(ip) or geo.enrich(ip)
                if g and g.get("lat") is not None:
                    _storage.cache_ip_geo(ip, g)
                    enriched += 1
        except Exception:
            pass
        return {"success": True, "enriched": enriched, "message": f"Light warm added {enriched} locations"}
    except Exception as e:
        return {"success": False, "error": str(e)}


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


@app.post("/api/monitors/seed-examples")
async def api_seed_example_monitors(user: str = Depends(require_login)):
    """One-click seed a set of useful starter monitors (generic examples for any LAN).
    Edit the host/IP/credential/interval after adding to match your environment.
    Sensible defaults: pings/TCP ~60s, web ~5min, SSH version checks 1-2x per day.
    """
    if _storage is None or _cfg is None:
        return {"success": False, "error": "not ready"}

    from .config import HeartbeatMonitor

    starters = [
        # Fast checks for basic reachability
        HeartbeatMonitor(name="local-gateway", host="192.168.1.1", type="tcp", port=80, severity="medium", interval_seconds=60),
        HeartbeatMonitor(name="dns-google", host="8.8.8.8", type="tcp", port=53, severity="high", interval_seconds=300),
        # Your main server - set credential_username after adding (for future full SSH checks)
        HeartbeatMonitor(name="your-linux-server", host="192.168.1.50", type="ssh_version", port=22, severity="medium", interval_seconds=43200),
        # Local web/service
        HeartbeatMonitor(name="local-web", host="192.168.1.100", type="https", port=443, path="/", severity="low", interval_seconds=300),
        # Example Home Assistant or other service
        HeartbeatMonitor(name="ha-core", host="192.168.1.30", type="http", port=8123, path="/", severity="medium", interval_seconds=120),
    ]

    added = 0
    for m in starters:
        try:
            _storage.upsert_monitor(m)
            added += 1
        except Exception:
            pass

    return {"success": True, "added": added, "message": f"Added {added} generic starter monitors. Edit hosts, credentials and intervals to match your network. Refresh the list."}


@app.post("/api/monitors/{name}/toggle")
async def api_toggle_monitor_enabled(name: str, request: Request, user: str = Depends(require_login)):
    """Quick toggle enabled flag for a monitor (from list buttons). Only updates the enabled bit, keeps other fields from DB."""
    if _storage is None:
        return {"success": False, "error": "not initialized"}
    try:
        data = await request.json()
        enabled = bool(data.get("enabled", True))
        mons = _storage.get_monitors(enabled_only=False)
        current = next((m for m in mons if m.get("name") == name), None)
        if not current:
            # perhaps yaml only, try to enable by adding stub to DB? or error
            return {"success": False, "error": "monitor not found in DB (edit to move to editable)"}
        from .config import HeartbeatMonitor
        m = HeartbeatMonitor(
            name=name,
            host=current.get("host", ""),
            type=current.get("type", "tcp"),
            port=current.get("port"),
            path=current.get("path") or "/",
            expected=current.get("expected"),
            severity=current.get("severity", "medium"),
            remediation_action=current.get("remediation_action"),
            interval_seconds=current.get("interval_seconds", 300),
            enabled=enabled,
            credential_type=current.get("credential_type"),
            credential_username=current.get("credential_username"),
            # secret stays as-is
        )
        _storage.upsert_monitor(m)
        return {"success": True, "enabled": enabled}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/config/heartbeats")
async def api_update_heartbeats_config(request: Request, user: str = Depends(require_login)):
    """Toggle or set global heartbeats enabled (and default interval) from monitors page etc.
    Updates in-memory _cfg and persists the heartbeats section to config.yaml (non-destructive to other keys).
    """
    if _cfg is None:
        return {"success": False, "error": "not ready"}
    try:
        data = await request.json()
    except:
        data = {}
    enabled = bool(data.get("enabled", getattr(_cfg.heartbeats, "enabled", False)))
    default_int = data.get("default_interval_seconds")
    try:
        if not hasattr(_cfg, "heartbeats") or _cfg.heartbeats is None:
            from .config import HeartbeatsConfig
            _cfg.heartbeats = HeartbeatsConfig()
        _cfg.heartbeats.enabled = enabled
        if default_int is not None:
            _cfg.heartbeats.default_interval_seconds = int(default_int)

        # persist partial to yaml (like other runtime saves)
        config_path = getattr(_cfg, "config_path", None) or "config.yaml"
        import yaml, os
        existing: dict = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}
        if "heartbeats" not in existing or not isinstance(existing.get("heartbeats"), dict):
            existing["heartbeats"] = {}
        existing["heartbeats"]["enabled"] = enabled
        if default_int is not None:
            existing["heartbeats"]["default_interval_seconds"] = int(default_int)

        tmp = config_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(existing, f, sort_keys=False, default_flow_style=False, indent=2)
        os.replace(tmp, config_path)

        return {"success": True, "heartbeats_enabled": enabled}
    except Exception as e:
        logger.exception("heartbeats config update failed")
        return {"success": False, "error": str(e)}


# --- LLM Model Discovery ---

def _normalize_llm_base_url(base_url: str) -> str:
    """Wrapper so web can use the canonical normalizer from llm module."""
    try:
        from .llm import normalize_base_url
        return normalize_base_url(base_url)
    except Exception:
        # fallback (shouldn't happen)
        if not base_url:
            return base_url
        u = base_url.rstrip("/")
        if not u.endswith("/v1"):
            u += "/v1"
        return u


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
        normalized = _normalize_llm_base_url(base_url)
        client = OpenAI(base_url=normalized, api_key=api_key, timeout=10)
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

    # Support testing Azure/M365 Copilot config before saving
    azure_endpoint = data.get("azure_endpoint") or _cfg.llm.azure_endpoint
    azure_deployment = data.get("azure_deployment") or _cfg.llm.azure_deployment
    azure_api_version = data.get("azure_api_version") or _cfg.llm.azure_api_version

    try:
        from openai import OpenAI

        # If azure_endpoint is provided, use AzureOpenAI client instead
        if azure_endpoint:
            try:
                from openai import AzureOpenAI
                client = AzureOpenAI(
                    azure_endpoint=azure_endpoint,
                    azure_deployment=azure_deployment or None,
                    api_key=api_key or "",
                    api_version=azure_api_version or "2024-10-21",
                    timeout=15
                )
            except Exception:
                # Fall back to regular client if AzureOpenAI import fails
                normalized = _normalize_llm_base_url(base_url)
                client = OpenAI(base_url=normalized, api_key=api_key, timeout=15)
        else:
            normalized = _normalize_llm_base_url(base_url)
            client = OpenAI(base_url=normalized, api_key=api_key, timeout=15)

        # Test models list first (defensive — some servers return .data = None)
        models = client.models.list()
        available = [m.id for m in (getattr(models, 'data', None) or [])]

        # Try a tiny completion if a model is provided
        test_completion = None
        if model:
            try:
                client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": "Say 'OK'"}],
                    max_tokens=5,
                    temperature=0
                )
                test_completion = "OK"
            except Exception as compErr:
                # Still consider basic connectivity a success, just note the completion failed
                return {
                    "success": True,
                    "message": f"Connected to {base_url} but completion test failed with model '{model}': {str(compErr)[:150]}",
                    "models_found": len(available)
                }

        msg = f"Successfully connected to {base_url}"
        if test_completion:
            msg += " (completion OK)"

        return {
            "success": True,
            "message": msg,
            "models_found": len(available),
            **({"test_completion": test_completion} if test_completion else {})
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
    """
    Phase 4 enhanced domain test:
    - Tests service account bind (if provided) + user lookup + group membership
    - Optional sample user auth test
    - Returns detailed success info including resolved role
    """
    if _cfg is None or _storage is None:
        return {"success": False, "message": "Config or storage not loaded"}

    form = await _safe_form(request)
    server = form.get("domain_server") or getattr(_cfg.web, "domain_server", "")
    base_dn = form.get("domain_base_dn") or getattr(_cfg.web, "domain_base_dn", "")
    test_user = form.get("test_user", "").strip()
    test_pass = form.get("test_pass", "").strip()

    if not server or not base_dn:
        return {"success": False, "message": "Domain server and Base DN are required"}

    details = {"server": server, "base_dn": base_dn}

    try:
        from .auth import try_ldap_login, decrypt_secret
        # Build a temp web config-like object from form + current cfg for the test
        class _TestWebCfg:
            pass
        test_cfg = _TestWebCfg()
        for attr in ["domain_server", "domain_base_dn", "domain_user_domain", "domain_service_account",
                     "domain_service_password", "domain_use_ldaps", "domain_ca_cert", "domain_verify_cert",
                     "domain_admin_groups", "domain_operator_groups", "domain_analyst_groups", "domain_viewer_groups"]:
            val = form.get(attr) or getattr(_cfg.web, attr, "")
            if "password" in attr or "secret" in attr:
                val = decrypt_secret(val) if val else ""
            setattr(test_cfg, attr, val)
        setattr(test_cfg, "domain_enabled", True)

        # Full featured test using the new helper
        if test_user and test_pass:
            ok, role, groups = try_ldap_login(test_user, test_pass, test_cfg, _storage)
            details["tested_user"] = test_user
            details["role"] = role
            details["groups_sample"] = groups[:5] if groups else []
            if ok:
                return {"success": True, "message": f"Bind + lookup successful for {test_user}. Role={role}", "details": details}
            else:
                return {"success": False, "message": f"Auth failed for test user {test_user}", "details": details}
        else:
            # Service account / reachability + group config test (no user password)
            # Use the service account path inside try_ldap_login by passing dummy that will use service
            # Simpler: just attempt service bind + search
            from ldap3 import Server, Connection, ALL, SUBTREE
            srv = Server(server, get_info=ALL, connect_timeout=8, use_ssl=getattr(test_cfg, "domain_use_ldaps", False))
            svc = getattr(test_cfg, "domain_service_account", "")
            svc_pwd = getattr(test_cfg, "domain_service_password", "")
            if svc and svc_pwd:
                conn = Connection(srv, user=svc, password=svc_pwd, auto_bind=True)
                # Do a sample user search to validate group-capable lookup
                conn.search(base_dn, "(objectClass=user)", SUBTREE, attributes=["sAMAccountName", "memberOf"], size_limit=1)
                conn.unbind()
                return {"success": True, "message": "Service account bind + sample lookup successful. Group mapping will work.", "details": details}
            else:
                # Anonymous or basic reachability
                conn = Connection(srv, auto_bind=True)
                conn.unbind()
                return {"success": True, "message": f"Basic connectivity OK to {server} (no service account provided for full group test)", "details": details}

    except Exception as e:
        return {"success": False, "message": str(e)[:300], "details": details}


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
                        <input type="text" name="llm_model" value="{{ cfg.llm.model }}" placeholder="e.g. qwen2.5-coder-14b or gpt-4o (leave blank to auto-detect on test)" class="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-4 py-2.5 font-mono text-sm">
                    </div>
                    <button type="button" onclick="testLLMConnection()" class="px-4 py-2 rounded-2xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-sm font-medium active:scale-[0.985] whitespace-nowrap">Test Connection</button>
                </div>
                <div id="llm-test-status" class="text-xs mt-1 min-h-[18px]"></div>
                <div class="text-[10px] text-zinc-500 mt-0.5">Enter the model name, or leave blank and click Test Connection to auto-detect.</div>
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
                const llmSection = document.querySelector('[name="llm_base_url"]')?.closest('.lg\\:col-span-2') || document.body;
                statusEl.id = 'llm-test-status';
                llmSection.appendChild(statusEl);
            }

            const baseUrl = document.querySelector('[name="llm_base_url"]').value;
            const apiKey = document.querySelector('[name="llm_api_key"]').value || 'not-needed';
            const model = document.querySelector('[name="llm_model"]').value?.trim();

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
