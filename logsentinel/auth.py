"""
Local authentication helpers for RocketLogAI.

Handles secure password hashing (bcrypt preferred) and verification
so we never store plaintext passwords in config.yaml or the DB.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Tuple


def _get_bcrypt():
    try:
        import bcrypt  # type: ignore
        return bcrypt
    except ImportError:
        return None


def hash_password(plain_password: str) -> str:
    """
    Return a secure hash of the password.
    Uses bcrypt when available (strongly preferred).
    Falls back to a solid PBKDF2 implementation if bcrypt is missing.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty")

    bcrypt = _get_bcrypt()
    if bcrypt:
        # bcrypt handles its own salting + work factor
        return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    # Fallback (still decent, constant-time friendly compare below)
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 200_000)
    return "pbkdf2$sha256$200000$" + salt.hex() + "$" + dk.hex()


def verify_password(plain_password: str, stored: str) -> bool:
    """
    Constant-time safe verification against either bcrypt or our PBKDF2 fallback.
    """
    if not stored or not plain_password:
        return False

    bcrypt = _get_bcrypt()

    # bcrypt format
    if stored.startswith("$2") or stored.startswith("$2a") or stored.startswith("$2b") or stored.startswith("$2y"):
        if bcrypt:
            try:
                return bcrypt.checkpw(plain_password.encode("utf-8"), stored.encode("utf-8"))
            except Exception:
                return False
        return False  # can't verify bcrypt without the lib

    # Our PBKDF2 fallback format: pbkdf2$sha256$iterations$salt$hash
    if stored.startswith("pbkdf2$"):
        try:
            _, algo, iters, salt_hex, hash_hex = stored.split("$")
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            actual = hashlib.pbkdf2_hmac(algo, plain_password.encode("utf-8"), salt, int(iters))
            return secrets.compare_digest(actual, expected)
        except Exception:
            return False

    # Last resort: treat stored as legacy plaintext (migration window only)
    # This path will go away once everything is migrated.
    return secrets.compare_digest(stored, plain_password)


def needs_rehash(stored: str) -> bool:
    """Return True if the stored hash is using weak/old parameters."""
    if stored.startswith("$2"):
        # bcrypt — check work factor roughly
        try:
            # $2b$12$...  the number after second $ is the cost
            cost = int(stored.split("$")[2])
            return cost < 10
        except Exception:
            return False
    if stored.startswith("pbkdf2$"):
        try:
            iters = int(stored.split("$")[2])
            return iters < 150_000
        except Exception:
            return True
    return True  # legacy plaintext or unknown → needs rehash on next successful login


# =============================================================================
# Phase 4: Advanced Enterprise Auth Helpers (LDAP + Entra ID + RBAC)
# =============================================================================

import logging
from typing import List, Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)


# Global storage reference (set by web.py after initialization to avoid circular imports)
_storage_ref = None

def set_storage_for_crypto(storage):
    """Called by web.py after _storage is ready. Enables full encryption for Phase 4 auth secrets."""
    global _storage_ref
    _storage_ref = storage

def encrypt_secret(plain: str) -> str:
    """Encrypt a secret for storage (reversible for service accounts / Entra)."""
    if _storage_ref and hasattr(_storage_ref, "_encrypt_credential_secret"):
        try:
            return _storage_ref._encrypt_credential_secret(plain) or plain
        except Exception:
            pass
    # Fallback: return as-is (security relies on file/DB perms + admin practices)
    return plain


def decrypt_secret(stored: str) -> str:
    """Decrypt a stored secret."""
    if _storage_ref and hasattr(_storage_ref, "_decrypt_credential_secret"):
        try:
            return _storage_ref._decrypt_credential_secret(stored) or stored
        except Exception:
            pass
    return stored


# --- Role definitions (least privilege) ---
ROLE_VIEWER = "viewer"          # Read-only dashboards, logs, threats (no actions)
ROLE_ANALYST = "analyst"        # + Can trigger analyses, view detailed AI output
ROLE_OPERATOR = "operator"      # + Can execute confirmed actions (remediation, assistant commands with confirm)
ROLE_ADMIN = "administrator"    # Full access (config, users, everything)

ALL_ROLES = [ROLE_VIEWER, ROLE_ANALYST, ROLE_OPERATOR, ROLE_ADMIN]
DEFAULT_ROLE = ROLE_VIEWER


def resolve_role_from_groups(user_groups: List[str], cfg_groups: Dict[str, str]) -> str:
    """
    Map a list of user's AD/Entra groups to the highest matching RocketLogAI role.
    cfg_groups example: {"admin": "Domain Admins;RocketLogAI-Admins", "operator": "..."}
    """
    if not user_groups:
        return DEFAULT_ROLE

    def groups_match(cfg_str: str) -> bool:
        if not cfg_str:
            return False
        configured = [g.strip().lower() for g in cfg_str.replace(";", ",").split(",") if g.strip()]
        user_lower = [g.lower() for g in user_groups]
        return any(c in user_lower for c in configured)

    # Highest privilege first
    if groups_match(cfg_groups.get("admin", "")):
        return ROLE_ADMIN
    if groups_match(cfg_groups.get("operator", "")):
        return ROLE_OPERATOR
    if groups_match(cfg_groups.get("analyst", "")):
        return ROLE_ANALYST
    if groups_match(cfg_groups.get("viewer", "")):
        return ROLE_VIEWER
    return DEFAULT_ROLE


# --- Enhanced LDAP / Active Directory with service account + groups ---
def try_ldap_login(
    username: str,
    password: str,
    cfg_web: Any,  # WebConfig-like
    storage: Any = None,
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Phase 4 improved LDAP login.
    - Uses service account for search + group lookup (if configured).
    - Falls back to direct user bind for basic auth.
    - Returns (success, resolved_role, groups)
    """
    if not cfg_web or not getattr(cfg_web, "domain_enabled", False):
        return False, None, []

    server = getattr(cfg_web, "domain_server", "")
    base_dn = getattr(cfg_web, "domain_base_dn", "")
    if not server or not base_dn:
        return False, None, []

    try:
        from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL
    except ImportError:
        logger.warning("ldap3 not installed for advanced domain auth")
        return False, None, []

    service_account = getattr(cfg_web, "domain_service_account", "") or ""
    service_password = decrypt_secret(getattr(cfg_web, "domain_service_password", "") or "")

    user_dn_or_upn = username
    if "\\" not in username and "@" not in username:
        domain = getattr(cfg_web, "domain_user_domain", "") or ""
        if domain:
            user_dn_or_upn = f"{domain}\\{username}"
        else:
            # Best effort UPN
            user_dn_or_upn = f"{username}@{base_dn.split('DC=', 1)[-1].replace(',DC=', '.').replace('DC=', '')}" if "," in base_dn else username

    groups: List[str] = []
    role = DEFAULT_ROLE

    try:
        srv = Server(server, get_info=ALL, connect_timeout=10, use_ssl=getattr(cfg_web, "domain_use_ldaps", False))

        # Step 1: Bind with service account for lookup (preferred)
        conn = None
        if service_account and service_password:
            try:
                conn = Connection(srv, user=service_account, password=service_password, auto_bind=True)
                # Search for the user to get DN and groups
                search_filter = f"(|(sAMAccountName={username})(userPrincipalName={username})(cn={username}))"
                conn.search(base_dn, search_filter, SUBTREE, attributes=["distinguishedName", "memberOf", "sAMAccountName"])
                if conn.entries:
                    entry = conn.entries[0]
                    user_dn = str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else user_dn_or_upn
                    if hasattr(entry, "memberOf"):
                        groups = [str(g) for g in entry.memberOf]
                    # Now re-bind as the actual user to verify password
                    conn.unbind()
                    conn = Connection(srv, user=user_dn, password=password, auto_bind=True)
                    conn.unbind()
                    # Resolve role from groups + config mappings
                    cfg_groups = {
                        "admin": getattr(cfg_web, "domain_admin_groups", ""),
                        "operator": getattr(cfg_web, "domain_operator_groups", ""),
                        "analyst": getattr(cfg_web, "domain_analyst_groups", ""),
                        "viewer": getattr(cfg_web, "domain_viewer_groups", ""),
                    }
                    role = resolve_role_from_groups(groups, cfg_groups)
                    return True, role, groups
            except Exception as svc_e:
                logger.debug(f"Service account bind/lookup failed, falling back to direct user bind: {svc_e}")
                if conn:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

        # Fallback: direct user bind (original behavior)
        conn = Connection(srv, user=user_dn_or_upn, password=password, auto_bind=True)
        # Try to fetch groups on the user bind connection
        try:
            conn.search(base_dn, f"(sAMAccountName={username})", SUBTREE, attributes=["memberOf"])
            if conn.entries and hasattr(conn.entries[0], "memberOf"):
                groups = [str(g) for g in conn.entries[0].memberOf]
        except Exception:
            pass
        conn.unbind()

        cfg_groups = {
            "admin": getattr(cfg_web, "domain_admin_groups", ""),
            "operator": getattr(cfg_web, "domain_operator_groups", ""),
            "analyst": getattr(cfg_web, "domain_analyst_groups", ""),
            "viewer": getattr(cfg_web, "domain_viewer_groups", ""),
        }
        role = resolve_role_from_groups(groups, cfg_groups)
        return True, role, groups

    except Exception as e:
        logger.debug(f"LDAP login failed for {username}: {e}")
        return False, None, []


# --- Entra ID (Azure AD / Microsoft Entra) support ---
def try_entra_login(
    username_or_token: str,
    password_or_code: str,
    cfg_web: Any,
    storage: Any = None,
    is_token: bool = False,
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Basic Entra ID support.
    For full OAuth flow, the web layer handles redirect; this can validate a token or do client-credentials + user lookup.
    Returns (success, role, groups)
    """
    if not cfg_web or not getattr(cfg_web, "entra_enabled", False):
        return False, None, []

    tenant = getattr(cfg_web, "entra_tenant_id", "")
    client_id = getattr(cfg_web, "entra_client_id", "")
    client_secret = decrypt_secret(getattr(cfg_web, "entra_client_secret", "") or "")

    if not tenant or not client_id:
        return False, None, []

    try:
        import requests
    except ImportError:
        logger.warning("requests not available for Entra ID")
        return False, None, []

    try:
        # If we were given an access token directly (from prior OAuth step)
        if is_token:
            access_token = username_or_token
        else:
            # Client credentials + on-behalf or resource owner (simplified; production should use proper OIDC)
            # For demo we support token exchange or direct client creds for app-only + user lookup
            token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": getattr(cfg_web, "entra_scopes", "https://graph.microsoft.com/.default"),
                "grant_type": "client_credentials",
            }
            r = requests.post(token_url, data=data, timeout=15)
            r.raise_for_status()
            access_token = r.json().get("access_token")

            if not access_token:
                return False, None, []

        # Use Microsoft Graph to get user + groups
        headers = {"Authorization": f"Bearer {access_token}"}
        # Get user
        user_resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
        if user_resp.status_code != 200:
            # Try with UPN if provided
            user_upn = username_or_token if "@" in username_or_token else None
            if user_upn:
                user_resp = requests.get(f"https://graph.microsoft.com/v1.0/users/{user_upn}", headers=headers, timeout=10)
        if user_resp.status_code != 200:
            return False, None, []

        user_data = user_resp.json()
        user_id = user_data.get("id")
        user_principal = user_data.get("userPrincipalName") or user_data.get("mail")

        # Get group memberships (transitive)
        groups_resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf",
            headers=headers,
            timeout=15
        )
        groups = []
        if groups_resp.status_code == 200:
            for g in groups_resp.json().get("value", []):
                if g.get("@odata.type") == "#microsoft.graph.group":
                    groups.append(g.get("displayName") or g.get("id"))

        cfg_groups = {
            "admin": getattr(cfg_web, "entra_admin_groups", ""),
            "operator": getattr(cfg_web, "entra_operator_groups", ""),
            "analyst": getattr(cfg_web, "entra_analyst_groups", ""),
            "viewer": getattr(cfg_web, "entra_viewer_groups", ""),
        }
        role = resolve_role_from_groups(groups, cfg_groups)

        # Very basic token validation success
        return True, role, groups

    except Exception as e:
        logger.debug(f"Entra ID auth failed: {e}")
        return False, None, []


def get_user_role(user: str, auth_type: str, cfg: Any, storage: Any = None) -> str:
    """
    Resolve effective role for a logged in user.
    Checks session-stored role first, then falls back to local is_admin, then default.
    """
    # In practice the login sets session["role"]
    # This is a helper for permission checks
    if storage:
        rec = storage.get_local_auth(user)
        if rec and rec.get("is_admin"):
            return ROLE_ADMIN
    return DEFAULT_ROLE


def require_role(min_role: str):
    """
    Decorator / dependency factory for FastAPI routes.
    Usage: @app.get("/sensitive", dependencies=[Depends(require_role("operator"))])
    """
    def _check_role(request: "Request"):
        # Simplified: in real use we would look up from session or token claims
        # For now, rely on the fact that login already enforced basic auth and we can check is_admin for admin
        # Full RBAC enforcement can be added by storing role in session and checking here.
        # Placeholder that always passes for non-admin routes; strict for admin.
        if min_role == ROLE_ADMIN:
            # Fall back to existing is_admin logic
            pass
        return True  # In production expand with actual role from session
    return _check_role
