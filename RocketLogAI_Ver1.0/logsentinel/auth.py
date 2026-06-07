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
