"""
Certificate management for RocketLogAI web UI.

- Generates self-signed certificates for easy HTTPS out of the box.
- Supports user-provided certificates and Let's Encrypt (via external tools or future integration).
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

DEFAULT_SSL_DIR = Path("data/ssl")
DEFAULT_CERT_FILE = DEFAULT_SSL_DIR / "cert.pem"
DEFAULT_KEY_FILE = DEFAULT_SSL_DIR / "key.pem"


def ensure_ssl_directory() -> Path:
    """Ensure the SSL directory exists."""
    DEFAULT_SSL_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_SSL_DIR


def generate_self_signed_cert(
    cert_path: str | Path | None = None,
    key_path: str | Path | None = None,
    common_name: str = "RocketLogAI",
    days_valid: int = 365 * 5,
    force: bool = False,
) -> Tuple[str, str]:
    """
    Generate a self-signed certificate using openssl (preferred) or fall back.

    Returns (cert_path, key_path).
    """
    ensure_ssl_directory()

    cert_file = Path(cert_path) if cert_path else DEFAULT_CERT_FILE
    key_file = Path(key_path) if key_path else DEFAULT_KEY_FILE

    if cert_file.exists() and key_file.exists() and not force:
        logger.info("SSL certificate already exists at %s", cert_file)
        return str(cert_file), str(key_file)

    logger.info("Generating self-signed SSL certificate for %s...", common_name)

    # Try openssl first (available on macOS, most Linux, WSL)
    try:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_file),
            "-out", str(cert_file),
            "-days", str(days_valid),
            "-nodes",
            "-subj", f"/CN={common_name}/O=RocketLogAI/C=US",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Self-signed certificate generated successfully using openssl.")
        return str(cert_file), str(key_file)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("openssl not available or failed: %s. Falling back to pure Python (cryptography recommended).", e)

    # Fallback: try using cryptography if installed (user can pip install it)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RocketLogAI"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
            .sign(private_key, hashes.SHA256())
        )

        key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("Self-signed certificate generated using cryptography library.")
        return str(cert_file), str(key_file)

    except ImportError:
        logger.error(
            "Neither openssl nor the 'cryptography' package is available. "
            "Please install one of them or provide your own certificate via config."
        )
        raise RuntimeError("Cannot generate SSL certificate automatically.")


def get_or_create_default_certs(cfg_web) -> Tuple[str | None, str | None]:
    """
    Returns (certfile, keyfile) based on config, generating defaults if needed.
    """
    cert = (cfg_web.ssl_certfile or "").strip()
    key = (cfg_web.ssl_keyfile or "").strip()

    if cert and key and Path(cert).exists() and Path(key).exists():
        return cert, key

    if cfg_web.ssl_auto_generate:
        try:
            return generate_self_signed_cert()
        except Exception as exc:
            logger.error("Failed to auto-generate SSL cert: %s", exc)
            return None, None

    return None, None