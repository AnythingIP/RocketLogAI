"""Compatibility helpers for optional open-interpreter integration."""

from __future__ import annotations

# open-interpreter 0.4.x imports pkg_resources, removed from setuptools 82+
SETTOOLS_PIN = "setuptools>=65,<81"
OPEN_INTERPRETER_SPEC = "open-interpreter>=0.2.0"


def missing_pkg_resources_hint(exc: BaseException) -> str | None:
    msg = str(exc)
    if "pkg_resources" in msg or "No module named 'pkg_resources'" in msg:
        return (
            "open-interpreter needs pkg_resources. Fix: "
            f'pip install "{SETTOOLS_PIN}" then restart RocketLogAI.'
        )
    return None


def probe_open_interpreter() -> tuple[str, str, str]:
    """Return (status, detail, hint) for diagnostics."""
    import subprocess
    import sys

    pip = subprocess.run(
        [sys.executable, "-m", "pip", "show", "open-interpreter"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    pip_ver = None
    if pip.returncode == 0:
        for line in (pip.stdout or "").splitlines():
            if line.lower().startswith("version:"):
                pip_ver = line.split(":", 1)[1].strip()
                break

    try:
        import interpreter  # noqa: F401

        mod_ver = getattr(interpreter, "__version__", None) or pip_ver or "unknown"
        return "ok", f"open-interpreter {mod_ver} importable", ""
    except Exception as exc:
        hint = missing_pkg_resources_hint(exc)
        if not hint and pip_ver:
            hint = (
                f"Reinstall with: {sys.executable} -m pip install "
                f'"{SETTOOLS_PIN}" "{OPEN_INTERPRETER_SPEC}"'
            )
        elif not hint:
            hint = (
                f"{sys.executable} -m pip install "
                f'"{SETTOOLS_PIN}" "{OPEN_INTERPRETER_SPEC}"'
            )
        status = "warn" if pip_ver else "fail"
        detail = (
            f"pip shows open-interpreter {pip_ver}, import failed: {type(exc).__name__}: {exc}"
            if pip_ver
            else f"import failed: {type(exc).__name__}: {exc}"
        )
        return status, detail[:400], hint