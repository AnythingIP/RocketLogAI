"""Live and install-time diagnostics for RocketLogAI."""

from __future__ import annotations

import importlib
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


def _check(name: str, fn: Callable[[], tuple[bool, str, str]]) -> dict[str, Any]:
    try:
        ok, detail, hint = fn()
        return {
            "name": name,
            "status": "ok" if ok else "fail",
            "detail": detail,
            "hint": hint,
        }
    except Exception as exc:
        return {
            "name": name,
            "status": "fail",
            "detail": str(exc)[:300],
            "hint": "See server logs for full traceback.",
        }


def _import_ok(module: str) -> tuple[bool, str, str]:
    importlib.import_module(module)
    return True, f"import {module}", ""


def _ping_local() -> tuple[bool, str, str]:
    host = "127.0.0.1"
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", "2000", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", host]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if proc.returncode == 0:
        return True, f"Host ping OK ({host})", ""
    return False, (proc.stderr or proc.stdout or "ping failed")[:200], "Check Windows firewall / ICMP rules."


def _open_interpreter_status() -> tuple[bool, str, str]:
    try:
        import interpreter  # noqa: F401
        return True, "open-interpreter installed", ""
    except ImportError:
        return (
            False,
            "open-interpreter not installed",
            "pip install open-interpreter (Python 3.10-3.12). Ping still works without it.",
        )


def run_install_checks(install_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for sub in ("brain", "remediate", "shield", "mobile", "mcp", "ueba", "agents"):
        path = install_dir / "logsentinel" / sub
        if path.is_dir():
            checks.append({"name": f"module:{sub}", "status": "ok", "detail": str(path), "hint": ""})
        else:
            checks.append({
                "name": f"module:{sub}",
                "status": "fail",
                "detail": f"Missing {path}",
                "hint": "Re-run upgrade or pip install -e '.[web,v2]' from install directory.",
            })

    templates = ("shield.html", "agents.html", "system_health.html", "assistant.html")
    for name in templates:
        path = install_dir / "templates" / name
        checks.append({
            "name": f"template:{name}",
            "status": "ok" if path.exists() else "warn",
            "detail": "present" if path.exists() else "missing (upgrade may be needed)",
            "hint": "Run scripts/upgrade.ps1 to sync templates.",
        })
    return checks


def run_live_checks(
    *,
    cfg: Any = None,
    llm_client: Any = None,
    storage: Any = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.append(_check("python", lambda: (
        sys.version_info >= (3, 10),
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "Use Python 3.12 in .venv for full AI Operator support.",
    )))
    checks.append(_check("ping_local", _ping_local))
    checks.append(_check("open_interpreter", _open_interpreter_status))

    for mod in ("fastapi", "uvicorn", "openai", "chromadb", "prometheus_client"):
        checks.append(_check(f"dep:{mod}", lambda m=mod: _import_ok(m)))

    if cfg and getattr(cfg, "llm", None):
        base = getattr(cfg.llm, "base_url", "") or ""
        model = getattr(cfg.llm, "model", "") or ""
        checks.append({
            "name": "llm:config",
            "status": "ok" if base else "warn",
            "detail": f"provider={getattr(cfg.llm, 'provider', 'local')} base_url={base} model={model}",
            "hint": "Set LLM in Config or config.yaml (LM Studio: http://localhost:1234/v1).",
        })
    else:
        checks.append({
            "name": "llm:config",
            "status": "warn",
            "detail": "No LLM config loaded",
            "hint": "Copy example-config.yaml to config.yaml and configure llm.base_url.",
        })

    if llm_client and hasattr(llm_client, "client") and hasattr(llm_client.client, "chat"):
        def _llm_ping() -> tuple[bool, str, str]:
            model = getattr(getattr(llm_client, "cfg", None), "model", None) or "local"
            resp = llm_client.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with exactly OK"}],
                max_tokens=8,
                temperature=0,
            )
            text = resp.choices[0].message.content if resp.choices else ""
            return True, f"LLM completion OK ({text!r})", ""

        checks.append(_check("llm:completion", _llm_ping))
    else:
        checks.append({
            "name": "llm:completion",
            "status": "warn",
            "detail": "LLM client not available for live test",
            "hint": "Start LM Studio server and match base_url/model in Config.",
        })

    if storage is not None:
        checks.append({
            "name": "storage",
            "status": "ok",
            "detail": "Storage backend initialized",
            "hint": "",
        })
    else:
        checks.append({
            "name": "storage",
            "status": "fail",
            "detail": "Storage not initialized",
            "hint": "Restart RocketLogAI; check data/ permissions.",
        })

    try:
        from .v2_runtime import get_v2_runtime

        rt = get_v2_runtime(cfg, storage)
        status = rt.status()
        checks.append({
            "name": "v2:runtime",
            "status": "ok",
            "detail": f"shield={status.get('shield', {})} agents={status.get('agents', {})}",
            "hint": "",
        })
        checks.append({
            "name": "v2:waf",
            "status": "ok" if rt.waf else "fail",
            "detail": str(rt.waf.status()),
            "hint": "Enable shield in config.yaml under shield.enabled",
        })
    except Exception as exc:
        checks.append({
            "name": "v2:runtime",
            "status": "fail",
            "detail": str(exc)[:200],
            "hint": "pip install -e '.[web,v2]' from install directory.",
        })

    ok = sum(1 for c in checks if c["status"] == "ok")
    warn = sum(1 for c in checks if c["status"] == "warn")
    fail = sum(1 for c in checks if c["status"] == "fail")
    return {
        "summary": {
            "ok": ok,
            "warn": warn,
            "fail": fail,
            "healthy": fail == 0,
            "checked_at": time.time(),
            "platform": platform.system(),
        },
        "checks": checks,
    }