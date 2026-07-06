#!/usr/bin/env python3
"""RocketLogAI install health check and repair utility.

Usage:
    python scripts/healthcheck.py [INSTALL_DIR] [--fix]

Exit codes:
    0 = all checks passed
    1 = issues found (not fixed)
    2 = fix attempted but issues remain
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_VERSION = "2.0.0"
PIP_CORE_EXTRAS = "web,v2"
REQUIRED_IMPORTS = [
    "fastapi",
    "uvicorn",
    "jinja2",
    "yaml",
    "click",
    "rich",
    "openai",
]


def _ok(msg: str) -> None:
    print(f"  OK   {msg}")


def _warn(msg: str) -> None:
    print(f"  WARN {msg}")


def _fail(msg: str) -> None:
    print(f"  FAIL {msg}")


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def find_python() -> str:
    return sys.executable


def detect_install_type(install_dir: Path) -> str:
    marker = install_dir / ".install-type"
    if marker.exists():
        value = marker.read_text(encoding="utf-8").strip().lower()
        if value in ("docker", "native"):
            return value

    if (install_dir / ".venv").is_dir():
        return "native"

    if shutil.which("docker"):
        proc = _run(
            ["docker", "ps", "-a", "--filter", "name=rocketlogai", "--format", "{{.Names}}"],
            cwd=install_dir,
        )
        if proc.returncode == 0 and "rocketlogai" in (proc.stdout or ""):
            return "docker"

    # docker-compose.yml ships with native installs — prefer native when data/config exist
    if (install_dir / "config.yaml").exists() or (install_dir / "data" / "logsentinel.db").exists():
        return "native"

    if (install_dir / "docker-compose.yml").exists() and shutil.which("docker"):
        proc = _run(["docker", "info"])
        if proc.returncode == 0:
            return "docker"

    return "native"


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    proc = _run(["docker", "info"])
    return proc.returncode == 0


def venv_python(install_dir: Path) -> Path | None:
    if sys.platform == "win32":
        candidate = install_dir / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = install_dir / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else None


def resolve_runtime_python(install_dir: Path, install_type: str) -> Path:
    if install_type == "native":
        vp = venv_python(install_dir)
        if vp:
            return vp
    return Path(find_python())


def pip_install_editable(install_dir: Path, python_exe: Path) -> bool:
    proc = _run(
        [str(python_exe), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
        cwd=install_dir,
    )
    if proc.returncode != 0:
        _fail(f"pip bootstrap failed: {proc.stderr.strip()}")
        return False

    proc = _run(
        [str(python_exe), "-m", "pip", "install", "-e", f".[{PIP_CORE_EXTRAS}]", "--upgrade"],
        cwd=install_dir,
    )
    if proc.returncode != 0:
        _fail(f"editable install failed: {proc.stderr.strip()}")
        return False

    # Optional AI Operator — fails on Python 3.13+ when tiktoken cannot build
    ai_proc = _run(
        [str(python_exe), "-m", "pip", "install", "open-interpreter", "--upgrade"],
        cwd=install_dir,
    )
    if ai_proc.returncode != 0:
        _warn("open-interpreter skipped (use Python 3.10-3.12 for full AI Operator)")
    return True


def create_venv(install_dir: Path) -> Path | None:
    python = find_python()
    proc = _run([python, "-m", "venv", str(install_dir / ".venv")], cwd=install_dir)
    if proc.returncode != 0:
        _fail(f"Could not create .venv: {proc.stderr.strip()}")
        return None
    vp = venv_python(install_dir)
    if vp:
        _ok(f"Created virtual environment at {install_dir / '.venv'}")
    return vp


def write_launchers(install_dir: Path) -> None:
    if sys.platform == "win32":
        bat = install_dir / "start-rocketlogai.bat"
        bat.write_text(
            "@echo off\r\n"
            "cd /d %~dp0\r\n"
            "call .venv\\Scripts\\activate.bat\r\n"
            "echo.\r\n"
            "echo Starting RocketLogAI...\r\n"
            "logsentinel run --web\r\n"
            "pause\r\n",
            encoding="ascii",
        )
        ps1 = install_dir / "start-rocketlogai.ps1"
        ps1.write_text(
            "Set-Location $PSScriptRoot\n"
            ". .\\.venv\\Scripts\\Activate.ps1\n"
            "logsentinel run --web\n",
            encoding="utf-8",
        )
    else:
        sh = install_dir / "start-rocketlogai.sh"
        sh.write_text(
            "#!/usr/bin/env bash\n"
            "set -e\n"
            'cd "$(dirname "$0")"\n'
            "source .venv/bin/activate\n"
            'echo "Starting RocketLogAI..."\n'
            "logsentinel run --web\n",
            encoding="utf-8",
        )
        sh.chmod(0o755)


def clean_pycache(install_dir: Path) -> None:
    for root, dirs, files in os.walk(install_dir):
        if "__pycache__" in dirs:
            shutil.rmtree(Path(root) / "__pycache__", ignore_errors=True)
        for name in files:
            if name.endswith(".pyc"):
                try:
                    (Path(root) / name).unlink()
                except OSError:
                    pass


def package_version_from_dir(install_dir: Path) -> str | None:
    init_py = install_dir / "logsentinel" / "__init__.py"
    if not init_py.exists():
        return None
    spec = importlib.util.spec_from_file_location("logsentinel_init", init_py)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "__version__", None)


def logsentinel_entrypoint(python_exe: Path) -> str | None:
    proc = _run([str(python_exe), "-m", "pip", "show", "logsentinel"])
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("Location:"):
            return line.split(":", 1)[1].strip()
    return None


def run_checks(install_dir: Path, fix: bool) -> list[str]:
    issues: list[str] = []

    print(f"RocketLogAI Health Check")
    print(f"Install directory: {install_dir}")
    print()

    # Structure
    print("[1] Directory structure")
    for rel in ("logsentinel", "templates", "pyproject.toml"):
        path = install_dir / rel
        if path.exists():
            _ok(rel)
        else:
            _fail(f"Missing {rel}")
            issues.append(f"missing:{rel}")

    if (install_dir / "config.yaml").exists():
        _ok("config.yaml")
    else:
        _warn("config.yaml not found (copy from example-config.yaml)")

    if (install_dir / "data").is_dir():
        _ok("data/")
    else:
        _warn("data/ directory missing (will be created on first run)")

    print()
    print("[2] Install type")
    install_type = detect_install_type(install_dir)
    _ok(f"Detected: {install_type}")
    if not (install_dir / ".install-type").exists():
        _warn("No .install-type marker — detection is heuristic")
        if fix:
            (install_dir / ".install-type").write_text(install_type + "\n", encoding="utf-8")
            _ok(f"Wrote .install-type = {install_type}")

    print()
    print("[3] Python runtime")
    if sys.version_info < (3, 10):
        _fail(f"Python {sys.version_info.major}.{sys.version_info.minor} — need 3.10+")
        issues.append("python:old")
    else:
        _ok(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    runtime = resolve_runtime_python(install_dir, install_type)
    _ok(f"Runtime python: {runtime}")

    if install_type == "native" and not venv_python(install_dir):
        _warn("No .venv — running from system Python (can cause version mismatches)")
        issues.append("venv:missing")
        if fix:
            vp = create_venv(install_dir)
            if vp:
                runtime = vp
                issues = [i for i in issues if i != "venv:missing"]

    print()
    print("[4] Package version")
    src_ver = package_version_from_dir(install_dir)
    if src_ver:
        _ok(f"Source tree version: {src_ver}")
        if src_ver != EXPECTED_VERSION:
            _warn(f"Expected {EXPECTED_VERSION}, found {src_ver}")
    else:
        _fail("Could not read logsentinel/__init__.py version")
        issues.append("version:unreadable")

    loc = logsentinel_entrypoint(runtime)
    if loc:
        _ok(f"pip package location: {loc}")
        install_str = str(install_dir.resolve()).lower()
        loc_str = loc.lower().replace("\\", "/")
        if install_str.replace("\\", "/") not in loc_str and "site-packages" in loc_str:
            _fail("logsentinel is installed globally, not from this directory")
            issues.append("pip:global")
        elif install_str.replace("\\", "/") in loc_str or "site-packages" not in loc_str:
            _ok("pip install points at this installation")
    else:
        _fail("logsentinel package not installed for runtime Python")
        issues.append("pip:not-installed")

    print()
    print("[5] Dependencies")
    for mod in REQUIRED_IMPORTS:
        proc = _run([str(runtime), "-c", f"import {mod}"])
        if proc.returncode == 0:
            _ok(mod)
        else:
            _fail(f"Missing module: {mod}")
            issues.append(f"dep:{mod}")

    # v2 optional imports (warn only)
    for mod in ("chromadb", "prometheus_client"):
        proc = _run([str(runtime), "-c", f"import {mod}"])
        if proc.returncode == 0:
            _ok(f"{mod} (v2)")
        else:
            _warn(f"v2 extra missing: {mod}")
            issues.append(f"v2:{mod}")

    print()
    print("[6] v2 module integrity")
    for sub in ("brain", "remediate", "shield", "mobile", "mcp", "ueba"):
        path = install_dir / "logsentinel" / sub
        if path.is_dir():
            _ok(f"logsentinel/{sub}/")
        else:
            _fail(f"Missing v2 module: logsentinel/{sub}/")
            issues.append(f"v2mod:{sub}")

    print()
    print("[7] Install folder hygiene")
    cleanup_script = install_dir / "scripts" / "rla_cleanup.py"
    if not cleanup_script.is_file():
        cleanup_script = Path(__file__).resolve().parent / "rla_cleanup.py"
    junk_markers = (
        "RocketLogAI_Ver1.0",
        ".git",
        "dist",
        "errors.txt",
    )
    junk_found = [name for name in junk_markers if (install_dir / name).exists()]
    if junk_found:
        _warn("Junk/legacy paths found: " + ", ".join(junk_found))
        issues.append("cleanup:junk")
    else:
        _ok("No common junk paths at install root")

    if install_type == "docker":
        print()
        print("[8] Docker")
        if docker_available():
            _ok("Docker daemon reachable")
        else:
            _fail("Docker not running (start Docker Desktop or docker service)")
            issues.append("docker:down")

    if fix and issues:
        print()
        print("[FIX] Attempting repairs...")
        if cleanup_script.is_file():
            proc = _run(
                [str(find_python()), str(cleanup_script), str(install_dir), "--fix"],
                cwd=install_dir,
            )
            if proc.returncode == 0:
                _ok("Install folder cleaned")
                issues = [i for i in issues if i != "cleanup:junk"]
        if install_type == "native":
            clean_pycache(install_dir)
            if pip_install_editable(install_dir, runtime):
                _ok("Reinstalled editable package with [web,v2] extras")
                write_launchers(install_dir)
                _ok("Updated launcher scripts")
                (install_dir / ".install-type").write_text("native\n", encoding="utf-8")
                # Re-check pip location
                issues = [i for i in issues if not i.startswith(("pip:", "dep:", "v2:", "venv:"))]
            else:
                issues.append("fix:pip-failed")

    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="RocketLogAI install health check")
    parser.add_argument("install_dir", nargs="?", default=".", help="Installation directory")
    parser.add_argument("--fix", action="store_true", help="Attempt to repair common issues")
    args = parser.parse_args()

    install_dir = Path(args.install_dir).resolve()
    if not install_dir.is_dir():
        print(f"ERROR: Not a directory: {install_dir}")
        return 1

    issues = run_checks(install_dir, fix=args.fix)

    print()
    if not issues:
        print("All checks passed.")
        return 0

    print(f"{len(issues)} issue(s) remain:")
    for item in issues:
        print(f"  - {item}")

    if args.fix:
        print()
        print("Some issues may need manual attention. Re-run without --fix to verify.")
        return 2
    print()
    print("Run with --fix to attempt automatic repair:")
    print(f"  python scripts/healthcheck.py \"{install_dir}\" --fix")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())