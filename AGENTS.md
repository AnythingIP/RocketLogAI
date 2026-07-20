# Agent rules — RockeLogAI

You are working on the **RocketLogAI product** (folder name: `RockeLogAI`).

## Scope

- Product code lives here: `logsentinel/`, `templates/`, `scripts/`, `tests/`, `docs/`.
- Lab host deploy: **home-grok-001** `192.168.20.54` → `/srv/storage/logsentinel` Docker image `rocketlogai:2.0`, UI **https://192.168.20.54:8787**.
- Do **not** implement LinuxBox lab infra, Comfy farm, or Studio features here — switch project (Ctrl-S).
- **GitHub / Pages / release notes for this product** → do them **from this session/folder**, not from `LinuxBox-Grok`.

## Remotes

| Remote | URL |
|--------|-----|
| `origin` | https://github.com/AnythingIP/RocketLogAI.git (public GitHub) |
| `forgejo` | http://192.168.20.92:3000/grok/RockeLogAI.git (lab) |

---

## Handoff status (2026-07-20) — read this first

Work was done from a **LinuxBox-Grok** lab session and written **into this tree**. When the user opens this project (Ctrl-S), **the source files are already on disk** — they do **not** need to re-implement the FP fix. They **do** still need (when asked):

1. **Git commit + push** (changes were **not** committed to GitHub yet).
2. Optional clean **Docker rebuild** on `.54` so image matches git (lab was **hot-patched** only).
3. Optional GitHub issue/PR/release note about home-lab AP-flow false positives.

### Files already changed / added in this workspace

| Path | Status | What |
|------|--------|------|
| `logsentinel/noise.py` | **NEW** | AP-flow / LAN / HA false-positive classifier |
| `logsentinel/analyzer.py` | **MOD** | Skip noise for LLM; post-filter threats; skip unchanged log window |
| `logsentinel/llm.py` | **MOD** | Home-lab system prompt (never flag UniFi flow as SYN flood) |
| `logsentinel/rules.py` | **MOD** | Exploit rule no longer matches bare `payload` |
| `logsentinel/storage.py` | **MOD** | Persist threat `status` from suppress path |
| `logsentinel/diagnostics.py` | **MOD** | Docker = OK for python runtime; softer ping missing |
| `Dockerfile` | **MOD** | `setuptools>=65,<81` before OI; `iputils-ping`; install `.[web,v2,ai]` |
| `scripts/sweep_false_positives.py` | **NEW** | Bulk mark open FPs `verified_benign` |
| `tests/test_noise.py` | **NEW** | Unit tests (5) — run with `pytest tests/test_noise.py` |
| `docs/FALSE_POSITIVES_HOME_LAB.md` | **NEW** | Full write-up for humans + agents |
| `AGENTS.md` | **NEW** | This file |

### System Health (Docker on .54)

- **open-interpreter / pkg_resources**: setuptools must stay **`<81`** (`oi_compat.SETTOOLS_PIN`). Image previously pulled setuptools 83 → OI import failed. Fixed live on `.54`; Dockerfile pinned for rebuilds.
- **python:runtime “not in a venv”**: normal in Docker; diagnostics now reports OK when `/.dockerenv` present.
- **ping / heartbeats**: need `iputils-ping` in image (added to Dockerfile).

Also present on disk (unrelated / pre-existing untracked): check `git status` before committing — do **not** blindly add junk.

### Lab server (already done — do not re-sweep unless asked)

- Code hot-copied into container paths:
  - `/app/logsentinel/`
  - `/usr/local/lib/python3.12/site-packages/logsentinel/`
- DB sweep: **~24.6k** threats → `verified_benign` (AP flow / HA noise).
- Live analyzer: ~**2** non-noise logs per batch (was 25 AP dumps); **no new SYN-flood spam**.
- **~7.9k** older open threats remain (mixed “unusual HTTPS” LLM history) — optional second cleanup.
- HTTPS UI: **https://192.168.20.54:8787** (TLS on; plain HTTP off).

### What the user should say after Ctrl-S

Examples:

- “Commit and push the home-lab false-positive fix to GitHub.”
- “Open/update a GitHub issue about UniFi AP flow false positives and link the fix.”
- “Rebuild rocketlogai on .54 from this tree so site-packages matches git.”
- “Draft release notes for the FP fix.”

---

## Product rules (ongoing)

- Home-lab syslog is full of **UniFi/Omada AP flow** lines and **Home Assistant IoT** noise — see `docs/FALSE_POSITIVES_HOME_LAB.md`.
- Prefer **deterministic pre/post filters** (`noise.py`) over trusting small local LLMs on Wi‑Fi flow dumps.
- After analyzer/noise changes: `pytest tests/test_noise.py` (and v2 tests if touched).
- Bulk FP cleanup:  
  `PYTHONPATH=. python3 scripts/sweep_false_positives.py /path/to/logsentinel.db [--dry-run]`
- Docker: after code change, **rebuild image** (preferred) so both install paths stay in sync. Hot-patch both trees only for emergency lab fix.
- Credentials: lab Ubuntu boxes use `grok` (not andrew/Atlas123).

## Never confuse with

| Folder | What |
|--------|------|
| `LinuxBox-Grok` | Lab IPs, SSH, multi-site Comfy docs — **not** product PRs |
| `rocket-fox-studio` | Studio UI / workers |
| `comfy-farm` | Comfy workers |
