# RocketLogAI v2 Architecture

## Overview

RocketLogAI v2 is a local-first security platform comprising four products sharing a unified AI brain:

| Product | Purpose |
|---------|---------|
| **RocketLogAI** | Syslog ingestion, threat detection, AI assistant, devices, daily briefing, config |
| **RocketRemediate** | Safe remediation with dry-run, approval workflow, backups, rollback |
| **RocketShield** | WAF + AV scanner on decrypted traffic, parental controls (inline/SPAN) |
| **RocketAI Mobile** | iOS/Android/TV API — local-first assistant, sync, remote PC/Mac control |

## Data Flow

```
Syslog UDP/TCP (5140) ──► Parser ──► SQLite Storage
                              │
                              ├──► Rule Engine ──► Threats
                              ├──► UEBA Detector ──► Anomalies
                              └──► Vector Store (RAG) ──► Unified AI Brain
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              AI Assistant        Daily Briefing      MCP Server
              RocketRemediate     Mobile API          External AI Clients
```

## Core Modules

### Unified AI Brain (`logsentinel/brain/`)
- **VectorStore** — Chroma (preferred) or SQLite fallback
- **RAGPipeline** — Ingest logs/threats/conversations for retrieval
- **ConversationMemory** — Persistent intent across sessions
- **AIOrchestrator** — Agentic coordination with visible execution results

### MCP Server (`logsentinel/mcp/`)
Graylog/Zabbix-style tool exposure via JSON-RPC (stdio + HTTP). Tools: `search_logs`, `list_threats`, `rag_search`, `device_status`.

### RocketRemediate (`logsentinel/remediate/`)
- Dry-run by default
- Human approval workflow
- Pre-action backups + rollback plans
- Plugin architecture for SSH/firewall/script responders

### RocketShield (`logsentinel/shield/`)
- WAF rules (SQLi, XSS, path traversal, command injection)
- AV scanner (signature + heuristic on decrypted payloads)
- Parental controls (time-based, category-based)
- Modes: inline, SPAN/tap, disabled

### Security
- Zero Trust: RBAC (Viewer/Analyst/Operator/Admin), encrypted secrets, audit logging
- TLS everywhere (HTTPS web, optional TLS syslog)
- Rate limits and circuit breakers on remediation

## API Endpoints (v2)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v2/status` | Ecosystem health |
| `GET /api/v2/metrics` | Prometheus metrics |
| `POST /api/v2/brain/ask` | Unified AI query |
| `POST /api/v2/remediate/dry-run` | Safe remediation preview |
| `GET /api/v2/ueba/report` | Explainable UEBA summary |
| `GET /api/v2/tasks` | Organization tasks |
| `POST /api/config/save/{section}` | Per-section config save |

## Deployment

- **Docker**: `docker compose up -d --build`
- **Helm**: `helm install rocketlogai ./helm/rocketlogai`
- **Native**: `scripts/install.sh` (generates systemd service on Linux)

## License

MIT — see [LICENSE](../LICENSE)