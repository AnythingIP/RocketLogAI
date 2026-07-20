# Home-lab false positives (UniFi/Omada AP flows + HA)

## What we saw on the production DB (2026-07-20)

| Metric | Value |
|--------|--------|
| Open threats | ~32k (almost all open forever) |
| Sample of last 3k evidence | **~97% UniFi/Omada AP flow accounting** |
| Top destination in “attacks” | **192.168.20.38 (Home Assistant)** |
| Top source port | **9999** (IoT → HA) |
| Newest logs in DB | **2026-07-19** (stale after Windows→Linux migrate) |
| Analyzer | `qwen2.5:7b` re-scoring the **same** flow logs every ~45s as “SYN flood” |

### Not real attacks

- `AP MAC=… MAC SRC=… IP SRC=… IP DST=… IP proto=6 SPT=… DPT=…`  
  = Wi‑Fi **client traffic logs**, not IDS.
- “SYN flood” with one or a few flow tuples = **LLM overconfidence**.
- ICMP to gateway = normal.
- IoT SPT=9999/7000 → HA = normal.
- Outbound DPT=443 to CDN = normal.
- HA Mosquitto `172.30.x` reconnects = Docker network noise.
- Rule match on bare word **`payload`** (`max. payload size`) = **bug** (fixed).

### Possibly real (keep / investigate)

- SSH failed password / invalid user from **external** IPs  
- Explicit firewall **deny/drop** floods from WAN  
- Clear malware strings (xmrig, reverse shell, etc.)  
- Heartbeat monitor failures (ops issue, not network attack)

### Offline ghost IPs (e.g. `.39`)

Device may be **offline now** while threats still reference it: evidence is **historical** AP logs. After migrate, analyzer was replaying **July 19** logs with no new syslog.

## Code fixes (this PR / tree)

1. `logsentinel/noise.py` — AP flow + LAN FP classifier  
2. `analyzer.py` — skip noise for LLM; post-filter threats; skip unchanged log window  
3. `llm.py` — home-lab system prompt (never flag AP flows as SYN flood)  
4. `rules.py` — exploit rule no longer matches bare `payload`  
5. `storage.py` — persist threat `status` from suppress path  
6. `scripts/sweep_false_positives.py` — bulk `verified_benign` on open FPs  

## Ops after deploy

```bash
# On .54 (example paths)
cd /srv/storage/logsentinel
# Prefer full image rebuild so both /app/logsentinel and site-packages match:
docker compose build --no-cache rocketlogai   # or normal build after Dockerfile fix
docker compose up -d

# Hot-patch (dev only) — copy into BOTH trees:
#   /app/logsentinel/
#   /usr/local/lib/python3.12/site-packages/logsentinel/

# One-shot DB sweep (host with PYTHONPATH=install root)
PYTHONPATH=/srv/storage/logsentinel \
  python3 scripts/sweep_false_positives.py data/logsentinel.db
# dry-run:
PYTHONPATH=/srv/storage/logsentinel \
  python3 scripts/sweep_false_positives.py data/logsentinel.db --dry-run
```

### Deployed lab results (2026-07-20)

| Action | Result |
|--------|--------|
| Bulk `verified_benign` | **~24.6k** AP-flow / HA noise |
| Open remaining | **~7.9k** older mixed LLM rows (many “unusual HTTPS to AWS” — review later) |
| Live analyzer | Sends **~2** non-noise logs/batch (was 25 AP dumps); **0** new SYN-flood threats |
| Heartbeats | Still open “Ping failed” / missing `ping` in container + offline switches — **ops**, not attacks |

Re-point live syslog to **UDP/TCP 5140** on the Linux host so analysis has **new** logs.

## Notes for build agents

- Prefer **deterministic pre/post filters** over trusting small local LLMs on Wi‑Fi flow dumps.  
- Never treat RFC1918↔RFC1918 flow accounting as DoS without deny/counters from a real firewall.  
- `summary` from models must be prose, not raw JSON blobs.  
- When adding patterns, exclude HA size/payload wording and AP flow formats.  
