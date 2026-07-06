# Canonical public copy (keep README + GitHub Pages in sync)

When you change marketing or legal wording, update **all** of these in one commit:

| File | Purpose |
|------|---------|
| `README.md` | GitHub repo landing (first paragraph + Disclaimer section) |
| `docs/index.html` | [anythingip.github.io/RocketLogAI](https://anythingip.github.io/RocketLogAI/) |
| `docs/architecture.html` | Architecture page footer |
| `INSTALL.md` | Install intro (if it mentions project positioning) |

## Hero tagline (use this — not "production")

```
RocketLogAI v2 is a local-first security platform for homelabs and learning —
syslog monitoring, unified AI brain, guarded remediation, WAF/AV shield, and
mobile API. Uses your own offline LLM and keeps every byte on your hardware.
```

Append on web + README:

```
Hobby software — provided AS IS. See DISCLAIMER.md.
```

## Words to avoid (legal)

- production-ready / production security platform / Production Release
- guaranteed secure / enterprise-grade
- we will support you (unless you mean best-effort GitHub issues)

## New repos

Copy `docs/` pattern or add `docs/index.html` + link from org site. Run the same
DISCLAIMER + README block from `legal/README_DISCLAIMER_BLOCK.md`.