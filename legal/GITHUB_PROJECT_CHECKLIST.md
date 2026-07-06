# AnythingIP — GitHub project legal checklist

Copy this checklist for **every** new public repo you publish for fun.

## Required files (minimum)

- [ ] **`LICENSE`** — MIT recommended (see [MIT template](../LICENSE))
- [ ] **`DISCLAIMER.md`** — copy from [DISCLAIMER.md](../DISCLAIMER.md) and adjust project name
- [ ] **`README.md`** — include the [README disclaimer block](README_DISCLAIMER_BLOCK.md)

## Strongly recommended

- [ ] **`SECURITY.md`** — how to report vulns; no SLA unless you mean it
- [ ] **`CONTRIBUTING.md`** — note that contributions are MIT-licensed
- [ ] **Issue templates** — link to DISCLAIMER.md in bug reports

## README wording — avoid

| Avoid | Prefer |
|-------|--------|
| "Production-ready" | "Experimental / hobby project" |
| "Guaranteed secure" | "Designed with safety rails; use at your own risk" |
| "We will support you" | "Best-effort community support via GitHub issues" |
| "Enterprise-grade" | "Local-first tool for learning and homelabs" |

## README wording — include

- Link to `DISCLAIMER.md` and `LICENSE`
- "MIT licensed — no warranty"
- "You are responsible for how you deploy this"
- For automation/AI/security tools: "Test in a lab first; review AI output"

## Web apps / installers

If the project has a UI or installer:

- [ ] Short disclaimer on login or first-run screen
- [ ] Footer: "Provided AS IS — see DISCLAIMER.md"
- [ ] Dangerous features **off by default** with explicit opt-in

## Organizations

If publishing under **AnythingIP**:

- Use consistent copyright: `Copyright (c) 2026 AnythingIP`
- Same MIT LICENSE across repos
- Do not imply AnythingIP is a registered company with insurance unless it is

## When to talk to a lawyer

- Selling support, hosting, or SaaS based on the project
- Handling regulated data (health, finance, children)
- Accepting paid contributions or CLAs
- Trademark or patent concerns

---

*This checklist is practical guidance, not legal advice.*