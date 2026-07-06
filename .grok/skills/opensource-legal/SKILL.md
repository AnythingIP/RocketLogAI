---
name: opensource-legal
description: >
  Project-local pointer to AnythingIP legal safety workflow. The canonical skill
  lives at ~/.grok/skills/opensource-legal/SKILL.md — use when working in this repo.
---

# Legal safety in RocketLogAI

See:

- [DISCLAIMER.md](../../DISCLAIMER.md)
- [legal/GITHUB_PROJECT_CHECKLIST.md](../../legal/GITHUB_PROJECT_CHECKLIST.md)
- [legal/README_DISCLAIMER_BLOCK.md](../../legal/README_DISCLAIMER_BLOCK.md)

When adding features that run commands, change systems, or call external APIs: keep them
off by default, require confirmation, and do not use "guaranteed" or "production-ready"
wording in user-facing copy without linking the disclaimer.

**Always sync README.md and docs/index.html in the same commit** when marketing or legal
copy changes. See [legal/SHARED_COPY.md](../../legal/SHARED_COPY.md).