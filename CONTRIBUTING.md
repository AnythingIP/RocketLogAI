# Contributing to RocketLogAI

Thanks for your interest in improving RocketLogAI!

## Quick Start for Contributors

1. Fork the repo and clone your fork.
2. Create a virtualenv and `pip install -e ".[web]"`.
3. Copy `example-config.yaml` to `config.yaml` and point it at a local LLM (LM Studio / Ollama recommended for development).
4. Run `logsentinel run` and send some test logs (see README or USAGE.md).

## What We're Looking For

- New or improved deterministic rules (especially for specific devices or common noise)
- Additional prebuilt remediation scripts (with safety comments and dry-run support)
- Better structured output prompts or few-shot examples for popular local models
- Parser improvements for more syslog formats or JSON logs
- Home Assistant integration enhancements
- Documentation, examples, and translations of error messages
- Windows Event Log ingestion
- Tests (we're light on them today)
- UI/UX improvements to the FastAPI + HTMX dashboard

## Pull Request Guidelines

- Keep changes focused.
- For security-sensitive changes, open a draft PR or contact us privately first.
- Update relevant docs (README, USAGE.md, or the in-app Assistant knowledge if it makes sense).
- If your change affects remediation scripts, make sure they remain heavily commented and safe-by-default.

## Code Style

- Python code follows the settings in pyproject.toml (ruff + black).
- The web templates use the existing Tailwind + HTMX patterns — keep the calm, dark, information-dense aesthetic.

## Questions?

Open an issue or use the built-in AI Assistant in a running instance and submit a suggestion — the maintainers review those.

We appreciate every contribution that makes local, private log intelligence better for everyone.
