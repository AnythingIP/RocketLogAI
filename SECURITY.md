# Security Policy

> **Legal:** This project is provided AS IS under the [MIT License](LICENSE).
> See [DISCLAIMER.md](DISCLAIMER.md). Reporting a vulnerability does not create a
> support contract, SLA, or bounty unless we agree in writing.

## Supported Versions

We aim to support the latest release with security updates.

## Reporting a Vulnerability

RocketLogAI is a local-first security tool that ingests logs from your environment. We take security seriously.

If you discover a security vulnerability in the core (log ingestion, analysis, remediation engine, web UI auth, etc.), please **do not open a public issue**.

Instead:
- Email: security@anythingip.com (or open a private security advisory on this GitHub repo if the feature is enabled)
- Include as much detail as possible: affected version, reproduction steps, potential impact, and any suggested fixes.

We will acknowledge receipt within 48 hours and aim to release a fix or mitigation plan promptly.

## Scope

In scope:
- Remote code execution via log parsing or LLM output handling
- Authentication / session issues in the web UI
- Unsafe remediation script execution paths
- Data exfiltration or unintended network calls
- Supply-chain issues in dependencies we control

Out of scope (for now):
- Issues that only affect users who have explicitly enabled `remediation.enabled: true` and bypassed the confirmation guards (this feature is intentionally heavily guarded and disabled by default)
- Attacks that require physical access or already-compromised hosts sending malicious syslog
- Social engineering of operators

Thank you for helping keep RocketLogAI (and the environments that rely on it) safe.

## Author liability

Security research and responsible disclosure are appreciated. Authors and contributors
are not liable for how you use information from this repository or for incidents on
systems where you chose to deploy the software. You are responsible for your own
environment and for validating any fix before production use.
