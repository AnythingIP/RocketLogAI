RocketLogAI v1.0 source backup (prepared on 2026-05-27)

This is a clean copy of the source code, templates, docs, and install scripts.
It does NOT include:
  - data/ (database, SSL certs, learned devices, session secrets)
  - GeoLite2-City.mmdb (large, download fresh)
  - Your config.yaml (contains secrets)

To deploy on a new server:
1. Copy this entire RocketLogAI_Ver1.0 folder to the new machine
2. cd into it
3. Run the appropriate install script (scripts/install.sh or install.ps1)
4. Copy your old data/ folder (or start fresh)
5. Edit config.yaml for the new environment (LLM URL, web_host, ports, HA token, etc.)
6. logsentinel run --web

Both HTTP and HTTPS are supported simultaneously on different ports
when you set http_enabled + ssl_enabled in config.yaml.

See README.md and docs/USAGE.md for details.
