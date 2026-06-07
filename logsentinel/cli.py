"""
RocketLogAI CLI (AnythingIP)

Commands:
  run          - Start syslog + analysis (add --web for the dashboard too!)
  analyze      - One-shot analysis of recent logs (no server)
  web          - Local web dashboard (see LLM reasoning + threats nicely)
  status       - Show DB stats, recent threats, config summary
  logs         - Query recent logs
  threats      - Show recent AI + rule detections
  config       - Show effective config or generate example
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import __version__
from .analyzer import Analyzer
from .config import Config
from .heartbeat import HeartbeatMonitorRunner
from .llm import get_llm_client, LocalLLM  # LocalLLM kept for type hints during transition
from .remediation import RemediationEngine
from .storage import Storage
from .syslog_server import SyslogServer
from .datasource import get_datasource_runner


def _suppress_windows_asyncio_connection_reset():
    """
    On Windows (ProactorEventLoop), when we talk to LM Studio, Home Assistant,
    or other local services and they close the TCP connection, Python's asyncio
    logs extremely noisy ERRORs like:

        ConnectionResetError: [WinError 10054] An existing connection was forcibly closed...

    These are completely harmless. This function installs a handler that quietly
    swallows exactly those errors so the logs stay clean.
    """
    if sys.platform != "win32":
        return

    def _handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, ConnectionResetError):
            # This is the exact noisy case we want to hide.
            return
        # Let everything else through (real bugs, etc.)
        loop.default_exception_handler(context)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    loop.set_exception_handler(_handler)


console = Console()
logger = logging.getLogger("logsentinel")


def _get_accessible_urls(host: str, port: int) -> list[str]:
    """Return a list of likely URLs the user can use to reach the web UI."""
    urls = []
    if host in ("0.0.0.0", "::", ""):
        # Try localhost first (always works from the same machine)
        urls.append(f"http://localhost:{port}")
        urls.append(f"http://127.0.0.1:{port}")
        # Try to discover actual LAN IPs (best effort)
        try:
            # Get all non-loopback IPv4 addresses
            for iface in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = iface[4][0]
                if not ip.startswith("127."):
                    urls.append(f"http://{ip}:{port}")
        except Exception:
            pass
        # Deduplicate while preserving order
        seen = set()
        urls = [u for u in urls if not (u in seen or seen.add(u))]
    else:
        urls.append(f"http://{host}:{port}")
    return urls


def _install_crash_logger():
    """Ensure unhandled exceptions (crashes) are written to the log file + live buffer."""
    import traceback

    def _excepthook(exc_type, exc_value, exc_tb):
        try:
            tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            logging.getLogger("logsentinel.crash").error("UNHANDLED EXCEPTION:\n%s", tb_text)
        except Exception:
            # Last ditch: print to stderr
            print("UNHANDLED EXCEPTION (logging failed):", file=sys.stderr)
            traceback.print_exception(exc_type, exc_value, exc_tb, file=sys.stderr)

    sys.excepthook = _excepthook

    # Also for asyncio
    try:
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(lambda loop, context: logging.getLogger("logsentinel.async").error(
            "Async exception: %s", context.get("message", context)))
    except Exception:
        pass


def setup_logging(verbose: bool = False) -> str | None:
    """Configure logging to console + live web buffer + persistent rotating file log.

    Returns the path to the log file if successfully opened, else None.
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Console handler (rich-compatible, clean timestamps)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        force=True,  # allow reconfig in some contexts
    )

    root = logging.getLogger()

    # Live web buffer (for /logs page) - attach if web module present
    try:
        from .web import live_log_buffer
        root.addHandler(live_log_buffer)
    except Exception:
        pass  # web extras not installed or not imported yet

    # Persistent rotating logfile (the key improvement for diagnostics)
    log_path: str | None = None
    try:
        log_dir = Path("data")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = str(log_dir / "logsentinel.log")

        fh = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,   # 5 MiB
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root.addHandler(fh)

        # Also capture Python warnings into the logs
        logging.captureWarnings(True)

        # Emit a startup marker so the file is immediately useful
        logging.getLogger("logsentinel").info("=== Log file initialized: %s ===", log_path)
    except Exception as e:
        # Never let logging setup break the app
        print(f"[logsentinel] Warning: could not open persistent log file: {e}", file=sys.stderr)

    _install_crash_logger()
    return log_path


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="logsentinel")
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def main(ctx, config: str | None, verbose: bool):
    """RocketLogAI - Local AI-powered syslog security analyzer (by AnythingIP)."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose
    log_file = setup_logging(verbose)
    ctx.obj["log_file"] = log_file

    # Windows-only: kill the extremely noisy "ConnectionResetError 10054" spam
    # that appears when talking to LM Studio / Home Assistant etc.
    _suppress_windows_asyncio_connection_reset()


@main.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (default)")
@click.option("--web", is_flag=True, help="Also start the local web dashboard (highly recommended)")
@click.option("--web-host", default=None, help="Web UI host (with --web). Defaults to value in config or 127.0.0.1")
@click.option("--web-port", default=8787, type=int, help="Web UI port (with --web)")
@click.option("--web-user", help="Basic auth username for the web UI")
@click.option("--web-password", help="Basic auth password for the web UI")
@click.pass_context
def run(ctx, foreground: bool, web: bool, web_host: str, web_port: int, web_user: str | None, web_password: str | None):
    """Start the syslog server + analysis engine.

    Recommended: logsentinel run --web   (now running as RocketLogAI)
    This gives you both the background collector and a nice live web UI.
    """
    cfg = Config.load(ctx.obj["config_path"])

    # First-run experience: create a usable default config so the web UI works out of the box
    config_path = ctx.obj.get("config_path") or "config.yaml"
    if not os.path.exists(config_path):
        try:
            default_cfg = Config()
            default_cfg.web.web_host = "0.0.0.0"
            default_cfg.llm.base_url = "http://localhost:1234/v1"
            default_cfg.llm.provider = "local"
            default_cfg.save(config_path)
            logger.info(f"Created default config at {config_path}. You can now start the web UI and finish configuration there (no more manual YAML editing required for basic use).")
            cfg = Config.load(config_path)
        except Exception as e:
            logger.warning(f"Could not auto-create default config: {e}")

    storage = Storage(cfg.storage.db_path)

    # Blacklist / reputation (download on startup + daily refresh)
    if getattr(cfg, "blacklist", None) and cfg.blacklist.enabled:
        try:
            from .blacklist import get_blacklist
            bl = get_blacklist(cfg.blacklist)
            bl.refresh_if_needed()
            logger.info("IP blacklist loaded/refreshed")
        except Exception as e:
            logger.warning("Blacklist initialization failed: %s", e)

    # MAC Vendor database (for device type identification + manufacturer behavior checks)
    try:
        from .mac_vendor import refresh_mac_vendors_if_needed
        refresh_mac_vendors_if_needed()
        logger.info("MAC vendor database ready")
    except Exception as e:
        logger.warning("MAC vendor database initialization failed: %s", e)

    from .llm import get_llm_client
    llm = get_llm_client(cfg.llm)
    analyzer = Analyzer(cfg, storage, llm)
    rem = RemediationEngine(cfg)

    # Optional: prune old data on start
    if cfg.storage.retention_days > 0:
        deleted = storage.prune_old_logs(cfg.storage.retention_days)
        if deleted:
            logger.info(f"Pruned {deleted} old log records")

    # Optionally start the web dashboard in a background thread (cross-platform)
    web_thread = None
    log_file_path = ctx.obj.get("log_file") if hasattr(ctx, "obj") else None

    # Compute the host we *want* for the dashboard (from CLI flag > config > safe default)
    # Do this *before* the try so the final log message is always accurate even if web thread fails.
    effective_web_host = web_host or (cfg.web.web_host if getattr(cfg, "web", None) else None) or "127.0.0.1"

    if web:
        try:
            from .web import run_web_in_thread
            web_thread = run_web_in_thread(
                host=effective_web_host,
                port=web_port,
                storage=storage,
                cfg=cfg,
                auth_user=web_user,
                auth_pass=web_password,
            )
        except Exception as exc:
            logger.warning("Failed to start web UI in background: %s", exc)

    async def main_loop():
        server = SyslogServer(
            callback=_make_log_handler(storage, analyzer, rem, cfg),
            host=cfg.syslog.listen[0].host if cfg.syslog.listen else "0.0.0.0",
            udp_port=cfg.syslog.listen[0].port if cfg.syslog.listen else None,
            tcp_port=cfg.syslog.listen[1].port if len(cfg.syslog.listen) > 1 else None,
            max_message_size=cfg.syslog.max_message_size,
            buffer_size=cfg.syslog.buffer_size,
        )

        await server.start()

        # Start analyzer loop as background task
        analysis_task = asyncio.create_task(analyzer.run_loop())

        # Start heartbeat / deep service monitoring task (always create for runtime enable/disable support via UI/config).
        # The loop gates on current cfg.heartbeats.enabled and refreshes monitors from DB each cycle.
        hb_runner = HeartbeatMonitorRunner(cfg.heartbeats, storage=storage)
        async def _hb_loop():
            while True:
                try:
                    # respect runtime toggles of heartbeats.enabled (from monitors page or config UI)
                    hb_enabled = bool(getattr(getattr(cfg, "heartbeats", None), "enabled", False))
                    if hb_enabled:
                        # refresh in case new monitors added via UI/DB
                        hb_runner._monitors = hb_runner._load_monitors()
                        results = hb_runner.run_all()
                        if results:
                            logger.info("Heartbeat checks completed: %d checks", len(results))

                    # PR5: Periodic HA sensors (gated, uses existing loop, zero new tasks)
                    if getattr(cfg.home_assistant, "create_sensors", False):
                        try:
                            from .ha import get_ha_client
                            ha = get_ha_client(cfg)
                            if ha:
                                counts = storage.get_threat_count_by_severity() if hasattr(storage, "get_threat_count_by_severity") else {}
                                open_count = sum(counts.values()) if counts else 0
                                ha.update_sensor(
                                    "sensor.logsentinel_open_threats",
                                    str(open_count),
                                    {"breakdown": counts, "last_updated": datetime.utcnow().isoformat() + "Z"},
                                )
                        except Exception as ha_err:
                            logger.debug("HA periodic sensor update skipped: %s", ha_err)
                except Exception as e:
                    logger.exception("Heartbeat loop error: %s", e)
                await asyncio.sleep(30)  # poll frequently; each monitor respects its own interval_seconds (60s pings, hours/days for SSH etc)
        heartbeat_task = asyncio.create_task(_hb_loop())
        if getattr(cfg.heartbeats, 'enabled', False):
            logger.info("Heartbeat monitoring enabled (loads monitors from config.yaml + DB; supports UI-added ones)")
        else:
            logger.info("Heartbeat monitoring task started (currently disabled; enable via UI or config to activate)")

        # Print nice banner
        _print_banner(cfg, storage, llm, rem, log_file_path)

        if web:
            auth_info = " (auth enabled)" if web_user else ""
            urls = _get_accessible_urls(effective_web_host, web_port)
            logger.info("Web dashboard is up and ready%s", auth_info)
            logger.info(">>> OPEN IN YOUR BROWSER (use plain http, not https):")
            for u in urls:
                logger.info("    %s", u)
            logger.info("    (If connection is refused: on macOS, look for a 'Python wants to accept incoming connections' dialog and allow it. Also check your firewall.)")
            logger.info("    Full details + live server logs are in: %s", log_file_path or "data/logsentinel.log")

        # Graceful shutdown
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def _signal_handler():
            logger.info("Shutdown signal received...")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                # Windows
                pass

        await stop_event.wait()

        analyzer.stop()
        analysis_task.cancel()
        if heartbeat_task:
            heartbeat_task.cancel()
        await server.stop()
        logger.info("Shutdown complete.")

    asyncio.run(main_loop())


# Phase 4 auth CLI helper (as suggested)
@main.command()
@click.option("--test-domain", is_flag=True, help="Test current domain settings with Phase 4 LDAP service-account + group + role logic")
@click.option("--server", default=None)
@click.option("--base-dn", default=None)
@click.option("--test-user", default=None)
@click.option("--test-pass", default=None)
@click.pass_context
def auth(ctx, test_domain, server, base_dn, test_user, test_pass):
    """Phase 4 enterprise auth testing utilities."""
    print("Use 'logsentinel run' for normal operation. For domain test use the web UI test button (recommended) or implement full CLI here.")
    if test_domain:
        print("Domain test via CLI is best done through the /config UI 'Test Domain + Groups + Role' button for full form support.")
    # Full implementation can call the same try_ldap_login logic as the web test endpoint.


def _make_log_handler(storage, analyzer, rem, cfg):
    """Create the callback that receives every syslog message."""
    async def handler(record: dict):
        # Store every log
        storage.insert_log(record)

        # Fast path: rule-based immediate alerts for very bad things
        score, matches = analyzer.rule_engine.score_record(record)
        if score >= 8.0 and cfg.alerting.console:
            console.print(f"[bold red]!!! HIGH SEVERITY RULE MATCH[/] {record.get('message')[:120]}")

        # Future: push to remediation suggestions here (currently disabled)
    return handler


def _print_banner(cfg: Config, storage: Storage, llm: LocalLLM, rem: RemediationEngine, log_file: str | None = None):
    extra = f"\nLog file: {log_file}" if log_file else ""
    console.print(Panel.fit(
        f"[bold cyan]RocketLogAI[/] v{__version__} — AI-Powered Syslog Security (AnythingIP) [BETA]\n\n"
        f"Listening on: {', '.join(f'{l.protocol}:{l.host}:{l.port}' for l in cfg.syslog.listen)}\n"
        f"LLM endpoint: {cfg.llm.base_url}\n"
        f"Database: {Path(cfg.storage.db_path).resolve()}\n"
        f"Analysis: every {cfg.analysis.interval_seconds}s\n"
        f"Remediation: {'ARMED (DANGEROUS)' if rem.would_execute() else 'DISABLED (safe)'}{extra}",
        title="RocketLogAI",
        border_style="cyan",
    ))

    # Quick connectivity check
    if llm.is_available():
        console.print("[green]✓[/] Local LLM endpoint reachable")
    else:
        console.print("[yellow]⚠[/] Local LLM endpoint not reachable (analysis will be rule-only)")


@main.command()
@click.option("--limit", "-n", default=30, help="Number of logs to analyze")
@click.pass_context
def analyze(ctx, limit: int):
    """Run one analysis pass on recent logs without starting the server."""
    cfg = Config.load(ctx.obj["config_path"])
    storage = Storage(cfg.storage.db_path)
    from .llm import get_llm_client
    llm = get_llm_client(cfg.llm)
    analyzer = Analyzer(cfg, storage, llm)

    console.print("[cyan]Running one-shot analysis...[/]")
    result = asyncio.run(analyzer.analyze_recent())

    console.print(Panel.fit(
        f"Logs evaluated: {result.get('logs_evaluated')}\n"
        f"Threats found: {result.get('threats_found')}\n"
        f"Used LLM: {result.get('used_llm')}\n\n"
        f"{result.get('summary', '')}",
        title="Analysis Result",
        border_style="green" if result.get("threats_found", 0) == 0 else "red",
    ))


@main.command()
@click.option("--limit", "-n", default=50, help="How many recent logs to show")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.pass_context
def logs(ctx, limit: int, as_json: bool):
    """Show the most recent stored logs."""
    cfg = Config.load(ctx.obj["config_path"])
    storage = Storage(cfg.storage.db_path)
    recent = storage.get_recent_logs(limit=limit)

    if as_json:
        console.print(json.dumps(recent, indent=2))
        return

    table = Table(title=f"Recent Logs ({len(recent)})", box=box.SIMPLE)
    table.add_column("Time", style="dim")
    table.add_column("Host")
    table.add_column("App")
    table.add_column("Sev", style="yellow")
    table.add_column("Message", overflow="fold")

    for r in reversed(recent[-limit:]):
        ts = r.get("timestamp", "")[11:19] if r.get("timestamp") else ""
        table.add_row(
            ts,
            r.get("hostname") or "-",
            r.get("appname") or "-",
            r.get("severity", "?"),
            (r.get("message") or "")[:140],
        )
    console.print(table)


@main.command()
@click.option("--limit", "-n", default=30, help="How many threats to show")
@click.pass_context
def threats(ctx, limit: int):
    """Show recent threats detected by rules + LLM."""
    cfg = Config.load(ctx.obj["config_path"])
    storage = Storage(cfg.storage.db_path)
    threats_list = storage.get_recent_threats(limit=limit)

    if not threats_list:
        console.print("[green]No threats recorded yet.[/]")
        return

    table = Table(title="Recent Threats", box=box.SIMPLE_HEAVY)
    table.add_column("Time", style="dim")
    table.add_column("Sev", style="red")
    table.add_column("Score")
    table.add_column("Description", overflow="fold")
    table.add_column("Host/App")

    for t in threats_list:
        table.add_row(
            t.get("created_at", "")[11:19],
            t.get("severity", ""),
            str(round(t.get("score", 0), 1)),
            t.get("description", "")[:100],
            f"{t.get('hostname') or ''}/{t.get('appname') or ''}",
        )
    console.print(table)


@main.command()
@click.pass_context
def status(ctx):
    """Show system status, DB stats, and recent activity."""
    cfg = Config.load(ctx.obj["config_path"])
    storage = Storage(cfg.storage.db_path)
    from .llm import get_llm_client
    llm = get_llm_client(cfg.llm)

    total = storage.count_logs()
    threats = storage.get_threat_count_by_severity()
    recent_threats = storage.get_recent_threats(limit=5)

    console.print(Panel.fit(
        f"Total logs stored: {total}\n"
        f"Threats by severity: {threats}\n"
        f"LLM reachable: {'yes' if llm.is_available() else 'NO'}\n"
        f"Remediation armed: {RemediationEngine(cfg).would_execute()}",
        title="RocketLogAI Status",
        border_style="cyan",
    ))

    if recent_threats:
        console.print("\n[bold]Latest threats:[/]")
        for t in recent_threats[:5]:
            console.print(f"  • [{t.get('severity')}] {t.get('description')}")


@main.command()
@click.option("--output", "-o", default="config.yaml.example", help="Where to write the example")
def example_config(output: str):
    """Generate a fully commented example config file."""
    cfg = Config()
    cfg.save_example(output)
    console.print(f"[green]Wrote example config to[/] {output}")


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind the web UI to")
@click.option("--port", default=8787, type=int, help="Port for the web UI")
@click.option("--user", help="Username for basic auth (optional but recommended if exposed)")
@click.option("--password", help="Password for basic auth")
@click.pass_context
def web(ctx, host: str, port: int, user: str | None, password: str | None):
    """Start the local web dashboard (nice HTML view of threats + LLM output)."""
    _suppress_windows_asyncio_connection_reset()

    try:
        from .web import run_web
    except ImportError as e:
        console.print(
            "[red]Web UI dependencies are not installed.[/]\n"
            "Install them with:\n\n"
            "  pip install 'logsentinel[web]'\n"
            "or\n"
            "  pip install fastapi 'uvicorn[standard]' jinja2"
        )
        raise click.Abort()

    cfg = Config.load(ctx.obj["config_path"])
    storage = Storage(cfg.storage.db_path)

    run_web(host=host, port=port, storage=storage, cfg=cfg, auth_user=user, auth_pass=password)


@main.command("enable-local-login")
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.pass_context
def enable_local_login(ctx, config: str | None):
    """Emergency escape hatch: force-enable local administrator login.

    Use this from the server console/SSH if domain auth is broken and you cannot log into the web UI.

    This edits config.yaml safely and prints instructions.
    """
    cfg_path = config or ctx.obj.get("config_path") or "config.yaml"
    try:
        import yaml
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        if "web" not in raw:
            raw["web"] = {}
        raw["web"]["allow_local_login"] = True

        tmp = cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, sort_keys=False, default_flow_style=False, indent=2)
        os.replace(tmp, cfg_path)

        print("✅ Local login has been force-enabled in config.yaml (web.allow_local_login: true).")
        print("Restart RocketLogAI for the change to take effect.")
        print("Example: systemctl restart rocketlogai   or   docker compose restart")
        print("Then log in with your local admin account. Re-configure domain settings from the UI once back in.")
    except Exception as e:
        print(f"Failed to update config.yaml: {e}")
        print("Manual recovery: edit the config.yaml file and ensure under the 'web:' section you have:")
        print("  allow_local_login: true")
        print("Then restart the service.")


if __name__ == "__main__":
    main()
