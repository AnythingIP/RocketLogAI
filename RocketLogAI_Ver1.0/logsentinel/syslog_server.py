"""
Async syslog server (UDP + TCP).

Receives raw messages and hands normalized records to a callback.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Awaitable, Callable, Any

from .parser import parse_syslog_message

logger = logging.getLogger(__name__)

LogCallback = Callable[[dict[str, Any]], Awaitable[None]]


class SyslogServer:
    """
    Async syslog receiver supporting UDP and TCP.

    Usage:
        server = SyslogServer(callback=my_handler, config=cfg)
        await server.start()
    """

    def __init__(
        self,
        callback: LogCallback,
        host: str = "0.0.0.0",
        udp_port: int | None = 5140,
        tcp_port: int | None = 5140,
        max_message_size: int = 8192,
        buffer_size: int = 10000,
    ):
        self.callback = callback
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.max_message_size = max_message_size
        self.buffer_size = buffer_size

        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._ring: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._running = False

    async def start(self) -> None:
        """Start all configured listeners."""
        self._running = True
        tasks = []

        if self.udp_port:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPSyslogProtocol(self),
                local_addr=(self.host, self.udp_port),
            )
            self._udp_transport = transport
            logger.info(f"Listening for syslog on UDP {self.host}:{self.udp_port}")

        if self.tcp_port:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                self.host,
                self.tcp_port,
            )
            logger.info(f"Listening for syslog on TCP {self.host}:{self.tcp_port}")

        if not self.udp_port and not self.tcp_port:
            logger.warning("No syslog listeners configured")

    async def stop(self) -> None:
        self._running = False
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        logger.info("Syslog server stopped")

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            while self._running:
                try:
                    data = await reader.readuntil(b"\n")
                except asyncio.IncompleteReadError as e:
                    data = e.partial
                    if not data:
                        break
                except (ConnectionResetError, BrokenPipeError):
                    break

                if not data:
                    break

                raw = data.decode("utf-8", errors="replace").strip()
                if raw:
                    await self._process_message(raw, source=f"tcp:{peer[0]}" if peer else "tcp")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_message(self, raw: str, source: str = "unknown") -> None:
        try:
            record = parse_syslog_message(raw)
            record["source"] = source
            self._ring.append(record)
            await self.callback(record)
        except Exception as exc:
            logger.exception("Failed to process syslog message: %s", exc)

    def get_recent(self, n: int = 100) -> list[dict[str, Any]]:
        """Return the most recent n normalized log records."""
        return list(self._ring)[-n:]


class _UDPSyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: SyslogServer):
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            raw = data.decode("utf-8", errors="replace").strip()
            if raw:
                # We cannot await here directly in UDP callback; schedule it
                loop = asyncio.get_running_loop()
                loop.create_task(
                    self.server._process_message(raw, source=f"udp:{addr[0]}")
                )
        except Exception as exc:
            logger.exception("UDP handler error: %s", exc)
