# ai_log_parser/connectors/syslog.py

"""
SyslogConnector — listens on a UDP/TCP port for syslog / CEF streams.

Designed to receive Suricata CEF output and generic syslog traffic
forwarded to the collector host (default port 514).

Supported YAML config keys
--------------------------
Required:
    type : "syslog"
    name : str          — human label

Optional:
    host          : str   — bind address (default: "0.0.0.0")
    port          : int   — UDP port to bind (default: 514)
    protocol      : str   — "udp" | "tcp" (default: "udp")
    max_line_size : int   — maximum byte length of a single datagram/line
                            (default: 65535)
    encoding      : str   — line encoding (default: "utf-8")
    errors        : str   — encoding error handler (default: "replace")

Example YAML block
------------------
    - type: syslog
      name: suricata-514
      host: 0.0.0.0
      port: 514
      protocol: udp
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncGenerator

from ai_log_parser.connectors.base import (
    ConnectorConfigError,
    ConnectorIOError,
    CustomConnector,
)

logger = logging.getLogger(__name__)

_DEFAULT_HOST = "0.0.0.0"
_DEFAULT_PORT = 514
_DEFAULT_MAX_LINE = 65535
_DEFAULT_ENCODING = "utf-8"
_DEFAULT_ERRORS = "replace"


# ---------------------------------------------------------------------------
# asyncio Protocol implementations
# ---------------------------------------------------------------------------

class _UDPSyslogProtocol(asyncio.DatagramProtocol):
    """
    asyncio UDP protocol that pushes received datagrams into an
    asyncio.Queue so the connector's read() generator can consume them.
    """

    def __init__(self, queue: asyncio.Queue, encoding: str, errors: str) -> None:
        self._queue = queue
        self._encoding = encoding
        self._errors = errors
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport
        logger.debug("UDP syslog transport ready: %s", transport.get_extra_info("sockname"))

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        line = data.decode(self._encoding, errors=self._errors).rstrip("\n")
        if line:
            try:
                self._queue.put_nowait(line)
            except asyncio.QueueFull:
                logger.warning(
                    "SyslogConnector UDP queue full — datagram from %s dropped.", addr
                )

    def error_received(self, exc: Exception) -> None:
        logger.error("UDP syslog error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("UDP syslog transport closed. exc=%s", exc)


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class SyslogConnector(CustomConnector):
    """
    Async connector that listens for syslog / CEF streams over UDP or TCP.

    The connector binds to ``host:port`` in ``connect()`` and yields
    received log lines from ``read()``.  Designed for Suricata CEF output
    and general RFC-5424 / RFC-3164 syslog traffic.
    """

    _VALID_PROTOCOLS = {"udp", "tcp"}

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._validate_config()

        self._host: str = self.config.get("host", _DEFAULT_HOST)
        self._port: int = int(self.config.get("port", _DEFAULT_PORT))
        self._protocol: str = self.config.get("protocol", "udp").lower()
        self._max_line_size: int = int(
            self.config.get("max_line_size", _DEFAULT_MAX_LINE)
        )
        self._encoding: str = self.config.get("encoding", _DEFAULT_ENCODING)
        self._errors: str = self.config.get("errors", _DEFAULT_ERRORS)

        # Internal queue — large enough to absorb burst traffic before
        # the read() loop drains it.
        self._internal_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)

        self._transport = None    # set by connect()
        self._server = None       # TCP server, set by connect()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        proto = self.config.get("protocol", "udp").lower()
        if proto not in self._VALID_PROTOCOLS:
            raise ConnectorConfigError(
                f"SyslogConnector {self.name!r}: 'protocol' must be one of "
                f"{sorted(self._VALID_PROTOCOLS)}, got {proto!r}"
            )
        port = self.config.get("port", _DEFAULT_PORT)
        try:
            if not (1 <= int(port) <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            raise ConnectorConfigError(
                f"SyslogConnector {self.name!r}: 'port' must be 1–65535, got {port!r}"
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Bind the UDP/TCP socket and start receiving syslog traffic."""
        loop = asyncio.get_running_loop()
        logger.info(
            "SyslogConnector %r binding %s %s:%d",
            self.name, self._protocol.upper(), self._host, self._port,
        )

        try:
            if self._protocol == "udp":
                self._transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UDPSyslogProtocol(
                        self._internal_queue, self._encoding, self._errors
                    ),
                    local_addr=(self._host, self._port),
                )
            else:  # tcp
                self._server = await asyncio.start_server(
                    self._make_tcp_handler(),
                    host=self._host,
                    port=self._port,
                )

        except OSError as exc:
            raise ConnectorIOError(
                f"SyslogConnector {self.name!r}: failed to bind "
                f"{self._protocol.upper()} {self._host}:{self._port} — {exc}"
            ) from exc

        self._running = True
        logger.info(
            "SyslogConnector %r listening on %s %s:%d",
            self.name, self._protocol.upper(), self._host, self._port,
        )

    def _make_tcp_handler(self):
        """
        Return an asyncio stream handler coroutine for asyncio.start_server.

        asyncio.start_server expects a coroutine function that accepts
        (StreamReader, StreamWriter) — not a Protocol factory.
        """
        queue = self._internal_queue
        encoding = self._encoding
        errors = self._errors

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            buf = b""
            try:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        raw_line, buf = buf.split(b"\n", 1)
                        line = raw_line.decode(encoding, errors=errors).strip()
                        if line:
                            try:
                                queue.put_nowait(line)
                            except asyncio.QueueFull:
                                logger.warning(
                                    "SyslogConnector TCP queue full — line dropped."
                                )
            except asyncio.CancelledError:
                pass
            finally:
                # Flush any remaining buffered data without a trailing newline
                if buf:
                    line = buf.decode(encoding, errors=errors).strip()
                    if line:
                        try:
                            queue.put_nowait(line)
                        except asyncio.QueueFull:
                            pass
                writer.close()

        return handler

    async def disconnect(self) -> None:
        """Close the socket / server."""
        self._running = False

        if self._transport is not None:
            self._transport.close()
            self._transport = None

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        logger.info("SyslogConnector %r disconnected.", self.name)

    # ------------------------------------------------------------------
    # Core read loop
    # ------------------------------------------------------------------

    async def read(self) -> AsyncGenerator[str, None]:
        """
        Yield log lines received on the bound syslog port.

        Lines are buffered in an internal asyncio.Queue by the protocol
        callbacks and drained here one at a time.  Blocks efficiently
        using ``queue.get()`` — no polling required.
        """
        if not self._running:
            raise ConnectorIOError(
                f"SyslogConnector {self.name!r}: call connect() before read()"
            )

        logger.debug("SyslogConnector %r starting read loop.", self.name)

        while self._running:
            try:
                # Wait up to 0.5 s so we can check _running periodically
                # even when no traffic arrives.
                line: str = await asyncio.wait_for(
                    self._internal_queue.get(), timeout=0.5
                )
                logger.debug(
                    "SyslogConnector %r yielding line: %.120s", self.name, line
                )
                yield line
                self._internal_queue.task_done()
            except asyncio.TimeoutError:
                # No data — loop again and re-check _running
                continue

        logger.debug("SyslogConnector %r read loop exited.", self.name) 
