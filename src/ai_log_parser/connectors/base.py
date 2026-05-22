# ai_log_parser/connectors/base.py

"""
CustomConnector — Abstract base class for all log-source connectors.

Design contract
---------------
* Every connector receives a single `config` dict (already loaded from YAML)
  at construction time.  No connector reaches outside its config block.
* `connect()` performs any one-time setup (open a file handle, bind a socket,
  authenticate with S3, etc.).  It is always called before `read()`.
* `read()` is an async generator that yields raw log lines (str) indefinitely
  until the source is exhausted or the connector is stopped.
* `disconnect()` tears down resources acquired in `connect()`.
  It is always safe to call even if `connect()` was never called.
* `stop()` sets the internal sentinel so the `read()` loop exits cleanly.

Subclasses MUST override: `connect`, `read`, `disconnect`.
Subclasses SHOULD NOT touch `_running` directly; call `stop()` instead.
"""

from __future__ import annotations

import abc
import logging
from typing import Any, AsyncGenerator

logger = logging.getLogger(__name__)


class CustomConnector(abc.ABC):
    """
    Abstract base class for every log-source connector in the pipeline.

    Parameters
    ----------
    config : dict
        The fully-parsed YAML block for this connector, e.g.::

            {
                "type": "file",
                "name": "nginx-access",
                "path": "/var/log/nginx/access.log",
            }

        Keys available depend on the connector type; each subclass documents
        its own required and optional keys.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        if not isinstance(config, dict):
            raise TypeError(
                f"config must be a dict, got {type(config).__name__!r}"
            )
        self.config: dict[str, Any] = config
        self.name: str = config.get("name", self.__class__.__name__)
        self._running: bool = False
        logger.debug("Connector %r initialised with config: %s", self.name, config)

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Signal the connector to stop reading and exit its `read()` loop."""
        logger.info("Connector %r received stop signal.", self.name)
        self._running = False

    # ------------------------------------------------------------------
    # Abstract interface — subclasses must implement all three
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def connect(self) -> None:
        """
        Perform any one-time setup required before log ingestion begins.

        Examples: open a file handle, bind a UDP socket, create a boto3
        session, etc.  Must set ``self._running = True`` when ready.

        Raises
        ------
        ConnectorError
            If the underlying resource cannot be reached or authenticated.
        """

    @abc.abstractmethod
    async def read(self) -> AsyncGenerator[str, None]:
        """
        Async generator that yields raw log lines (str) one at a time.

        The generator MUST honour ``self._running``:

            while self._running:
                line = await fetch_next_line()
                if line:
                    yield line

        Yields
        ------
        str
            A single raw log line.  Trailing newlines are stripped by
            convention but subclasses may preserve them if required.
        """
        # Satisfy static-analysis tools that expect a generator signature.
        yield  # pragma: no cover

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """
        Release all resources acquired in ``connect()``.

        Must be idempotent — safe to call multiple times or when
        ``connect()`` was never called.
        """

    # ------------------------------------------------------------------
    # Async context-manager protocol (connect / disconnect for free)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "CustomConnector":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, "
            f"running={self._running})"
        )


# ------------------------------------------------------------------
# Connector-specific exception hierarchy
# ------------------------------------------------------------------

class ConnectorError(Exception):
    """Base exception for all connector failures."""


class ConnectorConfigError(ConnectorError):
    """Raised when the YAML config block is missing required keys or has invalid values."""


class ConnectorIOError(ConnectorError):
    """Raised when the underlying I/O resource fails during ingestion."""
