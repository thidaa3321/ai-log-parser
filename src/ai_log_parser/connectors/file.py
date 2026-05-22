# ai_log_parser/connectors/file.py

"""
FileConnector — reads VM-local log files using aiofiles.

Supported YAML config keys
--------------------------
Required:
    type : "file"
    name : str          — human label for logs/metrics
    path : str          — absolute or relative path to the log file

Optional:
    poll_interval : float   — seconds to wait between polls when the
                              end of file is reached (default: 0.25)
    encoding      : str     — file encoding (default: "utf-8")
    tail          : bool    — if true, seek to end of file before
                              starting to read (default: false)

Example YAML block
------------------
    - type: file
      name: nginx-access
      path: /var/log/nginx/access.log
      tail: true
      poll_interval: 0.1
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, AsyncGenerator

import aiofiles

from ai_log_parser.connectors.base import (
    ConnectorConfigError,
    ConnectorIOError,
    CustomConnector,
)

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 0.25
_DEFAULT_ENCODING = "utf-8"


class FileConnector(CustomConnector):
    """
    Async connector that tails a log file on the local filesystem.

    The connector will keep running (polling for new lines) until
    ``stop()`` is called, making it suitable for live log tailing as
    well as for reading a static file to its end.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._validate_config()

        self._path = Path(self.config["path"])
        self._poll_interval: float = float(
            self.config.get("poll_interval", _DEFAULT_POLL_INTERVAL)
        )
        self._encoding: str = self.config.get("encoding", _DEFAULT_ENCODING)
        self._tail: bool = bool(self.config.get("tail", False))

        self._file_handle = None   # set by connect()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        if "path" not in self.config:
            raise ConnectorConfigError(
                f"FileConnector {self.name!r}: config is missing required key 'path'"
            )
        poll = self.config.get("poll_interval", _DEFAULT_POLL_INTERVAL)
        try:
            if float(poll) <= 0:
                raise ValueError
        except (ValueError, TypeError):
            raise ConnectorConfigError(
                f"FileConnector {self.name!r}: 'poll_interval' must be a "
                f"positive float, got {poll!r}"
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the log file for async reading."""
        if not self._path.exists():
            raise ConnectorIOError(
                f"FileConnector {self.name!r}: file not found: {self._path}"
            )

        logger.info(
            "FileConnector %r connecting to %s (tail=%s)",
            self.name, self._path, self._tail,
        )

        self._file_handle = await aiofiles.open(
            self._path, mode="r", encoding=self._encoding
        )

        if self._tail:
            # Jump to end of file — only yield lines appended from now on.
            await self._file_handle.seek(0, 2)  # SEEK_END

        self._running = True
        logger.info("FileConnector %r connected.", self.name)

    async def disconnect(self) -> None:
        """Close the file handle if it is open."""
        if self._file_handle is not None:
            try:
                await self._file_handle.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "FileConnector %r: error closing file handle: %s", self.name, exc
                )
            finally:
                self._file_handle = None
        self._running = False
        logger.info("FileConnector %r disconnected.", self.name)

    # ------------------------------------------------------------------
    # Core read loop
    # ------------------------------------------------------------------

    async def read(self) -> AsyncGenerator[str, None]:
        """
        Yield raw log lines from the file, one at a time.

        When EOF is reached the connector sleeps for ``poll_interval``
        seconds before checking for new lines, mimicking ``tail -f``.
        Stops as soon as ``stop()`` is called.
        """
        if self._file_handle is None:
            raise ConnectorIOError(
                f"FileConnector {self.name!r}: call connect() before read()"
            )

        logger.debug("FileConnector %r starting read loop.", self.name)

        try:
            while self._running:
                line: str = await self._file_handle.readline()

                if line:
                    stripped = line.rstrip("\n")
                    if stripped:  # skip blank lines
                        logger.debug(
                            "FileConnector %r yielding line: %.120s",
                            self.name, stripped,
                        )
                        yield stripped
                else:
                    # EOF — wait before polling again
                    await asyncio.sleep(self._poll_interval)

        except Exception as exc:
            raise ConnectorIOError(
                f"FileConnector {self.name!r}: I/O error during read: {exc}"
            ) from exc

        logger.debug("FileConnector %r read loop exited.", self.name)
