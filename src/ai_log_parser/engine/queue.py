# ai_log_parser/engine/queue.py

"""
InProcessQueue — asyncio.Queue-based bounded buffer between the
connector layer and the AI parse engine.

Design
------
* maxsize is pulled directly from the ``AppConfig.queue_max_size``
  property, which in turn reads the YAML ``queue.max_size`` variable.
* Provides typed put/get wrappers with optional timeout and a clean
  shutdown mechanism.
* Does NOT import any third-party infrastructure.  The only dependency
  is Python's built-in asyncio.

Usage
-----
::

    from ai_log_parser.config.loader import ConfigLoader
    from ai_log_parser.engine.queue import InProcessQueue

    config  = ConfigLoader("configs/default_config.yaml").load()
    queue   = InProcessQueue(config.queue_max_size)

    # Producer (connector side)
    await queue.put("raw log line here")

    # Consumer (AI engine side)
    line = await queue.get()
    queue.task_done()

    # Graceful shutdown
    await queue.join()      # wait for all items to be processed
    queue.close()           # mark queue as closed
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class QueueClosedError(Exception):
    """Raised when a put/get is attempted on a closed queue."""


class InProcessQueue:
    """
    Bounded async queue that decouples log ingestion from AI parsing.

    Parameters
    ----------
    maxsize : int
        Maximum number of log-line strings held in the buffer at once.
        When full, ``put()`` will block until the consumer catches up.
        Sourced from ``AppConfig.queue_max_size`` (YAML: ``queue.max_size``).

    Raises
    ------
    ValueError
        If ``maxsize`` is not a positive integer.
    """

    def __init__(self, maxsize: int) -> None:
        if not isinstance(maxsize, int) or maxsize < 1:
            raise ValueError(
                f"InProcessQueue maxsize must be a positive integer, got {maxsize!r}"
            )
        self._maxsize = maxsize
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._closed = False
        logger.info("InProcessQueue initialised with maxsize=%d", maxsize)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def maxsize(self) -> int:
        """The capacity this queue was created with."""
        return self._maxsize

    @property
    def closed(self) -> bool:
        """True after :meth:`close` has been called."""
        return self._closed

    def qsize(self) -> int:
        """Approximate number of items currently in the queue."""
        return self._queue.qsize()

    def empty(self) -> bool:
        """True if the queue currently holds zero items."""
        return self._queue.empty()

    def full(self) -> bool:
        """True if the queue is at capacity."""
        return self._queue.full()

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    async def put(self, item: str, timeout: Optional[float] = None) -> None:
        """
        Put a log-line string into the queue, blocking until space is
        available.

        Parameters
        ----------
        item    : str   — the raw log line to enqueue
        timeout : float — seconds to wait before raising asyncio.TimeoutError
                          (None = wait indefinitely)

        Raises
        ------
        QueueClosedError       if the queue has been closed.
        asyncio.TimeoutError   if ``timeout`` elapses before space opens up.
        TypeError              if ``item`` is not a str.
        """
        if self._closed:
            raise QueueClosedError(
                "Cannot put() onto a closed InProcessQueue."
            )
        if not isinstance(item, str):
            raise TypeError(
                f"InProcessQueue only accepts str items, got {type(item).__name__!r}"
            )

        if timeout is not None:
            await asyncio.wait_for(self._queue.put(item), timeout=timeout)
        else:
            await self._queue.put(item)

        logger.debug("InProcessQueue put — qsize=%d/%d", self.qsize(), self._maxsize)

    def put_nowait(self, item: str) -> None:
        """
        Non-blocking put.  Raises ``asyncio.QueueFull`` immediately if
        the queue is at capacity.

        Raises
        ------
        QueueClosedError     if the queue has been closed.
        asyncio.QueueFull    if there is no room right now.
        TypeError            if ``item`` is not a str.
        """
        if self._closed:
            raise QueueClosedError("Cannot put_nowait() onto a closed InProcessQueue.")
        if not isinstance(item, str):
            raise TypeError(
                f"InProcessQueue only accepts str items, got {type(item).__name__!r}"
            )
        self._queue.put_nowait(item)

    # ------------------------------------------------------------------
    # Consumer API
    # ------------------------------------------------------------------

    async def get(self, timeout: Optional[float] = None) -> str:
        """
        Remove and return the next log-line string from the queue.

        Parameters
        ----------
        timeout : float — seconds to wait before raising asyncio.TimeoutError
                          (None = wait indefinitely)

        Raises
        ------
        asyncio.TimeoutError  if ``timeout`` elapses with no item available.
        """
        if timeout is not None:
            item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        else:
            item = await self._queue.get()

        logger.debug("InProcessQueue get — qsize=%d/%d", self.qsize(), self._maxsize)
        return item

    def get_nowait(self) -> str:
        """
        Non-blocking get.  Raises ``asyncio.QueueEmpty`` immediately if
        the queue is empty.
        """
        return self._queue.get_nowait()

    def task_done(self) -> None:
        """
        Signal that a formerly enqueued item has been processed.
        Must be called once per :meth:`get`.
        """
        self._queue.task_done()

    async def join(self) -> None:
        """Block until every item that has been put() has had task_done() called."""
        await self._queue.join()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """
        Mark the queue as closed.  Further ``put()`` calls will raise
        ``QueueClosedError``.  Items already in the queue can still be
        consumed.
        """
        self._closed = True
        logger.info("InProcessQueue closed (remaining items: %d).", self.qsize())

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"InProcessQueue("
            f"maxsize={self._maxsize}, "
            f"qsize={self.qsize()}, "
            f"closed={self._closed})"
        )
