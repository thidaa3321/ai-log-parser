# ai_log_parser/connectors/s3.py

"""
S3Connector — downloads and streams log objects from S3 (or LocalStack).

Designed for AWS CloudTrail logs stored in S3.  Works against real AWS
and against a LocalStack endpoint (http://localhost:4566) transparently
— the only difference is the ``endpoint_url`` config key.

Supported YAML config keys
--------------------------
Required:
    type   : "s3"
    name   : str    — human label
    bucket : str    — S3 bucket name

Optional:
    prefix         : str   — key prefix to filter objects (default: "")
    endpoint_url   : str   — override endpoint for LocalStack
                             (default: None → real AWS)
    region_name    : str   — AWS region (default: "us-east-1")
    aws_access_key_id     : str — access key (default: "test" for LocalStack)
    aws_secret_access_key : str — secret key (default: "test" for LocalStack)
    poll_interval  : float — seconds to wait after exhausting all objects
                             before checking for new ones (default: 30.0)
    encoding       : str   — line encoding for log content (default: "utf-8")
    delete_after_read : bool — delete each object after reading it
                               (default: false)

Example YAML block — LocalStack
--------------------------------
    - type: s3
      name: cloudtrail-localstack
      bucket: cloudtrail-logs
      prefix: AWSLogs/
      endpoint_url: http://localhost:4566
      aws_access_key_id: test
      aws_secret_access_key: test
      region_name: us-east-1
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
from typing import Any, AsyncGenerator

import boto3
import botocore.exceptions

from ai_log_parser.connectors.base import (
    ConnectorConfigError,
    ConnectorIOError,
    CustomConnector,
)

logger = logging.getLogger(__name__)

_DEFAULT_REGION = "us-east-1"
_DEFAULT_POLL = 30.0
_DEFAULT_ENCODING = "utf-8"


class S3Connector(CustomConnector):
    """
    Async connector that ingests log objects from an S3 bucket.

    Object discovery and download are performed in a background thread
    pool via ``asyncio.to_thread`` so the event loop is never blocked by
    boto3's synchronous API.

    Processing order
    ----------------
    1. List all objects under ``bucket/prefix``.
    2. For each object (in S3 key order):
       a. Download the body.
       b. If the key ends with ``.gz``, decompress with gzip.
       c. If the content looks like a CloudTrail JSON envelope
          (``{"Records": [...]}``), unwrap it and yield each record's
          raw JSON string as a separate line.
       d. Otherwise yield each text line individually.
    3. After all objects are exhausted, sleep ``poll_interval`` seconds
       then repeat from step 1 (for long-running tailing use-cases).
    4. Stop when ``stop()`` is called.

    Duplicate avoidance
    -------------------
    Already-processed keys are tracked in ``self._seen_keys``.  New
    objects added to the bucket between polls are picked up automatically.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._validate_config()

        self._bucket: str = self.config["bucket"]
        self._prefix: str = self.config.get("prefix", "")
        self._endpoint_url: str | None = self.config.get("endpoint_url")
        self._region: str = self.config.get("region_name", _DEFAULT_REGION)
        self._access_key: str = self.config.get("aws_access_key_id", "test")
        self._secret_key: str = self.config.get("aws_secret_access_key", "test")
        self._poll_interval: float = float(
            self.config.get("poll_interval", _DEFAULT_POLL)
        )
        self._encoding: str = self.config.get("encoding", _DEFAULT_ENCODING)
        self._delete_after_read: bool = bool(
            self.config.get("delete_after_read", False)
        )

        self._s3_client = None
        self._seen_keys: set[str] = set()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        if "bucket" not in self.config:
            raise ConnectorConfigError(
                f"S3Connector {self.name!r}: config is missing required key 'bucket'"
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the boto3 S3 client (runs in thread to avoid any blocking init)."""
        logger.info(
            "S3Connector %r connecting to bucket %r (endpoint=%s)",
            self.name, self._bucket, self._endpoint_url or "AWS",
        )

        self._s3_client = await asyncio.to_thread(self._make_client)

        # Verify the bucket is reachable
        try:
            await asyncio.to_thread(
                self._s3_client.head_bucket, Bucket=self._bucket
            )
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            raise ConnectorIOError(
                f"S3Connector {self.name!r}: cannot access bucket "
                f"{self._bucket!r} — {error_code}: {exc}"
            ) from exc

        self._running = True
        logger.info("S3Connector %r connected.", self.name)

    def _make_client(self):
        """Synchronous boto3 client factory (called in thread pool)."""
        kwargs: dict[str, Any] = {
            "region_name": self._region,
            "aws_access_key_id": self._access_key,
            "aws_secret_access_key": self._secret_key,
        }
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        return boto3.client("s3", **kwargs)

    async def disconnect(self) -> None:
        """Release the S3 client."""
        self._running = False
        self._s3_client = None
        logger.info("S3Connector %r disconnected.", self.name)

    # ------------------------------------------------------------------
    # Core read loop
    # ------------------------------------------------------------------

    async def read(self) -> AsyncGenerator[str, None]:
        """
        Yield log lines from S3 objects under ``bucket/prefix``.

        Runs indefinitely, polling for new objects after each full pass.
        """
        if self._s3_client is None:
            raise ConnectorIOError(
                f"S3Connector {self.name!r}: call connect() before read()"
            )

        logger.debug("S3Connector %r starting read loop.", self.name)

        while self._running:
            keys = await asyncio.to_thread(self._list_new_keys)

            if not keys:
                logger.debug(
                    "S3Connector %r: no new objects, sleeping %.1fs",
                    self.name, self._poll_interval,
                )
                await asyncio.sleep(self._poll_interval)
                continue

            for key in keys:
                if not self._running:
                    break
                async for line in self._stream_object(key):
                    yield line

        logger.debug("S3Connector %r read loop exited.", self.name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _list_new_keys(self) -> list[str]:
        """
        Synchronous — list all objects under the prefix, returning only
        keys not yet processed.  Called via asyncio.to_thread.
        """
        paginator = self._s3_client.get_paginator("list_objects_v2")
        keys: list[str] = []

        try:
            for page in paginator.paginate(
                Bucket=self._bucket, Prefix=self._prefix
            ):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key not in self._seen_keys:
                        keys.append(key)
        except botocore.exceptions.ClientError as exc:
            logger.error(
                "S3Connector %r: error listing objects: %s", self.name, exc
            )

        return sorted(keys)  # deterministic order

    async def _stream_object(self, key: str) -> AsyncGenerator[str, None]:
        """Download one S3 object and yield its log lines."""
        logger.debug("S3Connector %r downloading s3://%s/%s", self.name, self._bucket, key)

        try:
            body_bytes: bytes = await asyncio.to_thread(self._download_object, key)
        except botocore.exceptions.ClientError as exc:
            logger.error(
                "S3Connector %r: failed to download %r: %s", self.name, key, exc
            )
            return

        # Decompress gzip objects (CloudTrail logs are .json.gz)
        if key.endswith(".gz"):
            try:
                body_bytes = gzip.decompress(body_bytes)
            except OSError as exc:
                logger.error(
                    "S3Connector %r: gzip decompress failed for %r: %s",
                    self.name, key, exc,
                )
                return

        text = body_bytes.decode(self._encoding, errors="replace")

        # CloudTrail envelope: {"Records": [...]}
        lines = self._unwrap_cloudtrail(text) or self._split_lines(text)

        for line in lines:
            if line and self._running:
                yield line

        # Mark key as processed
        self._seen_keys.add(key)

        if self._delete_after_read:
            await asyncio.to_thread(
                self._s3_client.delete_object, Bucket=self._bucket, Key=key
            )
            logger.debug("S3Connector %r deleted s3://%s/%s", self.name, self._bucket, key)

    def _download_object(self, key: str) -> bytes:
        """Synchronous download — called via asyncio.to_thread."""
        response = self._s3_client.get_object(Bucket=self._bucket, Key=key)
        return response["Body"].read()

    @staticmethod
    def _unwrap_cloudtrail(text: str) -> list[str] | None:
        """
        If ``text`` is a CloudTrail JSON envelope, return each Record as
        its own JSON string.  Returns None if the text is not CloudTrail.
        """
        stripped = text.strip()
        if not (stripped.startswith("{") and '"Records"' in stripped):
            return None
        try:
            doc = json.loads(stripped)
            records = doc.get("Records")
            if isinstance(records, list):
                return [json.dumps(r, separators=(",", ":")) for r in records]
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    @staticmethod
    def _split_lines(text: str) -> list[str]:
        """Split plain-text content into non-empty lines."""
        return [line.rstrip("\r") for line in text.splitlines() if line.strip()]
