# src/ai_log_parser/config/loader.py

"""
Configuration loader — reads YAML files and exposes a typed config object.

YAML structure expected
-----------------------

    queue:
      max_size: 1000          # Required — maps to InProcessQueue maxsize

    connectors:
      - type: file
        name: nginx-access
        path: /var/log/nginx/access.log

      - type: syslog
        name: suricata-514
        host: 0.0.0.0
        port: 514

      - type: s3
        name: cloudtrail
        bucket: my-cloudtrail-bucket
        prefix: AWSLogs/
        endpoint_url: http://localhost:4566   # LocalStack

All keys other than `queue` and `connectors` are preserved in
``AppConfig.raw`` so future layers (engine, output) can consume them
without touching this module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ai_log_parser.connectors.base import ConnectorConfigError

logger = logging.getLogger(__name__)

# Default config path — relative to this file inside the package
_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_config.yaml"


# ---------------------------------------------------------------------------
# Typed config containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class QueueConfig:
    """Validated queue settings."""
    max_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.max_size, int) or self.max_size < 1:
            raise ConnectorConfigError(
                f"queue.max_size must be a positive integer, got {self.max_size!r}"
            )


@dataclass
class AppConfig:
    """
    Top-level application configuration.

    Attributes
    ----------
    queue : QueueConfig
        Validated queue settings, including ``max_size``.
    connectors : list[dict]
        Raw connector blocks exactly as written in the YAML file.
        Each block must contain at least a ``type`` key.
    raw : dict
        The full, unmodified parsed YAML document — available to any
        downstream layer that needs keys not modelled here.
    source_path : Path | None
        File path from which this config was loaded (None if loaded from
        a raw dict, e.g. in tests).
    """
    queue:       QueueConfig
    connectors:  list[dict[str, Any]]
    raw:         dict[str, Any]
    source_path: Path | None = field(default=None, compare=False)

    @property
    def queue_max_size(self) -> int:
        return self.queue.max_size


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class ConfigLoader:
    """
    Loads and validates an application YAML config file.

    Usage
    -----
    ::

        # Load from explicit path
        loader = ConfigLoader("/path/to/config.yaml")
        config = loader.load()

        # Load the built-in default config bundled with the package
        config = ConfigLoader.load_default()

        print(config.queue_max_size)      # e.g. 1000
        print(config.connectors)          # list of connector dicts
    """

    _REQUIRED_ROOT_KEYS: frozenset[str] = frozenset({"queue", "connectors"})

    def __init__(self, path: str | os.PathLike) -> None:
        self._path = Path(path)

    @classmethod
    def load_default(cls) -> "AppConfig":
        """
        Load the default config bundled with the package.

        The default config lives at:
            src/ai_log_parser/config/default_config.yaml

        This works regardless of where the package is installed because
        the path is resolved relative to this source file, not the
        working directory or project root.
        """
        if not _DEFAULT_CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"Default config not found at {_DEFAULT_CONFIG_PATH}. "
                f"Ensure the package was installed correctly."
            )
        return cls(_DEFAULT_CONFIG_PATH).load()

    def load(self) -> "AppConfig":
        """
        Parse the YAML file and return a validated :class:`AppConfig`.

        Raises
        ------
        FileNotFoundError
            If the config file does not exist.
        ConnectorConfigError
            If any required key is missing or a value is invalid.
        yaml.YAMLError
            If the file contains invalid YAML syntax.
        """
        if not self._path.exists():
            raise FileNotFoundError(
                f"Config file not found: {self._path}"
            )

        logger.info("Loading config from %s", self._path)

        with self._path.open("r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh)

        if not isinstance(raw, dict):
            raise ConnectorConfigError(
                f"Config file must be a YAML mapping at the root level, "
                f"got {type(raw).__name__!r} in {self._path}"
            )

        return self._parse(raw, source_path=self._path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        """
        Build an :class:`AppConfig` directly from a pre-parsed dict.
        Useful for unit tests that don't want to touch the filesystem.
        """
        return cls._parse(data, source_path=None)

    @classmethod
    def _parse(
        cls,
        raw: dict[str, Any],
        source_path: Path | None,
    ) -> "AppConfig":
        cls._check_required_keys(raw, source_path)
        queue_config = cls._parse_queue(raw["queue"], source_path)
        connectors   = cls._parse_connectors(raw["connectors"], source_path)

        logger.debug(
            "Config loaded — queue.max_size=%d, connectors=%d",
            queue_config.max_size,
            len(connectors),
        )

        return AppConfig(
            queue=queue_config,
            connectors=connectors,
            raw=raw,
            source_path=source_path,
        )

    @classmethod
    def _check_required_keys(
        cls,
        raw: dict[str, Any],
        source_path: Path | None,
    ) -> None:
        missing = cls._REQUIRED_ROOT_KEYS - raw.keys()
        if missing:
            raise ConnectorConfigError(
                f"Config {'file ' + str(source_path) if source_path else 'dict'} "
                f"is missing required top-level key(s): {sorted(missing)}"
            )

    @classmethod
    def _parse_queue(
        cls,
        queue_block: Any,
        source_path: Path | None,
    ) -> QueueConfig:
        if not isinstance(queue_block, dict):
            raise ConnectorConfigError(
                f"'queue' must be a YAML mapping, "
                f"got {type(queue_block).__name__!r}"
            )
        if "max_size" not in queue_block:
            raise ConnectorConfigError(
                "'queue' block is missing required key 'max_size'"
            )
        return QueueConfig(max_size=int(queue_block["max_size"]))

    @classmethod
    def _parse_connectors(
        cls,
        connectors_block: Any,
        source_path: Path | None,
    ) -> list[dict[str, Any]]:
        if not isinstance(connectors_block, list):
            raise ConnectorConfigError(
                f"'connectors' must be a YAML sequence, "
                f"got {type(connectors_block).__name__!r}"
            )
        validated: list[dict[str, Any]] = []
        for idx, block in enumerate(connectors_block):
            if not isinstance(block, dict):
                raise ConnectorConfigError(
                    f"connectors[{idx}] must be a mapping, "
                    f"got {type(block).__name__!r}"
                )
            if "type" not in block:
                raise ConnectorConfigError(
                    f"connectors[{idx}] is missing required key 'type'"
                )
            validated.append(block)
        return validated 
