# ai_log_parser/output/writer.py

"""
Quarantine Writer — routes validated NormalizedLog events to the correct
output files and triggers formatters for confident events.

Design
------
* Replaces _route_event / _append_to_file from parser.py entirely.
* Receives a NormalizedLog instance (already validated by Pydantic).
* Routes based on review_flag:
    - False (confident) → data/staging/ai_confident.json + formatters
    - True  (flagged)   → data/output/review_needed.json only
* Deduplication: uses event_hash (SHA256 of raw) to prevent duplicate
  writes across runs — no data loss, no overwrites.
* Formatters are triggered only for confident events:
    - OCSF → data/output/processed_ocsf.json
    - CEF  → data/output/processed.cef

Output file layout
------------------
data/
  staging/
    ai_confident.json     — newline-delimited JSON, one event per line
  output/
    review_needed.json    — newline-delimited JSON, one event per line
    processed_ocsf.json   — newline-delimited OCSF JSON, one event per line
    processed.cef         — one CEF string per line
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ai_log_parser.models.schema import NormalizedLog
from ai_log_parser.output.formatter import to_ocsf, to_cef

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

CONFIDENT_PATH  = Path("data/output/processed.json")
REVIEW_PATH     = Path("data/output/review_needed.json")
OCSF_PATH       = Path("data/output/processed_ocsf.json")
CEF_PATH        = Path("data/output/processed.cef")

# Ensure all directories exist
for _p in (CONFIDENT_PATH, REVIEW_PATH, OCSF_PATH, CEF_PATH):
    _p.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _is_duplicate(path: Path, event_hash: str) -> bool:
    """
    Return True if an entry with the same event_hash already exists
    in the output file. Reads line by line — no full file load.
    """
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    existing = json.loads(line)
                    if existing.get("event_hash") == event_hash:
                        return True
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.error("Dedup check failed for %s: %s", path, exc)
    return False


def _is_duplicate_cef(path: Path, event_hash: str) -> bool:
    """
    Return True if a CEF line containing this event_hash already exists.
    CEF lines embed the hash in the extension field: event_hash=<hash>
    """
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if event_hash in line:
                    return True
    except OSError as exc:
        logger.error("CEF dedup check failed for %s: %s", path, exc)
    return False


# ---------------------------------------------------------------------------
# Append helpers
# ---------------------------------------------------------------------------

def _append_json(path: Path, data: dict[str, Any], event_hash: str) -> None:
    """Append a JSON event to a newline-delimited file, with dedup check."""
    if _is_duplicate(path, event_hash):
        logger.debug("Duplicate skipped (event_hash exists) → %s", path)
        return
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(data, ensure_ascii=False) + "\n")
        logger.debug("Wrote event %s to %s", event_hash[:16], path)
    except OSError as exc:
        logger.error("Failed to write to %s: %s", path, exc)


def _append_cef(path: Path, cef_line: str, event_hash: str) -> None:
    """Append a CEF string to file, with dedup check."""
    if _is_duplicate_cef(path, event_hash):
        logger.debug("Duplicate CEF skipped (event_hash exists) → %s", path)
        return
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(cef_line + "\n")
        logger.debug("Wrote CEF event %s to %s", event_hash[:16], path)
    except OSError as exc:
        logger.error("Failed to write CEF to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def route(event: NormalizedLog) -> None:
    """
    Route a validated NormalizedLog event to the correct output files.

    Parameters
    ----------
    event : NormalizedLog
        A fully validated Pydantic model instance from schema.py.

    Routing logic
    -------------
    review_flag=True  → review_needed.json only
    review_flag=False → ai_confident.json + OCSF formatter + CEF formatter
    """
    event_hash = event.event_hash
    event_dict = event.to_dict()

    if event.review_flag:
        logger.info(
            "Event %s flagged for review (confidence=%.2f, issues=%d) → %s",
            event_hash[:16],
            event.confidence,
            len(event.validation_issues),
            REVIEW_PATH,
        )
        _append_json(REVIEW_PATH, event_dict, event_hash)

    else:
        logger.info(
            "Event %s confident (confidence=%.2f) → %s + formatters",
            event_hash[:16],
            event.confidence,
            CONFIDENT_PATH,
        )
        # 1. Write normalized event
        _append_json(CONFIDENT_PATH, event_dict, event_hash)

        # 2. OCSF formatter
        try:
            ocsf_doc = to_ocsf(event)
            _append_json(OCSF_PATH, ocsf_doc, event_hash)
        except Exception as exc:
            logger.error(
                "OCSF formatter failed for %s: %s", event_hash[:16], exc
            )

        # 3. CEF formatter
        try:
            cef_line = to_cef(event)
            _append_cef(CEF_PATH, cef_line, event_hash)
        except Exception as exc:
            logger.error(
                "CEF formatter failed for %s: %s", event_hash[:16], exc
            )
