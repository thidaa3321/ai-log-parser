# ai_log_parser/output/formatter.py

"""
Multi-Standard Formatters — converts a NormalizedLog into OCSF and CEF.

OCSF (Open Cybersecurity Schema Framework)
------------------------------------------
Maps NormalizedLog fields to OCSF 1.0 base event structure.
event_hash is used as the unique activity_id across all OCSF records.
Output: dict → written as newline-delimited JSON to processed_ocsf.json

CEF (ArcSight Common Event Format)
-----------------------------------
Converts NormalizedLog to a CEF string.
event_hash is embedded in the CEF extension field for cross-platform
tracking.
Output: str → written as one line per event to processed.cef

References
----------
OCSF: https://schema.ocsf.io/
CEF:  ArcSight CEF Specification v26
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ai_log_parser.models.schema import NormalizedLog


# ---------------------------------------------------------------------------
# OCSF category → class_uid mapping
# ---------------------------------------------------------------------------
# OCSF class_uid reference:
#   1001 = File System Activity
#   2001 = Kernel Activity
#   3001 = Network Activity
#   3002 = HTTP Activity
#   4001 = Process Activity
#   4624 = Authentication (Windows-style, reused as OCSF convention)
#   6001 = Malware Activity
#   0    = Unknown

_CATEGORY_TO_CLASS_UID: dict[str, int] = {
    "authentication": 4624,
    "network":        3001,
    "file":           1001,
    "process":        4001,
    "other":          0,
}

_OUTCOME_TO_STATUS: dict[str, str] = {
    "success": "Success",
    "failure": "Failure",
    "unknown": "Unknown",
}

_CATEGORY_TO_SEVERITY: dict[str, int] = {
    "authentication": 3,   # Medium
    "network":        4,   # High
    "file":           2,   # Low
    "process":        3,   # Medium
    "other":          1,   # Informational
}


# ---------------------------------------------------------------------------
# OCSF Formatter
# ---------------------------------------------------------------------------

def to_ocsf(event: NormalizedLog) -> dict[str, Any]:
    """
    Map a NormalizedLog to an OCSF 1.0 base event dict.

    Parameters
    ----------
    event : NormalizedLog
        Validated Pydantic model instance.

    Returns
    -------
    dict
        OCSF-compliant event document ready for JSON serialisation.
    """
    class_uid  = _CATEGORY_TO_CLASS_UID.get(event.category, 0)
    severity   = _CATEGORY_TO_SEVERITY.get(event.category, 1)
    status     = _OUTCOME_TO_STATUS.get(event.outcome, "Unknown")

    ocsf: dict[str, Any] = {
        # --- OCSF metadata ---
        "metadata": {
            "version":    "1.0.0",
        },

        # --- Classification ---
        "class_uid":   class_uid,
        "class_name":  event.category.title(),
        "category_uid": class_uid // 1000 if class_uid else 0,
        "severity_id": severity,
        "status":      status,
        "status_id":   1 if status == "Success" else 2 if status == "Failure" else 0,

        # --- Identity ---
        "activity_id":  event.event_hash,   # event_hash as unique OCSF ID

        # --- Timing ---
        "time":         event.event_ts,
        "ts_source":    event.ts_source,

        # --- Actor ---
        "actor": {
            "user": {
                "name": event.actor_user,
            } if event.actor_user else None,
        },

        # --- Source ---
        "src_endpoint": {
            "hostname": event.source_host,
            "ip":       event.src_ip,
        },

        # --- Destination ---
        "dst_endpoint": {
            "hostname": event.target,
            "ip":       event.dst_ip,
        },

        # --- Action ---
        "action":    event.action,
        "message":   event.message,

        # --- Raw ---
        "raw_data":  event.raw,
        "raw_hash":  event.raw_hash,

        # --- AI metadata ---
        "enrichments": {
            "confidence":        event.confidence,
            "review_flag":       event.review_flag,
            "validation_issues": event.validation_issues,
            "extras":            event.extras,
        },

        # --- OCSF required ---
        "type_uid": class_uid * 100 + 1,
    }

    return ocsf


# ---------------------------------------------------------------------------
# CEF Formatter
# ---------------------------------------------------------------------------

# CEF severity mapping: 0–3=Low, 4–6=Medium, 7–8=High, 9–10=Very-High
_CATEGORY_TO_CEF_SEVERITY: dict[str, int] = {
    "authentication": 5,
    "network":        7,
    "file":           3,
    "process":        5,
    "other":          1,
}


def _cef_escape(value: str) -> str:
    """
    Escape special characters in CEF header and extension fields.
    CEF spec requires escaping: | \\ in headers, = \\ \\n in extensions.
    """
    if not value:
        return ""
    return (
        value
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def to_cef(event: NormalizedLog) -> str:
    """
    Convert a NormalizedLog to a CEF string.

    CEF format
    ----------
    CEF:Version|Device Vendor|Device Product|Device Version|
    Signature ID|Name|Severity|Extension

    event_hash is embedded in the extension as event_hash=<sha256>
    for cross-platform tracking.

    Parameters
    ----------
    event : NormalizedLog
        Validated Pydantic model instance.

    Returns
    -------
    str
        A single CEF-formatted log line.
    """
    severity    = _CATEGORY_TO_CEF_SEVERITY.get(event.category, 1)
    signature   = event.category.upper()
    name        = _cef_escape(event.action or event.message or event.category)
    outcome_str = event.outcome.capitalize()

    # --- Build extension fields ---
    ext: dict[str, str] = {}

    if event.src_ip:
        ext["src"]        = event.src_ip
    if event.dst_ip:
        ext["dst"]        = event.dst_ip
    if event.source_host:
        ext["dhost"]      = _cef_escape(event.source_host)
    if event.actor_user:
        ext["suser"]      = _cef_escape(event.actor_user)
    if event.target:
        ext["dhost"]      = _cef_escape(event.target)
    if event.message:
        ext["msg"]        = _cef_escape(event.message)

    ext["outcome"]        = outcome_str
    ext["confidence"]     = f"{event.confidence:.2f}"
    ext["review_flag"]    = str(event.review_flag).lower()
    ext["ts_source"]      = event.ts_source
    ext["event_hash"]     = event.event_hash   # cross-platform tracking key
    ext["rt"]             = event.event_ts

    extension_str = " ".join(f"{k}={v}" for k, v in ext.items())

    # --- CEF header ---
    cef_line = (
        f"CEF:0"
        f"|1.0"
        f"|{signature}"
        f"|{name}"
        f"|{severity}"
        f"|{extension_str}"
    )

    return cef_line
