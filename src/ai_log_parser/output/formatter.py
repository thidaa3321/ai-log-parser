# src/ai_log_parser/output/formatter.py

"""
Multi-Standard Formatters — converts a NormalizedLog into OCSF and CEF.

OCSF (Open Cybersecurity Schema Framework)
------------------------------------------
Maps NormalizedLog fields to OCSF 1.0 base event structure.
event_hash is stored in enrichments as the cross-platform correlation key.
Output: dict → written as newline-delimited JSON to processed_ocsf.json

CEF (ArcSight Common Event Format)
-----------------------------------
Converts NormalizedLog to a CEF string.
event_hash is embedded in the CEF extension field for cross-platform
tracking. Uses correct CEF field names:
  shost = source host (machine that wrote the log)
  dhost = destination host (machine being connected to)
  suser = source user (actor)
  action = action taken (process, command, verb)
Output: str → written as one line per event to processed.cef
"""

from __future__ import annotations

from typing import Any

from ai_log_parser.models.schema import NormalizedLog


# ---------------------------------------------------------------------------
# OCSF mappings
# ---------------------------------------------------------------------------

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
    "authentication": 3,
    "network":        4,
    "file":           2,
    "process":        3,
    "other":          1,
}


# ---------------------------------------------------------------------------
# OCSF Formatter
# ---------------------------------------------------------------------------

def to_ocsf(event: NormalizedLog) -> dict[str, Any]:
    """
    Map a NormalizedLog to an OCSF 1.0 base event dict.

    event_hash is stored in enrichments as the cross-platform correlation
    key — not as activity_id which is an OCSF numeric type field.
    """
    class_uid = _CATEGORY_TO_CLASS_UID.get(event.category, 0)
    severity  = _CATEGORY_TO_SEVERITY.get(event.category, 1)
    status    = _OUTCOME_TO_STATUS.get(event.outcome, "Unknown")

    return {
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name":   "AI Dynamic Log Parser",
            },
        },
        "class_uid":    class_uid,
        "class_name":   event.category.title(),
        "category_uid": class_uid // 1000 if class_uid else 0,
        "severity_id":  severity,
        "status":       status,
        "status_id":    1 if status == "Success" else 2 if status == "Failure" else 0,
        "time":         event.event_ts,
        "ts_source":    event.ts_source,
        "actor": {
            "user": {"name": event.actor_user} if event.actor_user else None,
        },
        "src_endpoint": {
            "hostname": event.source_host,
            "ip":       event.src_ip,
        },
        "dst_endpoint": {
            "hostname": event.target,
            "ip":       event.dst_ip,
        },
        "action":   event.action,
        "message":  event.message,
        "raw_data": event.raw,
        "enrichments": {
            "event_hash":        event.event_hash,  # cross-platform correlation key
            "confidence":        event.confidence,
            "review_flag":       event.review_flag,
            "validation_issues": event.validation_issues,
            "extras":            event.extras,
        },
        "type_uid": class_uid * 100 + 1,
    }


# ---------------------------------------------------------------------------
# CEF Formatter
# ---------------------------------------------------------------------------

_CATEGORY_TO_CEF_SEVERITY: dict[str, int] = {
    "authentication": 5,
    "network":        7,
    "file":           3,
    "process":        5,
    "other":          1,
}


def _cef_escape(value: str) -> str:
    """Escape special characters per CEF spec."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("|",  "\\|")
        .replace("=",  "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def to_cef(event: NormalizedLog) -> str:
    """
    Convert a NormalizedLog to a CEF string.

    CEF extension field mapping
    ---------------------------
    shost  = source_host  — machine that wrote the log (not destination)
    dhost  = target       — destination host being connected to (if applicable)
    src    = src_ip       — source IP address
    dst    = dst_ip       — destination IP address
    suser  = actor_user   — user who performed the action
    action = action       — verb describing what happened
    msg    = message      — human-readable summary
    event_hash            — SHA256(raw) for cross-platform correlation
    rt     = event_ts     — event timestamp
    """
    severity    = _CATEGORY_TO_CEF_SEVERITY.get(event.category, 1)
    signature   = event.category.upper()
    name        = _cef_escape(event.action or event.message or event.category)
    outcome_str = event.outcome.capitalize()

    ext: dict[str, str] = {}

    # Network fields
    if event.src_ip:
        ext["src"]    = event.src_ip
    if event.dst_ip:
        ext["dst"]    = event.dst_ip

    # Host fields — shost is source, dhost is destination
    if event.source_host:
        ext["shost"]  = _cef_escape(event.source_host)
    if event.target:
        ext["dhost"]  = _cef_escape(event.target)

    # Actor
    if event.actor_user:
        ext["suser"]  = _cef_escape(event.actor_user)

    # Action
    if event.action:
        ext["action"] = _cef_escape(event.action)

    # Message
    if event.message:
        ext["msg"]    = _cef_escape(event.message)

    # Metadata
    ext["outcome"]     = outcome_str
    ext["confidence"]  = f"{event.confidence:.2f}"
    ext["review_flag"] = str(event.review_flag).lower()
    ext["ts_source"]   = event.ts_source
    ext["event_hash"]  = event.event_hash
    ext["rt"]          = event.event_ts

    extension_str = " ".join(f"{k}={v}" for k, v in ext.items())

    return (
        f"CEF:0"
        f"|AI Dynamic Log Parser"
        f"|1.0"
        f"|{signature}"
        f"|{name}"
        f"|{severity}"
        f"|{extension_str}"
    ) 
