# src/ai_log_parser/models/schema.py

"""
NormalizedLog — Pydantic Schema 2.0 for the AI Dynamic Log Parser.

Design
------
* Extends the Phase 3 flat dict schema into a fully typed, validated
  Pydantic model.
* event_hash replaces event_id as the unique event identifier.
  It is always the SHA256 of the raw log line — stable, pipeline-computed,
  never AI-generated. Used as the dedup key, OCSF activity_id, and CEF
  event_hash extension field across all output formats.
* ts_source tracks whether event_ts came from the original log or was
  set by the pipeline as ingestion time.
* Self-healing validators automatically fix common 1.5b model errors:
    - Syslog RFC3164: format has no year — event_ts set to null,
      pipeline uses ingestion time. Not flagged as hallucination.
    - IP/Hostname Fix: src_ip containing a hostname → moved to source_host,
      src_ip set to null.
    - Hallucination Check: event_ts date not present in raw text →
      overridden with ingestion time, review_flag forced True,
      validation_issues updated.
* Strict type validation on all IP fields via regex.
* ValidationError is caught at the model boundary — if Pydantic cannot
  construct a valid model, a quarantine-safe fallback dict is returned
  by the class method safe_parse().

Fields
------
event_hash        : SHA256(raw) — unique event ID, pipeline-computed,
                    used as dedup key, OCSF activity_id, CEF event_hash
event_ts          : ISO8601 UTC — extracted from log or ingestion time
ts_source         : "original" | "ingestion" — tracks event_ts origin
source_host       : hostname of the log source
category          : authentication | network | file | process | other
action            : what happened (e.g. "login", "connect")
outcome           : success | failure | unknown
actor_user        : user who performed the action
src_ip            : source IP address (null if not present or was hostname)
target            : target resource
dst_ip            : destination IP address
message           : human-readable log message
raw               : original raw log line — never modified
extras            : any additional fields the AI extracted
confidence        : float 0.0–1.0 — AI self-reported parse certainty
review_flag       : true when confidence < 0.7 or validation failed
validation_issues : list of strings describing what failed validation
format_hint       : detected log format from pre-processor (optional)
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIDENCE_GATE = 0.7

_RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_HOSTNAME_ONLY = re.compile(r"^[a-zA-Z][a-zA-Z0-9\-]*$")

_VALID_CATEGORIES = {"authentication", "network", "file", "process", "other"}
_VALID_OUTCOMES   = {"success", "failure", "unknown"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_hash(raw: str) -> str:
    """Return SHA256 hex digest of the raw log line."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_ip(value: str) -> bool:
    return bool(_RE_IPV4.match(value) or _RE_IPV6.match(value))


def _is_hostname_not_ip(value: str) -> bool:
    return bool(_RE_HOSTNAME_ONLY.match(value))


def _date_in_raw(date_str: str, raw: str) -> bool:
    if not date_str or not raw:
        return False
    year_match = re.search(r"(\d{4})", date_str)
    if year_match and year_match.group(1) in raw:
        return True
    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", date_str)
    if date_match and date_match.group(1) in raw:
        return True
    months = ("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec")
    for month in months:
        if month in raw and month in date_str:
            return True
    return False


# ---------------------------------------------------------------------------
# Schema 2.0
# ---------------------------------------------------------------------------

class NormalizedLog(BaseModel):
    """
    Pydantic Schema 2.0 — fully validated normalized log event.

    Construct via NormalizedLog.safe_parse(raw_dict) to get automatic
    error handling and quarantine routing on ValidationError.
    """

    model_config = ConfigDict(
        extra="ignore",
        validate_assignment=True,
    )

    # --- Identity ---
    event_hash: str = Field(
        description=(
            "SHA256(raw) — unique event ID, pipeline-computed. "
            "Used as dedup key, OCSF activity_id, and CEF event_hash extension field."
        )
    )

    # --- Timing ---
    event_ts:  str = Field(
        description="ISO8601 UTC timestamp — from log or ingestion time"
    )
    ts_source: Literal["original", "ingestion"] = Field(
        default="ingestion",
        description="Tracks whether event_ts came from the log or pipeline",
    )

    # --- Source ---
    source_host: str | None = Field(default=None)

    # --- Classification ---
    category:   str       = Field(default="other")
    action:     str | None = Field(default=None)
    outcome:    str       = Field(default="unknown")

    # --- Actor ---
    actor_user: str | None = Field(default=None)

    # --- Network ---
    src_ip:  str | None = Field(default=None)
    dst_ip:  str | None = Field(default=None)
    target:  str | None = Field(default=None)

    # --- Content ---
    message: str | None = Field(default=None)
    raw:     str        = Field(description="Original raw log line — never modified")

    # --- AI metadata ---
    extras:     dict[str, Any] = Field(default_factory=dict)
    confidence: float          = Field(default=0.0, ge=0.0, le=1.0)

    # --- Routing ---
    review_flag:       bool      = Field(default=False)
    validation_issues: list[str] = Field(default_factory=list)

    # --- Pre-processor hint ---
    format_hint: str | None = Field(default=None)

    # ------------------------------------------------------------------
    # Field validators
    # ------------------------------------------------------------------

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> str:
        return v if v in _VALID_CATEGORIES else "other"

    @field_validator("outcome", mode="before")
    @classmethod
    def validate_outcome(cls, v: Any) -> str:
        return v if v in _VALID_OUTCOMES else "unknown"

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (ValueError, TypeError):
            return 0.0

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ip_fields(cls, v: Any) -> str | None:
        if v is None:
            return None
        s = str(v).strip()
        return s if (s and _is_ip(s)) else None

    @field_validator("extras", mode="before")
    @classmethod
    def validate_extras(cls, v: Any) -> dict:
        return v if isinstance(v, dict) else {}

    # ------------------------------------------------------------------
    # Model validator — cross-field self-healing
    # ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def self_heal(cls, data: dict[str, Any]) -> dict[str, Any]:
        """
        Cross-field self-healing — runs before individual field validators.

        Fixes applied (in order)
        ------------------------
        1. Syslog RFC3164 — no year in format, null event_ts, ingestion time.
        2. IP/Hostname Fix — hostname in src_ip moved to source_host.
        3. Hallucination Check — event_ts not in raw → ingestion time.
        4. event_hash — always pipeline-computed from raw.
        5. review_flag — set True if confidence < CONFIDENCE_GATE.
        6. ingestion time fallback if event_ts still missing.
        """
        issues:      list[str] = list(data.get("validation_issues") or [])
        raw         = str(data.get("raw", ""))
        format_hint = data.get("format_hint", "")

        # --- Fix 1: Syslog RFC3164 ---
        if format_hint == "syslog_rfc3164":
            data["event_ts"]  = None
            data["ts_source"] = "ingestion"

        # --- Fix 2: IP/Hostname in src_ip ---
        src_ip_raw = data.get("src_ip")
        if src_ip_raw is not None:
            s = str(src_ip_raw).strip()
            if s and not _is_ip(s):
                if _is_hostname_not_ip(s):
                    if not data.get("source_host"):
                        data["source_host"] = s
                        issues.append(
                            f"IP/Hostname Fix: src_ip '{s}' was a hostname "
                            f"— moved to source_host, src_ip set to null."
                        )
                    else:
                        issues.append(
                            f"IP/Hostname Fix: src_ip '{s}' was a hostname "
                            f"— set to null (source_host already populated)."
                        )
                else:
                    issues.append(
                        f"Invalid IP: src_ip '{s}' is not a valid IP address "
                        f"— set to null."
                    )
                data["src_ip"] = None

        # --- Fix 3: Hallucination Check ---
        event_ts = data.get("event_ts")
        if event_ts and raw and format_hint != "syslog_rfc3164":
            if not _date_in_raw(str(event_ts), raw):
                ingestion_time = datetime.now(timezone.utc).isoformat()
                issues.append(
                    f"Hallucination Fix: event_ts '{event_ts}' not found in "
                    f"raw log — overridden with ingestion time '{ingestion_time}'."
                )
                data["event_ts"]    = ingestion_time
                data["ts_source"]   = "ingestion"
                data["review_flag"] = True
            else:
                if data.get("ts_source") != "ingestion":
                    data["ts_source"] = "original"

        # --- Fix 4: event_hash — always pipeline-computed ---
        if raw:
            data["event_hash"] = _compute_hash(raw)

        # --- Fix 5: review_flag from confidence ---
        try:
            conf = float(data.get("confidence", 0.0))
        except (ValueError, TypeError):
            conf = 0.0
        if conf < CONFIDENCE_GATE:
            data["review_flag"] = True

        # --- Fix 6: ingestion time fallback ---
        if not data.get("event_ts"):
            data["event_ts"]  = datetime.now(timezone.utc).isoformat()
            data["ts_source"] = "ingestion"

        data["validation_issues"] = issues
        return data

    # ------------------------------------------------------------------
    # Safe construction
    # ------------------------------------------------------------------

    @classmethod
    def safe_parse(cls, raw_dict: dict[str, Any]) -> "NormalizedLog":
        """
        Construct a NormalizedLog from a raw dict.
        On ValidationError returns a quarantine-safe fallback.
        Never raises.
        """
        from pydantic import ValidationError

        try:
            return cls(**raw_dict)
        except ValidationError as exc:
            issues = [
                f"{err['loc'][0] if err['loc'] else 'unknown'}: {err['msg']}"
                for err in exc.errors()
            ]
            raw      = str(raw_dict.get("raw", ""))
            fallback = {
                "event_hash":        _compute_hash(raw) if raw else "",
                "event_ts":          datetime.now(timezone.utc).isoformat(),
                "ts_source":         "ingestion",
                "source_host":       None,
                "category":          "other",
                "action":            None,
                "outcome":           "unknown",
                "actor_user":        None,
                "src_ip":            None,
                "dst_ip":            None,
                "target":            None,
                "message":           f"[VALIDATION FAILURE] {'; '.join(issues)}",
                "raw":               raw,
                "extras":            {},
                "confidence":        0.0,
                "review_flag":       True,
                "validation_issues": issues,
                "format_hint":       None,
            }
            return cls.model_construct(**fallback)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def is_confident(self) -> bool:
        return not self.review_flag 
