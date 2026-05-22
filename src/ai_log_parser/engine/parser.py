# ai_log_parser/engine/parser.py

"""
Core AI Parse Engine — interfaces with Ollama to extract structured fields
from raw log lines using pre-processor format hints.

Design
------
* Receives a raw log line (str) + a LogFormatHint from the pre-processor.
* Builds a structured prompt that forces Ollama to return data in the
  predefined JSON schema including a confidence field.
* Parses and validates the JSON response against the schema.
* Passes the parsed dict through NormalizedLog.safe_parse() (Pydantic)
  for self-healing validation before routing.
* format_hint is passed into NormalizedLog so the syslog year injection
  validator can run correctly.
* Routing is handled entirely by output/writer.py.
* Never raises on AI response parse failure — returns a safe fallback
  event with confidence=0.0 and review_flag=True.

Pipeline flow
-------------
raw log line
  → preprocessor.detect()         # format hint
  → AIParseEngine.parse()         # Ollama extraction
  → _extract_json()               # JSON extraction from AI response
  → _build_raw_event()            # assemble raw dict with defaults
  → NormalizedLog.safe_parse()    # Pydantic validation + self-healing
  → writer.route()                # confidence gate + file routing

Ollama API
----------
Uses the Ollama REST API directly via httpx (async).
Endpoint: POST http://localhost:11434/api/generate
Model: qwen2.5:1.5b
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_log_parser.engine.preprocessor import LogFormatHint
from ai_log_parser.models.schema import NormalizedLog
from ai_log_parser.output.writer import route

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "qwen2.5:1.5b"
OLLAMA_TIMEOUT = 300.0


# ---------------------------------------------------------------------------
# Structured prompt builder
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert SOC (Security Operations Center) log parser.
Your HIGHEST PRIORITY task is ENTITY EXTRACTION — you must find and extract \
every IP address, username, and hostname present in the raw log line.

ENTITY EXTRACTION RULES — these override everything else:
A. src_ip: Extract the SOURCE IP ADDRESS of the actor/client/attacker.
   - In SSH logs: the IP after "from" is ALWAYS src_ip.
     "Accepted password for deploy from 10.10.1.50 port 54231" → src_ip = "10.10.1.50"
     "Failed password for root from 203.0.113.99 port 41512" → src_ip = "203.0.113.99"
     "Disconnected from user deploy 10.10.1.50 port 54231" → src_ip = "10.10.1.50"
   - In CEF logs: src= or SRC= field is ALWAYS src_ip.
   - In firewall logs: SRC= field is ALWAYS src_ip.
   - If no source IP exists anywhere in the log, set src_ip = null.

B. dst_ip: Extract the DESTINATION IP ADDRESS of the target system.
   - In CEF logs: dst= or DST= field is ALWAYS dst_ip.
   - In firewall logs: DST= field is ALWAYS dst_ip.
   - If no destination IP exists anywhere in the log, set dst_ip = null.

C. actor_user: Extract the USERNAME of the person performing the action.
   - In SSH logs: the username after "for" is ALWAYS actor_user.
     "Accepted password for deploy from 10.10.1.50" → actor_user = "deploy"
     "Failed password for root from 203.0.113.99" → actor_user = "root"
     "Failed password for invalid user admin from 10.0.0.1" → actor_user = "admin"
     "Disconnected from user deploy 10.10.1.50" → actor_user = "deploy"
   - In sudo logs: the name directly after "sudo:" is ALWAYS actor_user.
     "sudo: alice : TTY=pts/1 USER=root COMMAND=/bin/bash" → actor_user = "alice"
   - In CEF logs: suser= field is ALWAYS actor_user.
   - If no username exists, set actor_user = null.

D. source_host: Extract the HOSTNAME of the machine that generated the log.
   - In syslog: the hostname is the second token after the timestamp.
     "May 9 14:23:01 prod-server-01 sshd[22341]: ..." → source_host = "prod-server-01"
   - Do NOT put an IP address in source_host. IPs go in src_ip.

SCHEMA FIELD MAPPING — understand exactly what each field means:
  src_ip      = IP address of the connecting client / attacker / source
  dst_ip      = IP address of the target / destination system
  source_host = hostname of the machine that wrote this log entry
  actor_user  = username of the person who performed the action
  target      = resource being accessed (file path, bucket name, URL)
  action      = verb describing what happened (login, connect, block, ban)
  outcome     = success | failure | unknown
  message     = human-readable summary of the event

GENERAL RULES:
1. Return ONLY a single JSON object. No markdown, no backticks, no explanation.
2. Every field in the schema must be present in your response.
3. Use null for any field you cannot find in the raw log. Do NOT guess or invent.
4. The "confidence" field: 0.0–1.0. Be honest — if ambiguous, set below 0.7.
5. The "review_flag" field: always false — pipeline sets it automatically.
6. The "raw" field: copy the original log line exactly as provided.
7. The "event_hash", "raw_hash", "ts_source", "format_hint" fields: always null.
8. The "event_ts" field: ISO8601 UTC ONLY if a timestamp exists in the log.
   If no timestamp, return null. Do NOT invent a timestamp.
9. The "category" field: authentication | network | file | process | other.
10. The "outcome" field: success | failure | unknown.
11. The "validation_issues" field: always [].

FEW-SHOT EXAMPLES — these show exactly how to extract entities:

Input: "May  9 14:23:01 prod-server-01 sshd[22341]: Accepted password for deploy from 10.10.1.50 port 54231 ssh2"
Output: {
  "event_hash": null, "event_ts": null, "ts_source": null,
  "source_host": "prod-server-01", "category": "authentication",
  "action": "Accepted password", "outcome": "success",
  "actor_user": "deploy", "src_ip": "10.10.1.50", "target": null,
  "dst_ip": null, "message": "Accepted password for deploy from 10.10.1.50 port 54231 ssh2",
  "raw": "May  9 14:23:01 prod-server-01 sshd[22341]: Accepted password for deploy from 10.10.1.50 port 54231 ssh2",
  "raw_hash": null, "extras": {}, "confidence": 1.0, "review_flag": false,
  "validation_issues": [], "format_hint": null
}

Input: "May  9 14:23:05 prod-server-01 sshd[22342]: Failed password for root from 203.0.113.99 port 41512 ssh2"
Output: {
  "event_hash": null, "event_ts": null, "ts_source": null,
  "source_host": "prod-server-01", "category": "authentication",
  "action": "Failed password", "outcome": "failure",
  "actor_user": "root", "src_ip": "203.0.113.99", "target": null,
  "dst_ip": null, "message": "Failed password for root from 203.0.113.99 port 41512 ssh2",
  "raw": "May  9 14:23:05 prod-server-01 sshd[22342]: Failed password for root from 203.0.113.99 port 41512 ssh2",
  "raw_hash": null, "extras": {}, "confidence": 1.0, "review_flag": false,
  "validation_issues": [], "format_hint": null
}

Input: "May  9 14:23:10 prod-server-01 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update"
Output: {
  "event_hash": null, "event_ts": null, "ts_source": null,
  "source_host": "prod-server-01", "category": "process",
  "action": "sudo", "outcome": "success",
  "actor_user": "alice", "src_ip": null, "target": "/usr/bin/apt-get update",
  "dst_ip": null, "message": "alice ran /usr/bin/apt-get update as root",
  "raw": "May  9 14:23:10 prod-server-01 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update",
  "raw_hash": null, "extras": {}, "confidence": 1.0, "review_flag": false,
  "validation_issues": [], "format_hint": null
}

Input: "May  9 14:23:15 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.10.1.1 PROTO=TCP SPT=80 DPT=22 FLAGS=SYN"
Output: {
  "event_hash": null, "event_ts": null, "ts_source": null,
  "source_host": "fw-01", "category": "network",
  "action": "BLOCK", "outcome": "failure",
  "actor_user": null, "src_ip": "45.33.32.156", "target": null,
  "dst_ip": "10.10.1.1", "message": "UFW blocked TCP from 45.33.32.156:80 to 10.10.1.1:22",
  "raw": "May  9 14:23:15 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.10.1.1 PROTO=TCP SPT=80 DPT=22 FLAGS=SYN",
  "raw_hash": null, "extras": {}, "confidence": 1.0, "review_flag": false,
  "validation_issues": [], "format_hint": null
}

Input: "CEF:0|Suricata|ids|6.0|2001219|ET MALWARE Win32/Metasploit CnC Beacon|8|src=203.0.113.99 spt=4444 dst=10.10.1.22 dpt=443 proto=TCP"
Output: {
  "event_hash": null, "event_ts": null, "ts_source": null,
  "source_host": null, "category": "network",
  "action": "detected", "outcome": "unknown",
  "actor_user": null, "src_ip": "203.0.113.99", "target": null,
  "dst_ip": "10.10.1.22", "message": "ET MALWARE Win32/Metasploit CnC Beacon detected from 203.0.113.99 to 10.10.1.22",
  "raw": "CEF:0|Suricata|ids|6.0|2001219|ET MALWARE Win32/Metasploit CnC Beacon|8|src=203.0.113.99 spt=4444 dst=10.10.1.22 dpt=443 proto=TCP",
  "raw_hash": null, "extras": {}, "confidence": 1.0, "review_flag": false,
  "validation_issues": [], "format_hint": null
}

JSON SCHEMA (return exactly this structure):
{
  "event_hash":        null,
  "event_ts":          "<ISO8601-UTC or null if no timestamp in log>",
  "ts_source":         null,
  "source_host":       "<hostname of machine that wrote this log or null>",
  "category":          "<authentication|network|file|process|other>",
  "action":            "<verb describing what happened or null>",
  "outcome":           "<success|failure|unknown>",
  "actor_user":        "<username of person who acted or null>",
  "src_ip":            "<source IP address of client/attacker or null>",
  "target":            "<resource being accessed or null>",
  "dst_ip":            "<destination IP address of target system or null>",
  "message":           "<human-readable summary of the event or null>",
  "raw":               "<original log line exactly as provided>",
  "raw_hash":          null,
  "extras":            {},
  "confidence":        0.0,
  "review_flag":       false,
  "validation_issues": [],
  "format_hint":       null
}"""


def _build_user_prompt(raw: str, hint: LogFormatHint) -> str:
    """Build the user-turn prompt combining the pre-processor hint and raw log."""
    return (
        f"{hint.as_prompt_context()}\n\n"
        f"Parse the following log line and return the JSON schema:\n\n"
        f"{raw}"
    )


# ---------------------------------------------------------------------------
# JSON extraction from AI response
# ---------------------------------------------------------------------------

_RE_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str) -> dict[str, Any] | None:
    """
    Extract a JSON object from the AI response text.

    Handles cases where the model wraps its response in markdown fences
    or adds preamble text despite being instructed not to.
    """
    # 1. Try direct parse first
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown fences and retry
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 3. Extract first {...} block via regex
    match = _RE_JSON_BLOCK.search(text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


# ---------------------------------------------------------------------------
# Raw event builder
# ---------------------------------------------------------------------------

def _compute_hash(raw: str) -> str:
    """Return SHA256 hex digest of the raw log line."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_raw_event(
    raw_line: str,
    parsed: dict[str, Any],
    hint: LogFormatHint,
) -> dict[str, Any]:
    """
    Merge AI-parsed fields with pipeline-controlled defaults into a single
    dict ready for NormalizedLog.safe_parse().
    """
    event = dict(parsed)

    event["raw"]               = raw_line
    event["event_hash"]        = _compute_hash(raw_line)
    event["raw_hash"]          = event["event_hash"]
    event["format_hint"]       = hint.format
    event["validation_issues"] = []

    event.setdefault("ts_source",    "ingestion")
    event.setdefault("event_ts",     None)
    event.setdefault("source_host",  None)
    event.setdefault("category",     "other")
    event.setdefault("action",       None)
    event.setdefault("outcome",      "unknown")
    event.setdefault("actor_user",   None)
    event.setdefault("src_ip",       None)
    event.setdefault("dst_ip",       None)
    event.setdefault("target",       None)
    event.setdefault("message",      None)
    event.setdefault("extras",       {})
    event.setdefault("confidence",   0.0)
    event.setdefault("review_flag",  False)

    return event


# ---------------------------------------------------------------------------
# Fallback event
# ---------------------------------------------------------------------------

def _fallback_event(
    raw_line: str,
    reason: str,
    hint: LogFormatHint | None = None,
) -> NormalizedLog:
    """Return a quarantine-safe NormalizedLog when AI parsing fails entirely."""
    logger.warning("Parser fallback triggered: %s", reason)
    raw_hash = _compute_hash(raw_line)
    return NormalizedLog.safe_parse({
        "event_hash":        raw_hash,
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
        "message":           f"[PARSE FAILURE] {reason}",
        "raw":               raw_line,
        "raw_hash":          raw_hash,
        "extras":            {},
        "confidence":        0.0,
        "review_flag":       True,
        "validation_issues": [f"Parse failure: {reason}"],
        "format_hint":       hint.format if hint else None,
    })


# ---------------------------------------------------------------------------
# Core AI Parse Engine
# ---------------------------------------------------------------------------

class AIParseEngine:
    """
    Async AI parse engine that interfaces with Ollama to extract structured
    fields from raw log lines.
    """

    def __init__(
        self,
        ollama_url: str   = OLLAMA_URL,
        model:      str   = OLLAMA_MODEL,
        timeout:    float = OLLAMA_TIMEOUT,
    ) -> None:
        self._url     = ollama_url
        self._model   = model
        self._timeout = timeout

    async def parse(self, raw_line: str, hint: LogFormatHint) -> NormalizedLog:
        """
        Parse a single raw log line using Ollama.

        Returns a fully validated NormalizedLog. Never raises.
        On total failure returns a fallback event with confidence=0.0.
        """
        prompt = _build_user_prompt(raw_line, hint)

        try:
            ai_response = await self._call_ollama(prompt)
        except Exception as exc:
            event = _fallback_event(raw_line, f"Ollama call failed: {exc}", hint)
            route(event)
            return event

        parsed = _extract_json(ai_response)
        if parsed is None:
            event = _fallback_event(
                raw_line,
                f"AI returned non-JSON response: {ai_response[:120]}",
                hint,
            )
            route(event)
            return event

        raw_event = _build_raw_event(raw_line, parsed, hint)
        event     = NormalizedLog.safe_parse(raw_event)
        route(event)
        return event

    async def parse_batch(
        self,
        lines: list[str],
        hints: list[LogFormatHint],
    ) -> list[NormalizedLog]:
        """Parse multiple log lines sequentially."""
        if len(lines) != len(hints):
            raise ValueError(
                f"parse_batch: lines ({len(lines)}) and hints ({len(hints)}) "
                f"must be the same length"
            )
        events = []
        for raw_line, hint in zip(lines, hints):
            event = await self.parse(raw_line, hint)
            events.append(event)
        return events

    async def _call_ollama(self, prompt: str) -> str:
        """
        POST a prompt to Ollama and return the full response text.

        num_predict=1024 — prevents JSON truncation on longer log lines.
        """
        payload = {
            "model":  self._model,
            "prompt": f"{_SYSTEM_PROMPT}\n\nUser: {prompt}",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p":       0.9,
                "num_predict": 1024,
            },
        }

        async with httpx.AsyncClient(timeout=None) as client:
            response = await client.post(self._url, json=payload)
            response.raise_for_status()
            data = response.json()

        return data.get("response", "") 
