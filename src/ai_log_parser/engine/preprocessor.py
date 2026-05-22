# ai_log_parser/engine/preprocessor.py

"""
Lightweight Pre-processor — detects log format from raw log lines.

Design
------
* Receives a single raw log line (str) or file path (Path).
* Returns a LogFormatHint dataclass containing:
    - format     : detected format label
    - confidence : how certain the detector is (0.0–1.0)
    - hint       : short human-readable description passed to the AI prompt
* Detection is purely rule-based — regex and string matching only.
  No AI is involved at this stage.
* Handles ANY format, including unknown ones — never raises on unrecognised
  input, always returns LogFormatHint(format="unknown", ...).

Supported formats
-----------------
    syslog_rfc3164  — <priority> or standard syslog header
    cef             — CEF:0| prefix
    json            — starts with { or [
    xml             — starts with <?xml or <EventLog or <Events or <Event
    evtx_xml        — XML containing Windows Event Log namespace
    csv             — comma-separated with consistent column count
    kv              — key=value pairs (e.g. src=1.2.3.4 dst=4.5.6.7)
    plaintext       — human-readable but unstructured
    unknown         — nothing matched with sufficient confidence

Detection priority (highest → lowest)
--------------------------------------
    evtx_xml > cef > syslog_rfc3164 > json > xml > csv > kv > plaintext > unknown
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class LogFormatHint:
    """
    Result returned by the pre-processor for a single log line or file.

    Attributes
    ----------
    format : str
        Detected format label. One of: syslog_rfc3164, cef, json, xml,
        evtx_xml, csv, kv, plaintext, unknown.
    confidence : float
        Detector confidence in the format label (0.0–1.0).
        Rule-based detectors return 1.0 for strong pattern matches,
        lower values for heuristic guesses.
    hint : str
        Short description injected into the AI prompt as context, e.g.
        "Format: CEF (ArcSight Common Event Format). Fields are pipe-delimited."
    raw_sample : str
        The first 200 characters of the input — included in the AI prompt
        so the model sees what triggered the hint.
    """
    format: str
    confidence: float
    hint: str
    raw_sample: str = field(default="", repr=False)

    def as_prompt_context(self) -> str:
        """
        Return a formatted string ready to be injected into an AI prompt.

        Example output
        --------------
        [PRE-PROCESSOR HINT]
        Detected format : CEF (ArcSight Common Event Format)
        Detector confidence : 1.00
        Parsing guidance : Fields are pipe-delimited after CEF:0|. Extension
                           fields are space-separated key=value pairs.
        Raw sample : CEF:0|Suricata|ids|1.0|2013504|ET SCAN|3|src=10.0.0.5
        """
        return (
            f"[PRE-PROCESSOR HINT]\n"
            f"Detected format     : {self.hint}\n"
            f"Detector confidence : {self.confidence:.2f}\n"
            f"Raw sample          : {self.raw_sample[:200]}"
        )


# ---------------------------------------------------------------------------
# Compiled patterns — compiled once at import time for performance
# ---------------------------------------------------------------------------

# Syslog RFC3164: optional <priority> then Month Day HH:MM:SS
_RE_SYSLOG_PRIORITY = re.compile(r"^<(\d{1,3})>")
_RE_SYSLOG_HEADER   = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)

# CEF: starts with CEF:0| or CEF:1|
_RE_CEF = re.compile(r"^CEF:\d\|", re.IGNORECASE)

# JSON: starts with { or [
_RE_JSON = re.compile(r"^\s*[\[{]")

# XML declarations and common root tags
_RE_XML_DECL  = re.compile(r"^\s*<\?xml", re.IGNORECASE)
_RE_XML_TAG   = re.compile(r"^\s*<[A-Za-z_][\w:.-]*[\s>]")

# Windows Event Log namespace — distinguishes EVTX-derived XML from generic XML
_EVTX_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_EVTX_PROVIDERS = (
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-System",
    "Microsoft-Windows-Application",
    "EventID",
    "<System>",
    "<EventData>",
)

# Key=value: at least 3 key=value pairs
_RE_KV = re.compile(r"(?:\w[\w.\-]*=\S+\s*){3,}")

# CSV heuristic: at least 3 commas and no obvious other format markers
_RE_CSV = re.compile(r"^[^<{\[CEF][^\n]*,[^\n]*,[^\n]*,[^\n]*$")


# ---------------------------------------------------------------------------
# Format descriptions injected into the AI prompt
# ---------------------------------------------------------------------------

_FORMAT_HINTS: dict[str, str] = {
    "syslog_rfc3164": (
        "Syslog RFC3164. Header is: <priority>Month Day HH:MM:SS hostname process[pid]: message. "
        "Priority = facility*8 + severity."
    ),
    "cef": (
        "CEF (ArcSight Common Event Format). "
        "Structure: CEF:version|vendor|product|version|signatureId|name|severity|extensions. "
        "Extension fields are space-separated key=value pairs."
    ),
    "json": (
        "JSON log. Fields are key-value pairs inside a JSON object or array. "
        "Parse as standard JSON."
    ),
    "xml": (
        "XML log. Fields are enclosed in XML tags. "
        "Extract tag names and their text content as fields."
    ),
    "evtx_xml": (
        "Windows Event Log (EVTX) in XML form. "
        "Key fields are under <System> (EventID, TimeCreated, Computer, Channel) "
        "and <EventData> (named Data elements). "
        "EventID 4624=logon, 4625=failed logon, 4648=explicit logon, 4688=process create."
    ),
    "csv": (
        "CSV log. Fields are comma-separated. "
        "First row may be a header. Treat positionally if no header is present."
    ),
    "kv": (
        "Key=Value log. Fields are space-separated key=value pairs. "
        "Common keys: src, dst, spt, dpt, user, action, result, msg."
    ),
    "plaintext": (
        "Unstructured plain-text log. "
        "Extract any identifiable fields: timestamps, IPs, usernames, actions, outcomes."
    ),
    "unknown": (
        "Unknown or unrecognised log format. "
        "Attempt best-effort field extraction. Set confidence low."
    ),
}


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class LogPreprocessor:
    """
    Stateless log format detector.

    All public methods are synchronous — the pre-processor is designed to
    run inline in the async pipeline without blocking (detection is pure
    CPU string matching with no I/O).

    Usage
    -----
    ::

        preprocessor = LogPreprocessor()

        # Single line
        hint = preprocessor.detect(raw_line)
        print(hint.format)           # e.g. "syslog_rfc3164"
        print(hint.as_prompt_context())

        # Whole file (returns hint based on first non-empty line)
        hint = preprocessor.detect_file(Path("tests/corpus/sample_cef.log"))
    """

    def detect(self, raw: str) -> LogFormatHint:
        """
        Detect the format of a single raw log line.

        Parameters
        ----------
        raw : str
            A single raw log line. May be any length.

        Returns
        -------
        LogFormatHint
            Always returns a result — never raises.
        """
        if not isinstance(raw, str):
            raw = str(raw)

        sample = raw.strip()

        # Detection runs in priority order — first match wins
        fmt, confidence = self._run_detectors(sample)

        return LogFormatHint(
            format=fmt,
            confidence=confidence,
            hint=_FORMAT_HINTS[fmt],
            raw_sample=sample[:200],
        )

    def detect_file(self, path: Path) -> LogFormatHint:
        """
        Detect the format of a log file by sampling its first non-empty line.

        Parameters
        ----------
        path : Path
            Path to the log file. Supports .log, .json, .xml, .csv, .txt.

        Returns
        -------
        LogFormatHint
            Format hint based on the first meaningful line found.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"LogPreprocessor: file not found: {path}")

        # Extension-based pre-check for binary-origin formats
        suffix = path.suffix.lower()
        if suffix == ".evtx":
            # True binary EVTX — we can't read it as text; label directly
            return LogFormatHint(
                format="evtx_xml",
                confidence=1.0,
                hint=_FORMAT_HINTS["evtx_xml"],
                raw_sample=f"[binary EVTX file: {path.name}]",
            )

        # Read first non-empty line
        first_line = ""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        first_line = stripped
                        break
        except OSError as exc:
            return LogFormatHint(
                format="unknown",
                confidence=0.0,
                hint=_FORMAT_HINTS["unknown"],
                raw_sample=f"[error reading file: {exc}]",
            )

        if not first_line:
            return LogFormatHint(
                format="unknown",
                confidence=0.0,
                hint=_FORMAT_HINTS["unknown"],
                raw_sample="[empty file]",
            )

        hint = self.detect(first_line)

        # Upgrade generic xml → evtx_xml if file content contains EVTX markers
        if hint.format == "xml" and suffix in (".xml", ".log"):
            try:
                content_sample = path.read_text(encoding="utf-8", errors="replace")[:2000]
                if self._is_evtx_xml(content_sample):
                    return LogFormatHint(
                        format="evtx_xml",
                        confidence=1.0,
                        hint=_FORMAT_HINTS["evtx_xml"],
                        raw_sample=first_line[:200],
                    )
            except OSError:
                pass

        return hint

    # ------------------------------------------------------------------
    # Internal detection pipeline
    # ------------------------------------------------------------------

    def _run_detectors(self, sample: str) -> tuple[str, float]:
        """
        Run all detectors in priority order.
        Returns (format_label, confidence).
        """
        # 1. EVTX XML — must check before generic XML
        if self._is_evtx_xml(sample):
            return "evtx_xml", 1.0

        # 2. CEF
        if _RE_CEF.match(sample):
            return "cef", 1.0

        # 3. Syslog RFC3164
        if _RE_SYSLOG_HEADER.match(sample):
            return "syslog_rfc3164", 1.0
        if _RE_SYSLOG_PRIORITY.match(sample):
            return "syslog_rfc3164", 0.9

        # 4. JSON
        if _RE_JSON.match(sample):
            if self._is_valid_json_start(sample):
                return "json", 1.0
            return "json", 0.8  # looks like JSON but couldn't fully validate

        # 5. XML (generic) — after EVTX check
        if _RE_XML_DECL.match(sample) or self._looks_like_xml(sample):
            return "xml", 1.0

        # 6. CSV
        if _RE_CSV.match(sample) and sample.count(",") >= 3:
            return "csv", 0.85

        # 7. Key=Value
        if _RE_KV.search(sample):
            return "kv", 0.85

        # 8. Plain text — printable, has words, not empty
        if sample and sample.isprintable():
            return "plaintext", 0.6

        # 9. Unknown
        return "unknown", 0.0

    @staticmethod
    def _is_evtx_xml(text: str) -> bool:
        """Return True if text contains Windows Event Log namespace or key markers."""
        if _EVTX_NAMESPACE in text:
            return True
        # Count how many EVTX structural markers are present
        matches = sum(1 for marker in _EVTX_PROVIDERS if marker in text)
        return matches >= 2

    @staticmethod
    def _is_valid_json_start(sample: str) -> bool:
        """Light JSON validation — check balanced braces/brackets."""
        import json
        try:
            json.loads(sample)
            return True
        except (json.JSONDecodeError, ValueError):
            # Might be a partial line — still likely JSON if it starts with {
            return sample.strip().startswith("{") or sample.strip().startswith("[")

    @staticmethod
    def _looks_like_xml(sample: str) -> bool:
        """Return True if sample looks like an XML element."""
        return bool(_RE_XML_TAG.match(sample)) and "</" in sample or sample.endswith("/>")
