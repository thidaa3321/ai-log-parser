# AI Dynamic Log Parser

An AI-powered log parsing module for SOC pipelines. Ingests raw logs from
any source, extracts structured fields using a local LLM, and outputs
normalized events in JSON, OCSF, and CEF formats.

Built for SOC teams who need structured, actionable data from unstructured
logs — without writing a single parser.

---

## What It Does

- Pulls logs from local files, syslog streams (UDP/TCP), and AWS S3/CloudTrail
- Detects log format automatically — syslog, CEF, JSON, XML, Windows Event Log, and more
- Extracts fields (src_ip, actor_user, category, outcome, etc.) using a local AI model
- Validates and self-heals AI output using Pydantic — bad data never reaches your pipeline
- Routes confident events to OCSF and CEF output, uncertain events to a human review queue
- Works as a CLI tool or as an embeddable Python module

---

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) running locally
- Docker (for S3/CloudTrail testing via LocalStack — optional)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ai-dynamics-log-parser.git
cd ai-dynamics-log-parser

# Install the package
pip install -e .

# Install with dev dependencies (for running tests)
pip install -e ".[dev]"
```

---

## Setup

### 1. Install and start Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model
# Development (CPU):
ollama pull qwen2.5:1.5b

# Production (GPU):
ollama pull qwen2.5:7b

# Start Ollama
ollama serve
```

### 2. Verify everything is working

```bash
ai-parser verify
```

Expected output: 3 green PASS lines for File, Syslog, and S3 connectors.

---

## Usage

### As a CLI tool

```bash
# Run with default config
ai-parser run

# Run with a custom config file
ai-parser run --config /path/to/config.yaml

# Verify connectors are healthy
ai-parser verify
```

### As a Python module

```python
import asyncio
from ai_log_parser import AIParseEngine, LogPreprocessor

async def main():
    preprocessor = LogPreprocessor()
    engine       = AIParseEngine()

    raw   = "May  9 14:23:05 prod-server-01 sshd: Failed password for root from 203.0.113.99"
    hint  = preprocessor.detect(raw)
    event = await engine.parse(raw, hint)

    print(event.src_ip)      # 203.0.113.99
    print(event.category)    # authentication
    print(event.outcome)     # failure
    print(event.confidence)  # 0.0–1.0

asyncio.run(main())
```

---

## Configuration

All log sources are configured in YAML. No code changes required to add
or remove a source.

```yaml
# config.yaml

queue:
  max_size: 1000

connectors:
  # Read from a local log file
  - type: file
    name: auth-log
    path: /var/log/auth.log
    tail: true

  # Listen for syslog/CEF on UDP
  - type: syslog
    name: suricata
    host: 0.0.0.0
    port: 514
    protocol: udp

  # Poll AWS CloudTrail from S3
  - type: s3
    name: cloudtrail
    bucket: my-cloudtrail-bucket
    prefix: AWSLogs/
    region_name: us-east-1
    poll_interval: 60.0
```

Run with your config:

```bash
ai-parser run --config config.yaml
```

---

## Output

Every parsed event is written to one of four output files depending on
confidence and format:

| File | Contents |
|---|---|
| `data/staging/ai_confident.json` | Confident parsed events (normalized schema) |
| `data/output/review_needed.json` | Flagged events requiring human review |
| `data/output/processed_ocsf.json` | OCSF 1.0 formatted confident events |
| `data/output/processed.cef` | CEF formatted confident events |

Output directories are created automatically on first run in the directory
where the process is launched.

---

## Supported Log Formats

Detected automatically — no configuration required:

- Syslog RFC3164 — Linux auth, kernel, application logs
- CEF — Suricata, ArcSight, network IDS/IPS
- JSON — Application logs, AWS CloudTrail
- XML / EVTX — Windows Event Logs
- Plain text — Unstructured logs, custom formats
- Unknown — Best-effort extraction, routed to review queue

---

## Normalized Event Schema

Every parsed event conforms to this schema regardless of input format:

```json
{
  "event_hash":        "sha256-of-raw-log",
  "event_ts":          "2026-05-09T14:23:01Z",
  "ts_source":         "original | ingestion",
  "source_host":       "prod-server-01",
  "category":          "authentication | network | file | process | other",
  "action":            "login | block | null",
  "outcome":           "success | failure | unknown",
  "actor_user":        "alice | null",
  "src_ip":            "203.0.113.99 | null",
  "dst_ip":            "10.10.1.1 | null",
  "target":            "/var/log/auth.log | null",
  "message":           "human-readable summary",
  "raw":               "original raw log line — never modified",
  "raw_hash":          "sha256-of-raw-log",
  "confidence":        0.95,
  "review_flag":       false,
  "validation_issues": [],
  "format_hint":       "syslog_rfc3164"
}
```

---

## Changing the AI Model

One line in `src/ai_log_parser/engine/parser.py`:

```python
# Development (CPU)
OLLAMA_MODEL = "qwen2.5:1.5b"

# Production (GPU) — better accuracy, zero other changes needed
OLLAMA_MODEL = "qwen2.5:7b"
```

---

## Running Tests

```bash
# Unit tests — no Ollama required
pytest tests/unit/ -v

# Integration tests — no Ollama required
pytest tests/integration/ -v -k "not ai"

# Full test suite including AI
pytest -v
```

---

## Module Integration Demo

See how `ai_log_parser` works embedded inside a production SOC system:

```bash
python integration_demo.py
```

---

## Documentation

- [Connector Configuration Guide](docs/connector_guide.md) — all YAML config options
- [Integration Guide](docs/integration_guide.md) — architecture, SIEM integration, deployment

---

## Known Limitations

| Limitation | Impact | Resolution |
|---|---|---|
| Syslog RFC3164 has no year | `event_ts` set to ingestion time | Expected — format limitation |
| CEF has no timestamp | Routed to review queue | Expected — CEF limitation |
| Nested JSON field extraction | `actor_user` null on CloudTrail | Resolved with 7b model on GPU |
| CPU throughput ~15 logs/min | Not suitable for high volume | GPU deployment resolves this |
