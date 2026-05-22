# src/ai_log_parser/cli.py

"""
CLI entry point for ai-log-parser.

Usage
-----
::

    # After pip install -e .
    ai-parser                          # run with default config
    ai-parser --config /path/to.yaml   # run with custom config
    ai-parser verify                   # run live connector verification

    # Or directly
    python -m ai_log_parser.cli
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import logging
import socket
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

PASS = "\033[92m PASS \033[0m"
FAIL = "\033[91m FAIL \033[0m"


# ---------------------------------------------------------------------------
# Verify command — live connector verification
# ---------------------------------------------------------------------------

async def _verify_file_connector() -> bool:
    from ai_log_parser.connectors.file import FileConnector

    corpus = Path(__file__).parent.parent.parent / "tests" / "corpus" / "sample_syslog.log"
    if not corpus.exists():
        print(f"{FAIL} FileConnector — corpus file not found: {corpus}")
        return False

    cfg       = {"name": "verify-file", "path": str(corpus), "poll_interval": 0.1}
    conn      = FileConnector(cfg)
    collected: list[str] = []

    try:
        async with conn:
            async def _read():
                async for line in conn.read():
                    collected.append(line)
            async def _stop():
                await asyncio.sleep(0.5)
                conn.stop()
            await asyncio.gather(_read(), _stop())

        if collected:
            print(f"{PASS} FileConnector pulled {len(collected)} lines")
            return True
        print(f"{FAIL} FileConnector returned 0 lines")
        return False
    except Exception as exc:
        print(f"{FAIL} FileConnector raised: {exc}")
        return False


async def _verify_syslog_connector() -> bool:
    from ai_log_parser.connectors.syslog import SyslogConnector

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    cfg = {"name": "verify-syslog", "host": "127.0.0.1", "port": port, "protocol": "udp"}
    sample_lines = [
        "<134>May  9 12:00:01 fw01 CEF:0|Suricata|ids|1.0|2013504|ET SCAN|3|src=10.0.0.5",
        "<13>May  9 12:00:02 host sshd: Failed password for root from 10.0.0.99",
        "<14>May  9 12:00:03 host kernel: iptables DROP SRC=203.0.113.5 DST=10.0.0.1",
    ]
    collected: list[str] = []

    try:
        conn = SyslogConnector(cfg)

        async def _sender():
            await asyncio.sleep(0.1)
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=("127.0.0.1", port),
            )
            for line in sample_lines:
                transport.sendto(line.encode())
                await asyncio.sleep(0.05)
            transport.close()
            await asyncio.sleep(0.2)
            conn.stop()

        async def _reader():
            async for line in conn.read():
                collected.append(line)

        async with conn:
            await asyncio.gather(_sender(), _reader())

        if len(collected) == len(sample_lines):
            print(f"{PASS} SyslogConnector pulled {len(collected)} lines")
            return True
        print(f"{FAIL} SyslogConnector: expected {len(sample_lines)}, got {len(collected)}")
        return False
    except Exception as exc:
        print(f"{FAIL} SyslogConnector raised: {exc}")
        return False


async def _verify_s3_connector() -> bool:
    import boto3
    import botocore.exceptions
    from ai_log_parser.connectors.s3 import S3Connector

    endpoint = "http://localhost:4566"
    try:
        with socket.create_connection(("localhost", 4566), timeout=1):
            pass
    except OSError:
        print(f"{FAIL} S3Connector — LocalStack not reachable on localhost:4566")
        return False

    bucket = "verify-cli-cloudtrail"
    client = boto3.client(
        "s3", endpoint_url=endpoint, region_name="us-east-1",
        aws_access_key_id="test", aws_secret_access_key="test",
    )
    try:
        client.create_bucket(Bucket=bucket)
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"{FAIL} S3Connector — could not create bucket: {exc}")
            return False

    records = [
        {"eventVersion": "1.08", "eventName": f"VerifyEvent{i}",
         "eventTime": "2026-05-09T14:23:00Z",
         "userIdentity": {"type": "IAMUser", "userName": "alice"},
         "sourceIPAddress": "10.0.0.5", "eventSource": "s3.amazonaws.com"}
        for i in range(3)
    ]
    body = gzip.compress(json.dumps({"Records": records}).encode())
    client.put_object(Bucket=bucket, Key="AWSLogs/verify.json.gz", Body=body)

    cfg = {
        "name": "verify-s3", "bucket": bucket, "prefix": "AWSLogs/",
        "endpoint_url": endpoint, "aws_access_key_id": "test",
        "aws_secret_access_key": "test", "poll_interval": 1.0,
    }
    collected: list[str] = []

    try:
        conn = S3Connector(cfg)

        async def _stopper():
            await asyncio.sleep(3.0)
            conn.stop()

        async def _reader():
            async for line in conn.read():
                collected.append(line)

        async with conn:
            await asyncio.gather(_stopper(), _reader())

        if len(collected) == len(records):
            print(f"{PASS} S3Connector pulled {len(collected)} CloudTrail records")
            return True
        print(f"{FAIL} S3Connector: expected {len(records)}, got {len(collected)}")
        return False
    except Exception as exc:
        print(f"{FAIL} S3Connector raised: {exc}")
        return False
    finally:
        try:
            client.delete_object(Bucket=bucket, Key="AWSLogs/verify.json.gz")
            client.delete_bucket(Bucket=bucket)
        except Exception:
            pass


async def _run_verify() -> None:
    print("=" * 54)
    print("  ai-log-parser — Live Connector Verification")
    print("=" * 54)

    results = {
        "FileConnector":   await _verify_file_connector(),
        "SyslogConnector": await _verify_syslog_connector(),
        "S3Connector":     await _verify_s3_connector(),
    }

    print("\n" + "=" * 54)
    print("  Summary")
    print("=" * 54)
    all_passed = True
    for name, passed in results.items():
        status = PASS if passed else FAIL
        print(f"  {status}  {name}")
        if not passed:
            all_passed = False
    print("=" * 54)
    sys.exit(0 if all_passed else 1)


# ---------------------------------------------------------------------------
# Run command — parse logs from config
# ---------------------------------------------------------------------------

async def _run_pipeline(config_path: str | None) -> None:
    from ai_log_parser.config.loader import ConfigLoader
    from ai_log_parser.engine.preprocessor import LogPreprocessor
    from ai_log_parser.engine.parser import AIParseEngine
    from ai_log_parser.engine.queue import InProcessQueue

    if config_path:
        config = ConfigLoader(config_path).load()
    else:
        config = ConfigLoader.load_default()

    print(f"Loaded config: {config.source_path or 'default'}")
    print(f"Queue max size: {config.queue_max_size}")
    print(f"Connectors: {len(config.connectors)}")
    print("\nStarting pipeline — press Ctrl+C to stop.\n")

    queue        = InProcessQueue(config.queue_max_size)
    preprocessor = LogPreprocessor()
    engine       = AIParseEngine()
    processed    = 0

    try:
        while True:
            try:
                raw_line = await asyncio.wait_for(queue.get(), timeout=1.0)
                queue.task_done()
                hint  = preprocessor.detect(raw_line)
                event = await engine.parse(raw_line, hint)
                processed += 1
                status = "CONFIDENT" if not event.review_flag else "REVIEW"
                print(f"[{processed:04d}] {status:<10} "
                      f"format={hint.format:<15} "
                      f"confidence={event.confidence:.2f} "
                      f"src={event.src_ip or 'null'}")
            except asyncio.TimeoutError:
                continue
    except KeyboardInterrupt:
        print(f"\nStopped. Processed {processed} log lines.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ai-parser",
        description="AI-powered dynamic log parser for SOC pipelines.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # verify subcommand
    subparsers.add_parser(
        "verify",
        help="Run live connector verification against File, Syslog, and S3.",
    )

    # run subcommand
    run_parser = subparsers.add_parser(
        "run",
        help="Start the log parsing pipeline.",
    )
    run_parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to YAML config file (default: built-in default_config.yaml)",
    )

    args = parser.parse_args()

    if args.command == "verify":
        asyncio.run(_run_verify())
    elif args.command == "run":
        asyncio.run(_run_pipeline(args.config))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
