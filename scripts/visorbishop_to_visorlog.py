#!/usr/bin/env python3
"""Convert a VisorBishop cross-platform corpus to VisorLog NDJSON events.

Reads the platform-keyed JSON emitted by build_cross_platform_corpus.py,
and emits one VisorLog Event per confirmed VisorBishop row. Pipe the
output into `visorlog ingest --dedup` to populate the ledger.

Each confirmed VisorBishop finding becomes one event with:
  * event.category = "discovery"
  * event.severity = mapped from VisorBishop severity (critical, high,
    info, low)
  * host.ip + host.hostname + org.name + org.country
  * nuclide.source = "visorbishop"
  * nuclide.tags = ["AI-LLM", "<platform-key>", ...]
  * notes includes "platform=<key> · target=<url>" for VisorLog's
    (source, notes) dedup key
  * raw carries the platform metadata for downstream consumers

Configuration:
  VB_CORPUS_OUTPUT  — path to the cross-platform JSON produced by
                       build_cross_platform_corpus.py
                       Default: ./cross-platform.json

Usage:
  python3 visorbishop_to_visorlog.py | visorlog ingest --dedup
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


CORPUS_PATH = Path(
    os.environ.get("VB_CORPUS_OUTPUT", "./cross-platform.json")
).expanduser().resolve()


def ipport_from_target(t: str):
    u = urlparse(t)
    host = u.hostname or ""
    port = u.port
    if port is None:
        port = 443 if u.scheme == "https" else 80
    return host, port


def severity_map(sev: str, auth: str) -> str:
    """Map VisorBishop severity → VisorLog severity."""
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if auth == "unauth":
        return "high"
    if auth in ("protected", "auth"):
        return "info"
    return "low"


def main():
    if not CORPUS_PATH.exists():
        print(
            f"corpus not found at {CORPUS_PATH}\n"
            "Run build_cross_platform_corpus.py first, or set "
            "VB_CORPUS_OUTPUT to its output path.",
            file=sys.stderr,
        )
        sys.exit(1)

    corpus = json.loads(CORPUS_PATH.read_text())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    emitted = 0

    for plat_key, plat in corpus.get("platforms", {}).items():
        for row in plat.get("rows", []):
            target = row.get("target", "")
            ip, port = ipport_from_target(target)
            if not ip:
                continue

            severity = severity_map(row.get("sev", ""), row.get("auth", ""))

            tags = ["AI-LLM", plat_key]
            if row.get("sev") == "critical":
                tags.append("LLMJACKING" if plat_key == "litellm" else "UNAUTH-CRITICAL")
            if row.get("auth") == "unauth":
                tags.append("UNAUTH")

            hostnames = row.get("host", "")
            hostname = hostnames.split(";")[0] if hostnames else ""

            notes_parts = [f"platform={plat_key}"]
            if row.get("v"):
                notes_parts.append(f"version={row['v']}")
            if row.get("mc"):
                notes_parts.append(f"models={row['mc']}")
            notes_parts.append(f"target={target}")
            notes = " · ".join(notes_parts)

            event = {
                "timestamp": now,
                "event.category": "discovery",
                "event.type": "created",
                "event.severity": severity,
                "host.ip": ip,
                "host.hostname": hostname,
                "org.name": row.get("org", ""),
                "org.country": row.get("country", ""),
                "nuclide.sector": "commercial",
                "nuclide.source": "visorbishop",
                "nuclide.tags": tags,
                "lifecycle.status": "open",
                "notes": notes,
                "raw": {
                    "platform": plat.get("name"),
                    "platform_key": plat_key,
                    "target": target,
                    "port": port,
                    "version": row.get("v", ""),
                    "auth_state": row.get("auth", ""),
                    "severity_visorbishop": row.get("sev", ""),
                    "model_count": row.get("mc", 0),
                },
            }
            sys.stdout.write(json.dumps(event) + "\n")
            emitted += 1

    sys.stderr.write(f"emitted {emitted} VisorLog events\n")


if __name__ == "__main__":
    main()
