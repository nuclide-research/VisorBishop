#!/usr/bin/env python3
"""Refresh the cross-platform corpus JSON from the VisorLog ledger.

After VisorBishop ingests new findings into VisorLog via
visorbishop_to_visorlog.py, this script queries VisorLog for all
visorbishop-sourced events and rebuilds the cross-platform JSON from
the ledger state.

The advantage over re-reading the raw VisorBishop JSON: lifecycle
transitions (open → disclosed → remediated → verified) show up in
the dashboard on the next refresh, because the ledger is the source
of truth for finding state across multiple ingestions.

Configuration:
  VB_VISORLOG_BIN    — path to the visorlog binary
                        Default: visorlog (must be on PATH)
  VB_VISORLOG_DB     — path to the VisorLog SQLite DB
                        Default: ./visorlog.db
  VB_OUTPUT_PATH     — where to write the refreshed JSON
                        Default: ./cross-platform.json
  VB_PUBLIC_PATH     — optional second copy (e.g. site/public/)
                        Default: unset (no second copy)
  VB_CORPUS_FILE     — path to the corpus config (used for
                        platform metadata + total_probed preservation)
                        Default: corpus.json in this script's dir

Usage:
  python3 refresh_dashboard_from_visorlog.py
"""
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

VISORLOG = os.environ.get("VB_VISORLOG_BIN", "visorlog")
DB_PATH = Path(os.environ.get("VB_VISORLOG_DB", "./visorlog.db")).expanduser().resolve()
OUT_PATH = Path(os.environ.get("VB_OUTPUT_PATH", "./cross-platform.json")).expanduser().resolve()
PUBLIC_PATH = os.environ.get("VB_PUBLIC_PATH")
CORPUS_FILE = Path(os.environ.get("VB_CORPUS_FILE", SCRIPT_DIR / "corpus.json"))


def query_visorlog():
    """Query VisorLog for all visorbishop-sourced events."""
    cmd = [
        VISORLOG, "--db", str(DB_PATH),
        "query", "--source", "visorbishop",
        "--json", "--limit", "20000",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def load_platform_meta():
    """Load the static platform metadata from corpus.json."""
    if not CORPUS_FILE.exists():
        print(
            f"corpus config not found at {CORPUS_FILE}\n"
            "refresh_dashboard_from_visorlog.py needs the same corpus "
            "config that build_cross_platform_corpus.py uses, to carry "
            "category / iter / shodan_dork metadata that's not stored "
            "in VisorLog.",
            file=sys.stderr,
        )
        sys.exit(1)
    return json.loads(CORPUS_FILE.read_text())


def main():
    config = load_platform_meta()
    platforms_meta = config.get("platforms", {})
    iterations = config.get("iterations", 0)
    as_of = config.get("as_of", "")

    events = query_visorlog()
    print(
        f"loaded {len(events)} visorbishop events from VisorLog",
        file=sys.stderr,
    )

    by_platform = defaultdict(list)
    for ev in events:
        raw = ev.get("raw") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {}
        platform_key = raw.get("platform_key") or "unknown"
        by_platform[platform_key].append({"ev": ev, "raw": raw})

    out = {
        "as_of": as_of,
        "platforms": {},
        "totals": {
            "confirmed_total": 0,
            "critical_total": 0,
            "platforms": 0,
            "iterations": iterations,
        },
        "source": "visorlog-feed",
        "ledger_event_count": len(events),
    }

    # Preserve total_probed from the prior corpus output (the ledger
    # only stores confirmed events; probed counts come from the
    # original VisorBishop sweep)
    prior_corpus = {}
    if OUT_PATH.exists():
        try:
            prior_corpus = json.loads(OUT_PATH.read_text()).get("platforms", {})
        except Exception:
            pass

    for key, meta in platforms_meta.items():
        bucket = by_platform.get(key, [])
        rows = []
        confirmed = 0
        critical = 0
        protected = 0

        for item in bucket:
            ev = item["ev"]
            raw = item["raw"]
            sev = raw.get("severity_visorbishop", "")
            auth = raw.get("auth_state", "")
            confirmed += 1
            if sev == "critical":
                critical += 1
            if auth in ("protected", "auth"):
                protected += 1

            rows.append({
                "target": raw.get("target", ""),
                "v": raw.get("version", ""),
                "auth": auth,
                "sev": sev,
                "mc": raw.get("model_count", 0),
                "host": ev.get("host.hostname", ""),
                "org": ev.get("org.name", ""),
                "country": ev.get("org.country", ""),
                "lifecycle": ev.get("lifecycle.status", "open"),
            })

        prior_probed = prior_corpus.get(key, {}).get("total_probed")
        total_probed = prior_probed if prior_probed is not None else confirmed

        out["platforms"][key] = {
            "name": meta["name"],
            "category": meta["category"],
            "iter": meta["iter"],
            "shodan_dork": meta.get("shodan_dork", ""),
            "marker": meta.get("marker", ""),
            "total_probed": total_probed,
            "confirmed": confirmed,
            "critical": critical,
            "auth_protected": protected,
            "rows": rows,
        }
        out["totals"]["confirmed_total"] += confirmed
        out["totals"]["critical_total"] += critical
        out["totals"]["platforms"] += 1

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2))
    if PUBLIC_PATH:
        pub = Path(PUBLIC_PATH).expanduser().resolve()
        pub.parent.mkdir(parents=True, exist_ok=True)
        pub.write_text(OUT_PATH.read_text())

    print(
        f"wrote {OUT_PATH} "
        f"({'+ ' + str(Path(PUBLIC_PATH).expanduser().resolve()) if PUBLIC_PATH else ''}):\n"
        f"  {out['totals']['confirmed_total']} confirmed, "
        f"{out['totals']['critical_total']} critical across "
        f"{out['totals']['platforms']} platforms",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
