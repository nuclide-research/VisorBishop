#!/usr/bin/env python3
"""Build the cross-platform VisorBishop corpus for downstream consumers.

Walks the canonical per-platform VisorBishop output JSON files,
joins them to one or more Shodan-attribution TSVs (for org/country/
hostname enrichment), and emits a single platform-keyed JSON.

The output JSON is consumed by:
  * The /visorbishop/ dashboard on nuclide-research.com (Astro reads
    it as a build-time data dependency)
  * Disclosure-pipeline scripts that need (platform, target, org)
    tuples for outreach
  * Reporting / methodology writeups that need population stats

Configuration:
  VB_CORPUS_FILE       — path to a JSON config describing platforms +
                          their corpus files + attribution TSVs.
                          Default: corpus.json in this script's dir.
  VB_OUTPUT_PATH       — where to write the unified JSON.
                          Default: cross-platform.json in cwd.

The corpus.json shape is documented in scripts/README.md.
"""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).resolve().parent


def env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default)))


CORPUS_FILE = env_path("VB_CORPUS_FILE", SCRIPT_DIR / "corpus.json")
OUTPUT_PATH = env_path("VB_OUTPUT_PATH", Path("./cross-platform.json").resolve())


def load_attribution(attrib_paths):
    """ip:port -> (hostnames, org, country, isp), merged across attrib files.

    Also includes an ip-only fallback lookup keyed on the bare IP, so a
    finding at one port still gets country/org when the Shodan harvest
    has the same IP listed at a different port.
    """
    attrib = {}
    by_ip = {}
    for path in attrib_paths:
        p = Path(path).expanduser()
        if not p.exists():
            print(f"  attrib not found: {p}", file=sys.stderr)
            continue
        with p.open() as f:
            next(f, None)  # skip header
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 6:
                    continue
                ip, port, hostnames, org, country, isp = parts[:6]
                record = (hostnames, org, country, isp)
                attrib[f"{ip}:{port}"] = record
                by_ip.setdefault(ip, record)
    attrib["__by_ip__"] = by_ip
    return attrib


def ipport_from_target(t: str):
    u = urlparse(t)
    host = u.hostname or ""
    port = u.port
    if port is None:
        port = 443 if u.scheme == "https" else 80
    return f"{host}:{port}"


def extract_records(json_path: Path):
    if not json_path.exists():
        return
    try:
        data = json.loads(json_path.read_text())
    except Exception as e:
        print(f"  PARSE ERROR {json_path}: {e}", file=sys.stderr)
        return
    if not isinstance(data, list):
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target", "")
        body = (
            entry.get("platform") if isinstance(entry.get("platform"), dict) else entry
        )
        yield target, body


def main():
    if not CORPUS_FILE.exists():
        print(
            f"corpus config not found at {CORPUS_FILE}\n"
            "Create one (see scripts/README.md for the shape) or set "
            "VB_CORPUS_FILE to its path.",
            file=sys.stderr,
        )
        sys.exit(1)

    config = json.loads(CORPUS_FILE.read_text())
    platforms_cfg = config.get("platforms", {})
    attrib_paths = config.get("attribution_paths", [])
    iterations = config.get("iterations", len(set(p.get("iter") for p in platforms_cfg.values())))
    as_of = config.get("as_of", "")

    attrib = load_attribution(attrib_paths)
    out = {
        "as_of": as_of,
        "platforms": {},
        "totals": {
            "confirmed_total": 0,
            "critical_total": 0,
            "platforms": 0,
            "iterations": iterations,
        },
    }

    for key, meta in platforms_cfg.items():
        corpus_path = Path(meta["corpus"]).expanduser()
        rows = []
        confirmed = 0
        critical = 0
        protected = 0
        for target, body in extract_records(corpus_path):
            if not body or not isinstance(body, dict):
                continue
            is_confirmed = body.get("confirmed", False)
            severity = body.get("severity", "")
            auth = body.get("auth", "")
            if is_confirmed:
                confirmed += 1
            if severity == "critical":
                critical += 1
            if auth in ("protected", "auth"):
                protected += 1

            if is_confirmed:
                ipport = ipport_from_target(target)
                a = attrib.get(ipport)
                if not a:
                    bare_ip = ipport.split(":")[0]
                    a = attrib.get("__by_ip__", {}).get(bare_ip)
                ind = body.get("indicators") or {}
                mc = ind.get("model_count", 0)
                rows.append({
                    "target": target,
                    "v": body.get("version") or "",
                    "auth": auth,
                    "sev": severity,
                    "mc": mc,
                    "host": (a[0] if a else "")[:120],
                    "org": (a[1] if a else "")[:60],
                    "country": (a[2] if a else "") if a else "",
                })

        total_records = sum(1 for _ in extract_records(corpus_path))
        out["platforms"][key] = {
            "name": meta["name"],
            "category": meta["category"],
            "iter": meta["iter"],
            "shodan_dork": meta.get("shodan_dork", ""),
            "marker": meta.get("marker", ""),
            "total_probed": total_records,
            "confirmed": confirmed,
            "critical": critical,
            "auth_protected": protected,
            "rows": rows,
        }
        out["totals"]["confirmed_total"] += confirmed
        out["totals"]["critical_total"] += critical
        out["totals"]["platforms"] += 1

        print(
            f"{key:14s}  iter={meta.get('iter','?')}  "
            f"probed={total_records:5d}  confirmed={confirmed:4d}  "
            f"critical={critical:4d}",
            file=sys.stderr,
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(out, indent=2))
    print(
        f"\nwrote {OUTPUT_PATH}\n"
        f"totals: {out['totals']['confirmed_total']} confirmed, "
        f"{out['totals']['critical_total']} critical across "
        f"{out['totals']['platforms']} platforms",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
