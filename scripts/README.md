# VisorBishop pipeline scripts

Glue that takes raw VisorBishop sweep output and produces a unified
cross-platform corpus, ingests findings into VisorLog for lifecycle
tracking, and refreshes a downstream dashboard JSON from the ledger.

This directory is **operator-tooling**, separate from the VisorBishop
binary itself. The binary in `cmd/visorbishop/` produces per-sweep JSON
output; these scripts aggregate, persist, and refresh it across many
sweeps.

## The pipeline

```
[raw VisorBishop sweep JSON × N platforms]
            ↓
   build_cross_platform_corpus.py    # aggregate + attribution join
            ↓
   [cross-platform.json]
            ↓
   visorbishop_to_visorlog.py        # emit NDJSON events
            ↓
   visorlog ingest --dedup           # populate lifecycle-tracked ledger
            ↓
   refresh_dashboard_from_visorlog.py  # ledger → dashboard JSON
            ↓
   [cross-platform.json (refreshed, ledger-derived)]
            ↓
   (downstream: Astro site, disclosure pipeline, reports)
```

The wrapper `pipeline.sh` runs all three stages with shared env vars.

## Quick start

1. Copy `corpus.example.json` to `corpus.json` and edit the paths to
   point at your local VisorBishop sweep outputs and Shodan
   attribution TSVs:

   ```bash
   cp corpus.example.json corpus.json
   $EDITOR corpus.json
   ```

2. Run the pipeline (no rebuild):

   ```bash
   ./pipeline.sh
   ```

3. Optional — wire a downstream build (e.g. Astro static site) and a
   push step:

   ```bash
   export VB_BUILD_CMD='npm run build'
   export VB_BUILD_DIR=~/site
   export VB_PUSH_CMD='git -C ~/site push origin main'
   ./pipeline.sh --rebuild --push
   ```

## corpus.json shape

```json
{
  "as_of": "2026-05-11",
  "iterations": 7,
  "attribution_paths": [
    "/path/to/litellm-attribution.tsv",
    "/path/to/phoenix-attribution.tsv"
  ],
  "platforms": {
    "litellm": {
      "name": "LiteLLM Proxy",
      "category": "gateway",
      "iter": 6,
      "shodan_dork": "http.title:\"LiteLLM API\"",
      "corpus": "/path/to/iter6/litellm-full.json",
      "marker": "SPA title + /.well-known/litellm-ui-config"
    },
    ...
  }
}
```

Each platform entry needs:

| Field | Required | Notes |
|---|---|---|
| `name` | yes | Human-readable platform name |
| `category` | yes | Free-form category for grouping (e.g. observability / gateway / experiment-tracking) |
| `iter` | yes | Research iteration number this platform was added in |
| `corpus` | yes | Path to the VisorBishop JSON output for this platform's sweep |
| `shodan_dork` | no | Reference dork used to harvest the population |
| `marker` | no | Detection marker description for documentation |

`corpus` paths support `~` expansion.

## Attribution TSV format

Each TSV in `attribution_paths` is the Shodan harvest dump with one
record per `ip:port`:

```
ip	port	hostnames	org	country	isp
1.2.3.4	443	example.com	Hetzner	DE	Hetzner Online GmbH
```

The scripts merge all listed TSVs into a single lookup. When a
finding's `ip:port` isn't in any TSV, the scripts fall back to an
ip-only lookup so that a host probed at one port can be attributed
from a Shodan record at a different port.

## Environment variables

| Var | Default | Used by |
|---|---|---|
| `VB_CORPUS_FILE` | `./corpus.json` (relative to script dir) | build, refresh |
| `VB_OUTPUT_PATH` | `./cross-platform.json` | build, refresh |
| `VB_CORPUS_OUTPUT` | `./cross-platform.json` | visorbishop_to_visorlog |
| `VB_PUBLIC_PATH` | (unset) | refresh — optional second copy |
| `VB_VISORLOG_BIN` | `visorlog` (on PATH) | refresh, pipeline.sh |
| `VB_VISORLOG_DB` | `./visorlog.db` | refresh, pipeline.sh |
| `VB_BUILD_CMD` | (unset) | pipeline.sh `--rebuild` |
| `VB_BUILD_DIR` | (cwd) | pipeline.sh `--rebuild` |
| `VB_PUSH_CMD` | `git push origin main` | pipeline.sh `--push` |

## Why round-trip through VisorLog

The direct path (sweep JSON → dashboard JSON) is simpler and faster.
The ledger path enables three capabilities:

1. **Lifecycle reflection** — when a finding moves to `disclosed`,
   `acknowledged`, or `remediated`, the next dashboard refresh
   reflects it.
2. **Multi-tool unification** — VisorBishop findings share the same
   ledger as VisorGoose, aimap, ollama-recon. Disclosures can target
   any tool's findings uniformly.
3. **Persistent state** — the ledger survives losing the original
   sweep JSON. The dashboard can be regenerated from the ledger.

For pure exposure inventory (no lifecycle work), the direct path
suffices. For a public dashboard that tracks remediation over time,
the ledger path is the right architecture.

## Idempotency

VisorLog's `ingest --dedup` keys on `(source, notes)`. The
`visorbishop_to_visorlog.py` script writes
`platform=<key> · target=<url>` into `notes`, so the same finding
ingested twice produces no duplicate ledger entry.

The full pipeline is idempotent: running `./pipeline.sh` twice in a
row produces no new events and no dashboard changes.

## Debugging

```bash
# Inspect how many visorbishop events are in the ledger
sqlite3 "$VB_VISORLOG_DB" \
  "SELECT COUNT(*) FROM events WHERE source = 'visorbishop'"

# Wipe and start fresh
sqlite3 "$VB_VISORLOG_DB" \
  "DELETE FROM events WHERE source = 'visorbishop'"
./pipeline.sh

# Verify dashboard JSON matches ledger state
python3 -c "
import json, sys, os
d = json.load(open(os.environ['VB_OUTPUT_PATH']))
print('confirmed:', d['totals']['confirmed_total'])
print('critical :', d['totals']['critical_total'])
print('source   :', d.get('source', 'static'))
"
```
