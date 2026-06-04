# VisorBishop

Meta-fingerprinter for the AI observability tier.

VisorBishop walks a list of HTTP(S) targets, identifies which of 20 observability
platforms each runs, captures version and auth-posture signals, and optionally
sweeps the host IP for co-located unauthenticated services on 27 ports. Output
is terminal text, JSON, and CSV. Each host report carries a five-value AuthState
(`unauth`, `auth`, `info-leak`, `mixed`, `unknown`) and a severity verdict
(`critical` through `none`). JSON output feeds VisorLog ingest directly.

Read-only by design. No credential testing, no payload fuzzing, no destructive
operations.

## Install

```bash
git clone https://github.com/nuclide-research/VisorBishop
cd VisorBishop
go build -o bin/visorbishop ./cmd/visorbishop
```

Go 1.22 or later.

## Usage

```bash
# Single target
./bin/visorbishop -t http://example.com:6006

# Batch from file (one URL per line; optional tab-separated hostname for SNI)
./bin/visorbishop -i targets.txt -c 16 -timeout 8s

# IP-direct-shadow on every confirmed platform IP
./bin/visorbishop -i targets.txt -ip-shadow

# IP-shadow on every target even if no platform matched
./bin/visorbishop -i targets.txt -ip-shadow-all

# Emit JSON and CSV in addition to terminal text
./bin/visorbishop -i targets.txt -json out.json -csv out.csv
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-i <file>` | | Input file, one URL per line. Use `-` for stdin. |
| `-t <url>` | | Single target URL (alternative to `-i`). |
| `-c <n>` | `16` | Concurrent probes. |
| `-timeout <duration>` | `8s` | Per-probe timeout. |
| `-ip-shadow` | `false` | Run IP-direct-shadow sweep on each confirmed platform IP. |
| `-ip-shadow-all` | `false` | Run IP-shadow on every target, confirmed or not. |
| `-json <file>` | | Write JSON report. |
| `-csv <file>` | | Write CSV summary. |
| `-q` | `false` | Quiet mode: suppress per-target progress lines. |
| `-version` | | Print version and exit. |

## Platforms fingerprinted (20)

| Platform | Canonical ID |
|---|---|
| Arize AI Phoenix | `arize-phoenix` |
| Langfuse | `langfuse` |
| Helicone | `helicone` |
| LangSmith | `langsmith` |
| Lunary | `lunary` |
| OpenLIT | `openlit` |
| Pezzo | `pezzo` |
| Comet Opik | `comet-opik` |
| AgentOps | `agentops` |
| LiteLLM | `litellm` |
| Argilla | `argilla` |
| Promptfoo | `promptfoo` |
| MLflow | `mlflow` |
| Weights & Biases | `wandb` |
| Comet ML | `comet-ml` |
| Langflow | `langflow` |
| Dify | `dify` |
| Kubeflow | `kubeflow` |
| PostHog | `posthog` |
| Prefect | `prefect` |
| Airflow | `airflow` |

## Auth states

Each Finding carries one of five AuthState values:

| Value | Meaning |
|---|---|
| `unauth` | Primary API reachable without credentials |
| `auth` | 401/403 on the protected route |
| `info-leak` | Unauth-readable info endpoint; data routes protected |
| `mixed` | Some routes open, some gated |
| `unknown` | Probe failed or inconclusive |

## Output formats

### Terminal

Severity-sorted list of CRITICAL + HIGH findings with platform, version,
customer info if disclosed, and shadow findings inline.

### JSON (`-json`)

Array of `HostReport` objects. Each carries:

```json
{
  "target": "http://1.2.3.4:6006",
  "platform": {
    "target": "...",
    "platform": "arize-phoenix",
    "confirmed": true,
    "version": "8.6.0",
    "auth": "unauth",
    "severity": "critical",
    "indicators": { "customer_name": "..." },
    "notes": ["..."],
    "latency_ms": 84
  },
  "ip_shadow_findings": [
    {
      "ip": "1.2.3.4",
      "port": 9090,
      "service": "prometheus",
      "open": true,
      "confirmed": "Prometheus (unauth)",
      "unauth": true,
      "banner": "...",
      "notes": ["..."]
    }
  ]
}
```

### CSV (`-csv`)

One row per host: `target`, `platform`, `confirmed`, `version`, `auth`,
`severity`, `customer`, `license_expiry`, `shadow_unauth_count`, `notes`.

## IP-direct-shadow ports (27)

When `-ip-shadow` or `-ip-shadow-all` is active, VisorBishop probes 27 ports
per host concurrently:

```
111   rpcbind
1080  mailcatcher
2049  nfs
3306  mysql
4222  nats
5000  mlflow
5044  logstash
5432  postgresql
5601  kibana
5672  rabbitmq
6333  qdrant
6379  redis
7860  gradio
8000  chromadb
8025  mailhog
8086  influxdb
8123  clickhouse
8501  streamlit
9000  minio_api
9090  prometheus
9092  kafka
9093  alertmanager
9100  node_exporter
9200  elasticsearch
11211 memcached
19530 milvus
27017 mongodb
```

For HTTP-capable ports the probe hits the service's documented health/info
path. Redis probes with `INFO server`. NATS reads the server INFO frame.
Memcached sends `version\r\n`. TCP-only ports get a connect-and-close.
No credentials, no data extraction.

## Example

```
$ ./bin/visorbishop -t http://190.210.105.193:6006 -ip-shadow -timeout 10s

VisorBishop 0.1.7 — 1 targets, concurrency=16, timeout=10s
IP-direct-shadow enabled (27 ports per host)
  [critical] http://190.210.105.193:6006 — arize-phoenix v8.6.0

VisorBishop scan complete: 1 targets

PLATFORM DISTRIBUTION
  arize-phoenix      1

SEVERITY DISTRIBUTION
  critical           1

CRITICAL + HIGH FINDINGS (1)
======================================================================
[CRITICAL] http://190.210.105.193:6006 — arize-phoenix v8.6.0
    note: GraphQL /graphql returns project list without auth (default-no-auth)
    note: IP-shadow: unauth mailcatcher on :1080
    note: IP-shadow: unauth prometheus on :9090
    shadow: mailcatcher on :1080 — MailCatcher (unauth)
    shadow: prometheus on :9090 — Prometheus (unauth)
```

Example is built from source format strings. The tool emits em dashes in its
terminal output; they appear above exactly as the code prints them.

## Extension

Each platform fingerprint lives in `internal/fingerprint/<platform>.go` and
implements the `Prober` interface (`ID()` + `Probe()`). Add a new platform by
creating one file and appending a `Prober` instance to the slice in
`cmd/visorbishop/main.go`.

## What VisorBishop is not

VisorBishop does not test credentials, fuzz inputs, or exploit findings. It
characterizes what is publicly reachable. Use only on infrastructure you are
authorized to assess.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
