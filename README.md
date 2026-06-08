<h1 align="center">VisorBishop</h1>

<h4 align="center">Meta-fingerprinter for the AI observability tier.</h4>

<p align="center">
  <a href="https://github.com/nuclide-research/VisorBishop/releases"><img src="https://img.shields.io/github/v/release/nuclide-research/VisorBishop?style=flat-square" alt="release"></a>
  <a href="https://github.com/nuclide-research/VisorBishop/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/VisorBishop?style=flat-square" alt="license"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.21%2B-00ADD8?style=flat-square&logo=go" alt="go"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#platforms">Platforms</a> •
  <a href="#ip-direct-shadow">IP-shadow</a> •
  <a href="#scope">Scope</a>
</p>

---

VisorBishop walks a list of HTTP(S) targets, identifies which AI observability platform each one runs, extracts version and auth-posture signals, and optionally sweeps the host IP for co-located unauthenticated services. Single Go binary, read-only probes, JSON and CSV output for downstream tooling.

Built as the deliverable for [Phase 3 of the NuClide AI observability sweep](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/SYNTHESIS-ai-observability-2026-05-10.md). Each platform fingerprint is grounded in a published case study. No credential testing, no payload fuzzing, no destructive operations.

# Features

- 19 platform fingerprints across LLM observability, agent platforms, ML lifecycle tools, and feature flags
- Five-value AuthState: `unauth_confirmed`, `auth_confirmed`, `auth_inferred`, `unknown`, `error`
- Optional IP-direct-shadow probe: 27 co-located service ports per platform IP
- Concurrent probing with per-probe timeout
- Output: terminal (severity-sorted), JSON (structured), CSV (flat per-host)
- Single static Go binary, no runtime dependencies
- Read-only HTTP GETs. No POSTs to login forms, no credential testing

# Installation

```bash
go install -v github.com/nuclide-research/VisorBishop/cmd/visorbishop@latest
```

Or build from source:

```bash
git clone https://github.com/nuclide-research/VisorBishop
cd VisorBishop
go build -o bin/visorbishop ./cmd/visorbishop
```

Requires Go 1.21 or later.

# Usage

```console
# single target
./bin/visorbishop -t http://example.com:6006

# batch from file (one URL per line, optional tab-separated hostname)
./bin/visorbishop -i targets.txt -c 16 -timeout 8s

# add IP-direct-shadow probe on every confirmed platform IP
./bin/visorbishop -i targets.txt -ip-shadow

# force IP-shadow on every IP, even non-platform matches
./bin/visorbishop -i targets.txt -ip-shadow-all

# emit JSON + CSV in addition to terminal text
./bin/visorbishop -i targets.txt -json out.json -csv out.csv
```

<details>
  <summary>Flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `-i <file>` | | Input file, one URL per line. Use `-` for stdin |
| `-t <url>` | | Single target URL |
| `-c <n>` | 16 | Concurrent probes |
| `-timeout <duration>` | 8s | Per-probe timeout |
| `-ip-shadow` | false | Sweep 27 co-located ports on each confirmed platform IP |
| `-ip-shadow-all` | false | Run IP-shadow on every target |
| `-json <file>` | | Write JSON report |
| `-csv <file>` | | Write CSV summary |
| `-q` | false | Quiet mode |
| `-version` | | Print version and exit |

</details>

# Platforms

19 fingerprints across the AI observability and lifecycle tier:

| Platform | Signal | Severity |
|----------|--------|----------|
| Arize AI Phoenix | unauth GraphQL `/graphql` returning project list (`PHOENIX_ENABLE_AUTH=False` default) | CRITICAL |
| LangSmith | unauth `/api/v1/info` disclosing customer name, git SHA, license expiry | HIGH |
| Langfuse | platform + version + auth verification on `/api/public/projects` | INFO (CRITICAL if unauth) |
| Helicone | platform detection + co-located unauth ClickHouse via IP-shadow | HIGH |
| OpenLIT, Lunary, Pezzo | platform detection + auth verification | INFO |
| MLflow, Kubeflow, W&B | ML lifecycle exposure | varies |
| Airflow, Prefect, Argilla | workflow + agent memory | varies |
| LiteLLM, OpenWebUI, Dify, Langflow, AgentOps, Opik | gateway + agent observability | varies |
| Promptfoo, PostHog | eval + product analytics | varies |

Full case-study grounding per file in `internal/fingerprint/`.

# IP-direct-shadow

When `-ip-shadow` is enabled, VisorBishop probes 27 ports per platform IP for co-located unauthenticated services. Anchored to [Methodology Insight #12](https://github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT/blob/main/methodology/insight-12-ip-direct-shadow.md):

```
111   rpcbind / portmapper       8025  MailHog
1080  MailCatcher / SOCKS         8086  InfluxDB
2049  NFS                         8123  ClickHouse
3306  MySQL                       8501  Streamlit
4222  NATS                        9000  MinIO API
5000  MLflow                      9090  Prometheus
5044  Logstash                    9092  Kafka
5432  PostgreSQL                  9093  AlertManager
5601  Kibana                      9100  node_exporter
5672  RabbitMQ                    9200  Elasticsearch
6333  Qdrant                      11211 Memcached
6379  Redis (AUTH check)          19530 Milvus
7860  Gradio                      27017 MongoDB
8000  ChromaDB
```

Per port, the probe is non-destructive:

- TCP-only ports: SYN+RST handshake to confirm open
- HTTP ports: GET on the documented health or info path
- Redis: `INFO server` command (returns `-NOAUTH` if auth is enabled)
- ClickHouse: `SELECT 1` only after `/ping` returns `Ok.`

No credential testing. No data extraction.

# Example: one Phoenix with the full chain

```
$ ./bin/visorbishop -t http://190.210.105.193:6006 -ip-shadow -timeout 10s

[CRITICAL] http://190.210.105.193:6006 - arize-phoenix v8.6.0
    note: GraphQL /graphql returns project list without auth (default-no-auth)
    note: IP-shadow: unauth mailcatcher on :1080
    note: IP-shadow: unauth prometheus on :9090
    shadow: mailcatcher on :1080 - MailCatcher (unauth)
    shadow: prometheus on :9090 - Prometheus (unauth)
```

JSON output for this target includes `project_names`, `total_tokens`, and the full shadow-port enumeration with banner data.

# Output formats

**Terminal (default).** Severity-sorted list of CRITICAL and HIGH findings with platform, version, customer info (if disclosed), and shadow findings inline.

**JSON.** Full structured output per host with `platform` and `ip_shadow_findings` arrays. Suitable for downstream tooling and VisorLog ingestion.

**CSV.** Flat per-host summary: target, platform, confirmed, version, auth state, severity, customer name, license expiry, shadow_unauth_count, notes.

# Scope

VisorBishop makes read-only HTTP GETs and TCP connections. It does not authenticate, POST to login forms, fuzz parameters, or modify anything on the target. Only run it against infrastructure you own or have explicit written authorization to assess.

# Our other projects

- [aimap](https://github.com/nuclide-research/aimap) — AI/ML infrastructure fingerprint scanner (broader category coverage)
- [VisorLog](https://github.com/nuclide-research/visorlog) — findings ledger, accepts VisorBishop JSON
- [VisorScuba](https://github.com/nuclide-research/VisorScuba) — OPA compliance scoring over VisorLog
- [VisorGraph](https://github.com/nuclide-research/VisorGraph) — cert-pivot recon engine
- [scanner](https://github.com/nuclide-research/scanner) — fast active-banner stage

# License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
