# VisorBishop

Meta-fingerprinter for the AI observability tier. Walks a list of HTTP(S)
targets, identifies which observability platform each runs (Phoenix,
Langfuse, Helicone, LangSmith, Lunary, OpenLIT, Pezzo), extracts version
and auth-posture signals, and optionally probes the host IP for
co-located unauthenticated services.

Built by [NuClide Research](https://nuclide-research.com) as the
deliverable for [Phase 3 of the cross-platform AI observability sweep][synth].

Read-only by design. No credential testing, no payload fuzzing, no
destructive operations.

[synth]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/SYNTHESIS-ai-observability-2026-05-10.md

## What it catches

| Platform | Signal | Severity |
|---|---|---|
| Arize AI Phoenix | unauth GraphQL `/graphql` returning project list (`PHOENIX_ENABLE_AUTH=False` default) | **CRITICAL** |
| LangSmith | unauth `/api/v1/info` disclosing customer name + git SHA + license expiry | **HIGH** |
| Langfuse | platform detection + version + auth verification on `/api/public/projects` | INFO (unless unauth, then CRITICAL) |
| Helicone | platform detection + co-located unauth ClickHouse via IP-shadow | HIGH |
| OpenLIT, Lunary, Pezzo | platform detection + auth verification | INFO |
| IP-direct-shadow (any host) | unauth Prometheus, MailHog, MailCatcher, Kibana, Elasticsearch, ClickHouse, Redis | **CRITICAL/HIGH** when actualized |

## Build

```bash
go build -o bin/visorbishop ./cmd/visorbishop
```

## Use

```bash
# Single target
./bin/visorbishop -t http://example.com:6006

# Batch from file (one URL per line, optional tab-separated hostname)
./bin/visorbishop -i targets.txt -c 16 -timeout 8s

# Add IP-direct-shadow probe on every confirmed platform IP
./bin/visorbishop -i targets.txt -ip-shadow

# Force IP-shadow on every IP, even those that didn't match a platform
./bin/visorbishop -i targets.txt -ip-shadow-all

# Emit JSON + CSV in addition to terminal text
./bin/visorbishop -i targets.txt -json out.json -csv out.csv
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-i <file>` | — | Input file with one URL per line. Use `-` for stdin. |
| `-t <url>` | — | Single target URL (alternative to `-i`). |
| `-c <n>` | 16 | Concurrent probes. |
| `-timeout <duration>` | 8s | Per-probe timeout. |
| `-ip-shadow` | false | Run IP-direct-shadow port sweep on each confirmed platform IP. |
| `-ip-shadow-all` | false | Run IP-shadow on every target (even non-platform-confirmed). |
| `-json <file>` | — | Write JSON report. |
| `-csv <file>` | — | Write CSV summary. |
| `-q` | false | Quiet mode (no per-target progress). |
| `-version` | — | Print version and exit. |

## IP-direct-shadow ports

When `-ip-shadow` is enabled, VisorBishop probes 15 ports per platform IP
for co-located unauthenticated services. Per [Methodology Insight #12][m12]:

```
111   rpcbind / portmapper
1080  MailCatcher (Ruby thin server) / SOCKS
2049  NFS (announces exports via showmount -e)
3306  MySQL
5432  PostgreSQL
5601  Kibana
6379  Redis (AUTH check)
8025  MailHog (/api/v2/messages)
8086  InfluxDB
8123  ClickHouse (default user / no-password check)
9090  Prometheus (/api/v1/query?query=up)
9093  AlertManager (/-/healthy)
9100  Prometheus node_exporter (/metrics)
9200  Elasticsearch (/)
27017 MongoDB
```

For each port, the probe is non-destructive:
- TCP-only ports: SYN+RST handshake to confirm open
- HTTP ports: GET on the documented health/info path
- Redis: `INFO server` command (returns `-NOAUTH` if auth is enabled)
- ClickHouse: `SELECT 1` only after `/ping` returns `Ok.`

No credential testing. No data extraction.

[m12]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/methodology/insight-12-ip-direct-shadow.md

## Output formats

### Terminal (default)

Severity-sorted list of CRITICAL + HIGH findings with platform, version,
customer info (if disclosed), and shadow findings inline.

### JSON

Full structured output per host with `platform` and `ip_shadow_findings`
arrays. Suitable for downstream tooling and VisorLog ingestion.

### CSV

Flat per-host summary: target, platform, confirmed, version, auth state,
severity, customer name, license expiry, shadow_unauth_count, notes.

## Example: one Phoenix instance with the full chain

```
$ ./bin/visorbishop -t http://190.210.105.193:6006 -ip-shadow -timeout 10s

[CRITICAL] http://190.210.105.193:6006 — arize-phoenix v8.6.0
    note: GraphQL /graphql returns project list without auth (default-no-auth)
    note: IP-shadow: unauth mailcatcher on :1080
    note: IP-shadow: unauth prometheus on :9090
    shadow: mailcatcher on :1080 — MailCatcher (unauth)
    shadow: prometheus on :9090 — Prometheus (unauth)
```

The JSON output for this target includes `project_names`,
`total_tokens`, and the full shadow-port enumeration with banner data.

## Provenance

Built from research in the 2026-05-10 AI observability cross-platform
sweep. Each platform's fingerprint logic is grounded in a specific
case study in [AI-LLM-Infrastructure-OSINT][osint]:

- `phoenix.go` ← [phoenix-llm-observability-survey][p1] + [Phase 2 deep-dive][p2]
- `langsmith.go` ← [LangSmith Phase 1][ls1] + [Phase 2 deep-dive][ls2]
- `langfuse.go` ← [Langfuse Phase 1][lf1] + [Phase 2 deep-dive][lf2]
- `helicone.go` ← [Helicone Phase 1][h1] + [Phase 2 deep-dive][h2]
- `openlit.go`, `lunary.go`, `pezzo.go` ← [small-platforms survey][sm]

[osint]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT
[p1]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/phoenix-llm-observability-survey-2026-05-10.md
[p2]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/AR-reputacion-digital-multi-surface-2026-05-10.md
[ls1]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/langsmith-llm-observability-survey-2026-05-10.md
[ls2]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/langsmith-deep-dive-survey-2026-05-10.md
[lf1]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/langfuse-llm-observability-survey-2026-05-10.md
[lf2]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/langfuse-deep-dive-survey-2026-05-10.md
[h1]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/helicone-llm-observability-survey-2026-05-10.md
[h2]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/helicone-deep-dive-survey-2026-05-10.md
[sm]: https://github.com/nuclide-research/AI-LLM-Infrastructure-OSINT/blob/main/case-studies/commercial/observability-tier-small-platforms-survey-2026-05-10.md

## License

MIT.

## Disclaimer

VisorBishop characterizes publicly-reachable services. Use only on
infrastructure you are authorized to assess. Read-only by design.
