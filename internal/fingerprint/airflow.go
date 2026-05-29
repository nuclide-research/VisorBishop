package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nuclide-research/VisorBishop/internal/probe"
)

// AirflowProber detects Apache Airflow self-hosted instances.
//
// Airflow is a Python workflow scheduler used heavily for ML pipelines.
// The web UI defaults to authentication-required in modern releases
// (3.x), but older 2.x deployments and DEV-mode installs are
// commonly exposed without auth. CRITICAL when the REST API
// /api/v1/dags or /api/v2/dags returns the DAG list unauth.
//
// CVE-2024-39877 (Airflow CLI auth bypass) and other auth-related
// CVEs make exposed Airflow instances high-priority targets.
//
// Reference: github.com/apache/airflow
type AirflowProber struct{}

func (p AirflowProber) ID() Platform { return Airflow }

func (p AirflowProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Airflow,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm via SPA root with Airflow-specific marker
	// (title "Airflow" + the static asset path or pin_32.png favicon)
	ru := probe.Get(ctx, client, target+"/", hostname, 8192)
	f.LatencyMS = ru.LatencyMS
	if ru.Err != nil {
		return f
	}
	body := string(ru.Body)
	airflowSPA := strings.Contains(body, "<title>Airflow</title>") &&
		(strings.Contains(body, "pin_32.png") ||
			strings.Contains(body, "/static/assets/index-") ||
			strings.Contains(body, "airflow_logo") ||
			strings.Contains(body, "/static/pin_"))
	// Older 2.x deployments use a different shell — check /home or /login
	if !airflowSPA {
		rl := probe.Get(ctx, client, target+"/login/", hostname, 4096)
		bl := string(rl.Body)
		if rl.Status == 200 && strings.Contains(bl, "Airflow") &&
			(strings.Contains(bl, "Sign In") || strings.Contains(bl, "airflow") ||
				strings.Contains(bl, "Apache Airflow")) {
			airflowSPA = true
		}
	}
	if !airflowSPA {
		return f
	}

	indicators := map[string]interface{}{
		"airflow_marker": true,
	}

	// Step 2: probe both v1 and v2 DAG list endpoints
	for _, endpoint := range []string{
		"/api/v1/dags?limit=10",
		"/api/v2/dags?limit=10",
	} {
		r := probe.Get(ctx, client, target+endpoint, hostname, 32768)
		switch {
		case r.Status == 200:
			var resp struct {
				DAGs []struct {
					DAGID    string `json:"dag_id"`
					IsPaused bool   `json:"is_paused"`
				} `json:"dags"`
				TotalEntries int `json:"total_entries"`
			}
			if err := json.Unmarshal(r.Body, &resp); err == nil && resp.DAGs != nil {
				f.Confirmed = true
				f.Auth = AuthOpen
				f.Severity = SevCritical
				indicators["dags_unauth_endpoint"] = endpoint
				indicators["dag_count_total"] = resp.TotalEntries
				indicators["dag_count_sampled"] = len(resp.DAGs)
				if len(resp.DAGs) > 0 {
					ids := []string{}
					for _, d := range resp.DAGs {
						if d.DAGID != "" {
							ids = append(ids, d.DAGID)
						}
					}
					if len(ids) > 20 {
						ids = ids[:20]
					}
					indicators["dag_ids_sample"] = ids
				}
				f.Notes = append(f.Notes,
					"CRITICAL: "+endpoint+" returns DAG list without authentication",
					"DAG code reachable via /api/.../source — operator workflow logic + frequently embedded credentials",
				)
				break // got it; don't try the other endpoint
			}
		case r.Status == 401 || r.Status == 403:
			if f.Severity == SevNone {
				f.Confirmed = true
				f.Auth = AuthProtected
				f.Severity = SevInfo
			}
		}
	}

	// Step 3: version from /api/v1/version (legacy) or /api/v2/version
	for _, vpath := range []string{"/api/v1/version", "/api/v2/version"} {
		rv := probe.Get(ctx, client, target+vpath, hostname, 512)
		if rv.Status == 200 {
			var v struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(rv.Body, &v); err == nil && v.Version != "" {
				f.Version = v.Version
				break
			}
		}
	}

	if !f.Confirmed && airflowSPA {
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
