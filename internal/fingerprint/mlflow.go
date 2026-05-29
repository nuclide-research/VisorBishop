package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nuclide-research/VisorBishop/internal/probe"
)

// MLflowProber detects MLflow Tracking Server self-hosted instances.
//
// MLflow Tracking is the open-source ML experiment-tracking server from
// Databricks. By default it ships WITHOUT authentication — the server
// supports basic-auth only as an opt-in extension. The REST API at
// /api/2.0/mlflow/experiments/search and /api/2.0/mlflow/runs/search
// returns experiment + run metadata (including prompts, model parameters,
// artifact paths, and frequently exposed credentials in run tags) without
// any credential check when shipped with defaults.
//
// Pre-2.2.1 versions are vulnerable to CVE-2023-1177 (path traversal via
// the artifact URI), still seen in production deployments.
//
// Confirmation requires:
//   1. SPA HTML title is exactly "MLflow" with the static-files/favicon.ico
//      reference (the React SPA fingerprint)
//   2. /api/2.0/mlflow/experiments/search returns the documented JSON shape
//
// Reference: github.com/mlflow/mlflow
type MLflowProber struct{}

func (p MLflowProber) ID() Platform { return MLflow }

func (p MLflowProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: MLflow,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm MLflow via the SPA root.
	// The official MLflow UI is a React SPA with a very specific signature:
	// <title>MLflow</title> + ./static-files/favicon.ico reference. Generic
	// title-only matches are rejected — many tools use the title "MLflow"
	// for unrelated reasons (blog posts, ML pipelines named after MLflow).
	ru := probe.Get(ctx, client, target+"/", hostname, 4096)
	f.LatencyMS = ru.LatencyMS
	if ru.Err != nil {
		return f
	}
	body := string(ru.Body)
	mlflowSPA := strings.Contains(body, "<title>MLflow</title>") &&
		strings.Contains(body, "static-files/favicon.ico")
	if !mlflowSPA {
		return f
	}

	indicators := map[string]interface{}{
		"spa_root_match": true,
	}

	// Step 2: probe /api/2.0/mlflow/experiments/search for auth state + data.
	// MLflow's REST API takes POST with a JSON body, but a GET also returns
	// 405 vs 401/403 — useful to distinguish unauth (no auth layer at all)
	// from auth-protected (returns 401/403).
	r := probe.Get(ctx, client, target+"/api/2.0/mlflow/experiments/search?max_results=10", hostname, 65536)
	switch {
	case r.Status == 200:
		// Try to parse the experiments shape
		var resp struct {
			Experiments []struct {
				ExperimentID   string `json:"experiment_id"`
				Name           string `json:"name"`
				ArtifactLoc    string `json:"artifact_location"`
				LifecycleStage string `json:"lifecycle_stage"`
			} `json:"experiments"`
			NextPageToken string `json:"next_page_token"`
		}
		if err := json.Unmarshal(r.Body, &resp); err == nil {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			indicators["experiments_unauth"] = true
			indicators["experiment_count_sampled"] = len(resp.Experiments)
			if len(resp.Experiments) > 0 {
				// Surface experiment names + artifact locations (often
				// reveal cloud bucket paths, internal hostnames, team names)
				names := make([]string, 0, len(resp.Experiments))
				artifactLocs := make([]string, 0, len(resp.Experiments))
				for _, e := range resp.Experiments {
					if e.Name != "" {
						names = append(names, e.Name)
					}
					if e.ArtifactLoc != "" {
						artifactLocs = append(artifactLocs, e.ArtifactLoc)
					}
				}
				if len(names) > 20 {
					names = names[:20]
				}
				if len(artifactLocs) > 10 {
					artifactLocs = artifactLocs[:10]
				}
				indicators["experiment_names_sample"] = names
				indicators["artifact_locations_sample"] = artifactLocs
			}
			f.Notes = append(f.Notes,
				"CRITICAL: /api/2.0/mlflow/experiments/search returns experiment catalog without authentication",
				"Run history at /api/2.0/mlflow/runs/search likely also unauth — exposes prompts, params, metrics, artifact paths",
			)
		} else {
			// 200 but unexpected shape — could be an auth-gate page that
			// returns 200 with a login HTML
			f.Confirmed = true
			f.Auth = AuthUnknown
			f.Severity = SevInfo
			indicators["unexpected_200_shape"] = true
		}
	case r.Status == 401 || r.Status == 403:
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
		indicators["auth_protected"] = true
	case r.Status == 405:
		// API exists but rejects GET (uncommon for MLflow — it accepts GET
		// on search). Still confirms platform if SPA matched.
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	default:
		// SPA matched but API didn't respond as expected. Confirm but
		// don't claim auth state.
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	// Step 3: probe /version for the MLflow version string.
	// MLflow exposes /version as plain text (e.g. "2.9.2\n"). Older
	// versions (pre-2.2.1) are vulnerable to CVE-2023-1177.
	rv := probe.Get(ctx, client, target+"/version", hostname, 256)
	if rv.Status == 200 {
		v := strings.TrimSpace(string(rv.Body))
		// Sanity: should match X.Y.Z shape, not arbitrary HTML
		if len(v) < 32 && strings.Count(v, ".") >= 1 && !strings.Contains(v, "<") {
			f.Version = v
			if isMLflowVulnerable(v) {
				indicators["cve_2023_1177_likely"] = true
				f.Notes = append(f.Notes,
					"CVE-2023-1177 path traversal: version is pre-2.2.1, likely vulnerable",
				)
			}
		}
	}

	// Step 4: probe /ajax-api/2.0/mlflow/registered-models/search for
	// the model registry — additional data class disclosure when unauth.
	if f.Auth == AuthOpen {
		rm := probe.Get(ctx, client, target+"/api/2.0/mlflow/registered-models/search?max_results=10", hostname, 8192)
		if rm.Status == 200 {
			var modelsResp struct {
				RegisteredModels []struct {
					Name string `json:"name"`
				} `json:"registered_models"`
			}
			if err := json.Unmarshal(rm.Body, &modelsResp); err == nil && modelsResp.RegisteredModels != nil {
				indicators["registered_models_unauth"] = true
				indicators["registered_model_count_sampled"] = len(modelsResp.RegisteredModels)
				if len(modelsResp.RegisteredModels) > 0 {
					names := make([]string, 0, len(modelsResp.RegisteredModels))
					for _, m := range modelsResp.RegisteredModels {
						if m.Name != "" {
							names = append(names, m.Name)
						}
					}
					if len(names) > 20 {
						names = names[:20]
					}
					indicators["registered_model_names_sample"] = names
				}
			}
		}
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}

// isMLflowVulnerable returns true when the version string is pre-2.2.1
// (the cutoff for CVE-2023-1177 fix). Conservative: any parse failure
// returns false so we don't false-positive on weirdly-formatted versions.
func isMLflowVulnerable(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	major := parts[0]
	minor := parts[1]
	patch := "0"
	if len(parts) >= 3 {
		patch = parts[2]
	}
	// Easy cases: major < 2 = vulnerable
	if major == "0" || major == "1" {
		return true
	}
	if major != "2" {
		return false
	}
	// major == 2: vulnerable if minor < 2, or (minor == 2 and patch < 1)
	if minor < "2" || len(minor) == 0 {
		return true
	}
	if minor == "2" && patch == "0" {
		return true
	}
	return false
}
