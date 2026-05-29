package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nuclide-research/VisorBishop/internal/probe"
)

// LangflowProber detects Langflow self-hosted instances.
//
// Langflow is a visual LLM-pipeline builder from logspace-ai (now part
// of DataStax). The default deployment has no auth — operators run
// `langflow run` and the UI is publicly reachable. Flows often contain
// prompts, system messages, model configurations, and embedded API
// keys.
//
// CRITICAL when /api/v1/flows/ returns the operator's flow list
// (with prompts, tool configurations, sometimes API keys in node
// config) without authentication.
//
// Reference: github.com/langflow-ai/langflow
type LangflowProber struct{}

func (p LangflowProber) ID() Platform { return Langflow }

func (p LangflowProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Langflow,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm via SPA root with the Langflow title + signature script bundles
	ru := probe.Get(ctx, client, target+"/", hostname, 4096)
	f.LatencyMS = ru.LatencyMS
	if ru.Err != nil {
		return f
	}
	body := string(ru.Body)
	langflowSPA := strings.Contains(body, "<title>Langflow</title>") &&
		(strings.Contains(body, "/assets/index-") || strings.Contains(body, "favicon-new"))
	if !langflowSPA {
		return f
	}

	indicators := map[string]interface{}{
		"spa_root_match": true,
	}

	// Step 2: probe /api/v1/flows/ for flow disclosure
	// Langflow's flow API supports a paginated GET that returns the
	// flow list (including data graph) when no auth is configured.
	r := probe.Get(ctx, client, target+"/api/v1/flows/?page=1&size=10", hostname, 65536)
	switch {
	case r.Status == 200:
		var resp struct {
			Items []struct {
				ID          string                 `json:"id"`
				Name        string                 `json:"name"`
				Description string                 `json:"description"`
				Data        map[string]interface{} `json:"data"`
				UserID      string                 `json:"user_id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(r.Body, &resp); err == nil {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			indicators["flows_unauth"] = true
			indicators["flow_count_total"] = resp.Total
			indicators["flow_count_sampled"] = len(resp.Items)
			if len(resp.Items) > 0 {
				names := make([]string, 0, len(resp.Items))
				descs := make([]string, 0, len(resp.Items))
				for _, item := range resp.Items {
					if item.Name != "" {
						names = append(names, item.Name)
					}
					if item.Description != "" {
						descs = append(descs, item.Description[:min(len(item.Description), 80)])
					}
				}
				if len(names) > 20 {
					names = names[:20]
				}
				if len(descs) > 10 {
					descs = descs[:10]
				}
				indicators["flow_names_sample"] = names
				if len(descs) > 0 {
					indicators["flow_descriptions_sample"] = descs
				}
			}
			f.Notes = append(f.Notes,
				"CRITICAL: /api/v1/flows/ returns flow list without authentication",
				"Flow data includes prompts, system messages, model configs, and frequently embedded API keys",
			)
		} else {
			f.Confirmed = true
			f.Auth = AuthUnknown
			f.Severity = SevInfo
		}
	case r.Status == 401 || r.Status == 403:
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
	default:
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	// Step 3: version from /api/v1/version
	rv := probe.Get(ctx, client, target+"/api/v1/version", hostname, 1024)
	if rv.Status == 200 {
		var v struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(rv.Body, &v); err == nil && v.Version != "" {
			f.Version = v.Version
		}
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
