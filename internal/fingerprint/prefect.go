package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// PrefectProber detects Prefect (self-host) instances.
//
// Prefect is a Python workflow orchestrator. The "Prefect Server"
// self-host has no built-in auth — operators who expose it publicly
// without an external auth proxy disclose their workflow runs,
// deployment configs, and (in some flows) embedded credentials in
// the run parameters or logs.
//
// CRITICAL when /api/admin/version returns the server version OR
// /api/flows/filter returns the flow list, both without auth.
//
// Reference: github.com/PrefectHQ/prefect
type PrefectProber struct{}

func (p PrefectProber) ID() Platform { return Prefect }

func (p PrefectProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Prefect,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: SPA root marker
	ru := probe.Get(ctx, client, target+"/", hostname, 16384)
	f.LatencyMS = ru.LatencyMS
	if ru.Err != nil {
		return f
	}
	body := string(ru.Body)
	prefectSPA := (strings.Contains(body, "<title>Prefect</title>") ||
		strings.Contains(body, "prefect.io")) &&
		(strings.Contains(body, "/_next/") ||
			strings.Contains(body, "prefect-ui") ||
			strings.Contains(body, "Prefect"))
	if !prefectSPA {
		return f
	}

	indicators := map[string]interface{}{
		"prefect_marker": true,
	}

	// Step 2: probe /api/admin/version
	rv := probe.Get(ctx, client, target+"/api/admin/version", hostname, 1024)
	if rv.Status == 200 {
		var v struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(rv.Body, &v); err == nil && v.Version != "" {
			f.Version = v.Version
			indicators["version_disclosed"] = v.Version
		}
	}

	// Step 3: probe /api/flows/filter for unauth flow list
	flowFilterBody := strings.NewReader(`{"limit":10}`)
	req, err := http.NewRequestWithContext(ctx, "POST", target+"/api/flows/filter", flowFilterBody)
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if hostname != "" {
			req.Host = hostname
		}
		resp, herr := client.Do(req)
		if herr == nil && resp != nil {
			defer resp.Body.Close()
			buf := make([]byte, 65536)
			n, _ := readAll(resp.Body, buf)
			switch {
			case resp.StatusCode == 200:
				var flows []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}
				if jerr := json.Unmarshal(buf[:n], &flows); jerr == nil {
					f.Confirmed = true
					f.Auth = AuthOpen
					f.Severity = SevCritical
					indicators["flows_unauth"] = true
					indicators["flow_count_sampled"] = len(flows)
					if len(flows) > 0 {
						names := []string{}
						for _, fl := range flows {
							if fl.Name != "" {
								names = append(names, fl.Name)
							}
						}
						if len(names) > 15 {
							names = names[:15]
						}
						indicators["flow_names_sample"] = names
					}
					f.Notes = append(f.Notes,
						"CRITICAL: /api/flows/filter returns flow list without authentication",
					)
				}
			case resp.StatusCode == 401 || resp.StatusCode == 403:
				f.Confirmed = true
				f.Auth = AuthProtected
				f.Severity = SevInfo
			}
		}
	}

	if !f.Confirmed && prefectSPA {
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
