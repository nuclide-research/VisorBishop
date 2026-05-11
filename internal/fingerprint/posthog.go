package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// PostHogProber detects PostHog self-hosted instances.
//
// PostHog is a product-analytics platform with LLM-observability
// features baked in. Self-hosts default to requiring sign-in for the
// console, but the /_health and /api/projects/ endpoints are
// authenticated on default deployments. CRITICAL when /api/projects/
// returns the project list without auth.
//
// Reference: github.com/PostHog/posthog
type PostHogProber struct{}

func (p PostHogProber) ID() Platform { return PostHog }

func (p PostHogProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: PostHog,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: probe /_health — PostHog's documented health endpoint
	// returns the literal "ok" string as plain text (Content-Type:
	// text/plain). Many non-PostHog servers (GitLab, generic HTML
	// 200 catchalls) also return 200 on /_health with HTML bodies
	// containing "ok" deep inside — so we MUST require the body to
	// be exactly "ok" (after strip), not just contain it.
	rh := probe.Get(ctx, client, target+"/_health", hostname, 1024)
	f.LatencyMS = rh.LatencyMS
	if rh.Err != nil {
		return f
	}
	healthBody := strings.TrimSpace(string(rh.Body))
	posthogMarker := rh.Status == 200 && healthBody == "ok"

	if !posthogMarker {
		// Fall back to root SPA marker — must include the PostHog
		// React SPA bundle reference or a posthog-specific path
		ru := probe.Get(ctx, client, target+"/", hostname, 4096)
		body := string(ru.Body)
		if (strings.Contains(body, "<title>PostHog</title>") &&
			(strings.Contains(body, "posthog") || strings.Contains(body, "/static/"))) ||
			strings.Contains(body, "posthog-js") ||
			strings.Contains(body, "ph_") {
			posthogMarker = true
		}
	}
	if !posthogMarker {
		return f
	}

	indicators := map[string]interface{}{
		"posthog_marker": true,
	}

	// Step 2: probe /api/projects/ — if unauth, returns project list
	r := probe.Get(ctx, client, target+"/api/projects/", hostname, 16384)
	switch {
	case r.Status == 200:
		var resp struct {
			Count    int `json:"count"`
			Results  []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := json.Unmarshal(r.Body, &resp); err == nil && resp.Results != nil {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			indicators["projects_unauth"] = true
			indicators["project_count"] = resp.Count
			if len(resp.Results) > 0 {
				names := []string{}
				for _, p := range resp.Results {
					if p.Name != "" {
						names = append(names, p.Name)
					}
				}
				if len(names) > 15 {
					names = names[:15]
				}
				indicators["project_names_sample"] = names
			}
			f.Notes = append(f.Notes,
				"CRITICAL: /api/projects/ returns project list without authentication",
			)
		}
	case r.Status == 401 || r.Status == 403:
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
	default:
		if !f.Confirmed {
			f.Confirmed = true
			f.Auth = AuthUnknown
			f.Severity = SevInfo
		}
	}

	if !f.Confirmed && posthogMarker {
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
