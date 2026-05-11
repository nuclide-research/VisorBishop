package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// LangfuseProber detects Langfuse self-hosted instances. The platform is
// auth-mandatory by design; this prober mainly serves to identify hosts +
// version + verify the auth contract is intact at the population level.
//
// Reference: case-studies/commercial/langfuse-llm-observability-survey-2026-05-10.md
//            case-studies/commercial/langfuse-deep-dive-survey-2026-05-10.md
type LangfuseProber struct{}

func (p LangfuseProber) ID() Platform { return Langfuse }

type langfuseHealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func (p LangfuseProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Langfuse,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: Confirm via the unauth health endpoint
	r := probe.Get(ctx, client, target+"/api/public/health", hostname, 1024)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 {
		return f
	}
	var health langfuseHealthResponse
	if err := json.Unmarshal(r.Body, &health); err != nil {
		return f
	}
	if health.Status != "OK" || health.Version == "" {
		return f
	}
	f.Confirmed = true
	f.Version = health.Version

	indicators := map[string]interface{}{}

	// Step 2: Verify auth on /api/public/projects
	r2 := probe.Get(ctx, client, target+"/api/public/projects", hostname, 512)
	switch {
	case r2.Status == 401 || r2.Status == 403:
		f.Auth = AuthProtected
		f.Severity = SevInfo
	case r2.Status == 200:
		// Should never happen on Langfuse — would indicate a major misconfiguration
		body := string(r2.Body)
		if strings.Contains(body, `"data"`) {
			f.Auth = AuthOpen
			f.Severity = SevCritical
			f.Notes = append(f.Notes, "UNEXPECTED: /api/public/projects returned 200 unauth")
			indicators["projects_unauth"] = true
		} else {
			f.Auth = AuthProtected
			f.Severity = SevInfo
		}
	default:
		f.Auth = AuthUnknown
	}

	// Step 3: Flag legacy v2.x versions
	if strings.HasPrefix(f.Version, "2.") {
		indicators["legacy_v2"] = true
		f.Notes = append(f.Notes, "Legacy Langfuse v2.x deployment")
	}

	f.Indicators = indicators
	return f
}
