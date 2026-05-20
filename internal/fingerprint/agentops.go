package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// AgentOpsProber detects AgentOps self-hosted instances.
//
// AgentOps backends respond on /api/health with a JSON shape that
// may include service identity (`"service":"agentops"`) and the
// backing Langfuse host (`"langfuse_host":"..."`) — a cross-platform
// info-disclosure surface that mirrors LangSmith's customer_info pattern.
//
// Reference: github.com/AgentOps-AI/agentops/app/api
type AgentOpsProber struct{}

func (p AgentOpsProber) ID() Platform { return AgentOps }

func (p AgentOpsProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: AgentOps,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	r := probe.Get(ctx, client, base+"/api/health", hostname, 2048)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || (r.Status != 200 && r.Status != 503) {
		return f
	}

	body := string(r.Body)
	if !strings.Contains(body, `"status"`) {
		return f
	}

	// Try to parse
	var hresp struct {
		Status       string `json:"status"`
		Service      string `json:"service"`
		Version      string `json:"version"`
		Timestamp    string `json:"timestamp"`
		LangfuseHost string `json:"langfuse_host"`
	}
	if err := json.Unmarshal(r.Body, &hresp); err != nil {
		return f
	}

	// Confirm AgentOps: either service:"agentops" or langfuse_host:* indicates it
	isAgentOps := hresp.Service == "agentops" || hresp.LangfuseHost != "" ||
		(hresp.Status == "ok" && strings.Contains(body, "langfuse"))
	if !isAgentOps {
		return f
	}
	f.Confirmed = true
	f.Version = hresp.Version

	indicators := map[string]interface{}{}
	notes := []string{}

	if hresp.LangfuseHost != "" {
		indicators["langfuse_host"] = hresp.LangfuseHost
		notes = append(notes, "AgentOps /api/health discloses backing Langfuse host (unauthenticated)")
	}
	if hresp.Service != "" {
		indicators["service"] = hresp.Service
	}
	if hresp.Status != "" {
		indicators["status"] = hresp.Status
	}

	// Verify protected endpoint behavior
	rp := probe.Get(ctx, client, base+"/api/v1/sessions", hostname, 512)
	switch {
	case rp.Status == 401 || rp.Status == 403:
		f.Auth = AuthInfoOnly
		if hresp.LangfuseHost != "" {
			f.Severity = SevMedium
		} else {
			f.Severity = SevInfo
		}
	case rp.Status == 200:
		f.Auth = AuthOpen
		f.Severity = SevCritical
		notes = append(notes, "UNEXPECTED: /api/v1/sessions returned 200 unauth")
	default:
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if len(indicators) > 0 {
		f.Indicators = indicators
	}
	f.Notes = append(f.Notes, notes...)
	return f
}
