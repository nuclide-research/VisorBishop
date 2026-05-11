package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// OpikProber detects Comet ML Opik self-hosted instances.
//
// Opik uses Dropwizard (Java) with routes mounted under /api/. The health
// endpoint is /api/is-alive/ping returning {"message":"Healthy Server","healthy":true}.
// Authenticated routes are at /api/v1/private/...
//
// Source: github.com/comet-ml/opik (apps/opik-backend)
type OpikProber struct{}

func (p OpikProber) ID() Platform { return OpikPlatform }

func (p OpikProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: OpikPlatform,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	r := probe.Get(ctx, client, target+"/api/is-alive/ping", hostname, 512)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 {
		return f
	}
	var ping struct {
		Message string `json:"message"`
		Healthy bool   `json:"healthy"`
	}
	if err := json.Unmarshal(r.Body, &ping); err != nil || ping.Message != "Healthy Server" {
		return f
	}
	f.Confirmed = true

	// Pull version
	rv := probe.Get(ctx, client, target+"/api/is-alive/ver", hostname, 256)
	if rv.Status == 200 {
		var ver struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(rv.Body, &ver); err == nil && ver.Version != "" {
			f.Version = ver.Version
		}
	}

	// Verify auth on /api/v1/private/projects (should be auth-required in Cloud, may differ self-hosted)
	rp := probe.Get(ctx, client, target+"/api/v1/private/projects", hostname, 1024)
	switch {
	case rp.Status == 200 && strings.Contains(string(rp.Body), `"content"`):
		f.Auth = AuthOpen
		f.Severity = SevCritical
		f.Notes = append(f.Notes, "/api/v1/private/projects returned 200 without auth headers")
	case rp.Status == 401 || rp.Status == 403:
		f.Auth = AuthProtected
		f.Severity = SevInfo
	default:
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	return f
}
