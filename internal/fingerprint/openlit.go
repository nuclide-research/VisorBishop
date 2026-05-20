package fingerprint

import (
	"context"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// OpenLITProber detects OpenLIT self-hosted instances. Auth is mandatory
// via NextAuth.js — every API path redirects to /login.
type OpenLITProber struct{}

func (p OpenLITProber) ID() Platform { return OpenLIT }

func (p OpenLITProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: OpenLIT,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}
	r := probe.Get(ctx, client, base+"/", hostname, 32768)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}
	body := string(r.Body)
	if !strings.Contains(body, "OpenLIT") {
		return f
	}
	f.Confirmed = true

	// Verify API endpoint redirects to /login
	r2 := probe.Get(ctx, client, base+"/api/db/checkConnection", hostname, 256)
	loc := r2.Header.Get("Location")
	if r2.Status == 307 && strings.Contains(loc, "/login") {
		f.Auth = AuthProtected
		f.Severity = SevInfo
	} else if r2.Status == 200 {
		f.Auth = AuthOpen
		f.Severity = SevCritical
		f.Notes = append(f.Notes, "UNEXPECTED: /api/db/checkConnection returned 200 unauth")
	}
	return f
}

// LunaryProber detects Lunary self-hosted instances.
type LunaryProber struct{}

func (p LunaryProber) ID() Platform { return Lunary }

func (p LunaryProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Lunary,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}
	r := probe.Get(ctx, client, base+"/v1/health", hostname, 512)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 {
		return f
	}
	body := string(r.Body)
	if !strings.Contains(body, `"status":"OK"`) {
		return f
	}
	// Confirm via /v1/runs which should return 401
	r2 := probe.Get(ctx, client, base+"/v1/runs", hostname, 256)
	body2 := string(r2.Body)
	if r2.Status != 401 || !strings.Contains(body2, "Invalid access token") {
		// Not Lunary
		return f
	}
	f.Confirmed = true
	f.Auth = AuthProtected
	f.Severity = SevInfo
	return f
}

// PezzoProber detects Pezzo self-hosted instances.
type PezzoProber struct{}

func (p PezzoProber) ID() Platform { return Pezzo }

func (p PezzoProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Pezzo,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}
	r := probe.Get(ctx, client, base+"/", hostname, 32768)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 {
		return f
	}
	body := string(r.Body)
	if !strings.Contains(body, "<title>Pezzo</title>") {
		return f
	}
	f.Confirmed = true
	f.Auth = AuthProtected // Pezzo backend uses JWT; SPA-shadow on the frontend
	f.Severity = SevInfo
	return f
}
