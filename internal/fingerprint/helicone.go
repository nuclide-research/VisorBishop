package fingerprint

import (
	"context"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// HeliconeProber detects Helicone self-hosted instances. The signature
// finding for Helicone is co-located unauth ClickHouse (port 8123) per
// the Phase 2 deep-dive — but that requires nmap or a separate port probe,
// not the HTTP fingerprint. This prober only confirms Helicone presence;
// the IP-shadow check (in the ipshadow package) does the ClickHouse probe.
//
// Reference: case-studies/commercial/helicone-deep-dive-survey-2026-05-10.md
type HeliconeProber struct{}

func (p HeliconeProber) ID() Platform { return Helicone }

func (p HeliconeProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Helicone,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	r := probe.Get(ctx, client, base+"/", hostname, 32768)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}
	body := string(r.Body)

	// Helicone has two common landing states:
	//   1. 307 -> /signin  (Better Auth flow on the dashboard)
	//   2. 200 with Next.js SPA HTML containing "Helicone" markers
	confirmed := false

	// Case 1: 307 to /signin is a strong Better Auth signal
	if r.Status == 307 {
		loc := r.Header.Get("Location")
		if loc == "/signin" || strings.HasSuffix(loc, "/signin") {
			r2 := probe.Get(ctx, client, base+"/signin", hostname, 32768)
			body = string(r2.Body)
			if strings.Contains(body, "Helicone") || strings.Contains(body, "helicone") {
				confirmed = true
			}
		}
	}

	// Case 2: 200 with multiple Helicone markers in the HTML
	if !confirmed {
		heliconeMarkers := []string{"Helicone", "helicone", "_next/static"}
		matches := 0
		for _, m := range heliconeMarkers {
			if strings.Contains(body, m) {
				matches++
			}
		}
		confirmed = matches >= 2 && strings.Contains(body, "Helicone")
	}

	// Case 3: fall back to /api/health
	if !confirmed {
		r3 := probe.Get(ctx, client, base+"/api/health", hostname, 1024)
		if r3.Status == 200 && strings.Contains(string(r3.Body), "helicone") {
			confirmed = true
		}
	}

	if !confirmed {
		return f
	}

	f.Confirmed = true
	f.Auth = AuthProtected
	f.Severity = SevInfo
	f.Notes = append(f.Notes, "Helicone web UI detected (run with --ip-shadow to check for unauth ClickHouse on port 8123)")
	return f
}
