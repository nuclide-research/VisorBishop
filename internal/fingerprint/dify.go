package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// DifyProber detects Dify self-hosted instances.
//
// Dify is an LLM-app builder from LangGenius. Default deployment ships
// with an admin-account onboarding page at /install — if the operator
// never completed the install flow, the admin account is unclaimed
// and the first POST claims it (CRITICAL takeover primitive).
//
// Confirmation requires:
//   1. SPA HTML title is "Dify" with the Dify-specific Next.js
//      static path signature
//   2. /console/api/system-features returns the Dify-specific JSON shape
//
// Reference: github.com/langgenius/dify
type DifyProber struct{}

func (p DifyProber) ID() Platform { return Dify }

func (p DifyProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Dify,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: identity probe — /console/api/system-features returns
	// Dify-specific JSON with sso_enforced_for_signin field. This is
	// the strongest Dify marker (unique to Dify). Probe this FIRST
	// since some Dify hosts return only a redirect target from "/"
	// (no SPA HTML at root).
	r := probe.Get(ctx, client, base+"/console/api/system-features", hostname, 8192)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}
	if r.Status != 200 {
		return f
	}
	rBody := string(r.Body)
	// Must contain the Dify-specific field signature
	if !strings.Contains(rBody, "sso_enforced_for_signin") {
		return f
	}

	indicators := map[string]interface{}{
		"system_features_marker": true,
	}

	var feat struct {
		SSOEnforcedForSignin bool   `json:"sso_enforced_for_signin"`
		EnableMarketplace    bool   `json:"enable_marketplace"`
		BrandingEnabled      bool   `json:"branding"`
		LicenseStatus        string `json:"license_status"`
	}
	if err := json.Unmarshal(r.Body, &feat); err == nil {
		f.Confirmed = true
		indicators["sso_enforced"] = feat.SSOEnforcedForSignin
		indicators["enable_marketplace"] = feat.EnableMarketplace
		if feat.LicenseStatus != "" {
			indicators["license_status"] = feat.LicenseStatus
		}
	} else {
		// JSON parse failed but the marker string was present — likely
		// truncated response. Confirm but mark inconclusive.
		f.Confirmed = true
		indicators["json_parse_failed"] = true
	}

	// Step 2 (optional): SPA root marker for enrichment
	ru := probe.Get(ctx, client, base+"/", hostname, 8192)
	body := string(ru.Body)
	if strings.Contains(body, "<title>Dify</title>") {
		indicators["spa_root_match"] = true
	}

	// Step 3: probe /install for the unclaimed-admin-account primitive
	// If the install endpoint responds with 200 + a form, the admin
	// account has never been claimed — first POST takes it.
	ri := probe.Get(ctx, client, base+"/install", hostname, 4096)
	installCheck := probe.Get(ctx, client, base+"/console/api/setup", hostname, 2048)
	if installCheck.Status == 200 {
		var s struct {
			Step string `json:"step"`
		}
		if err := json.Unmarshal(installCheck.Body, &s); err == nil {
			if s.Step == "not_started" || s.Step == "" {
				f.Confirmed = true
				f.Auth = AuthOpen
				f.Severity = SevCritical
				indicators["install_unclaimed"] = true
				f.Notes = append(f.Notes,
					"CRITICAL: /console/api/setup returns step=not_started — admin account unclaimed, first POST claims it",
				)
			} else {
				indicators["install_step"] = s.Step
			}
		}
	}
	_ = ri

	// Step 4: if not unclaimed-install-critical, try the public apps list
	if f.Severity == SevNone {
		ra := probe.Get(ctx, client, base+"/console/api/apps", hostname, 16384)
		switch {
		case ra.Status == 200:
			// Some Dify deployments expose the app list without auth
			var resp struct {
				Data []struct {
					Name string `json:"name"`
				} `json:"data"`
				Total int `json:"total"`
			}
			if err := json.Unmarshal(ra.Body, &resp); err == nil && resp.Data != nil {
				f.Confirmed = true
				f.Auth = AuthOpen
				f.Severity = SevHigh
				indicators["apps_unauth"] = true
				indicators["app_count"] = resp.Total
				if len(resp.Data) > 0 {
					names := []string{}
					for _, a := range resp.Data {
						if a.Name != "" {
							names = append(names, a.Name)
						}
					}
					if len(names) > 15 {
						names = names[:15]
					}
					indicators["app_names_sample"] = names
				}
				f.Notes = append(f.Notes,
					"HIGH: /console/api/apps returns app list without authentication",
				)
			}
		case ra.Status == 401 || ra.Status == 403:
			f.Confirmed = true
			f.Auth = AuthProtected
			f.Severity = SevInfo
		default:
			if f.Confirmed {
				f.Auth = AuthUnknown
				f.Severity = SevInfo
			}
		}
	}

	// Default: if marker matched (we already returned earlier if it
	// didn't), keep as info-only when no critical/high signal landed.
	if f.Confirmed && f.Severity == SevNone {
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
