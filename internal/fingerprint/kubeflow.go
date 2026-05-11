package fingerprint

import (
	"context"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// KubeflowProber detects Kubeflow self-hosted instances.
//
// Kubeflow is a Kubernetes-native ML platform. Most deployments front
// the central dashboard with dex/oidc auth (we see HTTP 302 → /dex/auth
// on confirmed instances), so the platform identity is confirmed by
// detecting the dex redirect AND the kubeflow client-id query
// parameter.
//
// CRITICAL when the central dashboard is reachable without auth
// (rare — happens when operator skipped the istio-ingress / dex
// configuration).
//
// Reference: github.com/kubeflow/kubeflow
type KubeflowProber struct{}

func (p KubeflowProber) ID() Platform { return Kubeflow }

func (p KubeflowProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Kubeflow,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: probe root — most Kubeflow installs respond with a
	// 200 + a tiny anchor body that links to /dex/auth, OR a 302
	// redirect to /dex/auth. Either way the platform identity is
	// signalled by the dex/auth path + kubeflow-oidc-authservice
	// client_id.
	r := probe.Get(ctx, client, target+"/", hostname, 8192)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}
	body := string(r.Body)
	// Markers:
	//   - kubeflow-oidc-authservice    → full Kubeflow distribution
	//     with dex auth (most common; 302/200 + dex/auth path)
	//   - /dex/auth?...client_id=kubeflow-...  → dex redirect chain
	//   - <title>Kubeflow Pipelines</title> + KFP_FLAGS → Pipelines
	//     standalone (lighter-weight; no dex)
	//   - kf-dashboard / centraldashboard HTML → central dashboard SPA
	kubeflowMarker := strings.Contains(body, "kubeflow-oidc-authservice") ||
		strings.Contains(body, "/dex/auth?") ||
		(strings.Contains(body, "<title>Kubeflow Pipelines</title>") &&
			strings.Contains(body, "KFP_FLAGS")) ||
		(strings.Contains(body, "kf-dashboard") && strings.Contains(body, "kubeflow"))
	if !kubeflowMarker {
		// Try the central dashboard route directly. Require a real
		// Kubeflow-specific signal: dex/auth + the OIDC client_id, OR
		// a Kubeflow-branded title/asset reference. A short text body
		// that just says "/_/centraldashboard" (e.g. nginx redirect
		// target leak) is NOT enough.
		r2 := probe.Get(ctx, client, target+"/_/centraldashboard/", hostname, 4096)
		body2 := string(r2.Body)
		if r2.Status == 200 &&
			(strings.Contains(body2, "kubeflow-oidc-authservice") ||
				strings.Contains(body2, "<title>Kubeflow</title>") ||
				strings.Contains(body2, "kf-dashboard") ||
				(strings.Contains(body2, "kubeflow") && strings.Contains(body2, "centraldashboard"))) {
			kubeflowMarker = true
			body = body2
		}
	}
	if !kubeflowMarker {
		return f
	}

	indicators := map[string]interface{}{
		"kubeflow_marker": true,
	}

	// Step 2: classify auth state
	// - 302 to /dex/auth → auth-fronted (info)
	// - 200 + central dashboard HTML → potentially unauth (high/critical)
	// - 401/403 → protected
	if strings.Contains(body, "/dex/auth") {
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
		indicators["auth_fronted_via_dex"] = true
	}

	// Step 3: try the Pipelines API at /pipeline/apis/v1beta1/pipelines
	// or v2/pipelines — if the operator skipped istio gating, the
	// pipeline service may be reachable.
	rp := probe.Get(ctx, client, target+"/pipeline/apis/v1beta1/pipelines?page_size=10", hostname, 16384)
	if rp.Status == 200 {
		bp := string(rp.Body)
		if strings.Contains(bp, `"pipelines"`) || strings.Contains(bp, `"total_size"`) {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			indicators["pipelines_unauth"] = true
			f.Notes = append(f.Notes,
				"CRITICAL: /pipeline/apis/v1beta1/pipelines returns pipeline list without authentication",
			)
		}
	}

	if !f.Confirmed && kubeflowMarker {
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
