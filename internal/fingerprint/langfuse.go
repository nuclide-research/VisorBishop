package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
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

type langfuseNextData struct {
	Props struct {
		PageProps struct {
			SignUpDisabled *bool `json:"signUpDisabled"`
		} `json:"pageProps"`
	} `json:"props"`
}

var langfuseNextDataRE = regexp.MustCompile(`(?s)<script id="__NEXT_DATA__"[^>]*>(.*?)</script>`)

func (p LangfuseProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Langfuse,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: Confirm via the unauth health endpoint
	r := probe.Get(ctx, client, base+"/api/public/health", hostname, 1024)
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
	r2 := probe.Get(ctx, client, base+"/api/public/projects", hostname, 512)
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

	// Step 4: Check if self-registration is open.
	// Langfuse embeds enrollment policy in __NEXT_DATA__ on the sign-up page
	// as props.pageProps.signUpDisabled. A false value means anyone can create
	// an account — auth-gated API + open signup = Insight #55.
	r4 := probe.Get(ctx, client, base+"/auth/sign-up", hostname, 65536)
	if r4.Err == nil && r4.Status == 200 {
		if m := langfuseNextDataRE.FindSubmatch(r4.Body); len(m) == 2 {
			var nd langfuseNextData
			if json.Unmarshal(m[1], &nd) == nil && nd.Props.PageProps.SignUpDisabled != nil {
				if !*nd.Props.PageProps.SignUpDisabled {
					f.Auth = AuthSignupOpen
					f.Severity = SevHigh
					f.Notes = append(f.Notes, "signup-open: signUpDisabled=false in __NEXT_DATA__")
					indicators["signup_open"] = true
				}
			}
		}
	}

	f.Indicators = indicators
	return f
}
