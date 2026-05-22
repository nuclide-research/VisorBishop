package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// PhoenixProber detects Arize AI Phoenix instances and probes for the
// default-no-auth state plus secrets-extraction primitive (v15.x+).
//
// References:
//   case-studies/commercial/phoenix-llm-observability-survey-2026-05-10.md
//   methodology/insight-13-shipping-defaults-load-bearing.md
type PhoenixProber struct{}

func (p PhoenixProber) ID() Platform { return PhoenixArize }

var phoenixVersionRE = regexp.MustCompile(`platformVersion:\s*"([0-9]+\.[0-9]+\.[0-9]+)"`)

func (p PhoenixProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target)
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: PhoenixArize,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: Confirm this is Phoenix via the SPA HTML
	r := probe.Get(ctx, client, base+"/", hostname, 32768)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 {
		return f
	}
	body := string(r.Body)
	if !strings.Contains(body, "arize-phoenix") && !strings.Contains(body, "Arize Phoenix") {
		return f
	}
	f.Confirmed = true

	// Extract version from inline Config block
	if m := phoenixVersionRE.FindStringSubmatch(body); len(m) == 2 {
		f.Version = m[1]
	}

	indicators := make(map[string]interface{})

	// Step 2: Probe /graphql for unauth read access
	gqlBody := `{"query":"{ projects(first: 5) { edges { node { id name recordCount traceCount tokenCountTotal } } } }"}`
	r2 := probe.Do(ctx, client, "POST", base+"/graphql", hostname, strings.NewReader(gqlBody), 4096)
	if r2.Err == nil && r2.Status == 200 && strings.Contains(string(r2.Body), `"data":`) {
		f.Auth = AuthOpen
		f.Severity = SevCritical
		f.Notes = append(f.Notes, "GraphQL /graphql returns project list without auth (default-no-auth)")
		indicators["graphql_unauth"] = true

		// Try to extract project count
		var gqlResp struct {
			Data struct {
				Projects struct {
					Edges []struct {
						Node struct {
							Name             string `json:"name"`
							RecordCount      int64  `json:"recordCount"`
							TraceCount       int64  `json:"traceCount"`
							TokenCountTotal  *int64 `json:"tokenCountTotal"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"projects"`
			} `json:"data"`
		}
		if err := json.Unmarshal(r2.Body, &gqlResp); err == nil {
			indicators["project_count"] = len(gqlResp.Data.Projects.Edges)
			var totalTokens, totalTraces int64
			projectNames := []string{}
			for _, e := range gqlResp.Data.Projects.Edges {
				if e.Node.TokenCountTotal != nil {
					totalTokens += *e.Node.TokenCountTotal
				}
				totalTraces += e.Node.TraceCount
				if e.Node.Name != "" {
					projectNames = append(projectNames, e.Node.Name)
				}
			}
			indicators["total_tokens"] = totalTokens
			indicators["total_traces"] = totalTraces
			if len(projectNames) > 0 {
				indicators["project_names"] = projectNames
			}
		}
	} else if r2.Status == 401 || r2.Status == 403 {
		f.Auth = AuthProtected
		f.Severity = SevInfo
	} else {
		// Check for the "Invalid token" body signal (Phoenix with auth on)
		if strings.Contains(string(r2.Body), "Invalid token") ||
			strings.Contains(string(r2.Body), "1009001") {
			f.Auth = AuthProtected
			f.Severity = SevInfo
		}
	}

	// Step 3: If unauth, probe the secrets table (v15.x+)
	if f.Auth == AuthOpen && f.Version != "" && versionAtLeast(f.Version, "15.0.0") {
		secretsBody := `{"query":"{ secrets(first: 50) { edges { node { key } } } }"}`
		r3 := probe.Do(ctx, client, "POST", base+"/graphql", hostname, strings.NewReader(secretsBody), 4096)
		if r3.Err == nil && r3.Status == 200 && strings.Contains(string(r3.Body), `"secrets"`) {
			var sResp struct {
				Data struct {
					Secrets struct {
						Edges []struct {
							Node struct {
								Key string `json:"key"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"secrets"`
				} `json:"data"`
			}
			if err := json.Unmarshal(r3.Body, &sResp); err == nil {
				secretKeys := []string{}
				for _, e := range sResp.Data.Secrets.Edges {
					secretKeys = append(secretKeys, e.Node.Key)
				}
				indicators["secret_count"] = len(secretKeys)
				if len(secretKeys) > 0 {
					indicators["secret_keys"] = secretKeys
					f.Notes = append(f.Notes, "Phoenix secrets table populated; Secret.value field reachable via IsAdminIfAuthEnabled bypass")
				}
			}
		}
	}

	f.Indicators = indicators
	return f
}

// versionAtLeast does a naive semver comparison (X.Y.Z only, no pre-release tags).
func versionAtLeast(v, min string) bool {
	parse := func(s string) [3]int {
		var out [3]int
		parts := strings.SplitN(s, ".", 3)
		for i, p := range parts {
			if i >= 3 {
				break
			}
			n := 0
			for _, c := range p {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				} else {
					break
				}
			}
			out[i] = n
		}
		return out
	}
	a, b := parse(v), parse(min)
	for i := 0; i < 3; i++ {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return true
}
