// Package output formats VisorBishop results for human + machine consumption.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nuclide-research/VisorBishop/internal/fingerprint"
	"github.com/nuclide-research/VisorBishop/internal/probe"
)

// HostReport bundles all findings (platform + IP-shadow) for a single target.
type HostReport struct {
	Target         string                  `json:"target"`
	Platform       fingerprint.Finding     `json:"platform"`
	ShadowFindings []probe.ShadowFinding   `json:"ip_shadow_findings,omitempty"`
}

// SeverityRank returns a stable integer rank for severity ordering
// (higher = worse). Used for sorting reports.
func SeverityRank(s fingerprint.Severity) int {
	switch s {
	case fingerprint.SevCritical:
		return 5
	case fingerprint.SevHigh:
		return 4
	case fingerprint.SevMedium:
		return 3
	case fingerprint.SevLow:
		return 2
	case fingerprint.SevInfo:
		return 1
	default:
		return 0
	}
}

// SortReports orders reports by severity desc, then platform, then target.
func SortReports(reports []HostReport) {
	sort.Slice(reports, func(i, j int) bool {
		si := SeverityRank(reports[i].Platform.Severity)
		sj := SeverityRank(reports[j].Platform.Severity)
		if si != sj {
			return si > sj
		}
		if reports[i].Platform.Platform != reports[j].Platform.Platform {
			return reports[i].Platform.Platform < reports[j].Platform.Platform
		}
		return reports[i].Target < reports[j].Target
	})
}

// WriteJSON dumps all reports as a JSON array.
func WriteJSON(w io.Writer, reports []HostReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

// WriteCSV emits one row per host with summary fields.
func WriteCSV(w io.Writer, reports []HostReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	cw.Write([]string{
		"target", "platform", "confirmed", "version", "auth", "severity",
		"customer", "license_expiry", "shadow_unauth_count", "notes",
	})
	for _, r := range reports {
		shadowUnauth := 0
		for _, s := range r.ShadowFindings {
			if s.Unauth {
				shadowUnauth++
			}
		}
		customer := ""
		if v, ok := r.Platform.Indicators["customer_name"]; ok {
			customer = fmt.Sprint(v)
		}
		cw.Write([]string{
			r.Target,
			string(r.Platform.Platform),
			fmt.Sprintf("%t", r.Platform.Confirmed),
			r.Platform.Version,
			string(r.Platform.Auth),
			string(r.Platform.Severity),
			customer,
			r.Platform.LicenseExpiry,
			fmt.Sprintf("%d", shadowUnauth),
			strings.Join(r.Platform.Notes, "; "),
		})
	}
	return cw.Error()
}

// WriteText writes a human-readable summary for terminal output.
func WriteText(w io.Writer, reports []HostReport) {
	platformCounts := map[fingerprint.Platform]int{}
	severityCounts := map[fingerprint.Severity]int{}
	criticalReports := []HostReport{}

	for _, r := range reports {
		if r.Platform.Confirmed {
			platformCounts[r.Platform.Platform]++
		}
		severityCounts[r.Platform.Severity]++
		if r.Platform.Severity == fingerprint.SevCritical || r.Platform.Severity == fingerprint.SevHigh {
			criticalReports = append(criticalReports, r)
		}
	}

	fmt.Fprintf(w, "VisorBishop scan complete: %d targets\n", len(reports))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "PLATFORM DISTRIBUTION")
	for _, p := range fingerprint.AllPlatforms() {
		if n := platformCounts[p]; n > 0 {
			fmt.Fprintf(w, "  %-18s %d\n", p, n)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "SEVERITY DISTRIBUTION")
	for _, s := range []fingerprint.Severity{
		fingerprint.SevCritical, fingerprint.SevHigh, fingerprint.SevMedium,
		fingerprint.SevLow, fingerprint.SevInfo, fingerprint.SevNone,
	} {
		if n := severityCounts[s]; n > 0 {
			fmt.Fprintf(w, "  %-10s %d\n", s, n)
		}
	}
	fmt.Fprintln(w)

	if len(criticalReports) > 0 {
		fmt.Fprintf(w, "CRITICAL + HIGH FINDINGS (%d)\n", len(criticalReports))
		fmt.Fprintln(w, strings.Repeat("=", 70))
		for _, r := range criticalReports {
			fmt.Fprintf(w, "[%s] %s — %s v%s\n",
				strings.ToUpper(string(r.Platform.Severity)),
				r.Target,
				r.Platform.Platform,
				r.Platform.Version,
			)
			if customer, ok := r.Platform.Indicators["customer_name"]; ok && customer != "" {
				fmt.Fprintf(w, "    customer: %v\n", customer)
			}
			for _, n := range r.Platform.Notes {
				fmt.Fprintf(w, "    note: %s\n", n)
			}
			for _, s := range r.ShadowFindings {
				if s.Unauth {
					fmt.Fprintf(w, "    shadow: %s on :%d — %s\n", s.Service, s.Port, s.Confirmed)
				}
			}
			fmt.Fprintln(w)
		}
	}
}
