package probe

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ShadowPort is a port we probe for the IP-direct-shadow methodology.
type ShadowPort struct {
	Port     int
	Service  string
	HTTPPath string // probe path if HTTP; empty for TCP-only banner
}

// ShadowPorts are the cross-cutting ports VisorBishop probes on every
// identified observability platform IP, per Methodology Insight #12.
// Phase 2 added the database/cache ports that surfaced ClickHouse and
// Postgres exposures on Helicone's benchmarkit.solutions and Langfuse's
// langfuse.revdot.ai respectively.
var ShadowPorts = []ShadowPort{
	{111, "rpcbind", ""},
	{1080, "mailcatcher", "/"},
	{2049, "nfs", ""},
	{3306, "mysql", ""},
	{5432, "postgresql", ""},
	{5601, "kibana", "/api/status"},
	{6379, "redis", ""},
	{8025, "mailhog", "/api/v2/messages?limit=0"},
	{8086, "influxdb", "/ping"},
	{8123, "clickhouse", "/ping"},
	{9090, "prometheus", "/api/v1/query?query=up"},
	{9093, "alertmanager", "/-/healthy"},
	{9100, "node_exporter", "/metrics"},
	{9200, "elasticsearch", "/"},
	{27017, "mongodb", ""},
}

// ShadowFinding is one IP-direct-shadow result for a single port.
type ShadowFinding struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Open        bool   `json:"open"`
	Confirmed   string `json:"confirmed,omitempty"` // what we actually saw (e.g. "ClickHouse 25.6.13.41")
	Unauth      bool   `json:"unauth,omitempty"`     // true if the service answers without auth
	Banner      string `json:"banner,omitempty"`     // raw banner truncated to 200B
	Notes       []string `json:"notes,omitempty"`
}

// ShadowScan runs the IP-direct-shadow port sweep for one IP, probing all
// 15 ports concurrently. Returns one ShadowFinding per port that was open
// + meaningfully probed.
func ShadowScan(ctx context.Context, ip string, timeout time.Duration) []ShadowFinding {
	results := make([]ShadowFinding, len(ShadowPorts))
	var wg sync.WaitGroup
	for i, sp := range ShadowPorts {
		wg.Add(1)
		go func(i int, sp ShadowPort) {
			defer wg.Done()
			results[i] = scanOnePort(ctx, ip, sp, timeout)
		}(i, sp)
	}
	wg.Wait()
	findings := []ShadowFinding{}
	for _, f := range results {
		if f.Open {
			findings = append(findings, f)
		}
	}
	return findings
}

func scanOnePort(ctx context.Context, ip string, sp ShadowPort, timeout time.Duration) ShadowFinding {
	f := ShadowFinding{
		IP:      ip,
		Port:    sp.Port,
		Service: sp.Service,
	}

	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	conn.Close()
	f.Open = true

	// If HTTPPath is set, do an HTTP follow-up to characterize the service
	if sp.HTTPPath != "" {
		f = httpCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 5432 {
		f.Notes = []string{"PostgreSQL port open; password unknown (no credential test)"}
	} else if sp.Port == 6379 {
		f = redisCharacterize(ctx, ip, sp, f, timeout)
	} else if sp.Port == 2049 {
		f.Notes = []string{"NFS port open; run `showmount -e " + ip + "` to enumerate exports"}
	}

	return f
}

func httpCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	client := NewClient(timeout)
	target := fmt.Sprintf("http://%s:%d%s", ip, sp.Port, sp.HTTPPath)
	r := Get(ctx, client, target, "", 1024)
	if r.Err != nil {
		return f
	}
	body := string(r.Body)
	bodyTrimmed := body
	if len(bodyTrimmed) > 200 {
		bodyTrimmed = bodyTrimmed[:200]
	}
	f.Banner = bodyTrimmed

	switch sp.Service {
	case "prometheus":
		// /api/v1/query returning {"status":"success"} = unauth Prometheus
		if r.Status == 200 && strings.Contains(body, `"status":"success"`) {
			f.Unauth = true
			f.Confirmed = "Prometheus (unauth)"
			f.Notes = append(f.Notes, "/-/quit and /-/reload likely also reachable (DoS primitive)")
		}
	case "kibana":
		// /api/status returning JSON with version = unauth Kibana
		if r.Status == 200 && strings.Contains(body, `"version"`) && strings.Contains(body, `"build_hash"`) {
			f.Unauth = true
			f.Confirmed = "Kibana (unauth)"
		}
	case "mailhog":
		// /api/v2/messages returning {"total":N} = unauth Mailhog
		if r.Status == 200 && strings.Contains(body, `"total":`) {
			f.Unauth = true
			f.Confirmed = "MailHog (unauth)"
			if strings.Contains(body, `"total":0`) {
				f.Notes = append(f.Notes, "MailHog store currently empty (latent capture if app routes mail here)")
			} else {
				f.Notes = append(f.Notes, "ACTUALIZED: MailHog store has messages")
			}
		}
	case "mailcatcher":
		// MailCatcher returns its own HTML with "MailCatcher" in title/body
		if r.Status == 200 && strings.Contains(body, "MailCatcher") {
			f.Unauth = true
			f.Confirmed = "MailCatcher (unauth)"
		}
	case "clickhouse":
		// /ping returns "Ok." for ClickHouse
		if r.Status == 200 && strings.TrimSpace(body) == "Ok." {
			// Probe SELECT 1 to verify the default user has no password
			r2 := Get(ctx, client, fmt.Sprintf("http://%s:%d/?query=SELECT+1", ip, sp.Port), "", 256)
			if r2.Status == 200 && strings.TrimSpace(string(r2.Body)) == "1" {
				f.Unauth = true
				f.Confirmed = "ClickHouse (unauth, default user no password)"
				f.Notes = append(f.Notes, "CRITICAL: ClickHouse default user requires no password")
				// Try version
				rv := Get(ctx, client, fmt.Sprintf("http://%s:%d/?query=SELECT+version()", ip, sp.Port), "", 64)
				if rv.Status == 200 {
					f.Confirmed = "ClickHouse " + strings.TrimSpace(string(rv.Body)) + " (unauth, default user no password)"
				}
			} else if r2.Status == 401 || strings.Contains(string(r2.Body), "Authentication failed") {
				f.Confirmed = "ClickHouse (auth required)"
			}
		}
	case "node_exporter":
		if r.Status == 200 && strings.Contains(body, "go_gc_duration_seconds") {
			f.Unauth = true
			f.Confirmed = "Prometheus node_exporter (unauth)"
		}
	case "elasticsearch":
		if r.Status == 200 && strings.Contains(body, `"cluster_name"`) {
			f.Unauth = true
			f.Confirmed = "Elasticsearch (unauth)"
		}
	case "alertmanager":
		if r.Status == 200 {
			f.Unauth = true
			f.Confirmed = "AlertManager (unauth)"
		}
	case "influxdb":
		if r.Status == 204 || (r.Status == 200 && strings.Contains(body, "influxdb")) {
			f.Confirmed = "InfluxDB"
		}
	}
	return f
}

func redisCharacterize(ctx context.Context, ip string, sp ShadowPort, f ShadowFinding, timeout time.Duration) ShadowFinding {
	addr := fmt.Sprintf("%s:%d", ip, sp.Port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return f
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("INFO server\r\n"))
	if err != nil {
		return f
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.HasPrefix(resp, "-NOAUTH") {
		f.Confirmed = "Redis (auth required)"
		return f
	}
	if strings.Contains(resp, "redis_version") {
		f.Unauth = true
		f.Confirmed = "Redis (unauth)"
		f.Notes = append(f.Notes, "CRITICAL: Redis accepts commands without auth")
	}
	return f
}

// ExtractIP returns the host portion of a URL as an IP (or hostname if not parseable as IP).
func ExtractIP(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
