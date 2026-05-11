// Package probe provides shared HTTP probe utilities used by every platform
// fingerprint. All probes are read-only — no credential testing, no payload
// fuzzing, no destructive operations.
package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const UserAgent = "VisorBishop/0.1 (+https://github.com/Nicholas-Kloster/VisorBishop)"

// NewClient builds an HTTP client suitable for population-scale probing:
// - InsecureSkipVerify (we're cataloging exposure, not validating TLS chains)
// - Reasonable timeouts
// - Optional Host-header override via the dialer (for SNI-based hostname probing
//   without DNS resolution)
func NewClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Proxy:                 nil, // no proxy by default
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   timeout / 2,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Don't auto-follow redirects — we want to see the auth-redirect signals
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Response is a probe result with the body capped at maxBody bytes.
type Response struct {
	Status     int
	Body       []byte
	Header     http.Header
	LatencyMS  int64
	Err        error
}

// Get issues a GET against the target URL. If hostnameOverride is non-empty,
// it's used as the Host header and SNI (useful for testing hostname-routed
// services when probing by IP).
func Get(ctx context.Context, client *http.Client, target, hostnameOverride string, maxBody int64) Response {
	return Do(ctx, client, "GET", target, hostnameOverride, nil, maxBody)
}

// Do issues an arbitrary request. body may be nil. maxBody caps the response
// body read to that many bytes.
func Do(ctx context.Context, client *http.Client, method, target, hostnameOverride string, body io.Reader, maxBody int64) Response {
	start := time.Now()
	r := Response{}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		r.Err = err
		r.LatencyMS = time.Since(start).Milliseconds()
		return r
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.5")
	if method == "POST" || method == "PUT" || method == "PATCH" {
		// Default to JSON body for our probes; per-prober code can still
		// override via direct request manipulation if needed.
		req.Header.Set("Content-Type", "application/json")
	}
	if hostnameOverride != "" {
		req.Host = hostnameOverride
		// SNI is controlled separately; we rely on InsecureSkipVerify in the
		// client transport for the SNI mismatch case.
	}

	resp, err := client.Do(req)
	r.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		r.Err = err
		return r
	}
	defer resp.Body.Close()

	r.Status = resp.StatusCode
	r.Header = resp.Header
	r.Body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return r
}

// ResolveHost extracts the IP-or-hostname:port portion of a URL.
// Examples:
//   https://1.2.3.4:443/foo -> "1.2.3.4:443"
//   http://example.com/bar  -> "example.com:80"
func ResolveHost(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Host
	if !hasPort(host) {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}

func hasPort(s string) bool {
	for i := len(s) - 1; i >= 0 && i > len(s)-7; i-- {
		if s[i] == ':' {
			return true
		}
		if s[i] == ']' {
			return false
		}
	}
	return false
}
