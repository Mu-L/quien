package httpinfo

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Result struct {
	FinalURL       string
	StatusCode     int
	StatusText     string
	Redirects      []string // chain of URLs followed
	Headers        []Header
	ServerSoftware string
	TLSVersion     string
	TLSCipher      string
}

type Header struct {
	Name  string
	Value string
}

const timeout = 10 * time.Second

// Lookup performs a HEAD request to https://{domain}, follows redirects,
// and returns headers from the final destination.
func Lookup(domain string) (*Result, error) {
	var redirects []string

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			redirects = append(redirects, req.URL.String())
			return nil
		},
	}

	startURL := "https://" + domain
	redirects = append(redirects, startURL)

	resp, err := client.Head(startURL)
	if err != nil {
		// Try HTTP if HTTPS fails
		startURL = "http://" + domain
		redirects = []string{startURL}
		resp, err = client.Head(startURL)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
	}
	defer func() { _ = resp.Body.Close() }()

	result := &Result{
		FinalURL:   resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
		Redirects:  redirects,
	}

	// Extract server software
	if server := resp.Header.Get("Server"); server != "" {
		result.ServerSoftware = server
	}

	// TLS info from final response
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
		result.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	// Collect headers, sorted by name
	// Prioritize interesting headers first
	result.Headers = collectHeaders(resp.Header)

	return result, nil
}

// Priority headers shown first
var priorityHeaders = []string{
	"server",
	"content-type",
	"x-powered-by",
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"x-xss-protection",
	"cache-control",
	"cf-ray",
	"x-cache",
	"via",
}

func collectHeaders(h http.Header) []Header {
	prioritySet := make(map[string]bool)
	for _, p := range priorityHeaders {
		prioritySet[p] = true
	}

	var priority, rest []Header

	// Collect all headers
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		for _, v := range h[k] {
			header := Header{Name: k, Value: v}
			if prioritySet[strings.ToLower(k)] {
				priority = append(priority, header)
			} else {
				rest = append(rest, header)
			}
		}
	}

	// Sort priority headers by their defined order
	sort.SliceStable(priority, func(i, j int) bool {
		iIdx, jIdx := 999, 999
		for idx, p := range priorityHeaders {
			if strings.EqualFold(priority[i].Name, p) {
				iIdx = idx
			}
			if strings.EqualFold(priority[j].Name, p) {
				jIdx = idx
			}
		}
		return iIdx < jIdx
	})

	return append(priority, rest...)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
