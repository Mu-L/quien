package whois

import (
	"fmt"
	"strings"
	"sync"
)

// Server returns the WHOIS server for the given TLD.
// Resolution order: hardcoded map → IANA referral → whois.nic.{tld} guess.
func Server(domain string) string {
	parts := strings.Split(domain, ".")
	tld := strings.ToLower(parts[len(parts)-1])

	// 1. Check hardcoded map
	if server, ok := tldServers[tld]; ok {
		return server
	}

	// 2. Check IANA referral cache
	ianaCache.RLock()
	if server, ok := ianaCache.m[tld]; ok {
		ianaCache.RUnlock()
		return server
	}
	ianaCache.RUnlock()

	// 3. Query IANA for the authoritative WHOIS server
	if server := queryIANA(tld); server != "" {
		ianaCache.Lock()
		ianaCache.m[tld] = server
		ianaCache.Unlock()
		return server
	}

	// 4. Guess
	return "whois.nic." + tld
}

// queryIANA asks whois.iana.org for the WHOIS server for a TLD.
func queryIANA(tld string) string {
	resp, err := QueryServer(tld, "whois.iana.org")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					return server
				}
			}
		}
		// Some IANA responses use "whois:" instead of "refer:"
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					return server
				}
			}
		}
	}

	return ""
}

var ianaCache = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

var tldServers = map[string]string{
	"com": "whois.verisign-grs.com",
	"net": "whois.verisign-grs.com",
	"org": "whois.pir.org",
}

// PrintServer is a debug helper — prints what server would be used.
func PrintServer(domain string) string {
	return fmt.Sprintf("%s → %s", domain, Server(domain))
}
