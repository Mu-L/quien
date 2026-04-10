package resolver

import (
	"fmt"

	"github.com/retlehs/quien/internal/model"
	"github.com/retlehs/quien/internal/rdap"
	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/whois"
)

// LookupIP performs an RDAP lookup for an IP address with retry.
func LookupIP(ip string) (*rdap.IPInfo, error) {
	return retry.Do(func() (*rdap.IPInfo, error) {
		return rdap.QueryIP(ip)
	})
}

// Lookup tries RDAP first, then falls back to WHOIS, with retry on each.
func Lookup(domain string) (*model.DomainInfo, error) {
	// Try RDAP first
	if info, err := rdap.Query(domain); err == nil && info != nil {
		// Also grab raw WHOIS for the raw tab (best effort)
		if raw, err := whois.QueryWithReferral(domain); err == nil {
			info.RawResponse = raw
		}
		return info, nil
	}

	// Fall back to WHOIS with retry
	resp, err := retry.Do(func() (string, error) {
		return whois.QueryWithReferral(domain)
	})
	if err != nil {
		return nil, err
	}

	// Check if the response is effectively "not found"
	if whois.LooksEmpty(resp) {
		return nil, fmt.Errorf("domain %s not found", domain)
	}

	info := whois.Parse(resp)
	if info.DomainName == "" {
		info.DomainName = domain
	}
	info.RawResponse = resp
	return &info, nil
}
