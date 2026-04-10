package rdap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/retlehs/quien/internal/model"
)

// rdapResponse represents the relevant fields from an RDAP domain response.
type rdapResponse struct {
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Nameservers []rdapNS     `json:"nameservers"`
	Entities    []rdapEntity `json:"entities"`
	SecureDNS   *rdapDNSSEC  `json:"secureDNS"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"` // nested entities (e.g. registrar abuse contact)
}

type rdapDNSSEC struct {
	DelegationSigned bool `json:"delegationSigned"`
}

const timeout = 10 * time.Second

// Query performs an RDAP lookup for the given domain.
// Returns nil, nil if RDAP is not available for this TLD.
func Query(domain string) (*model.DomainInfo, error) {
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	baseURL := ServerForTLD(tld)
	if baseURL == "" {
		return nil, nil // RDAP not available for this TLD
	}

	// Ensure base URL ends with /
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	url := baseURL + "domain/" + domain

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("RDAP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("domain not found in RDAP")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RDAP returned status %d", resp.StatusCode)
	}

	var rdap rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	return convertRDAP(&rdap, domain), nil
}

func convertRDAP(rdap *rdapResponse, domain string) *model.DomainInfo {
	info := &model.DomainInfo{
		DomainName: rdap.LDHName,
		Status:     rdap.Status,
	}

	if info.DomainName == "" {
		info.DomainName = domain
	}

	// Events → dates
	for _, e := range rdap.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			// Try without timezone
			t, err = time.Parse("2006-01-02T15:04:05Z", e.Date)
			if err != nil {
				continue
			}
		}
		switch e.Action {
		case "registration":
			info.CreatedDate = t
		case "last changed":
			info.UpdatedDate = t
		case "expiration":
			info.ExpiryDate = t
		}
	}

	// Nameservers
	for _, ns := range rdap.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, ns.LDHName)
		}
	}

	// DNSSEC
	if rdap.SecureDNS != nil {
		info.DNSSEC = rdap.SecureDNS.DelegationSigned
	}

	// Entities → registrar + contacts
	for _, ent := range rdap.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				info.Registrar = extractVCardFN(ent.VCardArray)
			}
			if role == "registrant" || role == "administrative" || role == "technical" {
				contact := extractContact(ent, role)
				if contact.Name != "" || contact.Organization != "" || contact.Email != "" {
					info.Contacts = append(info.Contacts, contact)
				}
			}
		}
	}

	return info
}

func extractVCardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	entries, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, entry := range entries {
		arr, ok := entry.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		prop, _ := arr[0].(string)
		if prop == "fn" {
			val, _ := arr[3].(string)
			return val
		}
	}
	return ""
}

func extractContact(ent rdapEntity, role string) model.Contact {
	c := model.Contact{Role: role}
	if len(ent.VCardArray) < 2 {
		return c
	}
	entries, ok := ent.VCardArray[1].([]any)
	if !ok {
		return c
	}
	for _, entry := range entries {
		arr, ok := entry.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		prop, _ := arr[0].(string)
		val, _ := arr[3].(string)
		switch prop {
		case "fn":
			c.Name = val
		case "org":
			c.Organization = val
		case "email":
			c.Email = val
		case "tel":
			c.Phone = val
		}
	}
	return c
}
