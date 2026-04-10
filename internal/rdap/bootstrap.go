package rdap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const bootstrapURL = "https://data.iana.org/rdap/dns.json"

var (
	bootstrapCache struct {
		sync.RWMutex
		services map[string]string // tld -> rdap base URL
		loaded   bool
	}
)

type bootstrapResponse struct {
	Services [][][]string `json:"services"`
}

// ServerForTLD returns the RDAP base URL for the given TLD, or empty string if not found.
func ServerForTLD(tld string) string {
	bootstrapCache.RLock()
	if bootstrapCache.loaded {
		url := bootstrapCache.services[strings.ToLower(tld)]
		bootstrapCache.RUnlock()
		return url
	}
	bootstrapCache.RUnlock()

	if err := loadBootstrap(); err != nil {
		return ""
	}

	bootstrapCache.RLock()
	defer bootstrapCache.RUnlock()
	return bootstrapCache.services[strings.ToLower(tld)]
}

func loadBootstrap() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(bootstrapURL)
	if err != nil {
		return fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var data bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("parsing RDAP bootstrap: %w", err)
	}

	services := make(map[string]string)
	for _, entry := range data.Services {
		if len(entry) != 2 {
			continue
		}
		tlds := entry[0]
		urls := entry[1]
		if len(urls) == 0 {
			continue
		}
		baseURL := urls[0]
		for _, tld := range tlds {
			services[strings.ToLower(tld)] = baseURL
		}
	}

	bootstrapCache.Lock()
	bootstrapCache.services = services
	bootstrapCache.loaded = true
	bootstrapCache.Unlock()

	return nil
}
