package display

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/retlehs/quien/internal/rdap"
)

// RenderIPJSON returns IP info as JSON.
func RenderIPJSON(info *rdap.IPInfo) string {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return string(data)
}

// RenderIP returns a lipgloss-styled string for IP RDAP info.
func RenderIP(info *rdap.IPInfo) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle(info.IP))
	b.WriteString("\n")

	if len(info.Hostnames) > 0 {
		b.WriteString(row("Hostname", nsStyle.Render(info.Hostnames[0])))
		for _, h := range info.Hostnames[1:] {
			b.WriteString(row("", nsStyle.Render(h)))
		}
	}
	if info.Network != "" {
		b.WriteString(row("Network", info.Network))
	}
	if info.Name != "" {
		b.WriteString(row("Name", info.Name))
	}
	if info.Type != "" {
		b.WriteString(row("Type", info.Type))
	}
	if info.Org != "" {
		b.WriteString(row("Org", info.Org))
	}
	if info.Country != "" {
		b.WriteString(row("Country", info.Country))
	}
	if info.Abuse != "" {
		b.WriteString(row("Abuse", info.Abuse))
	}

	if info.StartAddr != "" && info.EndAddr != "" {
		b.WriteString("\n")
		b.WriteString(section("Range"))
		b.WriteString(row("Start", info.StartAddr))
		b.WriteString(row("End", info.EndAddr))
		b.WriteString(row("Handle", info.Handle))
	}

	return b.String()
}
