package display

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/retlehs/quien/internal/mail"
)

var (
	foundStyle    = lipgloss.NewStyle().Foreground(green)
	notFoundStyle = lipgloss.NewStyle().Foreground(red)
	recordStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#A8A8A8"))
)

// RenderMail returns a lipgloss-styled string for email-related DNS records.
func RenderMail(records *mail.Records) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("Mail Configuration"))
	b.WriteString("\n\n")

	// MX Records
	b.WriteString(section("MX Records"))
	if len(records.MX) > 0 {
		for _, mx := range records.MX {
			pri := dimStyle.Render(fmt.Sprintf("(%d)", mx.Priority))
			b.WriteString(row("", nsStyle.Render(mx.Host)+" "+pri))
		}
	} else {
		b.WriteString(row("", notFoundStyle.Render("No MX records found")))
	}

	// SPF
	b.WriteString("\n")
	b.WriteString(section("SPF"))
	if records.SPF != "" {
		b.WriteString(row("Status", foundStyle.Render("found")))
		// Word-wrap long SPF records
		b.WriteString(wrapRecord(records.SPF))
	} else {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
	}

	// DMARC
	b.WriteString("\n")
	b.WriteString(section("DMARC"))
	if records.DMARC != "" {
		b.WriteString(row("Status", foundStyle.Render("found")))
		b.WriteString(wrapRecord(records.DMARC))
	} else {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
	}

	// DKIM
	b.WriteString("\n")
	b.WriteString(section("DKIM"))
	if len(records.DKIM) > 0 {
		for _, dk := range records.DKIM {
			sel := nsStyle.Render(dk.Selector)
			b.WriteString(row("Selector", sel))
			b.WriteString(wrapRecord(dk.Value))
		}
	} else {
		b.WriteString(row("Status", dimStyle.Render("no records found (checked common selectors)")))
	}

	return b.String()
}

func wrapRecord(s string) string {
	maxWidth := valueWidth()
	if maxWidth < 10 {
		maxWidth = 10
	}
	indent := strings.Repeat(" ", labelWidth+gutter)
	lines := wrapText(s, maxWidth)
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(indent + recordStyle.Render(line) + "\n")
	}
	return b.String()
}
