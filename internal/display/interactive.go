package display

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/httpinfo"
	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/model"
	"github.com/retlehs/quien/internal/rdap"
	"github.com/retlehs/quien/internal/resolver"
	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/stack"
	"github.com/retlehs/quien/internal/tlsinfo"

	tea "github.com/charmbracelet/bubbletea"
)

type tab int

const (
	tabWhois tab = iota
	tabDNS
	tabMail
	tabTLS
	tabHTTP
	tabStack
)

var (
	tabBarStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	tabStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A0A0A0")).
			PaddingRight(2)

	tabKeyStyle = lipgloss.NewStyle().
			Foreground(dim)

	activeTabStyle = lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true).
			PaddingRight(2)

	activeTabKeyStyle = lipgloss.NewStyle().
				Foreground(cyan)

	loadingStyle = lipgloss.NewStyle().
			Foreground(yellow).
			Italic(true)

	footerStyle = lipgloss.NewStyle().
			Foreground(dim).
			PaddingLeft(2)

	borderColor = lipgloss.Color("#3A3A3A")
	borderFg    = lipgloss.NewStyle().Foreground(borderColor)
)

// chrome = tab bar (1) + top border (1) + bottom border (1) + footer (1)
const chromeHeight = 4

type Model struct {
	domain    string
	isIP      bool
	active    tab
	showRaw   bool
	info      *model.DomainInfo
	ipInfo    *rdap.IPInfo
	whoisErr  error
	dnsData   *dns.Records
	mailData  *mail.Records
	tlsData   *tlsinfo.CertInfo
	httpData  *httpinfo.Result
	stackData *stack.Result
	dnsErr    error
	mailErr   error
	tlsErr    error
	httpErr   error
	stackErr  error
	loading   bool
	quitting  bool
	viewport  viewport.Model
	spinner   spinner.Model
	ready     bool
	width     int
	height    int
}

type whoisResultMsg struct {
	info *model.DomainInfo
	err  error
}

type ipResultMsg struct {
	info *rdap.IPInfo
	err  error
}

type dnsResultMsg struct {
	records *dns.Records
	err     error
}

type mailResultMsg struct {
	records *mail.Records
	err     error
}

type tlsResultMsg struct {
	cert *tlsinfo.CertInfo
	err  error
}

type httpResultMsg struct {
	result *httpinfo.Result
	err    error
}

type stackResultMsg struct {
	result *stack.Result
	err    error
}

func NewModel(domain string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(cyan)

	return Model{
		domain:  domain,
		active:  tabWhois,
		loading: true,
		spinner: s,
	}
}

func NewIPModel(ip string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(cyan)

	return Model{
		domain:  ip,
		isIP:    true,
		active:  tabWhois,
		loading: true,
		spinner: s,
	}
}

func (m Model) Init() tea.Cmd {
	if m.isIP {
		return tea.Batch(m.spinner.Tick, fetchIP(m.domain))
	}
	return tea.Batch(m.spinner.Tick, fetchWhois(m.domain))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		SetWidth(m.width)

		chrome := chromeHeight
		if m.isIP {
			chrome = 3 // top border + bottom border + footer (no tab bar)
		}
		vpHeight := m.height - chrome
		if vpHeight < 1 {
			vpHeight = 1
		}

		vpWidth := innerWidth()

		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.viewport.SetContent(m.contentForTab(m.active))
			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
		}
		return m, nil

	case tea.KeyMsg:
		if m.loading {
			if msg.String() == "q" || msg.String() == "esc" || msg.String() == "ctrl+c" {
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc", "w":
			m.switchTab(tabWhois)
			return m, nil
		case "d":
			m.switchTab(tabDNS)
			if m.dnsData == nil && m.dnsErr == nil {
				m.loading = true
				m.updateViewport()
				return m, fetchDNS(m.domain)
			}
			return m, nil
		case "m":
			m.switchTab(tabMail)
			if m.mailData == nil && m.mailErr == nil {
				m.loading = true
				m.updateViewport()
				return m, fetchMail(m.domain)
			}
			return m, nil
		case "s":
			m.switchTab(tabTLS)
			if m.tlsData == nil && m.tlsErr == nil {
				m.loading = true
				m.updateViewport()
				return m, fetchTLS(m.domain)
			}
			return m, nil
		case "h":
			m.switchTab(tabHTTP)
			if m.httpData == nil && m.httpErr == nil {
				m.loading = true
				m.updateViewport()
				return m, fetchHTTP(m.domain)
			}
			return m, nil
		case "t":
			m.switchTab(tabStack)
			if m.stackData == nil && m.stackErr == nil {
				m.loading = true
				m.updateViewport()
				return m, fetchStack(m.domain)
			}
			return m, nil
		case "r":
			if m.active == tabWhois && m.info != nil && m.info.RawResponse != "" {
				m.showRaw = !m.showRaw
				m.updateViewport()
				m.viewport.GotoTop()
				return m, nil
			}
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.loading {
			m.updateViewport()
		}
		cmds = append(cmds, cmd)
		return m, tea.Batch(cmds...)

	case whoisResultMsg:
		m.loading = false
		if msg.err != nil {
			m.whoisErr = msg.err
		} else {
			m.info = msg.info
		}
		m.updateViewport()
		return m, nil

	case ipResultMsg:
		m.loading = false
		if msg.err != nil {
			m.whoisErr = msg.err
		} else {
			m.ipInfo = msg.info
		}
		m.updateViewport()
		return m, nil

	case mailResultMsg:
		m.loading = false
		m.mailData = msg.records
		m.mailErr = msg.err
		m.updateViewport()
		return m, nil

	case dnsResultMsg:
		m.loading = false
		m.dnsData = msg.records
		m.dnsErr = msg.err
		m.updateViewport()
		return m, nil

	case tlsResultMsg:
		m.loading = false
		m.tlsData = msg.cert
		m.tlsErr = msg.err
		m.updateViewport()
		return m, nil

	case httpResultMsg:
		m.loading = false
		m.httpData = msg.result
		m.httpErr = msg.err
		m.updateViewport()
		return m, nil

	case stackResultMsg:
		m.loading = false
		m.stackData = msg.result
		m.stackErr = msg.err
		m.updateViewport()
		return m, nil
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) switchTab(t tab) {
	m.active = t
	m.showRaw = false
	m.updateViewport()
	m.viewport.GotoTop()
}

func (m *Model) updateViewport() {
	if m.ready {
		m.viewport.SetContent(m.contentForTab(m.active))
	}
}

func (m Model) loadingText(msg string) string {
	return "\n  " + m.spinner.View() + " " + loadingStyle.Render(msg)
}

func (m Model) contentForTab(t tab) string {
	switch t {
	case tabWhois:
		if m.isIP {
			if m.loading && m.ipInfo == nil {
				return m.loadingText("Looking up IP...")
			}
			if m.whoisErr != nil {
				return errorBox("IP Lookup Failed", m.whoisErr)
			}
			if m.ipInfo != nil {
				return RenderIP(m.ipInfo)
			}
			return ""
		}
		if m.loading && m.info == nil {
			return m.loadingText("Looking up WHOIS...")
		}
		if m.whoisErr != nil {
			return errorBox("WHOIS Lookup Failed", m.whoisErr)
		}
		if m.info != nil {
			if m.showRaw && m.info.RawResponse != "" {
				return RenderRawWhois(m.info.RawResponse)
			}
			return RenderWhois(*m.info)
		}
		return ""
	case tabMail:
		if m.loading {
			return m.loadingText("Looking up mail records...")
		} else if m.mailErr != nil {
			return errorBox("Mail Lookup Failed", m.mailErr)
		} else if m.mailData != nil {
			return RenderMail(m.mailData)
		}
	case tabDNS:
		if m.loading {
			return m.loadingText("Looking up DNS records...")
		} else if m.dnsErr != nil {
			return errorBox("DNS Lookup Failed", m.dnsErr)
		} else if m.dnsData != nil {
			return RenderDNS(m.dnsData)
		}
	case tabTLS:
		if m.loading {
			return m.loadingText("Checking TLS certificate...")
		} else if m.tlsErr != nil {
			return errorBox("TLS Lookup Failed", m.tlsErr)
		} else if m.tlsData != nil {
			return RenderTLS(m.tlsData)
		}
	case tabHTTP:
		if m.loading {
			return m.loadingText("Fetching HTTP headers...")
		} else if m.httpErr != nil {
			return errorBox("HTTP Lookup Failed", m.httpErr)
		} else if m.httpData != nil {
			return RenderHTTP(m.httpData)
		}
	case tabStack:
		if m.loading {
			return m.loadingText("Detecting tech stack...")
		} else if m.stackErr != nil {
			return errorBox("Stack Detection Failed", m.stackErr)
		} else if m.stackData != nil {
			return RenderStack(m.stackData)
		}
	}
	return ""
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if !m.ready {
		return "\n  Loading..."
	}

	boxWidth := displayWidth
	if boxWidth > m.width {
		boxWidth = m.width
	}
	innerW := boxWidth - 2 - (boxPadH * 2)
	if innerW < 10 {
		innerW = 10
	}

	pad := strings.Repeat(" ", boxPadH)
	border := borderFg.Render("│")

	var b strings.Builder

	// Tab bar (hide for IP mode — single view, no tabs)
	if !m.isIP {
		b.WriteString(renderTabBar(m.active, m.tabList()))
		b.WriteString("\n")
	}

	// Top border
	b.WriteString(borderFg.Render("╭" + strings.Repeat("─", boxWidth-2) + "╮"))
	b.WriteString("\n")

	// Viewport content — each line gets left/right borders
	// Split and pad to exactly viewport height
	vpView := m.viewport.View()
	vpLines := strings.Split(vpView, "\n")

	vpHeight := m.viewport.Height
	for i := 0; i < vpHeight; i++ {
		line := ""
		if i < len(vpLines) {
			line = vpLines[i]
		}
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerW {
			line = line + strings.Repeat(" ", innerW-lineWidth)
		}
		b.WriteString(border + pad + line + pad + border + "\n")
	}

	// Bottom border
	b.WriteString(borderFg.Render("╰" + strings.Repeat("─", boxWidth-2) + "╯"))
	b.WriteString("\n")

	// Footer
	var footerParts []string
	if m.viewport.TotalLineCount() > m.viewport.Height {
		pct := fmt.Sprintf("%d%%", int(m.viewport.ScrollPercent()*100))
		footerParts = append(footerParts, fmt.Sprintf("↑↓ scroll • %s", pct))
	}
	if m.active == tabWhois && m.info != nil && m.info.RawResponse != "" {
		if m.showRaw {
			footerParts = append(footerParts, "r parsed")
		} else {
			footerParts = append(footerParts, "r raw")
		}
	}
	footerParts = append(footerParts, "q quit")
	b.WriteString(footerStyle.Render(strings.Join(footerParts, "  •  ")))

	return b.String()
}

func (m Model) tabList() []struct {
	key   string
	label string
	t     tab
} {
	if m.isIP {
		return []struct {
			key   string
			label string
			t     tab
		}{
			{"w", "IP Info", tabWhois},
		}
	}
	return []struct {
		key   string
		label string
		t     tab
	}{
		{"w", "WHOIS", tabWhois},
		{"d", "DNS", tabDNS},
		{"m", "Mail", tabMail},
		{"s", "SSL/TLS", tabTLS},
		{"h", "HTTP", tabHTTP},
		{"t", "Stack", tabStack},
	}
}

func renderTabBar(active tab, tabs []struct {
	key   string
	label string
	t     tab
}) string {

	var parts []string
	for _, t := range tabs {
		if t.t == active {
			key := activeTabKeyStyle.Render("[" + t.key + "]")
			label := activeTabStyle.Render(t.label)
			parts = append(parts, key+" "+label)
		} else {
			key := tabKeyStyle.Render("[" + t.key + "]")
			label := tabStyle.Render(t.label)
			parts = append(parts, key+" "+label)
		}
	}

	return tabBarStyle.Render(strings.Join(parts, "  "))
}

func errorBox(title string, err error) string {
	var b strings.Builder
	b.WriteString(domainSectionTitle(title))
	b.WriteString("\n\n")
	errStyle := lipgloss.NewStyle().Foreground(red)
	b.WriteString(errStyle.Render(fmt.Sprintf("  %v", err)))
	return b.String()
}

func fetchIP(ip string) tea.Cmd {
	return func() tea.Msg {
		info, err := retry.Do(func() (*rdap.IPInfo, error) {
			return rdap.QueryIP(ip)
		})
		return ipResultMsg{info: info, err: err}
	}
}

func fetchWhois(domain string) tea.Cmd {
	return func() tea.Msg {
		info, err := resolver.Lookup(domain)
		return whoisResultMsg{info: info, err: err}
	}
}

func fetchMail(domain string) tea.Cmd {
	return func() tea.Msg {
		records, err := retry.Do(func() (*mail.Records, error) {
			return mail.Lookup(domain)
		})
		return mailResultMsg{records: records, err: err}
	}
}

func fetchDNS(domain string) tea.Cmd {
	return func() tea.Msg {
		records, err := retry.Do(func() (*dns.Records, error) {
			return dns.Lookup(domain)
		})
		return dnsResultMsg{records: records, err: err}
	}
}

func fetchStack(domain string) tea.Cmd {
	return func() tea.Msg {
		result, err := retry.Do(func() (*stack.Result, error) {
			return stack.Detect(domain)
		})
		return stackResultMsg{result: result, err: err}
	}
}

func fetchHTTP(domain string) tea.Cmd {
	return func() tea.Msg {
		result, err := retry.Do(func() (*httpinfo.Result, error) {
			return httpinfo.Lookup(domain)
		})
		return httpResultMsg{result: result, err: err}
	}
}

func fetchTLS(domain string) tea.Cmd {
	return func() tea.Msg {
		cert, err := retry.Do(func() (*tlsinfo.CertInfo, error) {
			return tlsinfo.Lookup(domain)
		})
		return tlsResultMsg{cert: cert, err: err}
	}
}
