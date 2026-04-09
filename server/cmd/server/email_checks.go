package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"hostit/shared/emailcfg"
)

type emailCheckStatus string

const (
	emailCheckOK   emailCheckStatus = "ok"
	emailCheckWarn emailCheckStatus = "warn"
	emailCheckFail emailCheckStatus = "fail"
)

type emailCheckResult struct {
	Code    string           `json:"code"`
	Name    string           `json:"name"`
	Status  emailCheckStatus `json:"status"`
	Summary string           `json:"summary"`
	Fix     string           `json:"fix,omitempty"`
	Details []string         `json:"details,omitempty"`
}

type emailCheckCounts struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

type emailCheckReport struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Summary     string             `json:"summary"`
	Counts      emailCheckCounts   `json:"counts"`
	Checks      []emailCheckResult `json:"checks"`
}

type emailDNSChecker struct {
	lookupMX  func(context.Context, string) ([]*net.MX, error)
	lookupTXT func(context.Context, string) ([]string, error)
	lookupIP  func(context.Context, string) ([]net.IPAddr, error)
	dial      func(context.Context, string, string) (net.Conn, error)
}

func newEmailDNSChecker() emailDNSChecker {
	resolver := net.DefaultResolver
	var dialer net.Dialer
	return emailDNSChecker{
		lookupMX: resolver.LookupMX,
		lookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return resolver.LookupTXT(ctx, name)
		},
		lookupIP: resolver.LookupIPAddr,
		dial:     dialer.DialContext,
	}
}

func runEmailCheckReport(ctx context.Context, cfg emailcfg.Config) emailCheckReport {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return newEmailDNSChecker().Run(ctx, cfg)
}

func (c emailDNSChecker) Run(ctx context.Context, cfg emailcfg.Config) emailCheckReport {
	cfg = emailcfg.Normalize(cfg)
	report := emailCheckReport{GeneratedAt: time.Now().UTC()}
	checks := make([]emailCheckResult, 0, 8)
	appendCheck := func(ch emailCheckResult) {
		checks = append(checks, ch)
	}

	domain := normalizeDNSName(cfg.Domain)
	mailHost := normalizeDNSName(cfg.EffectiveMailHost())
	dkimSelector := strings.TrimSpace(cfg.DKIMSelector)
	if dkimSelector == "" {
		dkimSelector = "hostit"
	}
	dkimName := normalizeDNSName(dkimSelector + "._domainkey." + domain)
	dmarcName := normalizeDNSName("_dmarc." + domain)
	recommendedSPF := ""
	recommendedDMARC := ""
	if domain != "" && mailHost != "" {
		recommendedSPF = fmt.Sprintf("v=spf1 mx a:%s -all", mailHost)
		recommendedDMARC = fmt.Sprintf("v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:postmaster@%s", domain)
	}

	if !cfg.Enabled {
		appendCheck(emailCheckResult{
			Code:    "email_enabled",
			Name:    "Email enabled",
			Status:  emailCheckWarn,
			Summary: "Email is disabled.",
			Fix:     "Enable Email on the Email page before relying on DNS or mail delivery.",
		})
	}
	if domain == "" {
		appendCheck(emailCheckResult{
			Code:    "domain",
			Name:    "Mailbox domain",
			Status:  emailCheckFail,
			Summary: "Mailbox domain is not configured.",
			Fix:     "Set Domain on the Email page to the exact part after the @ in your mailbox addresses.",
		})
	} else {
		appendCheck(emailCheckResult{Code: "domain", Name: "Mailbox domain", Status: emailCheckOK, Summary: "Mailbox domain is set to " + domain + "."})
	}
	if mailHost == "" {
		appendCheck(emailCheckResult{
			Code:    "mail_host",
			Name:    "Mail host",
			Status:  emailCheckFail,
			Summary: "Mail host is not configured.",
			Fix:     "Set Mail Host on the Email page to the public hostname other servers and mail clients should use.",
		})
	} else {
		appendCheck(emailCheckResult{Code: "mail_host", Name: "Mail host", Status: emailCheckOK, Summary: "Mail host is set to " + mailHost + "."})
	}
	if !cfg.InboundSMTP {
		appendCheck(emailCheckResult{
			Code:    "inbound_enabled",
			Name:    "Inbound SMTP",
			Status:  emailCheckWarn,
			Summary: "Inbound SMTP is disabled.",
			Fix:     "Enable Inbound SMTP if you want other servers to deliver mail to this domain.",
		})
	}

	if mailHost != "" {
		ips, err := c.lookupIP(ctx, mailHost)
		if err != nil || len(ips) == 0 {
			appendCheck(emailCheckResult{
				Code:    "mail_host_dns",
				Name:    "Mail host A / AAAA",
				Status:  emailCheckFail,
				Summary: "Mail host does not resolve to a public address.",
				Fix:     "Create an A or AAAA record for " + mailHost + " pointing to the host that accepts mail.",
				Details: compactDetails(errString(err)),
			})
		} else {
			details := make([]string, 0, len(ips))
			for _, ip := range uniqueIPAddrs(ips) {
				details = append(details, ip.String())
			}
			appendCheck(emailCheckResult{
				Code:    "mail_host_dns",
				Name:    "Mail host A / AAAA",
				Status:  emailCheckOK,
				Summary: "Mail host resolves correctly.",
				Details: details,
			})
			appendCheck(c.checkTCPPort(ctx, "smtp_port_25", "Inbound SMTP port 25", mailHost, ips, 25,
				"Open or forward public TCP 25 on "+mailHost+" to the machine that accepts inbound mail."))
			appendCheck(c.checkTCPPort(ctx, "submission_port_587", "Submission port 587", mailHost, ips, 587,
				"Open or forward public TCP 587 on "+mailHost+" so mail clients and apps can send using authenticated submission."))
			appendCheck(c.checkTCPPort(ctx, "submission_tls_port_465", "Submission TLS port 465", mailHost, ips, 465,
				"Open or forward public TCP 465 on "+mailHost+" so mail clients and apps can send using implicit TLS submission."))
			appendCheck(c.checkTCPPort(ctx, "imap_port_143", "IMAP port 143", mailHost, ips, 143,
				"Open or forward public TCP 143 on "+mailHost+" so mail clients can connect with IMAP STARTTLS."))
			appendCheck(c.checkTCPPort(ctx, "imap_tls_port_993", "IMAP TLS port 993", mailHost, ips, 993,
				"Open or forward public TCP 993 on "+mailHost+" so mail clients can connect with IMAPS."))
			if cfg.AutoTLS {
				appendCheck(c.checkTCPPort(ctx, "acme_port_80", "ACME port 80", mailHost, ips, 80,
					"Free or forward public TCP 80 on "+mailHost+" so Automatic Public TLS can complete Let's Encrypt validation."))
			}
		}
	}

	if domain != "" {
		appendCheck(c.checkMX(ctx, domain, mailHost))
		appendCheck(c.checkSPF(ctx, domain, recommendedSPF, mailHost))
		appendCheck(c.checkDMARC(ctx, dmarcName, recommendedDMARC, dkimName))
		appendCheck(c.checkDKIM(ctx, dkimName, dmarcName))
	}

	report.Checks = checks
	for _, ch := range checks {
		switch ch.Status {
		case emailCheckOK:
			report.Counts.OK++
		case emailCheckWarn:
			report.Counts.Warn++
		case emailCheckFail:
			report.Counts.Fail++
		}
	}
	report.Summary = fmt.Sprintf("%d passed, %d warnings, %d failures", report.Counts.OK, report.Counts.Warn, report.Counts.Fail)
	return report
}

func (c emailDNSChecker) checkMX(ctx context.Context, domain, mailHost string) emailCheckResult {
	result := emailCheckResult{Code: "mx", Name: "MX record"}
	mxRecords, err := c.lookupMX(ctx, domain)
	if err != nil || len(mxRecords) == 0 {
		result.Status = emailCheckFail
		result.Summary = "MX record is missing."
		result.Fix = "Create an MX record for " + domain + " pointing to " + fallbackName(mailHost, "your mail host") + " with priority 10."
		result.Details = compactDetails(errString(err))
		return result
	}
	sort.Slice(mxRecords, func(i, j int) bool {
		if mxRecords[i].Pref == mxRecords[j].Pref {
			return normalizeDNSName(mxRecords[i].Host) < normalizeDNSName(mxRecords[j].Host)
		}
		return mxRecords[i].Pref < mxRecords[j].Pref
	})
	details := make([]string, 0, len(mxRecords))
	found := false
	for _, mx := range mxRecords {
		host := normalizeDNSName(mx.Host)
		details = append(details, fmt.Sprintf("priority %d → %s", mx.Pref, host))
		if host == mailHost && mailHost != "" {
			found = true
		}
	}
	if found {
		result.Status = emailCheckOK
		result.Summary = "MX record points to the configured mail host."
		result.Details = details
		return result
	}
	result.Status = emailCheckFail
	result.Summary = "MX record does not point to the configured mail host."
	result.Fix = "Update the MX record for " + domain + " so it points to " + fallbackName(mailHost, "your mail host") + "."
	result.Details = details
	return result
}

func (c emailDNSChecker) checkSPF(ctx context.Context, domain, recommended, mailHost string) emailCheckResult {
	result := emailCheckResult{Code: "spf", Name: "SPF TXT"}
	txts, err := c.lookupTXT(ctx, domain)
	if err != nil {
		result.Status = emailCheckFail
		result.Summary = "SPF TXT lookup failed."
		result.Fix = "Publish a TXT record on " + domain + " with: " + fallbackName(recommended, "your SPF policy")
		result.Details = compactDetails(errString(err))
		return result
	}
	spf := matchingTXT(txts, func(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=spf1") })
	if len(spf) == 0 {
		result.Status = emailCheckFail
		result.Summary = "SPF TXT record is missing."
		result.Fix = "Publish a TXT record on " + domain + " with: " + fallbackName(recommended, "your SPF policy")
		return result
	}
	result.Details = spf
	good := false
	for _, rec := range spf {
		norm := strings.ToLower(strings.TrimSpace(rec))
		if strings.Contains(norm, " mx") || strings.Contains(norm, " a:"+strings.ToLower(mailHost)) || strings.Contains(norm, " ip4:") || strings.Contains(norm, " include:") {
			good = true
			break
		}
	}
	if good {
		result.Status = emailCheckOK
		result.Summary = "SPF TXT record looks usable."
		return result
	}
	result.Status = emailCheckWarn
	result.Summary = "SPF TXT exists, but it may not authorize this mail setup."
	result.Fix = "If mail is sent directly from this stack, update SPF to something like: " + fallbackName(recommended, "your SPF policy")
	return result
}

func (c emailDNSChecker) checkDMARC(ctx context.Context, dmarcName, recommended, dkimName string) emailCheckResult {
	result := emailCheckResult{Code: "dmarc", Name: "DMARC TXT"}
	txts, err := c.lookupTXT(ctx, dmarcName)
	if err != nil {
		result.Status = emailCheckFail
		result.Summary = "DMARC TXT lookup failed."
		result.Fix = "Publish a TXT record at " + dmarcName + " with: " + fallbackName(recommended, "your DMARC policy")
		result.Details = compactDetails(errString(err))
		return result
	}
	dmarc := matchingTXT(txts, func(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dmarc1") })
	if len(dmarc) > 0 {
		result.Status = emailCheckOK
		result.Summary = "DMARC TXT record is present."
		result.Details = dmarc
		return result
	}
	if swapped := matchingTXT(txts, func(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dkim1") }); len(swapped) > 0 {
		result.Status = emailCheckFail
		result.Summary = "DMARC location contains a DKIM key instead of a DMARC policy."
		result.Fix = "Move the DKIM key to " + dkimName + " and publish the DMARC policy at " + dmarcName + "."
		result.Details = swapped
		return result
	}
	result.Status = emailCheckFail
	result.Summary = "DMARC TXT record is missing or invalid."
	result.Fix = "Publish a TXT record at " + dmarcName + " with: " + fallbackName(recommended, "your DMARC policy")
	result.Details = nonEmptyTXT(txts)
	return result
}

func (c emailDNSChecker) checkDKIM(ctx context.Context, dkimName, dmarcName string) emailCheckResult {
	result := emailCheckResult{Code: "dkim", Name: "DKIM TXT"}
	txts, err := c.lookupTXT(ctx, dkimName)
	if err != nil {
		result.Status = emailCheckFail
		result.Summary = "DKIM TXT lookup failed."
		result.Fix = "Publish the exact DKIM TXT value from the agent dashboard at " + dkimName + "."
		result.Details = compactDetails(errString(err))
		return result
	}
	dkim := matchingTXT(txts, func(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dkim1") })
	if len(dkim) > 0 {
		result.Status = emailCheckOK
		result.Summary = "DKIM TXT record is present."
		result.Details = trimDetails(dkim, 1)
		return result
	}
	if swapped := matchingTXT(txts, func(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dmarc1") }); len(swapped) > 0 {
		result.Status = emailCheckFail
		result.Summary = "DKIM location contains a DMARC policy instead of a DKIM key."
		result.Fix = "Move the DMARC policy to " + dmarcName + " and publish the DKIM key at " + dkimName + "."
		result.Details = swapped
		return result
	}
	result.Status = emailCheckFail
	result.Summary = "DKIM TXT record is missing or invalid."
	result.Fix = "Publish the exact DKIM TXT value from the agent dashboard at " + dkimName + "."
	result.Details = nonEmptyTXT(txts)
	return result
}

func (c emailDNSChecker) checkTCPPort(ctx context.Context, code, name, host string, ips []net.IPAddr, port int, fix string) emailCheckResult {
	result := emailCheckResult{Code: code, Name: name}
	var errs []string
	for _, ip := range uniqueIPAddrs(ips) {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		dialCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		conn, err := c.dial(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			result.Status = emailCheckOK
			result.Summary = fmt.Sprintf("%s is reachable on %s.", name, host)
			result.Details = []string{addr}
			return result
		}
		errs = append(errs, addr+": "+err.Error())
	}
	result.Status = emailCheckFail
	result.Summary = fmt.Sprintf("%s is not reachable on %s.", name, host)
	result.Fix = fix
	result.Details = trimDetails(errs, 3)
	return result
}

func normalizeDNSName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	return strings.TrimSuffix(v, ".")
}

func matchingTXT(records []string, match func(string) bool) []string {
	out := make([]string, 0, len(records))
	for _, rec := range records {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		if match(rec) {
			out = append(out, rec)
		}
	}
	return out
}

func nonEmptyTXT(records []string) []string {
	out := make([]string, 0, len(records))
	for _, rec := range records {
		rec = strings.TrimSpace(rec)
		if rec != "" {
			out = append(out, rec)
		}
	}
	return trimDetails(out, 3)
}

func trimDetails(in []string, max int) []string {
	if max <= 0 || len(in) <= max {
		return in
	}
	out := append([]string(nil), in[:max]...)
	out = append(out, fmt.Sprintf("…and %d more", len(in)-max))
	return out
}

func uniqueIPAddrs(in []net.IPAddr) []net.IP {
	seen := map[string]struct{}{}
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		if ip.IP == nil {
			continue
		}
		s := ip.IP.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, ip.IP)
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func compactDetails(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return []string{v}
}

func fallbackName(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}
