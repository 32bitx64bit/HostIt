package tunnel

import (
	"fmt"
	"net"
	"strings"

	"hostit/shared/emailcfg"
)

var emailInboundPublicAddr = ":25"

const (
	internalEmailInboundRouteName       = "hostit_mail_inbound"
	internalEmailSubmissionRouteName    = "hostit_mail_submission"
	internalEmailSubmissionTLSRouteName = "hostit_mail_submission_tls"
	internalEmailIMAPRouteName          = "hostit_mail_imap"
	internalEmailIMAPTLSRouteName       = "hostit_mail_imap_tls"
	internalEmailACMEHTTPRouteName      = "hostit_mail_acme_http"
)

func effectiveRoutes(cfg ServerConfig) []RouteConfig {
	routes := append([]RouteConfig(nil), cfg.Routes...)
	routes = append(routes, emailSynthRoutes(cfg)...)
	return routes
}

func emailSynthRoutes(cfg ServerConfig) []RouteConfig {
	var routes []RouteConfig
	if rt, ok := emailInboundRoute(cfg); ok {
		routes = append(routes, rt)
	}
	routes = append(routes, emailClientRoutes(cfg)...)
	if rt, ok := emailACMEHTTPRoute(cfg); ok {
		routes = append(routes, rt)
	}
	return routes
}

func emailClientRoutes(cfg ServerConfig) []RouteConfig {
	email := emailcfg.Normalize(cfg.Email)
	if !email.Enabled {
		return nil
	}
	return []RouteConfig{
		{Name: internalEmailSubmissionRouteName, Proto: "tcp", PublicAddr: ":587", LocalAddr: emailDialAddr(email.SubmissionAddr, 587)},
		{Name: internalEmailSubmissionTLSRouteName, Proto: "tcp", PublicAddr: ":465", LocalAddr: emailDialAddr(email.SubmissionTLSAddr, 465)},
		{Name: internalEmailIMAPRouteName, Proto: "tcp", PublicAddr: ":143", LocalAddr: emailDialAddr(email.IMAPAddr, 143)},
		{Name: internalEmailIMAPTLSRouteName, Proto: "tcp", PublicAddr: ":993", LocalAddr: emailDialAddr(email.IMAPTLSAddr, 993)},
	}
}

func emailInboundRoute(cfg ServerConfig) (RouteConfig, bool) {
	email := emailcfg.Normalize(cfg.Email)
	if !email.Enabled || !email.InboundSMTP {
		return RouteConfig{}, false
	}
	return RouteConfig{
		Name:       internalEmailInboundRouteName,
		Proto:      "tcp",
		PublicAddr: emailInboundPublicAddr,
		LocalAddr:  emailDialAddr(email.InboundSMTPAddr, 25),
	}, true
}

func emailACMEHTTPRoute(cfg ServerConfig) (RouteConfig, bool) {
	email := emailcfg.Normalize(cfg.Email)
	if !email.Enabled || !email.AutoTLS {
		return RouteConfig{}, false
	}
	if strings.TrimSpace(email.ACMEHTTPAddr) == "" {
		return RouteConfig{}, false
	}
	return RouteConfig{
		Name:      internalEmailACMEHTTPRouteName,
		Proto:     "tcp",
		LocalAddr: emailDialAddr(email.ACMEHTTPAddr, 80),
	}, true
}

func emailDialAddr(listenAddr string, fallbackPort int) string {
	addr, err := net.ResolveTCPAddr("tcp", strings.TrimSpace(listenAddr))
	if err != nil || addr == nil {
		return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", fallbackPort))
	}
	host := "127.0.0.1"
	if addr.IP != nil && !addr.IP.IsUnspecified() {
		host = addr.IP.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", addr.Port))
}

func normalizeRoutes(cfg *ServerConfig) {
	reserved := map[string]int{}
	for i := range cfg.Routes {
		name := strings.TrimSpace(cfg.Routes[i].Name)
		if name == "" {
			name = "default"
		}
		cfg.Routes[i].Name = name
		reserved[name]++
	}

	used := map[string]bool{}
	for i := range cfg.Routes {
		base := cfg.Routes[i].Name
		name := base
		if used[name] {
			n := 2
			for {
				cand := fmt.Sprintf("%s-%d", base, n)
				if !used[cand] && reserved[cand] == 0 {
					name = cand
					break
				}
				n++
			}
		}
		cfg.Routes[i].Name = name
		used[name] = true

		cfg.Routes[i].Proto = strings.ToLower(strings.TrimSpace(cfg.Routes[i].Proto))
		if cfg.Routes[i].Proto == "" {
			cfg.Routes[i].Proto = "tcp"
		}
		cfg.Routes[i].PublicAddr = strings.TrimSpace(cfg.Routes[i].PublicAddr)
		cfg.Routes[i].LocalAddr = strings.TrimSpace(cfg.Routes[i].LocalAddr)
		cfg.Routes[i].Domain = normalizeHostname(cfg.Routes[i].Domain)
	}

	cfg.DomainHTTPAddr = strings.TrimSpace(cfg.DomainHTTPAddr)
	cfg.DomainHTTPSAddr = strings.TrimSpace(cfg.DomainHTTPSAddr)
	cfg.DomainBase = normalizeHostname(cfg.DomainBase)
	cfg.DomainACMEEmail = strings.TrimSpace(cfg.DomainACMEEmail)
	cfg.Email = emailcfg.Normalize(cfg.Email)
}

func publicTCPAddrsConflict(a, b string) bool {
	aa, errA := net.ResolveTCPAddr("tcp", strings.TrimSpace(a))
	bb, errB := net.ResolveTCPAddr("tcp", strings.TrimSpace(b))
	if errA != nil || errB != nil || aa == nil || bb == nil {
		return false
	}
	if aa.Port != bb.Port {
		return false
	}
	aHostWildcard := aa.IP == nil || aa.IP.IsUnspecified()
	bHostWildcard := bb.IP == nil || bb.IP.IsUnspecified()
	if aHostWildcard || bHostWildcard {
		return true
	}
	return aa.IP.Equal(bb.IP)
}
