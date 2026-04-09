package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	stdsmtp "net/smtp"
	"strings"
	"time"

	"hostit/shared/emailcfg"
	"hostit/shared/protocol"
)

func runEmailCheckReportWithLive(ctx context.Context, cfg emailcfg.Config, runner *serverRunner) emailCheckReport {
	report := runEmailCheckReport(ctx, cfg)
	if runner == nil {
		return report
	}
	for _, ch := range runLiveEmailChecks(ctx, cfg, runner) {
		report.Checks = append(report.Checks, ch)
	}
	recomputeEmailCheckReport(&report)
	return report
}

func runLiveEmailChecks(ctx context.Context, cfg emailcfg.Config, runner *serverRunner) []emailCheckResult {
	cfg = emailcfg.Normalize(cfg)
	checks := make([]emailCheckResult, 0, 10)
	runtime := runner.EmailStatus()
	if runtime.PublicInboundListening {
		checks = append(checks, emailCheckResult{
			Code:    "server_listener_25",
			Name:    "Server runtime listener :25",
			Status:  emailCheckOK,
			Summary: "Server is listening for inbound SMTP on the public side.",
			Details: compactDetails(runtime.PublicInboundAddr),
		})
	} else {
		checks = append(checks, emailCheckResult{
			Code:    "server_listener_25",
			Name:    "Server runtime listener :25",
			Status:  emailCheckFail,
			Summary: "Server is not listening for inbound SMTP on public TCP 25.",
			Fix:     "Make sure inbound SMTP is enabled and nothing else on the server is occupying public TCP 25.",
		})
	}

	var probeAcct emailcfg.Account
	foundAccount := false
	for _, acct := range cfg.Accounts {
		if acct.Enabled && cfg.AddressFor(acct.Username) != "" {
			probeAcct = acct
			foundAccount = true
			break
		}
	}
	if !foundAccount {
		checks = append(checks, emailCheckResult{
			Code:    "probe_account",
			Name:    "Probe mailbox",
			Status:  emailCheckWarn,
			Summary: "No enabled mailbox account is available for a real mail architecture test.",
			Fix:     "Enable at least one mailbox account on the Email page so the tester can deliver a probe message.",
		})
		return checks
	}
	probeAddress := cfg.AddressFor(probeAcct.Username)
	inboundProbeID := randomProbeID()
	outboundProbeID := randomProbeID()

	sinkAddr, sinkCh, closeSink, err := startEmailProbeSink(ctx)
	if err != nil {
		checks = append(checks, emailCheckResult{
			Code:    "outbound_sink",
			Name:    "Outbound test sink",
			Status:  emailCheckFail,
			Summary: "Could not start the temporary outbound SMTP sink on the server.",
			Details: compactDetails(err.Error()),
		})
		return checks
	}
	defer closeSink()

	inboundErr := sendInboundProbeSMTP("127.0.0.1:25", probeAddress, inboundProbeID)
	if inboundErr == nil {
		checks = append(checks, emailCheckResult{
			Code:    "inbound_probe_send",
			Name:    "Server → client SMTP inject",
			Status:  emailCheckOK,
			Summary: "Server accepted the inbound SMTP probe for delivery to the agent mailbox.",
		})
	} else {
		checks = append(checks, emailCheckResult{
			Code:    "inbound_probe_send",
			Name:    "Server → client SMTP inject",
			Status:  emailCheckFail,
			Summary: "Server could not inject the inbound SMTP probe through public port 25.",
			Fix:     "Make sure the server is listening on TCP 25 and forwarding the inbound mail route to the agent.",
			Details: compactDetails(inboundErr.Error()),
		})
	}

	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	probeRes, probeErr := runner.RunAgentEmailProbe(probeCtx, protocol.EmailProbeRequest{
		Username:        probeAcct.Username,
		Address:         probeAddress,
		InboundProbeID:  inboundProbeID,
		OutboundProbeID: outboundProbeID,
		OutboundTarget:  sinkAddr,
		OutboundRcpt:    "probe@hostit.invalid",
		TimeoutSeconds:  8,
	})
	if probeErr != nil {
		checks = append(checks, emailCheckResult{
			Code:    "agent_mail_probe",
			Name:    "Agent mail probe",
			Status:  emailCheckFail,
			Summary: "The server could not run the live mail probe on the agent.",
			Fix:     "Make sure the agent is connected and the built-in mail service is running.",
			Details: compactDetails(probeErr.Error()),
		})
		return checks
	}

	for _, listener := range probeRes.ListenerChecks {
		status := emailCheckOK
		summary := listener.Name + " listener is running."
		if !listener.Listening {
			status = emailCheckFail
			summary = listener.Name + " listener is not running."
		}
		ch := emailCheckResult{
			Code:    "agent_listener_" + listener.Code,
			Name:    listener.Name + " listener",
			Status:  status,
			Summary: summary,
		}
		if listener.Addr != "" || listener.Details != "" {
			ch.Details = trimDetails([]string{listener.Addr, listener.Details}, 2)
		}
		if !listener.Listening {
			ch.Fix = "Make sure the agent mail service started successfully and nothing else is occupying that local port."
		}
		checks = append(checks, ch)
	}

	inboundStatus := emailCheckFail
	if probeRes.InboundReady {
		inboundStatus = emailCheckOK
	}
	checks = append(checks, emailCheckResult{
		Code:    "inbound_probe_receive",
		Name:    "Inbound architecture probe",
		Status:  inboundStatus,
		Summary: fallbackName(strings.TrimSpace(probeRes.InboundSummary), "Inbound probe did not reach the mailbox."),
		Fix:     map[emailCheckStatus]string{emailCheckFail: "Check the server public TCP 25 listener, the mail inbound tunnel route, and the agent inbound SMTP listener."}[inboundStatus],
	})

	outboundStatus := emailCheckFail
	outboundSummary := strings.TrimSpace(probeRes.OutboundSummary)
	if probeRes.OutboundReady {
		select {
		case raw := <-sinkCh:
			if probeMessageContains(raw, outboundProbeID) {
				outboundStatus = emailCheckOK
				outboundSummary = "Outbound probe was relayed back to the server SMTP sink."
			} else {
				outboundSummary = "Outbound probe reached the server sink, but the probe marker was missing."
			}
		case <-time.After(2 * time.Second):
			outboundSummary = "Agent reported outbound success, but the server sink did not receive the probe message in time."
		}
		if outboundStatus != emailCheckOK && outboundSummary == "" {
			outboundSummary = "Outbound probe failed."
		}
	} else if outboundSummary == "" {
		outboundSummary = "Outbound probe failed."
	}
	checks = append(checks, emailCheckResult{
		Code:    "outbound_probe",
		Name:    "Outbound architecture probe",
		Status:  outboundStatus,
		Summary: outboundSummary,
		Fix:     map[emailCheckStatus]string{emailCheckFail: "Check agent submission/outbound mail startup, the server data tunnel, and server egress SMTP connectivity."}[outboundStatus],
	})

	if strings.TrimSpace(probeRes.Error) != "" {
		checks = append(checks, emailCheckResult{
			Code:    "agent_probe_error",
			Name:    "Agent probe detail",
			Status:  emailCheckWarn,
			Summary: "The agent reported additional probe details.",
			Details: compactDetails(probeRes.Error),
		})
	}

	return checks
}

func recomputeEmailCheckReport(report *emailCheckReport) {
	report.Counts = emailCheckCounts{}
	for _, ch := range report.Checks {
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
}

func randomProbeID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("probe-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func sendInboundProbeSMTP(targetAddr, toAddress, probeID string) error {
	from := "probe@hostit.invalid"
	raw := buildServerProbeMessage(from, toAddress, probeID)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil || strings.TrimSpace(host) == "" {
		host = "localhost"
	}
	client, err := stdsmtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(toAddress); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(raw); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildServerProbeMessage(from, to, probeID string) []byte {
	return []byte(strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: HostIt inbound probe",
		"Message-ID: <" + probeID + "@hostit.server>",
		"X-HostIt-Probe: " + probeID,
		"",
		"HostIt inbound architecture probe",
		"",
	}, "\r\n"))
}

func probeMessageContains(raw []byte, probeID string) bool {
	return bytes.Contains(raw, []byte("X-HostIt-Probe: "+probeID))
}

func startEmailProbeSink(ctx context.Context) (string, <-chan []byte, func() error, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	ch := make(chan []byte, 1)
	go func() {
		defer close(ch)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleEmailProbeSinkConn(ctx, conn, ch)
		}
	}()
	return ln.Addr().String(), ch, ln.Close, nil
}

func handleEmailProbeSinkConn(ctx context.Context, conn net.Conn, ch chan<- []byte) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	_, _ = io.WriteString(conn, "220 hostit-probe ESMTP\r\n")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			_, _ = io.WriteString(conn, "250-hostit-probe\r\n250 OK\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			_, _ = io.WriteString(conn, "250 2.1.0 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			_, _ = io.WriteString(conn, "250 2.1.5 OK\r\n")
		case strings.HasPrefix(cmd, "DATA"):
			_, _ = io.WriteString(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			var raw bytes.Buffer
			for {
				part, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if part == ".\r\n" || strings.TrimSpace(part) == "." {
					break
				}
				raw.WriteString(part)
			}
			select {
			case ch <- raw.Bytes():
			default:
			}
			_, _ = io.WriteString(conn, "250 2.0.0 queued\r\n")
		case strings.HasPrefix(cmd, "QUIT"):
			_, _ = io.WriteString(conn, "221 2.0.0 bye\r\n")
			return
		default:
			_, _ = io.WriteString(conn, "250 OK\r\n")
		}
	}
}
