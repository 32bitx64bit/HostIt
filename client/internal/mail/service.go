package mail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdmail "net/mail"
	"net"
	"net/http"
	stdsmtp "net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"hostit/shared/emailcfg"
)

type Status struct {
	Enabled         bool      `json:"enabled"`
	Running         bool      `json:"running"`
	Domain          string    `json:"domain,omitempty"`
	MailHost        string    `json:"mailHost,omitempty"`
	TLSReady        bool      `json:"tlsReady"`
	TLSCertSource   string    `json:"tlsCertSource,omitempty"`
	DKIMReady       bool      `json:"dkimReady"`
	DKIMSelector    string    `json:"dkimSelector,omitempty"`
	DKIMDNSName     string    `json:"dkimDNSName,omitempty"`
	DKIMTXTValue    string    `json:"dkimTXTValue,omitempty"`
	DKIMKeySource   string    `json:"dkimKeySource,omitempty"`
	SubmissionAddr  string    `json:"submissionAddr,omitempty"`
	IMAPAddr        string    `json:"imapAddr,omitempty"`
	InboundSMTPAddr string    `json:"inboundSMTPAddr,omitempty"`
	InboundSMTP     bool      `json:"inboundSMTP"`
	MaxMessageBytes int64     `json:"maxMessageBytes,omitempty"`
	MaxRecipients   int       `json:"maxRecipients,omitempty"`
	AccountCount    int       `json:"accountCount"`
	MessageCount    int       `json:"messageCount"`
	LastError       string    `json:"lastError,omitempty"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type Service struct {
	dataDir string
	db      *sql.DB

	mu      sync.RWMutex
	cfg     emailcfg.Config
	status  Status
	started bool
	ctx     context.Context
	cancel  context.CancelFunc
	tlsCfg          *tls.Config
	tlsSrc          string
	acmeHTTPServer  *http.Server
	acmeHTTPLn      net.Listener
	dkimSigner      crypto.Signer
	dkimDNSName     string
	dkimTXTValue    string
	dkimKeySource   string

	submissionServer *smtp.Server
	submissionLn     net.Listener
	inboundServer    *smtp.Server
	inboundLn        net.Listener
	imapServer       *imapserver.Server
	imapLn           net.Listener
}

type accountRecord struct {
	Username     string
	Address      string
	PasswordHash string
	Enabled      bool
}

type storedMessage struct {
	ID           int64
	Username     string
	Mailbox      string
	InternalDate time.Time
	Flags        []string
	Raw          []byte
}

func NewService(dataDir string) (*Service, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("mail data dir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "mail.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Service{dataDir: dataDir, db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	cfg, _ := s.loadConfig(context.Background())
	s.cfg = cfg
	s.refreshStatusLocked("")
	return s, nil
}

func (s *Service) Close() error {
	s.Stop()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	return s.restartServersLocked("")
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.started = false
	s.closeListenersLocked()
	s.refreshStatusLocked("")
}

func (s *Service) ApplyConfig(cfg emailcfg.Config) error {
	cfg = emailcfg.Normalize(cfg)
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.saveConfigLocked(cfg); err != nil {
		return err
	}
	if err := s.reconcileAccountsLocked(cfg); err != nil {
		return err
	}
	s.cfg = cfg
	if s.started {
		return s.restartServersLocked("")
	}
	s.refreshStatusLocked("")
	return nil
}

func (s *Service) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.status
	st.UpdatedAt = st.UpdatedAt.UTC()
	return st
}

func (s *Service) Config() emailcfg.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Service) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			address TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			mailbox TEXT NOT NULL,
			internal_date INTEGER NOT NULL,
			flags_json TEXT NOT NULL,
			raw BLOB NOT NULL,
			created_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_messages_user_mailbox ON messages(username, mailbox, internal_date, id);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) loadConfig(ctx context.Context) (emailcfg.Config, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM config WHERE key = 'emailcfg'`).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return emailcfg.Config{}, nil
		}
		return emailcfg.Config{}, err
	}
	var cfg emailcfg.Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return emailcfg.Config{}, err
	}
	return emailcfg.Normalize(cfg), nil
}

func (s *Service) saveConfigLocked(cfg emailcfg.Config) error {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO config(key, value) VALUES('emailcfg', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(payload))
	return err
}

func (s *Service) reconcileAccountsLocked(cfg emailcfg.Config) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().Unix()
	seen := make(map[string]bool, len(cfg.Accounts))
	for _, acct := range cfg.Accounts {
		seen[strings.ToLower(acct.Username)] = true
		address := cfg.AddressFor(acct.Username)
		if address == "" {
			continue
		}
		_, err = tx.Exec(`INSERT INTO accounts(username, address, password_hash, enabled, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET address = excluded.address, password_hash = excluded.password_hash, enabled = excluded.enabled, updated_at = excluded.updated_at`,
			acct.Username, address, acct.PasswordHash, boolToInt(acct.Enabled), now, now)
		if err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT username FROM accounts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var stale []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return err
		}
		if !seen[strings.ToLower(username)] {
			stale = append(stale, username)
		}
	}
	for _, username := range stale {
		if _, err := tx.Exec(`DELETE FROM messages WHERE username = ?`, username); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM accounts WHERE username = ?`, username); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) refreshStatusLocked(lastErr string) {
	accountCount, _ := s.countAccountsLocked()
	messageCount, _ := s.countMessagesLocked()
	s.status = Status{
		Enabled:         s.cfg.Enabled,
		Running:         s.started && s.cfg.Enabled,
		Domain:          s.cfg.Domain,
		MailHost:        s.cfg.EffectiveMailHost(),
		TLSReady:        s.tlsCfg != nil,
		TLSCertSource:   s.tlsSrc,
		DKIMReady:       s.dkimSigner != nil,
		DKIMSelector:    s.cfg.DKIMSelector,
		DKIMDNSName:     s.dkimDNSName,
		DKIMTXTValue:    s.dkimTXTValue,
		DKIMKeySource:   s.dkimKeySource,
		SubmissionAddr:  s.cfg.SubmissionAddr,
		IMAPAddr:        s.cfg.IMAPAddr,
		InboundSMTPAddr: s.cfg.InboundSMTPAddr,
		InboundSMTP:     s.cfg.InboundSMTP,
		MaxMessageBytes: s.cfg.MaxMessageBytes,
		MaxRecipients:   s.cfg.MaxRecipients,
		AccountCount:    accountCount,
		MessageCount:    messageCount,
		LastError:       lastErr,
		UpdatedAt:       time.Now(),
	}
}

func (s *Service) countAccountsLocked() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&n)
	return n, err
}

func (s *Service) countMessagesLocked() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n)
	return n, err
}

func (s *Service) restartServersLocked(lastErr string) error {
	s.closeListenersLocked()
	s.tlsCfg = nil
	s.tlsSrc = ""
	s.dkimSigner = nil
	s.dkimDNSName = ""
	s.dkimTXTValue = ""
	s.dkimKeySource = ""
	if !s.cfg.Enabled {
		s.refreshStatusLocked(lastErr)
		return nil
	}
	tlsSetup, err := ensureMailTLSConfig(s.dataDir, s.cfg)
	if err != nil {
		s.refreshStatusLocked(err.Error())
		return err
	}
	s.tlsCfg = tlsSetup.Config
	s.tlsSrc = tlsSetup.Source
	if err := s.startACMEHTTPChallengeLocked(tlsSetup); err != nil {
		s.refreshStatusLocked(err.Error())
		return err
	}
	dkimSigner, dkimDNSName, dkimTXTValue, dkimKeySource, err := ensureDKIMSigner(s.dataDir, s.cfg)
	if err != nil {
		s.refreshStatusLocked(err.Error())
		return err
	}
	s.dkimSigner = dkimSigner
	s.dkimDNSName = dkimDNSName
	s.dkimTXTValue = dkimTXTValue
	s.dkimKeySource = dkimKeySource
	if err := s.startSubmissionLocked(); err != nil {
		s.refreshStatusLocked(err.Error())
		return err
	}
	if s.cfg.InboundSMTP {
		if err := s.startInboundLocked(); err != nil {
			s.closeListenersLocked()
			s.refreshStatusLocked(err.Error())
			return err
		}
	}
	if err := s.startIMAPLocked(); err != nil {
		s.closeListenersLocked()
		s.refreshStatusLocked(err.Error())
		return err
	}
	s.refreshStatusLocked(lastErr)
	return nil
}

func (s *Service) startACMEHTTPChallengeLocked(setup *mailTLSSetup) error {
	if setup == nil || setup.ACMEHTTPHandler == nil {
		return nil
	}
	ln, err := net.Listen("tcp", setup.ACMEHTTPAddr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:              setup.ACMEHTTPAddr,
		Handler:           setup.ACMEHTTPHandler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() { _ = httpSrv.Serve(ln) }()
	s.acmeHTTPLn = ln
	s.acmeHTTPServer = httpSrv
	return nil
}

func (s *Service) closeListenersLocked() {
	if s.submissionServer != nil {
		_ = s.submissionServer.Close()
		s.submissionServer = nil
	}
	if s.submissionLn != nil {
		_ = s.submissionLn.Close()
		s.submissionLn = nil
	}
	if s.inboundServer != nil {
		_ = s.inboundServer.Close()
		s.inboundServer = nil
	}
	if s.inboundLn != nil {
		_ = s.inboundLn.Close()
		s.inboundLn = nil
	}
	if s.imapServer != nil {
		_ = s.imapServer.Close()
		s.imapServer = nil
	}
	if s.imapLn != nil {
		_ = s.imapLn.Close()
		s.imapLn = nil
	}
	if s.acmeHTTPServer != nil {
		_ = s.acmeHTTPServer.Close()
		s.acmeHTTPServer = nil
	}
	if s.acmeHTTPLn != nil {
		_ = s.acmeHTTPLn.Close()
		s.acmeHTTPLn = nil
	}
}

func (s *Service) startSubmissionLocked() error {
	ln, err := net.Listen("tcp", s.cfg.SubmissionAddr)
	if err != nil {
		return err
	}
	backend := &smtpBackend{svc: s, submission: true}
	srv := smtp.NewServer(backend)
	srv.Addr = s.cfg.SubmissionAddr
	srv.Domain = s.cfg.EffectiveMailHost()
	srv.AllowInsecureAuth = false
	srv.TLSConfig = s.tlsCfg
	srv.MaxMessageBytes = s.cfg.MaxMessageBytes
	srv.MaxRecipients = s.cfg.MaxRecipients
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	go func() { _ = srv.Serve(ln) }()
	s.submissionLn = ln
	s.submissionServer = srv
	return nil
}

func (s *Service) startInboundLocked() error {
	ln, err := net.Listen("tcp", s.cfg.InboundSMTPAddr)
	if err != nil {
		return err
	}
	backend := &smtpBackend{svc: s, submission: false}
	srv := smtp.NewServer(backend)
	srv.Addr = s.cfg.InboundSMTPAddr
	srv.Domain = s.cfg.EffectiveMailHost()
	srv.AllowInsecureAuth = false
	srv.TLSConfig = s.tlsCfg
	srv.MaxMessageBytes = s.cfg.MaxMessageBytes
	srv.MaxRecipients = s.cfg.MaxRecipients
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second
	go func() { _ = srv.Serve(ln) }()
	s.inboundLn = ln
	s.inboundServer = srv
	return nil
}

func (s *Service) startIMAPLocked() error {
	ln, err := net.Listen("tcp", s.cfg.IMAPAddr)
	if err != nil {
		return err
	}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &imapSession{svc: s}, nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
		InsecureAuth: false,
		TLSConfig:    s.tlsCfg,
	})
	go func() { _ = srv.Serve(ln) }()
	s.imapLn = ln
	s.imapServer = srv
	return nil
}

func (s *Service) authenticate(username, password string) (*accountRecord, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	var rec accountRecord
	candidates := []string{username}
	if at := strings.IndexByte(username, '@'); at > 0 {
		candidates = append([]string{username[:at]}, candidates...)
	}
	for _, candidate := range candidates {
		err := s.db.QueryRow(`SELECT username, address, password_hash, enabled FROM accounts WHERE username = ? OR address = ? LIMIT 1`, candidate, username).Scan(&rec.Username, &rec.Address, &rec.PasswordHash, &rec.Enabled)
		if err == nil {
			if !rec.Enabled {
				return nil, fmt.Errorf("account disabled")
			}
			if bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)) != nil {
				return nil, fmt.Errorf("authentication failed")
			}
			return &rec, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("authentication failed")
}

func (s *Service) accountByAddress(address string) (*accountRecord, error) {
	address = strings.TrimSpace(strings.ToLower(address))
	var rec accountRecord
	err := s.db.QueryRow(`SELECT username, address, password_hash, enabled FROM accounts WHERE address = ? LIMIT 1`, address).Scan(&rec.Username, &rec.Address, &rec.PasswordHash, &rec.Enabled)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Service) listMessages(username string) ([]storedMessage, error) {
	rows, err := s.db.Query(`SELECT id, username, mailbox, internal_date, flags_json, raw FROM messages WHERE username = ? ORDER BY mailbox, internal_date, id`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedMessage
	for rows.Next() {
		var msg storedMessage
		var internal int64
		var flagsRaw string
		if err := rows.Scan(&msg.ID, &msg.Username, &msg.Mailbox, &internal, &flagsRaw, &msg.Raw); err != nil {
			return nil, err
		}
		msg.InternalDate = time.Unix(internal, 0)
		_ = json.Unmarshal([]byte(flagsRaw), &msg.Flags)
		out = append(out, msg)
	}
	return out, rows.Err()
}

func (s *Service) storeMessage(username, mailbox string, flags []string, raw []byte) error {
	flagsJSON, _ := json.Marshal(flags)
	_, err := s.db.Exec(`INSERT INTO messages(username, mailbox, internal_date, flags_json, raw, created_at) VALUES(?, ?, ?, ?, ?, ?)`, username, mailbox, time.Now().Unix(), string(flagsJSON), raw, time.Now().Unix())
	return err
}

func (s *Service) deliverLocal(address, mailbox string, raw []byte) error {
	rec, err := s.accountByAddress(address)
	if err != nil {
		return err
	}
	return s.storeMessage(rec.Username, mailbox, nil, raw)
}

func (s *Service) classifyRecipients(rcpts []string) (local []string, external []string) {
	domain := strings.ToLower(strings.TrimSpace(s.cfg.Domain))
	for _, rcpt := range rcpts {
		rcpt = strings.ToLower(strings.TrimSpace(rcpt))
		if rcpt == "" {
			continue
		}
		parts := strings.Split(rcpt, "@")
		if len(parts) == 2 && parts[1] == domain {
			local = append(local, rcpt)
		} else {
			external = append(external, rcpt)
		}
	}
	return local, external
}

func sendOutboundSMTP(from string, rcpts []string, raw []byte) error {
	for _, rcpt := range rcpts {
		parts := strings.Split(strings.TrimSpace(rcpt), "@")
		if len(parts) != 2 {
			return fmt.Errorf("invalid recipient %q", rcpt)
		}
		mxRecords, err := net.LookupMX(parts[1])
		if err != nil || len(mxRecords) == 0 {
			return fmt.Errorf("mx lookup failed for %s: %w", parts[1], err)
		}
		sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref })
		var sendErr error
		for _, mx := range mxRecords {
			host := strings.TrimSuffix(mx.Host, ".")
			sendErr = stdsmtp.SendMail(net.JoinHostPort(host, "25"), nil, from, []string{rcpt}, raw)
			if sendErr == nil {
				break
			}
		}
		if sendErr != nil {
			return sendErr
		}
	}
	return nil
}

type smtpBackend struct {
	svc        *Service
	submission bool
}

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &smtpSession{svc: b.svc, submission: b.submission}, nil
}

type smtpSession struct {
	svc          *Service
	submission   bool
	authenticated bool
	authAddress  string
	from         string
	rcpts        []string
}

func (s *smtpSession) AuthMechanisms() []string {
	if !s.submission {
		return nil
	}
	return []string{"PLAIN"}
}

func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	if !s.submission || strings.ToUpper(mech) != "PLAIN" {
		return nil, fmt.Errorf("unsupported auth mechanism")
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		rec, err := s.svc.authenticate(username, password)
		if err != nil {
			return err
		}
		s.authenticated = true
		s.authAddress = rec.Address
		return nil
	}), nil
}

func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	if s.submission && !s.authenticated {
		return fmt.Errorf("authentication required")
	}
	from = strings.ToLower(strings.TrimSpace(from))
	if s.submission && from != "" && s.authAddress != "" && !strings.EqualFold(from, s.authAddress) {
		return fmt.Errorf("authenticated sender must match mailbox")
	}
	s.from = from
	s.rcpts = nil
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	to = strings.ToLower(strings.TrimSpace(to))
	if to == "" {
		return fmt.Errorf("recipient required")
	}
	local, _ := s.svc.classifyRecipients([]string{to})
	if !s.submission && len(local) == 0 {
		return fmt.Errorf("relay denied")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if len(s.rcpts) == 0 {
		return fmt.Errorf("no recipients")
	}
	if s.from == "" && s.authAddress != "" {
		s.from = s.authAddress
	}
	local, external := s.svc.classifyRecipients(s.rcpts)
	for _, rcpt := range local {
		if err := s.svc.deliverLocal(rcpt, "INBOX", raw); err != nil {
			return err
		}
	}
	if len(external) > 0 {
		if !s.submission || !s.authenticated {
			return fmt.Errorf("relay denied")
		}
		signedRaw, err := signOutboundMessage(raw, s.svc.cfg, s.svc.dkimSigner, s.authAddress)
		if err != nil {
			return err
		}
		if err := sendOutboundSMTP(s.from, external, signedRaw); err != nil {
			return err
		}
	}
	if s.authenticated && s.authAddress != "" {
		if err := s.svc.deliverLocal(s.authAddress, "Sent", raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *smtpSession) Logout() error { return nil }

type imapSession struct {
	*imapmemserver.UserSession
	svc *Service
}

func (s *imapSession) Login(username, password string) error {
	rec, err := s.svc.authenticate(username, password)
	if err != nil {
		return imapserver.ErrAuthFailed
	}
	user, err := s.svc.buildIMAPUser(rec, password)
	if err != nil {
		return err
	}
	s.UserSession = imapmemserver.NewUserSession(user)
	return nil
}

func (s *imapSession) Close() error {
	if s.UserSession != nil {
		return s.UserSession.Close()
	}
	return nil
}

func (s *Service) buildIMAPUser(rec *accountRecord, password string) (*imapmemserver.User, error) {
	user := imapmemserver.NewUser(rec.Address, password)
	for _, box := range []string{"INBOX", "Drafts", "Sent", "Trash", "Archive"} {
		if box == "INBOX" {
			_ = user.Create(box, nil)
			continue
		}
		_ = user.Create(box, &imap.CreateOptions{})
	}
	msgs, err := s.listMessages(rec.Username)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		flags := make([]imap.Flag, 0, len(msg.Flags))
		for _, flag := range msg.Flags {
			flags = append(flags, imap.Flag(flag))
		}
		_, err := user.Append(msg.Mailbox, bytes.NewReader(msg.Raw), &imap.AppendOptions{Time: msg.InternalDate, Flags: flags})
		if err != nil {
			return nil, err
		}
	}
	return user, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ParseMessageSummary(raw []byte) (from string, subject string, err error) {
	msg, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", "", err
	}
	return msg.Header.Get("From"), msg.Header.Get("Subject"), nil
}
