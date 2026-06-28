package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"hostit/server/internal/appstore"
	"hostit/server/internal/auth"
	"hostit/server/internal/serverlog"
	"hostit/server/internal/tlsutil"
	"hostit/server/internal/tunnel"
	"hostit/shared/configio"
	"hostit/shared/crypto"
	"hostit/shared/emailcfg"
	"hostit/shared/logging"
	"hostit/shared/module"
	"hostit/shared/protocol"
	"hostit/shared/systemdutil"
	"hostit/shared/updater"
	"hostit/shared/version"
	"hostit/shared/web"

	"golang.org/x/crypto/bcrypt"
)

var startTime = time.Now()

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logging.Global().Warnf(logging.CatSystem, "failed to encode JSON response: %v", err)
	}
}

func main() {
	var controlAddr string
	var dataAddr string
	var token string
	var pairTimeout time.Duration
	var webAddr string
	var configPath string
	var authDBPath string
	var cookieSecure bool
	var sessionTTL time.Duration
	var disableTLS bool
	var tlsCert string
	var tlsKey string
	var webShutdownTimeout time.Duration

	flag.StringVar(&controlAddr, "control", ":7000", "control listen address")
	flag.StringVar(&dataAddr, "data", ":7001", "data listen address")
	flag.StringVar(&token, "token", "", "shared token (optional)")
	flag.BoolVar(&disableTLS, "disable-tls", false, "disable TLS for agent<->server control/data TCP")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate PEM path (default: alongside config)")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key PEM path (default: alongside config)")
	flag.DurationVar(&pairTimeout, "pair-timeout", 10*time.Second, "max wait for agent to attach")
	flag.StringVar(&webAddr, "web", "127.0.0.1:7002", "web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "server.json", "path to server config JSON")
	flag.StringVar(&authDBPath, "auth-db", "auth.db", "sqlite auth db path")
	flag.BoolVar(&cookieSecure, "cookie-secure", true, "set Secure on cookies (enabled by default since dashboard uses HTTPS)")
	flag.DurationVar(&sessionTTL, "session-ttl", 7*24*time.Hour, "session lifetime")
	flag.DurationVar(&webShutdownTimeout, "web-shutdown-timeout", 2*time.Second, "web server graceful shutdown timeout")
	flag.Parse()

	serverlog.Init()
	log.SetOutput(io.MultiWriter(os.Stderr, serverlog.NewUILogWriter("stdio", serverlog.UILogs)))
	slog := serverlog.Log

	ctx, cancel := notifyContext(context.Background())
	defer cancel()

	cfg := tunnel.ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       token,
		DisableTLS:  disableTLS,
		TLSCertFile: tlsCert,
		TLSKeyFile:  tlsKey,
		PairTimeout: pairTimeout,
	}
	loaded, _ := configio.Load(configPath, &cfg)
	if disableTLS {
		cfg.DisableTLS = true
	}
	if strings.TrimSpace(tlsCert) != "" {
		cfg.TLSCertFile = tlsCert
	}
	if strings.TrimSpace(tlsKey) != "" {
		cfg.TLSKeyFile = tlsKey
	}
	// Default encryption: aes-128 for fresh installs (~14% faster than aes-256 on AES-NI),
	// "none" for existing installs so upgrades are not silently opted-in.
	if cfg.EncryptionAlgorithm == "" {
		if !loaded {
			cfg.EncryptionAlgorithm = "aes-128"
		} else {
			cfg.EncryptionAlgorithm = "none"
		}
	}

	if strings.TrimSpace(cfg.Token) == "" {
		tok, err := genToken()
		if err != nil {
			slog.Fatal(logging.CatSystem, "failed to generate server token", serverlog.F("error", err))
		}
		cfg.Token = tok
		_ = configio.Save(configPath, cfg)
		slog.Info(logging.CatSystem, "generated new server token (was empty)")
	}

	if !cfg.DisableTLS {
		cfgDir := filepath.Dir(configPath)
		if strings.TrimSpace(cfg.TLSCertFile) == "" {
			cfg.TLSCertFile = filepath.Join(cfgDir, "server.crt")
		}
		if strings.TrimSpace(cfg.TLSKeyFile) == "" {
			cfg.TLSKeyFile = filepath.Join(cfgDir, "server.key")
		}
		fp, err := tlsutil.EnsureSelfSigned(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			slog.Fatal(logging.CatSystem, "TLS setup failed", serverlog.F("error", err))
		}
		_ = configio.Save(configPath, cfg)
		slog.Info(logging.CatEncryption, "tunnel TLS enabled", serverlog.F("cert_sha256", fp))
	}

	// Enable WebHTTPS by default for new configs.
	cfgDir := filepath.Dir(configPath)
	if cfg.DomainRenewBefore <= 0 {
		cfg.DomainRenewBefore = 7 * 24 * time.Hour
	}
	if strings.TrimSpace(cfg.DomainHTTPAddr) == "" {
		cfg.DomainHTTPAddr = ":80"
	}
	if strings.TrimSpace(cfg.DomainHTTPSAddr) == "" {
		cfg.DomainHTTPSAddr = ":443"
	}
	if strings.TrimSpace(cfg.DomainCertDir) == "" {
		cfg.DomainCertDir = filepath.Join(cfgDir, "domains")
	}
	cfg.DomainBase = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.DomainBase)), ".")
	cfg.DomainACMEEmail = strings.TrimSpace(cfg.DomainACMEEmail)
	for i := range cfg.Routes {
		cfg.Routes[i].Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cfg.Routes[i].Domain)), ".")
	}
	if !cfg.WebHTTPS {
		// Fresh config: enable HTTPS by default.
		webCert := strings.TrimSpace(cfg.WebTLSCertFile)
		if webCert == "" {
			webCert = filepath.Join(cfgDir, "web.crt")
		}
		if _, err := os.Stat(webCert); os.IsNotExist(err) {
			cfg.WebHTTPS = true
			slog.Info(logging.CatSystem, "enabling WebHTTPS by default for new installation")
		}
	}
	if cfg.WebHTTPS {
		if strings.TrimSpace(cfg.WebTLSCertFile) == "" {
			cfg.WebTLSCertFile = filepath.Join(cfgDir, "web.crt")
		}
		if strings.TrimSpace(cfg.WebTLSKeyFile) == "" {
			cfg.WebTLSKeyFile = filepath.Join(cfgDir, "web.key")
		}
		fp, err := tlsutil.EnsureSelfSignedDashboard(cfg.WebTLSCertFile, cfg.WebTLSKeyFile)
		if err != nil {
			slog.Error(logging.CatSystem, "dashboard TLS setup failed", serverlog.F("error", err))
		} else {
			_ = configio.Save(configPath, cfg)
			slog.Info(logging.CatEncryption, "dashboard HTTPS enabled", serverlog.F("cert_sha256", fp))
		}
	}

	appStore, err := appstore.Open(authDBPath)
	if err != nil {
		slog.Fatal(logging.CatSystem, "failed to open app database", serverlog.F("error", err, "path", authDBPath))
	}
	defer appStore.Close()

	runner := newServerRunner(ctx, cfg, appStore)
	runner.Start()
	slog.Info(logging.CatSystem, "server started", serverlog.F(
		"control_addr", cfg.ControlAddr,
		"data_addr", cfg.DataAddr,
		"tls_enabled", !cfg.DisableTLS,
	))

	if webAddr != "" {
		// Warn if dashboard is bound to a public address without cookie-secure.
		if !cookieSecure {
			host, _, _ := net.SplitHostPort(webAddr)
			if host != "127.0.0.1" && host != "::1" && host != "localhost" {
				slog.Warn(logging.CatDashboard, "WARNING: Dashboard is bound to a public address without cookie-secure. This is insecure for production use.", serverlog.F("addr", webAddr))
			}
		}
		go func() {
			store, err := auth.Open(authDBPath)
			if err != nil {
				slog.Error(logging.CatAuth, "auth database open failed", serverlog.F("error", err, "path", authDBPath))
				return
			}
			defer store.Close()

			scheme := "http"
			if cfg.WebHTTPS {
				scheme = "https"
			}
			slog.Info(logging.CatDashboard, "web dashboard starting", serverlog.F("url", scheme+"://"+webAddr))
			if err := serveServerDashboard(ctx, webAddr, configPath, authDBPath, runner, store, cookieSecure, sessionTTL, webShutdownTimeout); err != nil {
				slog.Error(logging.CatDashboard, "web dashboard error", serverlog.F("error", err))
			}
		}()
	}

	<-ctx.Done()
}

type serverRunner struct {
	root context.Context

	mu       sync.Mutex
	cfg      tunnel.ServerConfig
	srv      *tunnel.Server
	appStore *appstore.Store
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
}

func newServerRunner(root context.Context, cfg tunnel.ServerConfig, appStore *appstore.Store) *serverRunner {
	return &serverRunner{root: root, cfg: cfg, appStore: appStore}
}

func (r *serverRunner) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.root)
	r.cancel = cancel
	r.srv = tunnel.NewServer(r.cfg, r.appStore)
	done := make(chan struct{})
	r.done = done
	go func(s *tunnel.Server) {
		defer close(done)
		err := s.Run(ctx)
		r.mu.Lock()
		r.err = err
		if r.cancel != nil {
			r.cancel = nil
		}
		r.done = nil
		r.mu.Unlock()
	}(r.srv)
}

func (r *serverRunner) Restart(cfg tunnel.ServerConfig) {
	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.cancel = nil
	r.cfg = cfg
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	r.Start()
}

func (r *serverRunner) Get() (tunnel.ServerConfig, tunnel.ServerStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var st tunnel.ServerStatus
	if r.srv != nil {
		st = r.srv.Status()
	}
	return r.cfg, st, r.err
}

func (r *serverRunner) Dashboard(now time.Time) (tunnel.ServerConfig, tunnel.ServerStatus, tunnel.DashboardSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var st tunnel.ServerStatus
	var snap tunnel.DashboardSnapshot
	if r.srv != nil {
		st = r.srv.Status()
		snap = r.srv.Dashboard(now)
	}
	return r.cfg, st, snap, r.err
}

func (r *serverRunner) RunAgentNettest(ctx context.Context, req tunnel.AgentNettestRequest) (tunnel.AgentNettestResult, error) {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return tunnel.AgentNettestResult{}, fmt.Errorf("server not running")
	}
	return srv.RunAgentNettest(ctx, req)
}

func (r *serverRunner) RunAgentEmailProbe(ctx context.Context, req protocol.EmailProbeRequest) (protocol.EmailProbeResult, error) {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return protocol.EmailProbeResult{}, fmt.Errorf("server not running")
	}
	return srv.RunAgentEmailProbe(ctx, req)
}

func (r *serverRunner) EmailStatus() tunnel.EmailRuntimeStatus {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return tunnel.EmailRuntimeStatus{}
	}
	return srv.EmailStatus()
}

func (r *serverRunner) OverrideAgentID(ctx context.Context, oldID, newID string) error {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return fmt.Errorf("server not running")
	}
	if err := srv.OverrideAgentID(ctx, oldID, newID); err != nil {
		return err
	}
	// Mirror the static config route-owner change so a Save persists it.
	r.mu.Lock()
	for i := range r.cfg.Routes {
		if r.cfg.Routes[i].OwnerAgent() == oldID {
			r.cfg.Routes[i].Agent = newID
		}
	}
	r.mu.Unlock()
	return nil
}

func (r *serverRunner) ForgetAgent(ctx context.Context, agentID string) error {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return fmt.Errorf("server not running")
	}
	return srv.ForgetAgent(ctx, agentID)
}

func (r *serverRunner) SetAgentDomainEnabled(agentID string, enabled bool) {
	agentID = strings.TrimSpace(agentID)
	r.mu.Lock()
	srv := r.srv
	filtered := make([]string, 0, len(r.cfg.DomainDisabledAgents))
	for _, id := range r.cfg.DomainDisabledAgents {
		if strings.TrimSpace(id) != agentID {
			filtered = append(filtered, id)
		}
	}
	if !enabled {
		filtered = append(filtered, agentID)
	}
	r.cfg.DomainDisabledAgents = filtered
	r.mu.Unlock()
	if srv != nil {
		srv.SetAgentDomainEnabled(agentID, enabled)
	}
}

func (r *serverRunner) SetEmailAgent(agentID string) {
	agentID = strings.TrimSpace(agentID)
	r.mu.Lock()
	srv := r.srv
	r.cfg.EmailAgent = agentID
	r.mu.Unlock()
	if srv != nil {
		srv.SetEmailAgent(agentID)
	}
}

func (r *serverRunner) KnownAgentIDs() []string {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return []string{protocol.DefaultAgentID}
	}
	return srv.KnownAgentIDs()
}

func (r *serverRunner) ListApps(ctx context.Context) ([]appstore.Application, error) {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return nil, fmt.Errorf("server not running")
	}
	return srv.ListApps(ctx)
}

func (r *serverRunner) SetAppEnabled(label string, enabled bool) bool {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return false
	}
	return srv.SetAppEnabled(label, enabled)
}

func (r *serverRunner) DeleteApp(label string) bool {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return false
	}
	return srv.DeleteApp(label)
}

func (r *serverRunner) SetRouteEnabled(routeName string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	found := false
	for i, rt := range r.cfg.Routes {
		if rt.Name == routeName {
			val := enabled
			r.cfg.Routes[i].Enabled = &val
			found = true
			break
		}
	}

	if !found {
		return false
	}

	if r.srv != nil {
		r.srv.SetRouteEnabled(routeName, enabled)
	}
	return true
}

func (r *serverRunner) GetRouteEnabled(routeName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srv != nil {
		return r.srv.GetRouteEnabled(routeName)
	}
	// When the tunnel server isn't running, fall back to the persisted config
	// so the dashboard reflects toggles made before/without a live server
	// instead of always reporting the default (enabled).
	for _, rt := range r.cfg.Routes {
		if rt.Name == routeName {
			return rt.IsEnabled()
		}
	}
	return true
}

type ctxKey int

const (
	ctxUserID ctxKey = iota
)

func serveServerDashboard(ctx context.Context, addr string, configPath string, authDBPath string, runner *serverRunner, store *auth.Store, cookieSecure bool, sessionTTL time.Duration, shutdownTimeout time.Duration) error {
	sessionMaxAge = int(sessionTTL.Seconds())
	tplStats := template.Must(template.ParseFS(templateFS, "templates/stats.html"))
	tplConfig := template.Must(template.ParseFS(templateFS, "templates/config.html"))
	tplEmail := template.Must(template.ParseFS(templateFS, "templates/email.html"))
	tplEmailSetup := template.Must(template.ParseFS(templateFS, "templates/email-setup.html"))
	tplDomainGuide := template.Must(template.ParseFS(templateFS, "templates/domain-guide.html"))
	tplControls := template.Must(template.ParseFS(templateFS, "templates/controls.html"))
	tplNetwork := template.Must(template.ParseFS(templateFS, "templates/network.html"))
	tplApps := template.Must(template.ParseFS(templateFS, "templates/apps.html"))
	tplLogin := template.Must(template.ParseFS(templateFS, "templates/login.html"))
	tplSetup := template.Must(template.ParseFS(templateFS, "templates/setup.html"))

	absCfg := configPath
	if p, err := filepath.Abs(configPath); err == nil {
		absCfg = p
	}
	absAuthDB := authDBPath
	if p, err := filepath.Abs(authDBPath); err == nil {
		absAuthDB = p
	}
	updStatePath := filepath.Join(filepath.Dir(absCfg), "update_state_server.json")
	moduleDir := module.DetectModuleDir(absCfg)
	upd := updater.NewManager("32bitx64bit/HostIt", updater.ComponentServer, "server.zip", moduleDir, updStatePath)
	upd.PreservePaths = serverUpdaterPreservePaths(absCfg, absAuthDB, runner)
	upd.Restart = func() error {
		bin := upd.BuiltBinaryPath()
		if _, err := os.Stat(bin); err != nil {
			return err
		}
		// systemd: ask the unit to restart.
		if systemdutil.RunningUnderSystemd() {
			if systemdutil.SystemctlAvailable() {
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "systemctl", "restart", "--no-block", "hostit-server.service")
				out, err := cmd.CombinedOutput()
				if err == nil {
					return nil
				}
				// Fallback: SIGTERM triggers systemd restart.
				_ = out
			}
			_ = sendSIGTERM(os.Getpid())
			return nil
		}
		// Non-systemd: replace the current process immediately.
		return updater.ExecReplace(bin, os.Args)
	}
	upd.Start(ctx)

	var msgMu sync.Mutex
	var msg string
	setMsg := func(s string) {
		msgMu.Lock()
		msg = s
		msgMu.Unlock()
	}
	getMsg := func() string {
		msgMu.Lock()
		defer msgMu.Unlock()
		return msg
	}

	restartCh := make(chan struct{}, 1)
	requestRestart := func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	}

	buildMux := func(cookieSecure bool, webHTTPS bool, webCertFile string, webKeyFile string, webFingerprint string) *http.ServeMux {
		mux := http.NewServeMux()
		mux.Handle("/static/", web.Handler())
		lim := newIPRateLimiter(10, 30*time.Second)

		mux.HandleFunc("/healthz", securityHeaders(cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			_, st, _ := runner.Get()
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"status":          "ok",
				"agent_connected": st.AgentConnected,
				"version":         version.Current,
			})
		}))

		mux.HandleFunc("/setup", securityHeaders(cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			hasUsers, err := store.HasAnyUsers(r.Context())
			if err != nil {
				http.Error(w, "auth db error", http.StatusInternalServerError)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			render := func(errMsg string, username string, errUser bool, errPass bool, errConfirm bool) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_ = tplSetup.Execute(w, map[string]any{
					"CSRF":        csrf,
					"Msg":         getMsg(),
					"Err":         errMsg,
					"Username":    username,
					"ErrUsername": errUser,
					"ErrPassword": errPass,
					"ErrConfirm":  errConfirm,
					"Version":     version.Current,
				})
			}
			if hasUsers {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			switch r.Method {
			case http.MethodGet:
				render("", "", false, false, false)
				return
			case http.MethodPost:
				if !lim.Allow(clientIP(r)) {
					render("Too many attempts. Please wait a moment and try again.", "", false, false, false)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				if err := r.ParseForm(); err != nil {
					render("Invalid form input.", "", false, false, false)
					return
				}
				if !checkCSRF(r) {
					render("Session expired. Please refresh and try again.", "", false, false, false)
					return
				}
				username := strings.TrimSpace(r.Form.Get("username"))
				password := r.Form.Get("password")
				confirm := r.Form.Get("confirm")
				errUser := username == ""
				errPass := len(password) < 10
				errConfirm := password != confirm
				if errUser || errPass || errConfirm {
					errMsg := "Please fix the highlighted fields."
					if errPass {
						errMsg = "Password must be at least 10 characters."
					}
					if errConfirm {
						errMsg = "Passwords must match."
					}
					render(errMsg, username, errUser, errPass, errConfirm)
					return
				}
				if err := store.CreateFirstUser(r.Context(), username, password); err != nil {
					render("Create account failed. A user may already exist.", username, true, false, false)
					return
				}
				userID, ok, err := store.Authenticate(r.Context(), username, password)
				if err != nil || !ok {
					render("Account was created, but login failed. Please try logging in.", username, false, false, false)
					return
				}
				sid, err := store.CreateSession(r.Context(), userID, sessionTTL)
				if err != nil {
					http.Error(w, "session failed", http.StatusInternalServerError)
					return
				}
				setSessionCookie(w, sid, cookieSecure)
				setMsg("")
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}))

		// Login.
		mux.HandleFunc("/login", securityHeaders(cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			hasUsers, err := store.HasAnyUsers(r.Context())
			if err != nil {
				http.Error(w, "auth db error", http.StatusInternalServerError)
				return
			}
			if !hasUsers {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}

			switch r.Method {
			case http.MethodGet:
				_ = tplLogin.Execute(w, map[string]any{"CSRF": csrf, "Msg": getMsg(), "Version": version.Current})
				return
			case http.MethodPost:
				if !lim.Allow(clientIP(r)) {
					http.Error(w, "too many attempts", http.StatusTooManyRequests)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if !checkCSRF(r) {
					http.Error(w, "csrf", http.StatusBadRequest)
					return
				}
				username := strings.TrimSpace(r.Form.Get("username"))
				password := r.Form.Get("password")
				userID, ok, err := store.Authenticate(r.Context(), username, password)
				if err != nil {
					http.Error(w, "auth error", http.StatusInternalServerError)
					return
				}
				if !ok {
					setMsg("Bad username or password")
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
				// Invalidate existing sessions on login.
				_ = store.DeleteSessionsByUserID(r.Context(), userID)
				sid, err := store.CreateSession(r.Context(), userID, sessionTTL)
				if err != nil {
					http.Error(w, "session failed", http.StatusInternalServerError)
					return
				}
				setSessionCookie(w, sid, cookieSecure)
				setMsg("")
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}))

		// Logout.
		mux.HandleFunc("/logout", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			if sid, ok := readSessionCookie(r); ok {
				_ = store.DeleteSession(r.Context(), sid)
			}
			clearSessionCookie(w, cookieSecure)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		})))

		// Stats (protected)
		mux.HandleFunc("/", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			routes := cfg.Routes
			data := map[string]any{
				"Cfg":        cfg,
				"Status":     st,
				"ConfigPath": configPath,
				"Msg":        getMsg(),
				"Err":        err,
				"CSRF":       csrf,
				"Routes":     routes,
				"RouteCount": len(routes),
				"WebHTTPS":   webHTTPS,
				"Version":    version.Current,
			}
			_ = tplStats.Execute(w, data)
		})))

		// Network test page (protected)
		mux.HandleFunc("/network-test", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			data := map[string]any{
				"Cfg":      cfg,
				"Status":   st,
				"CSRF":     csrf,
				"Err":      err,
				"Version":  version.Current,
				"WebHTTPS": webHTTPS,
			}
			_ = tplNetwork.Execute(w, data)
		})))

		mux.HandleFunc("/apps", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			apps, err := runner.ListApps(r.Context())
			if err != nil {
				apps = nil
			}
			cfg, _, _ := runner.Get()
			data := map[string]any{
				"CSRF":     csrf,
				"Msg":      getMsg(),
				"Apps":     apps,
				"Cfg":      cfg,
				"WebHTTPS": webHTTPS,
				"Version":  version.Current,
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = tplApps.Execute(w, data)
		})))

		mux.HandleFunc("/api/apps/toggle", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			label := strings.TrimSpace(r.Form.Get("app"))
			if label == "" {
				http.Error(w, "app label required", http.StatusBadRequest)
				return
			}
			enabled := strings.TrimSpace(r.Form.Get("enabled")) != ""
			if !runner.SetAppEnabled(label, enabled) {
				http.Error(w, "app not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"app":     label,
				"enabled": enabled,
			})
		})))

		mux.HandleFunc("/api/apps/delete", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			label := strings.TrimSpace(r.Form.Get("app"))
			if label == "" {
				http.Error(w, "app label required", http.StatusBadRequest)
				return
			}
			if !runner.DeleteApp(label) {
				http.Error(w, "app not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"app":     label,
				"deleted": true,
			})
		})))

		mux.HandleFunc("/api/apps/list", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			apps, err := runner.ListApps(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if apps == nil {
				apps = []appstore.Application{}
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, apps)
		})))

		// Metrics
		mux.HandleFunc("/metrics", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			cfg, _, snap, _ := runner.Dashboard(time.Now())
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"uptime_seconds":     int64(time.Since(startTime).Seconds()),
				"agent_connected":    snap.AgentConnected,
				"agents":             snap.Agents,
				"routes_count":       len(cfg.Routes),
				"active_connections": snap.ActiveClients,
				"bytes_total":        snap.BytesTotal,
				"version":            version.Current,
			})
		})))

		// Live stats
		mux.HandleFunc("/api/stats", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			cfg, _, snap, err := runner.Dashboard(time.Now())
			type routeOut struct {
				Name       string                  `json:"name"`
				Proto      string                  `json:"proto"`
				PublicAddr string                  `json:"publicAddr"`
				Agent      string                  `json:"agent"`
				Active     int64                   `json:"active"`
				Enabled    bool                    `json:"enabled"`
				Events     []tunnel.DashboardEvent `json:"events"`
			}
			outRoutes := make([]routeOut, 0, len(cfg.Routes))
			for _, rt := range cfg.Routes {
				rs := snap.Routes[rt.Name]
				outRoutes = append(outRoutes, routeOut{
					Name:       rt.Name,
					Proto:      rt.Proto,
					PublicAddr: rt.PublicAddr,
					Agent:      rt.OwnerAgent(),
					Active:     rs.ActiveClients,
					Enabled:    runner.GetRouteEnabled(rt.Name),
					Events:     rs.Events,
				})
			}
			resp := map[string]any{
				"nowUnix":        snap.NowUnix,
				"bucketSec":      snap.BucketSec,
				"agentConnected": snap.AgentConnected,
				"agents":         snap.Agents,
				"domainManager":  cfg.DomainManagerEnabled,
				"emailEnabled":   cfg.Email.Enabled,
				"activeClients":  snap.ActiveClients,
				"bytesTotal":     snap.BytesTotal,
				"runtime":        snap.Runtime,
				"series":         snap.Series,
				"routes":         outRoutes,
				"systemEvents":   snap.Routes["_system"].Events,
				"err": func() string {
					if err == nil {
						return ""
					}
					return err.Error()
				}(),
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, resp)
		})))

		mux.HandleFunc("/api/nettest/ping", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"serverTimeUnixMs": time.Now().UnixMilli()})
		})))

		mux.HandleFunc("/api/nettest/direct-download", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !nettestDownloadLimiter.Allow(clientIP(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			sz := 8 * 1024 * 1024
			if raw := strings.TrimSpace(r.URL.Query().Get("bytes")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					sz = n
				}
			}
			if sz < 1024 {
				sz = 1024
			}
			if sz > 16*1024*1024 {
				sz = 16 * 1024 * 1024
			}
			buf := make([]byte, 32*1024)
			_, _ = rand.Read(buf)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Length", strconv.Itoa(sz))
			written := 0
			for written < sz {
				chunk := len(buf)
				if remain := sz - written; remain < chunk {
					chunk = remain
				}
				n, err := w.Write(buf[:chunk])
				if err != nil {
					return
				}
				written += n
			}
		})))

		mux.HandleFunc("/api/nettest/direct-upload", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
			start := time.Now()
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			elapsed := time.Since(start)
			if elapsed <= 0 {
				elapsed = time.Millisecond
			}
			mbps := (float64(n) * 8.0 / elapsed.Seconds()) / 1e6
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"bytes":      n,
				"durationMs": elapsed.Milliseconds(),
				"mbps":       mbps,
			})
		})))

		mux.HandleFunc("/api/nettest/agent", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			count := 40
			if raw := strings.TrimSpace(r.Form.Get("count")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					count = n
				}
			}
			payload := 1024
			if raw := strings.TrimSpace(r.Form.Get("payload_bytes")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					payload = n
				}
			}
			timeoutMs := 1500
			if raw := strings.TrimSpace(r.Form.Get("timeout_ms")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					timeoutMs = n
				}
			}
			ctx2, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()
			result, err := runner.RunAgentNettest(ctx2, tunnel.AgentNettestRequest{
				Count:        count,
				PayloadBytes: payload,
				Timeout:      time.Duration(timeoutMs) * time.Millisecond,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, result)
		})))

		// Update check
		mux.HandleFunc("/api/update/check-now", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			_ = upd.CheckNow(r.Context())
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, upd.Status())
		})))

		// systemd
		mux.HandleFunc("/api/systemd/status", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			st := systemdutil.Status(r.Context(), "hostit-server.service")
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, st)
		})))
		mux.HandleFunc("/api/systemd/restart", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			if err := systemdutil.Action(r.Context(), "restart", "hostit-server.service"); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})))
		mux.HandleFunc("/api/systemd/stop", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			if err := systemdutil.Action(r.Context(), "stop", "hostit-server.service"); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})))

		// Updates
		mux.HandleFunc("/api/update/status", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			upd.CheckIfDue(r.Context())
			st := upd.Status()
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, st)
		})))
		mux.HandleFunc("/api/update/remind", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			_ = upd.RemindLater(24 * time.Hour)
			w.WriteHeader(http.StatusNoContent)
		})))
		mux.HandleFunc("/api/update/skip", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			_ = upd.SkipAvailableVersion()
			w.WriteHeader(http.StatusNoContent)
		})))
		mux.HandleFunc("/api/update/apply", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			started, err := upd.Apply(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !started {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		})))
		mux.HandleFunc("/api/update/apply-local", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
			if err := r.ParseMultipartForm(512 << 20); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}

			componentZipPath, hasComponent, err := writeUploadedZipTemp(r, "componentZip", "hostit-server-component-*.zip")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !hasComponent {
				http.Error(w, "component zip is required", http.StatusBadRequest)
				return
			}
			defer os.Remove(componentZipPath)

			sharedZipPath, hasShared, err := writeUploadedZipTemp(r, "sharedZip", "hostit-server-shared-*.zip")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if hasShared {
				defer os.Remove(sharedZipPath)
			}

			started, err := upd.ApplyLocal(r.Context(), componentZipPath, sharedZipPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !started {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		})))

		// Process control
		mux.HandleFunc("/api/process/restart", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			go func() {
				time.Sleep(250 * time.Millisecond)
				_ = sendSIGTERM(os.Getpid())
			}()
		})))
		mux.HandleFunc("/api/process/exit", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			go func() {
				time.Sleep(250 * time.Millisecond)
				os.Exit(0)
			}()
		})))

		// Config (protected)
		mux.HandleFunc("/config", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			routes := cfg.Routes
			type routeView struct {
				Name            string
				Proto           string
				PublicAddr      string
				LocalAddr       string
				Domain          string
				Agent           string
				IsEncrypted     bool
				IsDomainEnabled bool
			}
			routeViews := make([]routeView, 0, len(routes))
			for _, rt := range routes {
				routeViews = append(routeViews, routeView{
					Name:            rt.Name,
					Proto:           rt.Proto,
					PublicAddr:      rt.PublicAddr,
					LocalAddr:       rt.LocalAddr,
					Domain:          rt.Domain,
					Agent:           rt.OwnerAgent(),
					IsEncrypted:     rt.IsEncrypted(),
					IsDomainEnabled: rt.IsDomainEnabled(),
				})
			}
			agentOptions := runner.KnownAgentIDs()
			seen := make(map[string]bool, len(agentOptions))
			for _, id := range agentOptions {
				seen[id] = true
			}
			for _, rv := range routeViews {
				if !seen[rv.Agent] {
					agentOptions = append(agentOptions, rv.Agent)
					seen[rv.Agent] = true
				}
			}
			data := map[string]any{
				"Cfg":        cfg,
				"Status":     st,
				"ConfigPath": configPath,
				"Msg":        getMsg(),
				"Err":        err,
				"CSRF":       csrf,
				"Version":    version.Current,
				"Routes":     routeViews,
				"RouteCount": len(routeViews),
				"Agents":     agentOptions,
				"WebHTTPS":   webHTTPS,
				"WebTLSCert": webCertFile,
				"WebTLSKey":  webKeyFile,
				"WebTLSFP":   webFingerprint,
			}
			_ = tplConfig.Execute(w, data)
		})))

		mux.HandleFunc("/email", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			type emailAccountView struct {
				Username    string
				Address     string
				PasswordSet bool
				Enabled     bool
			}
			accounts := make([]emailAccountView, 0, len(cfg.Email.Accounts))
			for _, acct := range cfg.Email.Accounts {
				accounts = append(accounts, emailAccountView{
					Username:    acct.Username,
					Address:     cfg.Email.AddressFor(acct.Username),
					PasswordSet: acct.PasswordSet || strings.TrimSpace(acct.PasswordHash) != "",
					Enabled:     acct.Enabled,
				})
			}
			data := map[string]any{
				"Cfg":               cfg,
				"Status":            st,
				"ConfigPath":        configPath,
				"Msg":               getMsg(),
				"Err":               err,
				"CSRF":              csrf,
				"Version":           version.Current,
				"EmailAccounts":     accounts,
				"EmailCount":        len(accounts),
				"EmailMaxMessageMB": cfg.Email.MaxMessageBytes / (1 << 20),
				"EmailStorageLimit": emailcfg.FormatByteSize(cfg.Email.StorageLimitBytes),
			}
			_ = tplEmail.Execute(w, data)
		})))

		mux.HandleFunc("/email/setup", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			emailDomain := cfg.Email.Domain
			mailHost := cfg.Email.EffectiveMailHost()
			dkimSelector := cfg.Email.DKIMSelector
			if dkimSelector == "" {
				dkimSelector = "hostit"
			}
			spfValue := ""
			dmarcValue := ""
			dkimName := ""
			if emailDomain != "" && mailHost != "" {
				spfValue = fmt.Sprintf("v=spf1 mx a:%s -all", mailHost)
				dmarcValue = fmt.Sprintf("v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:postmaster@%s", emailDomain)
				dkimName = dkimSelector + "._domainkey." + emailDomain
			}
			data := map[string]any{
				"Cfg":          cfg,
				"Status":       st,
				"ConfigPath":   configPath,
				"Msg":          getMsg(),
				"Err":          err,
				"CSRF":         csrf,
				"Version":      version.Current,
				"EmailDomain":  emailDomain,
				"MailHost":     mailHost,
				"DKIMSelector": dkimSelector,
				"DKIMDNSName":  dkimName,
				"SPFValue":     spfValue,
				"DMARCValue":   dmarcValue,
			}
			_ = tplEmailSetup.Execute(w, data)
		})))

		mux.HandleFunc("/api/email/check", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			cfg, _, err := runner.Get()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			report := runEmailCheckReportWithLive(r.Context(), cfg.Email, runner)
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, report)
		})))

		mux.HandleFunc("/domain-manager-info", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			data := map[string]any{
				"Cfg":        cfg,
				"Status":     st,
				"ConfigPath": configPath,
				"Msg":        getMsg(),
				"Err":        err,
				"CSRF":       csrf,
				"Version":    version.Current,
			}
			_ = tplDomainGuide.Execute(w, data)
		})))

		mux.HandleFunc("/controls", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
			if csrf == "" {
				return
			}
			cfg, st, err := runner.Get()
			dashInterval := cfg.DashboardInterval
			if dashInterval <= 0 {
				dashInterval = 30 * time.Second
			}
			domainRenewBefore := cfg.DomainRenewBefore
			if domainRenewBefore <= 0 {
				domainRenewBefore = 7 * 24 * time.Hour
			}
			data := map[string]any{
				"Cfg":               cfg,
				"Status":            st,
				"ConfigPath":        configPath,
				"Msg":               getMsg(),
				"Err":               err,
				"CSRF":              csrf,
				"Version":           version.Current,
				"DashInterval":      dashInterval.String(),
				"DomainRenewBefore": domainRenewBefore.String(),
			}
			_ = tplControls.Execute(w, data)
		})))

		mux.HandleFunc("/api/logs", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			level := strings.TrimSpace(r.URL.Query().Get("level"))
			limit := 300
			if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil && n > 0 {
					limit = n
				}
			}
			stats := map[string]int{"all": 0, "warning": 0, "error": 0}
			entries := []serverlog.UILogEntry{}
			if serverlog.UILogs != nil {
				stats = serverlog.UILogs.Stats()
				entries = serverlog.UILogs.Entries(level, limit)
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"level":   level,
				"limit":   limit,
				"stats":   stats,
				"entries": entries,
			})
		})))

		mux.HandleFunc("/config/save", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			pt, err := time.ParseDuration(r.Form.Get("pair_timeout"))
			if err != nil {
				http.Error(w, "invalid pair timeout", http.StatusBadRequest)
				return
			}
			if pt < 1*time.Second {
				http.Error(w, "pair timeout must be at least 1 second", http.StatusBadRequest)
				return
			}
			if pt > 5*time.Minute {
				http.Error(w, "pair timeout must be at most 5 minutes", http.StatusBadRequest)
				return
			}

			msgs := make([]string, 0, 3)
			addMsg := func(s string) {
				if strings.TrimSpace(s) == "" {
					return
				}
				msgs = append(msgs, s)
			}
			old, _, _ := runner.Get()
			cfg := old
			webWas := cfg.WebHTTPS
			cfg.ControlAddr = r.Form.Get("control")
			cfg.DataAddr = r.Form.Get("data")
			cfg.Token = strings.TrimSpace(r.Form.Get("token"))
			cfg.PairTimeout = pt
			cfg.WebHTTPS = strings.TrimSpace(r.Form.Get("web_https")) != ""
			cfg.DomainManagerEnabled = strings.TrimSpace(r.Form.Get("domain_manager_enabled")) != ""
			cfg.DomainHTTPAddr = strings.TrimSpace(r.Form.Get("domain_http_addr"))
			cfg.DomainHTTPSAddr = strings.TrimSpace(r.Form.Get("domain_https_addr"))
			cfg.DomainBase = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Form.Get("domain_base"))), ".")
			cfg.DomainAutoTLS = strings.TrimSpace(r.Form.Get("domain_auto_tls")) != ""
			cfg.DomainACMEEmail = strings.TrimSpace(r.Form.Get("domain_acme_email"))
			cfg.EncryptionAlgorithm = r.Form.Get("encryption_algorithm")
			if cfg.Token == "" {
				tok, err := genToken()
				if err != nil {
					http.Error(w, "token generation failed", http.StatusInternalServerError)
					return
				}
				cfg.Token = tok
				addMsg("Token was empty; generated a new token")
			}
			cfg.Routes = parseServerRoutesForm(r, old.Routes)

			if strings.TrimSpace(r.Form.Get("tls_regen")) != "" {
				if cfg.DisableTLS {
					addMsg("TLS is disabled; skipped TLS cert/key regeneration")
				} else {
					cfgDir := filepath.Dir(configPath)
					if strings.TrimSpace(cfg.TLSCertFile) == "" {
						cfg.TLSCertFile = filepath.Join(cfgDir, "server.crt")
					}
					if strings.TrimSpace(cfg.TLSKeyFile) == "" {
						cfg.TLSKeyFile = filepath.Join(cfgDir, "server.key")
					}
					fp, err := tlsutil.RegenerateSelfSigned(cfg.TLSCertFile, cfg.TLSKeyFile)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					serverlog.Log.Infof(logging.CatSystem, "tunnel tls regenerated; cert sha256=%s", fp)
					addMsg("Regenerated TLS cert/key; new cert sha256=" + fp)
				}
			} else if !cfg.DisableTLS {
				cfgDir := filepath.Dir(configPath)
				if strings.TrimSpace(cfg.TLSCertFile) == "" {
					cfg.TLSCertFile = filepath.Join(cfgDir, "server.crt")
				}
				if strings.TrimSpace(cfg.TLSKeyFile) == "" {
					cfg.TLSKeyFile = filepath.Join(cfgDir, "server.key")
				}
				fp, err := tlsutil.EnsureSelfSigned(cfg.TLSCertFile, cfg.TLSKeyFile)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				serverlog.Log.Infof(logging.CatSystem, "tunnel tls enabled; cert sha256=%s", fp)
			}

			cfgDir := filepath.Dir(configPath)
			if cfg.DomainRenewBefore <= 0 {
				cfg.DomainRenewBefore = 7 * 24 * time.Hour
			}
			if strings.TrimSpace(cfg.DomainHTTPAddr) == "" {
				cfg.DomainHTTPAddr = ":80"
			}
			if strings.TrimSpace(cfg.DomainHTTPSAddr) == "" {
				cfg.DomainHTTPSAddr = ":443"
			}
			if strings.TrimSpace(cfg.DomainCertDir) == "" {
				cfg.DomainCertDir = filepath.Join(cfgDir, "domains")
			}
			if strings.TrimSpace(cfg.WebTLSCertFile) == "" {
				cfg.WebTLSCertFile = filepath.Join(cfgDir, "web.crt")
			}
			if strings.TrimSpace(cfg.WebTLSKeyFile) == "" {
				cfg.WebTLSKeyFile = filepath.Join(cfgDir, "web.key")
			}
			if strings.TrimSpace(r.Form.Get("web_tls_regen")) != "" {
				fp, err := tlsutil.RegenerateSelfSignedDashboard(cfg.WebTLSCertFile, cfg.WebTLSKeyFile)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				addMsg("Regenerated dashboard HTTPS cert/key; cert sha256=" + fp)
			}
			if cfg.WebHTTPS {
				fp, err := tlsutil.EnsureSelfSignedDashboard(cfg.WebTLSCertFile, cfg.WebTLSKeyFile)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				addMsg("Dashboard HTTPS enabled (self-signed); cert sha256=" + fp)
			}

			cfg.Email = emailcfg.Normalize(cfg.Email)
			if err := cfg.Validate(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := configio.Save(configPath, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			runner.Restart(cfg)
			addMsg("Saved + restarted")

			webNow := cfg.WebHTTPS
			needsWebRestart := webWas != webNow || strings.TrimSpace(r.Form.Get("web_tls_regen")) != ""
			if needsWebRestart {
				requestRestart()
			}
			if webWas != webNow {
				scheme := "http"
				if webNow {
					scheme = "https"
				}
				target := scheme + "://" + r.Host + "/config"
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/><title>Redirect</title></head><body style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:24px\"><h2>Dashboard HTTPS updated</h2><p>Open: <a href=\"%s\">%s</a></p><p style=\"opacity:.8\">Self-signed certs will show a browser warning; that's expected.</p></body></html>", target, target)
				return
			}
			http.Redirect(w, r, "/config", http.StatusSeeOther)
		})))

		mux.HandleFunc("/email/save", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			cfg, _, _ := runner.Get()
			emailCfg, err := parseServerEmailForm(r, cfg.Email)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cfg.Email = emailcfg.Normalize(emailCfg)
			if err := cfg.Validate(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := configio.Save(configPath, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			runner.Restart(cfg)
			setMsg("Saved email settings + restarted")
			http.Redirect(w, r, "/email", http.StatusSeeOther)
		})))

		mux.HandleFunc("/api/routes/toggle", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			routeName := strings.TrimSpace(r.Form.Get("route"))
			if routeName == "" {
				http.Error(w, "route name required", http.StatusBadRequest)
				return
			}
			enabled := strings.TrimSpace(r.Form.Get("enabled")) != ""
			if !runner.SetRouteEnabled(routeName, enabled) {
				http.Error(w, "route not found", http.StatusNotFound)
				return
			}

			cfg, _, _ := runner.Get()
			if err := configio.Save(configPath, cfg); err != nil {
				serverlog.Log.Error(logging.CatSystem, "failed to save config after route toggle", serverlog.F("error", err))
			}

			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"route":   routeName,
				"enabled": enabled,
			})
		})))

		mux.HandleFunc("/api/agents/override", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			oldID := strings.TrimSpace(r.Form.Get("agent"))
			newID := strings.TrimSpace(r.Form.Get("newId"))
			if oldID == "" || newID == "" {
				http.Error(w, "agent and newId are required", http.StatusBadRequest)
				return
			}
			if err := runner.OverrideAgentID(r.Context(), oldID, newID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cfg, _, _ := runner.Get()
			if err := configio.Save(configPath, cfg); err != nil {
				serverlog.Log.Error(logging.CatSystem, "failed to save config after agent override", serverlog.F("error", err))
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"agent": newID})
		})))

		mux.HandleFunc("/api/agents/forget", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			agentID := strings.TrimSpace(r.Form.Get("agent"))
			if agentID == "" {
				http.Error(w, "agent is required", http.StatusBadRequest)
				return
			}
			if err := runner.ForgetAgent(r.Context(), agentID); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"agent": agentID, "forgotten": true})
		})))

		mux.HandleFunc("/api/agents/domain", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			agentID := strings.TrimSpace(r.Form.Get("agent"))
			if agentID == "" {
				http.Error(w, "agent is required", http.StatusBadRequest)
				return
			}
			enabled := strings.TrimSpace(r.Form.Get("enabled")) != ""
			runner.SetAgentDomainEnabled(agentID, enabled)
			cfg, _, _ := runner.Get()
			if err := configio.Save(configPath, cfg); err != nil {
				serverlog.Log.Error(logging.CatSystem, "failed to save config after domain toggle", serverlog.F("error", err))
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"agent": agentID, "domainEnabled": enabled})
		})))

		mux.HandleFunc("/api/agents/email", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			agentID := strings.TrimSpace(r.Form.Get("agent"))
			if agentID == "" {
				http.Error(w, "agent is required", http.StatusBadRequest)
				return
			}
			runner.SetEmailAgent(agentID)
			cfg, _, _ := runner.Get()
			if err := configio.Save(configPath, cfg); err != nil {
				serverlog.Log.Error(logging.CatSystem, "failed to save config after email assignment", serverlog.F("error", err))
			}
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"agent": agentID, "emailAgent": true})
		})))

		mux.HandleFunc("/api/dashboard/interval", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			dur, err := time.ParseDuration(r.Form.Get("interval"))
			if err != nil {
				http.Error(w, "invalid interval: "+err.Error(), http.StatusBadRequest)
				return
			}
			if dur < 5*time.Second {
				dur = 5 * time.Second
			}
			if dur > 10*time.Minute {
				dur = 10 * time.Minute
			}
			cfg, _, _ := runner.Get()
			cfg.DashboardInterval = dur
			if err := configio.Save(configPath, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			runner.Restart(cfg)
			setMsg(fmt.Sprintf("Dashboard interval set to %s — restarted", dur))
			http.Redirect(w, r, "/controls", http.StatusSeeOther)
		})))

		mux.HandleFunc("/gen-token", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, sessionTTL, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !checkCSRF(r) {
				http.Error(w, "csrf", http.StatusBadRequest)
				return
			}
			cfg, _, _ := runner.Get()
			tok, err := genToken()
			if err != nil {
				http.Error(w, "token generation failed", http.StatusInternalServerError)
				return
			}
			cfg.Token = tok
			if err := configio.Save(configPath, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			runner.Restart(cfg)
			setMsg("Generated token + restarted")
			http.Redirect(w, r, "/config", http.StatusSeeOther)
		})))

		return mux
	}

nextLoop:
	for {
		cfg, _, _ := runner.Get()
		useTLS := cfg.WebHTTPS
		cookieSecureEff := cookieSecure || useTLS

		cfgDir := filepath.Dir(configPath)
		webCert := strings.TrimSpace(cfg.WebTLSCertFile)
		webKey := strings.TrimSpace(cfg.WebTLSKeyFile)
		if webCert == "" {
			webCert = filepath.Join(cfgDir, "web.crt")
		}
		if webKey == "" {
			webKey = filepath.Join(cfgDir, "web.key")
		}
		webFP := ""
		if useTLS {
			fp, err := tlsutil.EnsureSelfSignedDashboard(webCert, webKey)
			if err != nil {
				return err
			}
			webFP = fp
		}

		h := &http.Server{
			Addr:              addr,
			Handler:           buildMux(cookieSecureEff, useTLS, webCert, webKey, webFP),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			if useTLS {
				errCh <- h.ListenAndServeTLS(webCert, webKey)
				return
			}
			errCh <- h.ListenAndServe()
		}()

		select {
		case <-ctx.Done():
			ctx2, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			_ = h.Shutdown(ctx2)
			cancel()
			err := <-errCh
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		case <-restartCh:
			ctx2, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			_ = h.Shutdown(ctx2)
			cancel()
			err := <-errCh
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			for {
				select {
				case <-restartCh:
				default:
					continue nextLoop
				}
			}
		case err := <-errCh:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}
	}
}

func serverUpdaterPreservePaths(absCfg string, absAuthDB string, runner *serverRunner) []string {
	paths := make([]string, 0, 8)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(absCfg), path)
		}
		if p, err := filepath.Abs(path); err == nil {
			path = p
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		paths = append(paths, path)
	}

	add(absCfg)
	add(absAuthDB)

	cfgDir := filepath.Dir(absCfg)
	cfg, _, _ := runner.Get()

	serverCert := strings.TrimSpace(cfg.TLSCertFile)
	if serverCert == "" {
		serverCert = filepath.Join(cfgDir, "server.crt")
	}
	serverKey := strings.TrimSpace(cfg.TLSKeyFile)
	if serverKey == "" {
		serverKey = filepath.Join(cfgDir, "server.key")
	}
	webCert := strings.TrimSpace(cfg.WebTLSCertFile)
	if webCert == "" {
		webCert = filepath.Join(cfgDir, "web.crt")
	}
	webKey := strings.TrimSpace(cfg.WebTLSKeyFile)
	if webKey == "" {
		webKey = filepath.Join(cfgDir, "web.key")
	}
	domainCertDir := strings.TrimSpace(cfg.DomainCertDir)
	if domainCertDir == "" {
		domainCertDir = filepath.Join(cfgDir, "domains")
	}

	add(serverCert)
	add(serverKey)
	add(webCert)
	add(webKey)
	add(domainCertDir)

	return paths
}

func genToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("genToken: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func writeUploadedZipTemp(r *http.Request, fieldName string, pattern string) (string, bool, error) {
	f, _, err := r.FormFile(fieldName)
	if err != nil {
		if err == http.ErrMissingFile {
			return "", false, nil
		}
		return "", false, err
	}
	defer f.Close()

	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", false, err
	}
	name := tmp.Name()
	if _, err := io.Copy(tmp, f); err != nil {
		tmp.Close()
		_ = os.Remove(name)
		return "", false, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", false, err
	}
	return name, true, nil
}

func parseServerRoutesForm(r *http.Request, existing []tunnel.RouteConfig) []tunnel.RouteConfig {
	count, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("route_count")))
	if count < 0 {
		count = 0
	}
	if count > 64 {
		count = 64
	}
	// The config form has no enabled control (routes are toggled from the
	// dashboard), so preserve the enabled state of any route that already
	// exists by name. Without this, saving the config page would reset every
	// route to its default (enabled), undoing any dashboard toggle.
	existingEnabled := make(map[string]*bool, len(existing))
	for _, rt := range existing {
		if name := strings.TrimSpace(rt.Name); name != "" {
			existingEnabled[strings.ToLower(name)] = rt.Enabled
		}
	}
	routes := make([]tunnel.RouteConfig, 0, count)
	for i := 0; i < count; i++ {
		del := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_delete"))
		if del != "" && del != "0" {
			continue
		}
		name := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_name"))
		proto := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_proto"))
		pub := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_public"))
		local := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_local"))
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Form.Get("route_"+strconv.Itoa(i)+"_domain"))), ".")
		if name == "" && proto == "" && pub == "" && local == "" && domain == "" {
			continue
		}
		if name == "" {
			name = fmt.Sprintf("route-%d", i)
		}
		// Route name must be alphanumeric with hyphens/underscores, max 64 chars.
		sanitized := make([]rune, 0, len(name))
		for _, r := range name {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				sanitized = append(sanitized, r)
			} else {
				sanitized = append(sanitized, '-')
			}
		}
		if len(sanitized) > 64 {
			name = string(sanitized[:64])
		} else {
			name = string(sanitized)
		}
		if proto == "" {
			proto = "tcp"
		}
		encrypted := strings.TrimSpace(r.Form.Get("route_"+strconv.Itoa(i)+"_encrypted")) == "1"
		var encPtr *bool
		if encrypted {
			encPtr = &encrypted
		}
		domainEnabled := strings.TrimSpace(r.Form.Get("route_"+strconv.Itoa(i)+"_domain_enabled")) == "1"
		var domainPtr *bool
		if domainEnabled {
			domainPtr = &domainEnabled
		}
		agent := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_agent"))
		if len(agent) > crypto.MaxAgentIDLen {
			agent = agent[:crypto.MaxAgentIDLen]
		}
		rc := tunnel.RouteConfig{Name: name, Proto: proto, PublicAddr: pub, LocalAddr: local, Encrypted: encPtr, Domain: domain, DomainEnabled: domainPtr, Agent: agent}
		if prev, ok := existingEnabled[strings.ToLower(name)]; ok && prev != nil {
			v := *prev
			rc.Enabled = &v
		}
		routes = append(routes, rc)
	}
	return routes
}

func parseServerEmailForm(r *http.Request, existing emailcfg.Config) (emailcfg.Config, error) {
	existing = emailcfg.Normalize(existing)
	existingByUser := make(map[string]emailcfg.Account, len(existing.Accounts))
	for _, acct := range existing.Accounts {
		existingByUser[strings.ToLower(strings.TrimSpace(acct.Username))] = acct
	}

	count, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("email_account_count")))
	if count < 0 {
		count = 0
	}
	if count > 128 {
		count = 128
	}

	cfg := emailcfg.Config{
		Enabled:           strings.TrimSpace(r.Form.Get("email_enabled")) != "",
		Domain:            strings.TrimSpace(r.Form.Get("email_domain")),
		MailHost:          strings.TrimSpace(r.Form.Get("email_mail_host")),
		AutoTLS:           strings.TrimSpace(r.Form.Get("email_auto_tls")) != "",
		ACMEEmail:         strings.TrimSpace(r.Form.Get("email_acme_email")),
		ACMEHTTPAddr:      strings.TrimSpace(r.Form.Get("email_acme_http_addr")),
		TLSCertPath:       strings.TrimSpace(r.Form.Get("email_tls_cert_path")),
		TLSKeyPath:        strings.TrimSpace(r.Form.Get("email_tls_key_path")),
		DKIMSelector:      strings.TrimSpace(r.Form.Get("email_dkim_selector")),
		DKIMKeyPath:       strings.TrimSpace(r.Form.Get("email_dkim_key_path")),
		SubmissionAddr:    strings.TrimSpace(r.Form.Get("email_submission_addr")),
		SubmissionTLSAddr: strings.TrimSpace(r.Form.Get("email_submission_tls_addr")),
		IMAPAddr:          strings.TrimSpace(r.Form.Get("email_imap_addr")),
		IMAPTLSAddr:       strings.TrimSpace(r.Form.Get("email_imap_tls_addr")),
		InboundSMTP:       strings.TrimSpace(r.Form.Get("email_inbound_smtp")) != "",
		InboundSMTPAddr:   strings.TrimSpace(r.Form.Get("email_inbound_smtp_addr")),
		MaxMessageBytes:   parseInt64Default(strings.TrimSpace(r.Form.Get("email_max_message_mb")), 25) * (1 << 20),
		MaxRecipients:     parseIntDefault(strings.TrimSpace(r.Form.Get("email_max_recipients")), 100),
		Accounts:          make([]emailcfg.Account, 0, count),
	}
	if strings.TrimSpace(r.Form.Get("email_storage_unlimited")) == "" {
		rawStorageLimit := strings.TrimSpace(r.Form.Get("email_storage_limit"))
		if rawStorageLimit == "" {
			return emailcfg.Config{}, fmt.Errorf("email storage limit is required when unlimited storage is turned off")
		}
		limit, err := emailcfg.ParseByteSize(rawStorageLimit)
		if err != nil {
			return emailcfg.Config{}, fmt.Errorf("invalid email storage limit: %w", err)
		}
		cfg.StorageLimitBytes = limit
	}

	for i := 0; i < count; i++ {
		prefix := "email_account_" + strconv.Itoa(i) + "_"
		if strings.TrimSpace(r.Form.Get(prefix+"delete")) != "" && strings.TrimSpace(r.Form.Get(prefix+"delete")) != "0" {
			continue
		}
		username := strings.ToLower(strings.TrimSpace(r.Form.Get(prefix + "username")))
		password := r.Form.Get(prefix + "password")
		enabled := strings.TrimSpace(r.Form.Get(prefix+"enabled")) != ""
		if username == "" && strings.TrimSpace(password) == "" {
			continue
		}
		acct := emailcfg.Account{Username: username, Enabled: enabled}
		if password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return emailcfg.Config{}, err
			}
			acct.PasswordHash = string(hash)
			acct.PasswordSet = true
		} else if prev, ok := existingByUser[username]; ok {
			acct.PasswordHash = prev.PasswordHash
			acct.PasswordSet = prev.PasswordSet || strings.TrimSpace(prev.PasswordHash) != ""
		}
		cfg.Accounts = append(cfg.Accounts, acct)
	}

	return emailcfg.Normalize(cfg), nil
}

func parseIntDefault(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseInt64Default(raw string, fallback int64) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func securityHeaders(secureCookies bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// Only emit HSTS when cookies are marked Secure (should only be enabled behind HTTPS).
		if secureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next(w, r)
	}
}

type ipRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	byIP   map[string][]time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	l := &ipRateLimiter{limit: limit, window: window, byIP: map[string][]time.Time{}}
	// Background cleanup prevents the byIP map from growing without bound.
	go l.cleanupLoop()
	return l
}

func (l *ipRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		cut := now.Add(-l.window)
		for ip, arr := range l.byIP {
			j := 0
			for ; j < len(arr); j++ {
				if arr[j].After(cut) {
					break
				}
			}
			if j > 0 {
				if j >= len(arr) {
					delete(l.byIP, ip)
				} else {
					l.byIP[ip] = append([]time.Time(nil), arr[j:]...)
				}
			}
		}
		l.mu.Unlock()
	}
}

func (l *ipRateLimiter) Allow(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	cut := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()
	arr := l.byIP[ip]
	// Prune entries older than the window.
	j := 0
	for ; j < len(arr); j++ {
		if arr[j].After(cut) {
			break
		}
	}
	if j > 0 {
		arr = append([]time.Time(nil), arr[j:]...)
	}
	if len(arr) >= l.limit {
		l.byIP[ip] = arr
		return false
	}
	arr = append(arr, now)
	l.byIP[ip] = arr
	return true
}

func clientIP(r *http.Request) string {
	// Note: we deliberately do NOT trust X-Forwarded-For. If you run
	// behind a reverse proxy, enforce auth/rate-limit there too.
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// Rate limiter for invalid auth session lookups. This preserves brute-force
// protection without throttling normal authenticated dashboard polling.
var invalidSessionLimiter = newIPRateLimiter(60, 1*time.Minute)

var nettestDownloadLimiter = newIPRateLimiter(4, 1*time.Minute)

var sessionMaxAge int

// csrfSecret is a random 32-byte key generated at startup, used to HMAC-sign
// CSRF nonces so that an attacker who can inject cookies cannot forge a
// matching form token (signed double-submit cookie pattern).
var csrfSecret [32]byte

func init() {
	if _, err := io.ReadFull(rand.Reader, csrfSecret[:]); err != nil {
		panic("failed to generate CSRF secret: " + err.Error())
	}
}

// computeCSRFToken computes HMAC-SHA256(csrfSecret, nonce) and returns it
// as a hex string. The nonce is the random value stored in the cookie.
func computeCSRFToken(nonce string) string {
	mac := hmac.New(sha256.New, csrfSecret[:])
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

func requireAuth(store *auth.Store, cookieSecure bool, sessionTTL time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hasUsers, err := store.HasAnyUsers(r.Context())
		if err != nil {
			http.Error(w, "auth db error", http.StatusInternalServerError)
			return
		}
		if !hasUsers {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		sid, ok := readSessionCookie(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		userID, ok, err := store.GetSession(r.Context(), sid, sessionTTL)
		if err != nil {
			http.Error(w, "auth db error", http.StatusInternalServerError)
			return
		}
		if !ok {
			if !invalidSessionLimiter.Allow(clientIP(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			clearSessionCookie(w, cookieSecure)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxUserID, userID)))
	}
}

func ensureCSRF(w http.ResponseWriter, r *http.Request, secure bool) string {
	// Reuse the existing nonce from the cookie if present.
	if c, err := r.Cookie("csrf"); err == nil && c.Value != "" {
		return computeCSRFToken(c.Value)
	}
	// Otherwise generate a fresh random nonce and set it as the cookie value.
	nonce, err := genToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return ""
	}
	if nonce == "" {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   sessionMaxAge,
	})
	return computeCSRFToken(nonce)
}

func checkCSRF(r *http.Request) bool {
	formTok := r.Form.Get("csrf")
	if formTok == "" {
		formTok = r.Header.Get("X-CSRF-Token")
	}
	formTok = strings.TrimSpace(formTok)
	if len(formTok) >= 2 && formTok[0] == '"' && formTok[len(formTok)-1] == '"' {
		if unq, err := strconv.Unquote(formTok); err == nil {
			formTok = unq
		} else {
			formTok = strings.Trim(formTok, "\"")
		}
	}
	c, err := r.Cookie("csrf")
	if err != nil || c.Value == "" {
		return false
	}
	// Recompute the expected HMAC from the cookie nonce and compare in
	// constant time against the form-submitted token.
	expected := computeCSRFToken(c.Value)
	return formTok != "" && subtle.ConstantTimeCompare([]byte(formTok), []byte(expected)) == 1
}

func setSessionCookie(w http.ResponseWriter, sid string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   sessionMaxAge,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   -1,
	})
}

func readSessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
