package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hostit/server/internal/auth"
	"hostit/server/internal/configio"
	"hostit/server/internal/serverlog"
	"hostit/server/internal/tlsutil"
	"hostit/server/internal/tunnel"
	"hostit/shared/logging"
	"hostit/shared/updater"
	"hostit/shared/version"
)

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
	var disableUDPEnc bool

	flag.StringVar(&controlAddr, "control", ":7000", "control listen address")
	flag.StringVar(&dataAddr, "data", ":7001", "data listen address")
	flag.StringVar(&token, "token", "", "shared token (optional)")
	flag.BoolVar(&disableTLS, "disable-tls", false, "disable TLS for agent<->server control/data TCP")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate PEM path (default: alongside config)")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key PEM path (default: alongside config)")
	flag.BoolVar(&disableUDPEnc, "disable-udp-encryption", false, "disable application-layer encryption for agent<->server UDP data (deprecated; use server config: UDP Encryption = none)")
	flag.DurationVar(&pairTimeout, "pair-timeout", 10*time.Second, "max wait for agent to attach")
	flag.StringVar(&webAddr, "web", "127.0.0.1:7002", "web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "server.json", "path to server config JSON")
	flag.StringVar(&authDBPath, "auth-db", "auth.db", "sqlite auth db path")
	flag.BoolVar(&cookieSecure, "cookie-secure", false, "set Secure on cookies (recommended behind HTTPS)")
	flag.DurationVar(&sessionTTL, "session-ttl", 7*24*time.Hour, "session lifetime")
	flag.Parse()

	// Initialize centralized logging
	serverlog.Init()
	slog := serverlog.Log

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := tunnel.ServerConfig{
		ControlAddr:          controlAddr,
		DataAddr:             dataAddr,
		Token:                token,
		DisableTLS:           disableTLS,
		TLSCertFile:          tlsCert,
		TLSKeyFile:           tlsKey,
		DisableUDPEncryption: disableUDPEnc,
		PairTimeout:          pairTimeout,
	}
	_, _ = configio.Load(configPath, &cfg)

	// Apply flag overrides after loading.
	if disableTLS {
		cfg.DisableTLS = true
	}
	if strings.TrimSpace(tlsCert) != "" {
		cfg.TLSCertFile = tlsCert
	}
	if strings.TrimSpace(tlsKey) != "" {
		cfg.TLSKeyFile = tlsKey
	}
	if disableUDPEnc {
		cfg.DisableUDPEncryption = true
		cfg.UDPEncryptionMode = "none"
	}

	if strings.TrimSpace(cfg.Token) == "" {
		cfg.Token = genToken()
		_ = configio.Save(configPath, cfg)
		slog.Info(logging.CatSystem, "generated new server token (was empty)")
	}

	// Normalize/ensure UDP encryption settings + key material.
	if changed := tunnel.EnsureUDPKeys(&cfg, time.Now()); changed {
		_ = configio.Save(configPath, cfg)
		slog.Info(logging.CatEncryption, "UDP encryption keys updated", serverlog.F("key_id", cfg.UDPKeyID))
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

	runner := newServerRunner(ctx, cfg)
	runner.Start()
	slog.Info(logging.CatSystem, "server started", serverlog.F(
		"control_addr", cfg.ControlAddr,
		"data_addr", cfg.DataAddr,
		"tls_enabled", !cfg.DisableTLS,
	))

	// Auto-rotate UDP keys every 60 days (checked periodically).
	go func() {
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cfg, _, _ := runner.Get()
			if strings.EqualFold(strings.TrimSpace(cfg.UDPEncryptionMode), "none") {
				continue
			}
			beforeID := cfg.UDPKeyID
			beforeCreated := cfg.UDPKeyCreatedUnix
			if !tunnel.EnsureUDPKeys(&cfg, time.Now()) {
				continue
			}
			if cfg.UDPKeyID == beforeID && cfg.UDPKeyCreatedUnix == beforeCreated {
				continue
			}
			if err := configio.Save(configPath, cfg); err != nil {
				slog.Error(logging.CatEncryption, "UDP key rotation save failed", serverlog.F("error", err))
				continue
			}
			runner.Restart(cfg)
			slog.Info(logging.CatEncryption, "UDP keys rotated", serverlog.F("new_key_id", cfg.UDPKeyID))
		}
	}()

	if webAddr != "" {
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
			if err := serveServerDashboard(ctx, webAddr, configPath, authDBPath, runner, store, cookieSecure, sessionTTL); err != nil {
				slog.Error(logging.CatDashboard, "web dashboard error", serverlog.F("error", err))
			}
		}()
	}

	<-ctx.Done()
}

type serverRunner struct {
	root context.Context

	mu     sync.Mutex
	cfg    tunnel.ServerConfig
	srv    *tunnel.Server
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func newServerRunner(root context.Context, cfg tunnel.ServerConfig) *serverRunner {
	return &serverRunner{root: root, cfg: cfg}
}

func (r *serverRunner) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.root)
	r.cancel = cancel
	r.srv = tunnel.NewServer(r.cfg)
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

type ctxKey int

const (
	ctxUserID ctxKey = iota
)

func serveServerDashboard(ctx context.Context, addr string, configPath string, authDBPath string, runner *serverRunner, store *auth.Store, cookieSecure bool, sessionTTL time.Duration) error {
	tplStats := template.Must(template.New("stats").Parse(serverStatsHTML))
	tplConfig := template.Must(template.New("config").Parse(serverConfigHTML))
	tplControls := template.Must(template.New("controls").Parse(serverControlsHTML))
	tplLogin := template.Must(template.New("login").Parse(loginPageHTML))
	tplSetup := template.Must(template.New("setup").Parse(setupPageHTML))

	absCfg := configPath
	if p, err := filepath.Abs(configPath); err == nil {
		absCfg = p
	}
	absAuthDB := authDBPath
	if p, err := filepath.Abs(authDBPath); err == nil {
		absAuthDB = p
	}
	updStatePath := filepath.Join(filepath.Dir(absCfg), "update_state_server.json")
	moduleDir := detectModuleDir(absCfg)
	upd := updater.NewManager("32bitx64bit/HostIt", updater.ComponentServer, "server.zip", moduleDir, updStatePath)
	upd.PreservePaths = []string{absCfg, absAuthDB}
	upd.Restart = func() error {
		bin := upd.BuiltBinaryPath()
		if _, err := os.Stat(bin); err != nil {
			return err
		}
		// If we're running under systemd, restart the service (or exit and let systemd restart).
		if runningUnderSystemd() {
			if systemctlAvailable() {
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "systemctl", "restart", "--no-block", "hostit-server.service")
				out, err := cmd.CombinedOutput()
				if err == nil {
					return nil
				}
				// Fall back to SIGTERM; unit has Restart=always.
				_ = out
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			return nil
		}
		// Non-systemd run: replace the current process so the restart is immediate.
		return updater.ExecReplace(bin, os.Args[1:])
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
		lim := newIPRateLimiter(10, 30*time.Second) // 10 attempts per 30s per IP

		// Setup: only available if no users exist.
		mux.HandleFunc("/setup", securityHeaders(cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		hasUsers, err := store.HasAnyUsers(r.Context())
		if err != nil {
			http.Error(w, "auth db error", http.StatusInternalServerError)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
		render := func(errMsg string, username string, errUser bool, errPass bool, errConfirm bool) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = tplSetup.Execute(w, map[string]any{
				"CSRF":       csrf,
				"Msg":        getMsg(),
				"Err":        errMsg,
				"Username":   username,
				"ErrUsername": errUser,
				"ErrPassword": errPass,
				"ErrConfirm":  errConfirm,
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
					// If both are true, this message is more actionable.
					errMsg = "Passwords must match."
				}
				render(errMsg, username, errUser, errPass, errConfirm)
				return
			}
			if err := store.CreateUser(r.Context(), username, password); err != nil {
				render("Create account failed. Please try a different username.", username, true, false, false)
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

		switch r.Method {
		case http.MethodGet:
			_ = tplLogin.Execute(w, map[string]any{"CSRF": csrf, "Msg": getMsg()})
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
		mux.HandleFunc("/logout", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		mux.HandleFunc("/", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
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
		}
		_ = tplStats.Execute(w, data)
		})))

		// Live stats API (protected)
		mux.HandleFunc("/api/stats", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg, _, snap, err := runner.Dashboard(time.Now())
		type routeOut struct {
			Name       string               `json:"name"`
			Proto      string               `json:"proto"`
			PublicAddr string               `json:"publicAddr"`
			Active     int64                `json:"active"`
			Events     []tunnel.DashboardEvent `json:"events"`
		}
		outRoutes := make([]routeOut, 0, len(cfg.Routes))
		for _, rt := range cfg.Routes {
			rs := snap.Routes[rt.Name]
			outRoutes = append(outRoutes, routeOut{Name: rt.Name, Proto: rt.Proto, PublicAddr: rt.PublicAddr, Active: rs.ActiveClients, Events: rs.Events})
		}
		resp := map[string]any{
			"nowUnix":        snap.NowUnix,
			"agentConnected": snap.AgentConnected,
			"activeClients":  snap.ActiveClients,
			"bytesTotal":     snap.BytesTotal,
			"series":         snap.Series,
			"routes":         outRoutes,
			"err": func() string {
				if err == nil {
					return ""
				}
				return err.Error()
			}(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		})))

		// Manual update check (protected)
		mux.HandleFunc("/api/update/check-now", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
			_ = json.NewEncoder(w).Encode(upd.Status())
		})))

		// systemd status + control (protected)
		mux.HandleFunc("/api/systemd/status", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			st := systemdStatus(r.Context(), "hostit-server.service")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
		})))
		mux.HandleFunc("/api/systemd/restart", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
			if err := systemdAction(r.Context(), "restart", "hostit-server.service"); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})))
		mux.HandleFunc("/api/systemd/stop", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
			if err := systemdAction(r.Context(), "stop", "hostit-server.service"); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})))

		// Update APIs (protected)
		mux.HandleFunc("/api/update/status", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			upd.CheckIfDue(r.Context())
			st := upd.Status()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
		})))
		mux.HandleFunc("/api/update/remind", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		mux.HandleFunc("/api/update/skip", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		mux.HandleFunc("/api/update/apply", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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

		// Process control (protected): exits the whole server process.
		mux.HandleFunc("/api/process/restart", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}()
		})))
		mux.HandleFunc("/api/process/exit", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}()
		})))

		// Config (protected)
		mux.HandleFunc("/config", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
		cfg, st, err := runner.Get()
		routes := cfg.Routes
		type routeView struct {
			Name       string
			Proto      string
			PublicAddr string
			TCPNoDelay bool
			TunnelTLS  bool
			Preconnect int
		}
		routeViews := make([]routeView, 0, len(routes))
		for _, rt := range routes {
			noDelay := true
			if rt.TCPNoDelay != nil {
				noDelay = *rt.TCPNoDelay
			}
			tlsOn := true
			if rt.TunnelTLS != nil {
				tlsOn = *rt.TunnelTLS
			}
			pc := 0
			if rt.Preconnect != nil {
				pc = *rt.Preconnect
			} else {
				p := strings.ToLower(strings.TrimSpace(rt.Proto))
				if p == "tcp" || p == "both" {
					pc = 4
				}
			}
			routeViews = append(routeViews, routeView{Name: rt.Name, Proto: rt.Proto, PublicAddr: rt.PublicAddr, TCPNoDelay: noDelay, TunnelTLS: tlsOn, Preconnect: pc})
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
			"WebHTTPS":   webHTTPS,
			"WebTLSCert": webCertFile,
			"WebTLSKey":  webKeyFile,
			"WebTLSFP":   webFingerprint,
			"UDPKeyCreated": func() string {
				if cfg.UDPKeyCreatedUnix == 0 {
					return ""
				}
				return time.Unix(cfg.UDPKeyCreatedUnix, 0).Format(time.RFC3339)
			}(),
		}
		_ = tplConfig.Execute(w, data)
		})))

		// Controls (protected)
		mux.HandleFunc("/controls", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
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
			_ = tplControls.Execute(w, data)
		})))

		mux.HandleFunc("/config/save", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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

		msgs := make([]string, 0, 3)
		addMsg := func(s string) {
			if strings.TrimSpace(s) == "" {
				return
			}
			msgs = append(msgs, s)
		}
		old, _, _ := runner.Get()
		cfg := old
		oldEnc := strings.TrimSpace(cfg.UDPEncryptionMode)
		webWas := cfg.WebHTTPS
		cfg.ControlAddr = r.Form.Get("control")
		cfg.DataAddr = r.Form.Get("data")
		cfg.DataAddrInsecure = r.Form.Get("data_insecure")
		cfg.Token = strings.TrimSpace(r.Form.Get("token"))
		cfg.PairTimeout = pt
		cfg.WebHTTPS = strings.TrimSpace(r.Form.Get("web_https")) != ""
		if cfg.Token == "" {
			cfg.Token = genToken()
			addMsg("Token was empty; generated a new token")
		}
		cfg.Routes = parseServerRoutesForm(r)

		// UDP encryption config
		cfg.UDPEncryptionMode = strings.TrimSpace(r.Form.Get("udp_enc"))
		if strings.EqualFold(cfg.UDPEncryptionMode, "none") {
			cfg.DisableUDPEncryption = true
		} else {
			cfg.DisableUDPEncryption = false
		}
		if strings.TrimSpace(r.Form.Get("udp_regen")) != "" {
			tunnel.RotateUDPKeys(&cfg, time.Now())
			addMsg("Regenerated UDP keys")
		} else if strings.TrimSpace(oldEnc) != strings.TrimSpace(cfg.UDPEncryptionMode) {
			// Mode changed: regenerate keys to force a clean cutover.
			tunnel.RotateUDPKeys(&cfg, time.Now())
			addMsg("UDP encryption changed; regenerated UDP keys")
		}
		_ = tunnel.EnsureUDPKeys(&cfg, time.Now())
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
				log.Printf("tunnel tls regenerated; cert sha256=%s", fp)
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
			log.Printf("tunnel tls enabled; cert sha256=%s", fp)
		}

		// Dashboard HTTPS (self-signed)
		cfgDir := filepath.Dir(configPath)
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

		if err := configio.Save(configPath, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		runner.Restart(cfg)
		addMsg("Saved + restarted")
		setMsg(strings.Join(msgs, " · "))

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

		// Back-compat: old save endpoint
		mux.HandleFunc("/save", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
		})))

		mux.HandleFunc("/gen-token", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		cfg.Token = genToken()
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
			ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = h.Shutdown(ctx2)
			cancel()
			err := <-errCh
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		case <-restartCh:
			ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = h.Shutdown(ctx2)
			cancel()
			err := <-errCh
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			// Drain any queued restarts.
			for {
				select {
				case <-restartCh:
				default:
					goto next
				}
			}
		case err := <-errCh:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}
		
	next:
		continue
	}
}

func genToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func detectModuleDir(configPath string) string {
	// Prefer current working directory if build.sh is present.
	if wd, err := os.Getwd(); err == nil && wd != "" {
		if fileExists(filepath.Join(wd, "build.sh")) {
			return wd
		}
	}
	// If we're running from ./bin/<binary>, prefer the parent dir.
	if exe, err := os.Executable(); err == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		if filepath.Base(exeDir) == "bin" {
			parent := filepath.Dir(exeDir)
			if fileExists(filepath.Join(parent, "build.sh")) {
				return parent
			}
		}
	}
	// Fallback: alongside config.
	if strings.TrimSpace(configPath) != "" {
		return filepath.Dir(configPath)
	}
	return "."
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func effectiveServerRoutes(cfg tunnel.ServerConfig) []tunnel.RouteConfig {
	return cfg.Routes
}

func parseServerRoutesForm(r *http.Request) []tunnel.RouteConfig {
	count, _ := strconv.Atoi(strings.TrimSpace(r.Form.Get("route_count")))
	if count < 0 {
		count = 0
	}
	if count > 64 {
		count = 64
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
		nodelayRaw := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_nodelay"))
		nodelay := nodelayRaw != "" && nodelayRaw != "0" && !strings.EqualFold(nodelayRaw, "false")
		tlsRaw := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_tls"))
		tlsOn := tlsRaw != "" && tlsRaw != "0" && !strings.EqualFold(tlsRaw, "false")
		pcRaw := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_preconnect"))
		pc := 0
		if pcRaw != "" {
			if n, err := strconv.Atoi(pcRaw); err == nil {
				if n < 0 {
					n = 0
				}
				if n > 64 {
					n = 64
				}
				pc = n
			}
		}
		if name == "" && proto == "" && pub == "" {
			continue
		}
		if name == "" {
			name = "default"
		}
		if proto == "" {
			proto = "tcp"
		}
		routes = append(routes, tunnel.RouteConfig{Name: name, Proto: proto, PublicAddr: pub, TCPNoDelay: &nodelay, TunnelTLS: &tlsOn, Preconnect: &pc})
	}
	return routes
}

const serverStatsHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tunnel Server</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 0; }
		.wrap { max-width: 920px; margin: 0 auto; padding: 24px 16px 56px; }
    .top { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    h2 { margin: 22px 0 10px; font-size: 16px; }
    .muted { opacity: .8; }
    .card { border: 1px solid rgba(127,127,127,.25); border-radius: 12px; padding: 14px; background: rgba(127,127,127,.06); }
    .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
    .row { margin-bottom: 10px; }
    .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
    button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
    button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
    .pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
    .ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
    .bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
    .flash { margin: 10px 0 0; }
		.nav { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
		.nav a { text-decoration:none; padding: 6px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); }
		.nav a.active { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.updatePopup { position: fixed; right: 16px; bottom: 16px; max-width: 520px; width: calc(100% - 32px); z-index: 1000; display:none; }
		.updatePopup pre { white-space: pre-wrap; margin: 10px 0 0; padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); background: rgba(127,127,127,.06); max-height: 220px; overflow:auto; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>Tunnel Server</h1>
				<div class="muted">Public routes that forward to one connected agent.</div>
      </div>
      <div class="card">
				<div class="nav">
					<a class="active" href="/">Stats</a>
					<a href="/config">Config</a>
					<a href="/controls">Controls</a>
					<form method="post" action="/logout" style="display:inline; margin: 0">
						<input type="hidden" name="csrf" value="{{.CSRF}}" />
						<button type="submit">Logout</button>
					</form>
				</div>
        <div class="row"><b>Status:</b>
          {{if .Status.AgentConnected}}<span class="pill ok">Agent connected</span>{{else}}<span class="pill bad">No agent</span>{{end}}
        </div>
        <div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
        {{if .Err}}<div class="row"><b>Last server error:</b> <span class="muted">{{.Err}}</span></div>{{end}}
      </div>
    </div>

    {{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

		<h2>Overview</h2>
    <div class="card">
			<div class="muted">Clients connect to a <b>Route</b> on this server. The server notifies the agent over <b>Control</b>. TCP is paired over <b>Data (TCP)</b>; UDP is relayed over <b>Data (UDP)</b>.</div>
    </div>

		<h2>Statistics</h2>
		<div class="grid">
			<div class="card">
				<div class="row"><b>Agent:</b>
					<span id="agentPill" class="pill {{if .Status.AgentConnected}}ok{{else}}bad{{end}}">{{if .Status.AgentConnected}}Connected{{else}}Disconnected{{end}}</span>
				</div>
				<div class="row"><b>Public clients:</b> <span id="activeClientsVal">—</span></div>
				<div class="row"><b>Bandwidth (last 5m):</b> <span id="bw5mVal">—</span></div>
				<div class="row"><b>Total transferred:</b> <span id="bytesTotalVal">—</span></div>
				<div class="row"><b>Routes:</b> {{.RouteCount}}</div>
				<div class="row"><b>Control:</b> <code>{{.Cfg.ControlAddr}}</code></div>
				<div class="row"><b>Data:</b> <code>{{.Cfg.DataAddr}}</code></div>
				<div class="row" id="errRow" style="display:none"><b>Last server error:</b> <span class="muted" id="errText"></span></div>
				<div class="row"><span class="muted" id="liveText">Updating…</span></div>
			</div>
			<div class="card">
				<div class="muted">Edit server settings on the <a href="/config">Config</a> page.</div>
			</div>
		</div>


		<h2>Bandwidth</h2>
		<div class="card">
			<div class="btns" style="margin-top:0">
				<button type="button" id="bwScale1h">1 hour</button>
				<button type="button" id="bwScale6h">6 hours</button>
				<button type="button" id="bwScale12h">12 hours</button>
				<button type="button" id="bwScale24h">1 day</button>
				<span class="muted" id="bwScaleLabel" style="align-self:center">—</span>
			</div>
			<canvas id="bwChart" width="880" height="160" style="width:100%; max-width:100%;"></canvas>
			<div class="muted" style="margin-top:8px">Shows bytes transferred per 5-minute interval.</div>
		</div>

		<h2>Routes</h2>
		{{if eq .RouteCount 0}}
			<div class="card">
				<div class="muted">No routes are configured. Add routes in <a href="/config">Config</a> to start accepting public connections.</div>
			</div>
		{{end}}
		{{range .Routes}}
			<details class="card" style="margin-top:12px" data-route="{{.Name}}">
				<summary style="cursor:pointer">
					<b>{{.Name}}</b> <span class="muted">({{.Proto}})</span> — <code>{{.PublicAddr}}</code>
				</summary>
				<div style="margin-top:10px">
					<div class="row"><b>Active clients:</b> <span data-route-active>—</span></div>
					<div class="row"><b>Recent events</b> <span class="muted">(newest first)</span></div>
					<pre data-route-console style="white-space:pre-wrap; margin:0; padding:10px; border-radius:10px; border:1px solid rgba(127,127,127,.25); background: rgba(127,127,127,.06); max-height: 260px; overflow:auto;"></pre>
				</div>
			</details>
		{{end}}
  </div>
	<div id="updatePopup" class="card updatePopup">
		<div class="row"><b>Update available</b> <span class="muted" id="updVer">—</span></div>
		<div class="row muted" id="updInfo">Current: <code>{{.Version}}</code></div>
		<div class="btns" style="margin-top:0">
			<button type="button" id="updRemind">Remind later</button>
			<button type="button" id="updSkip">Skip version</button>
			<button type="button" class="primary" id="updApply">Update</button>
		</div>
		<pre id="updSteps" class="muted" style="display:none; margin: 10px 0 0; padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); background: rgba(127,127,127,.06);"></pre>
		<pre id="updLog" style="display:none"></pre>
	</div>
	<div id="procPopup" class="card updatePopup" style="right: 16px; bottom: 162px; max-width: 360px;">
		<div class="row"><b>Process</b> <span class="muted">(server)</span></div>
		<div class="btns" style="margin-top:0">
			<button type="button" id="procRestart">Restart</button>
			<button type="button" id="procExit">Exit</button>
		</div>
		<div class="muted" style="margin-top:8px">If running under systemd, it will restart automatically.</div>
	</div>
	<script>
		(function(){
			var csrf = "{{.CSRF}}";
			var procPopup = document.getElementById('procPopup');
			var procRestart = document.getElementById('procRestart');
			var procExit = document.getElementById('procExit');
			var updPopup = document.getElementById('updatePopup');
			var updVer = document.getElementById('updVer');
			var updInfo = document.getElementById('updInfo');
			var updSteps = document.getElementById('updSteps');
			var updLog = document.getElementById('updLog');
			var updRemind = document.getElementById('updRemind');
			var updSkip = document.getElementById('updSkip');
			var updApply = document.getElementById('updApply');

			function sleep(ms){ return new Promise(function(r){ setTimeout(r, ms); }); }
			async function postForm(path){
				try {
					return await fetch(path, {
						method: 'POST',
						headers: {'Content-Type':'application/x-www-form-urlencoded'},
						body: 'csrf=' + encodeURIComponent(csrf)
					});
				} catch (e) {
					return null;
				}
			}
			async function postFormRaw(path){
				return await postForm(path);
			}
			async function fetchUpdateStatus(){
				try {
					var res = await fetch('/api/update/status', {cache:'no-store'});
					if(!res.ok) return null;
					return await res.json();
				} catch (e) {
					return null;
				}
			}
			function setPopupVisible(v){
				if(!updPopup) return;
				updPopup.style.display = v ? '' : 'none';
			}
			function renderUpdateSteps(st){
				if(!updSteps) return;
				var running = !!(st && st.job && st.job.state === 'running');
				var log = (st && st.job && st.job.log) ? String(st.job.log) : '';
				if(!running){
					updSteps.style.display = 'none';
					updSteps.textContent = '';
					return;
				}
				var has = function(re){ try { return re.test(log); } catch(e){ return false; } };
				var s1 = has(/Downloading:/) && has(/Downloaded\s+\d+\s+bytes/);
				var s2 = has(/Extracted source:/) && has(/Applying into:/);
				var s3 = has(/Running build\.sh/);
				var s4 = has(/Build succeeded/) || has(/Build failed/);
				var s5 = !!(st && st.job && st.job.restarting);
				var fmt = function(done, label){ return (done ? '[x] ' : '[ ] ') + label; };
				updSteps.textContent = [
					fmt(s1, 'Download release assets'),
					fmt(s2, 'Apply files'),
					fmt(s3, 'Build'),
					fmt(s4, 'Build finished'),
					fmt(s5, 'Restarting'),
				].join('\n');
				updSteps.style.display = '';
			}
			function renderUpdate(st){
				if(!st){
					return;
				}
				var show = !!st.showPopup || (st.job && st.job.state && st.job.state !== 'idle');
				setPopupVisible(show);
				if(!show) return;
				if(updVer) updVer.textContent = st.availableVersion ? ('→ ' + st.availableVersion) : '';
				if(updInfo){
					var s = 'Current: {{.Version}}';
					if(st.availableURL){ s += ' · ' + st.availableURL; }
					if(st.job && st.job.state === 'running') s = 'Updating…';
					if(st.job && st.job.state === 'success') s = 'Update complete. Restarting…';
					if(st.job && st.job.state === 'failed') s = 'Update failed.';
					updInfo.textContent = s;
				}
				renderUpdateSteps(st);
				if(updLog){
					var log = (st.job && st.job.log) ? String(st.job.log) : '';
					if(st.job && (st.job.state === 'failed' || st.job.state === 'success' || st.job.state === 'running')){
						updLog.style.display = '';
						updLog.textContent = log || '(no log)';
					} else {
						updLog.style.display = 'none';
						updLog.textContent = '';
					}
				}
				var busy = st.job && st.job.state === 'running';
				if(updApply) updApply.disabled = busy;
				if(updRemind) updRemind.disabled = busy;
				if(updSkip) updSkip.disabled = busy;
			}
			async function pollUpdateUntilDone(){
				for(;;){
					var st = await fetchUpdateStatus();
					if(st){
						renderUpdate(st);
						if(st.job && st.job.state && st.job.state !== 'running'){
							break;
						}
					}
					await sleep(500);
				}
				// If we successfully updated, the process may restart; wait until it comes back then reload.
				for (var i=0;i<90;i++){
					var st2 = await fetchUpdateStatus();
					if(st2){
						location.replace(location.pathname + '?r=' + Date.now());
						return;
					}
					await sleep(1000);
				}
			}

			if (updRemind) updRemind.addEventListener('click', async function(){
				await postForm('/api/update/remind');
				setPopupVisible(false);
			});
			if (updSkip) updSkip.addEventListener('click', async function(){
				await postForm('/api/update/skip');
				setPopupVisible(false);
			});
			if (updApply) updApply.addEventListener('click', async function(){
				var res = await postForm('/api/update/apply');
				if(res && (res.status === 202 || res.status === 409 || res.status === 204)){
					pollUpdateUntilDone();
					return;
				}
				await pollUpdateUntilDone();
			});

			if (procPopup) procPopup.style.display = '';
			if (procRestart) procRestart.addEventListener('click', async function(){
				await postFormRaw('/api/process/restart');
				// Let the browser show something briefly then the server will go away.
				setTimeout(function(){ location.replace(location.pathname + '?r=' + Date.now()); }, 1000);
			});
			if (procExit) procExit.addEventListener('click', async function(){
				await postFormRaw('/api/process/exit');
				setTimeout(function(){ location.replace(location.pathname + '?r=' + Date.now()); }, 1000);
			});

			// initial load
			fetchUpdateStatus().then(renderUpdate);
			setInterval(function(){ fetchUpdateStatus().then(renderUpdate); }, 30000);

			function fmtBytes(n){
				n = Number(n||0);
				if (!isFinite(n) || n < 0) n = 0;
				var units = ['B','KiB','MiB','GiB','TiB'];
				var u = 0;
				while (n >= 1024 && u < units.length-1){ n /= 1024; u++; }
				return (u === 0 ? String(Math.round(n)) : n.toFixed(2)) + ' ' + units[u];
			}
			function setPill(el, ok, text){
				if(!el) return;
				el.classList.remove('ok');
				el.classList.remove('bad');
				el.classList.add(ok ? 'ok' : 'bad');
				el.textContent = text;
			}
			function drawChart(series){
				var c = document.getElementById('bwChart');
				if(!c || !c.getContext) return;
				var ctx = c.getContext('2d');
				var w = c.width, h = c.height;
				ctx.clearRect(0,0,w,h);
				if(!series || !series.length) return;
				var max = 0;
				for (var i=0;i<series.length;i++) max = Math.max(max, Number(series[i].bytes||0));
				if (max <= 0) max = 1;
				ctx.strokeStyle = 'rgba(46, 125, 255, .85)';
				ctx.lineWidth = 2;
				ctx.beginPath();
				for (var i2=0;i2<series.length;i2++){
					var x = (i2/(series.length-1)) * (w-2) + 1;
					var y = h - ((Number(series[i2].bytes||0)/max) * (h-10)) - 5;
					if(i2===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
				}
				ctx.stroke();
				ctx.strokeStyle = 'rgba(127,127,127,.35)';
				ctx.lineWidth = 1;
				ctx.strokeRect(0.5,0.5,w-1,h-1);
			}
			function bucketSeconds(series){
				if(!series || series.length < 2) return 300;
				var a = Number(series[0].t||0);
				var b = Number(series[1].t||0);
				var dt = b - a;
				if(!isFinite(dt) || dt <= 0) return 300;
				// clamp to something sane
				if(dt > 3600) return 3600;
				return dt;
			}
			function sliceWindow(series, windowSec){
				if(!series || !series.length) return series;
				windowSec = Number(windowSec||0);
				if(!isFinite(windowSec) || windowSec <= 0) return series;
				var dt = bucketSeconds(series);
				var n = Math.floor(windowSec / dt);
				if(n < 1) n = 1;
				if(n > series.length) n = series.length;
				return series.slice(series.length - n);
			}
			function renderRouteConsole(el, route){
				if(!el) return;
				var lines = [];
				var ev = (route && route.events) ? route.events : [];
				for (var i=ev.length-1;i>=0;i--){
					var e = ev[i] || {};
					var ts = e.t ? new Date(e.t*1000).toLocaleString() : '';
					var s = ts + '  ' + (e.kind||'')
						+ (e.ip ? ('  ip=' + e.ip) : '')
						+ (e.id ? ('  id=' + e.id) : '')
						+ (e.bytes ? ('  bytes=' + fmtBytes(e.bytes)) : '')
						+ (e.durMs ? ('  dur=' + e.durMs + 'ms') : '')
						+ (e.detail ? ('  ' + e.detail) : '');
					lines.push(s);
					if (lines.length >= 20) break;
				}
				el.textContent = lines.length ? lines.join('\n') : 'No events yet.';
			}

			var agentPill = document.getElementById('agentPill');
			var activeClientsVal = document.getElementById('activeClientsVal');
			var bw5mVal = document.getElementById('bw5mVal');
			var bytesTotalVal = document.getElementById('bytesTotalVal');
			var liveText = document.getElementById('liveText');
			var errRow = document.getElementById('errRow');
			var errText = document.getElementById('errText');
			var lastSeries = null;
			var bwScaleSec = 24 * 3600;
			var bwScaleLabel = document.getElementById('bwScaleLabel');
			var bwBtn1h = document.getElementById('bwScale1h');
			var bwBtn6h = document.getElementById('bwScale6h');
			var bwBtn12h = document.getElementById('bwScale12h');
			var bwBtn24h = document.getElementById('bwScale24h');

			function setScale(sec){
				bwScaleSec = Number(sec||0);
				if(!isFinite(bwScaleSec) || bwScaleSec <= 0) bwScaleSec = 24*3600;
				var btns = [bwBtn1h,bwBtn6h,bwBtn12h,bwBtn24h];
				for(var i=0;i<btns.length;i++){
					var b = btns[i];
					if(!b) continue;
					b.classList.remove('primary');
				}
				if(bwScaleSec === 3600 && bwBtn1h) bwBtn1h.classList.add('primary');
				else if(bwScaleSec === 6*3600 && bwBtn6h) bwBtn6h.classList.add('primary');
				else if(bwScaleSec === 12*3600 && bwBtn12h) bwBtn12h.classList.add('primary');
				else if(bwScaleSec === 24*3600 && bwBtn24h) bwBtn24h.classList.add('primary');
				if(bwScaleLabel){
					var txt = 'Range: ';
					if(bwScaleSec === 3600) txt += '1 hour';
					else if(bwScaleSec === 6*3600) txt += '6 hours';
					else if(bwScaleSec === 12*3600) txt += '12 hours';
					else if(bwScaleSec === 24*3600) txt += '1 day';
					else txt += Math.round(bwScaleSec/3600) + 'h';
					bwScaleLabel.textContent = txt;
				}
				if(lastSeries){
					drawChart(sliceWindow(lastSeries, bwScaleSec));
				}
			}

			function computeLast5m(series){
				if(!series || !series.length) return 0;
				var p = series[series.length-1];
				return Number(p && p.bytes ? p.bytes : 0);
			}

			async function poll(){
				try {
					var res = await fetch('/api/stats', {cache:'no-store'});
					if(!res.ok) throw new Error('http ' + res.status);
					var j = await res.json();
					setPill(agentPill, !!j.agentConnected, j.agentConnected ? 'Connected' : 'Disconnected');
					if(activeClientsVal) activeClientsVal.textContent = String(j.activeClients == null ? '—' : j.activeClients);
					if(bw5mVal) bw5mVal.textContent = fmtBytes(computeLast5m(j.series));
					if(bytesTotalVal) bytesTotalVal.textContent = fmtBytes(j.bytesTotal || 0);
					if(errRow && errText){
						if(j.err){ errRow.style.display = ''; errText.textContent = j.err; }
						else { errRow.style.display = 'none'; errText.textContent = ''; }
					}
					if(liveText) liveText.textContent = 'Last update: ' + new Date().toLocaleTimeString();
					if(j.series && j.series !== lastSeries){
						lastSeries = j.series;
						drawChart(sliceWindow(j.series, bwScaleSec));
					}
					var routes = j.routes || [];
					for (var i=0;i<routes.length;i++){
						var rt = routes[i] || {};
						var det = document.querySelector('details[data-route="' + (rt.name||'') + '"]');
						if(!det) continue;
						var a = det.querySelector('[data-route-active]');
						if(a) a.textContent = String(rt.active == null ? '—' : rt.active);
						var c = det.querySelector('[data-route-console]');
						renderRouteConsole(c, rt);
					}
				} catch (e) {
					if(liveText) liveText.textContent = 'Offline (' + (e && e.message ? e.message : 'error') + ')';
				}
			}

			if(bwBtn1h) bwBtn1h.addEventListener('click', function(){ setScale(3600); });
			if(bwBtn6h) bwBtn6h.addEventListener('click', function(){ setScale(6*3600); });
			if(bwBtn12h) bwBtn12h.addEventListener('click', function(){ setScale(12*3600); });
			if(bwBtn24h) bwBtn24h.addEventListener('click', function(){ setScale(24*3600); });
			setScale(24*3600);
			poll();
			setInterval(poll, 2000);
		})();
	</script>
</body>
</html>`

const serverConfigHTML = `<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Server - Config</title>
	<style>
		:root { color-scheme: light dark; }
		body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 0; }
		.wrap { max-width: 920px; margin: 0 auto; padding: 24px 16px 56px; }
		.top { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; }
		h1 { margin: 0 0 8px; font-size: 22px; }
		h2 { margin: 22px 0 10px; font-size: 16px; }
		.muted { opacity: .8; }
		.card { border: 1px solid rgba(127,127,127,.25); border-radius: 12px; padding: 14px; background: rgba(127,127,127,.06); }
		.grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
		@media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
		label { font-weight: 600; display:block; margin: 0 0 4px; }
		.help { font-size: 12px; margin: 0 0 8px; opacity: .85; line-height: 1.35; }
		input, select { width: 100%; max-width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
		.row { margin-bottom: 10px; }
		.btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
		button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
		button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
		.ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
		.bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
		code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
		.flash { margin: 10px 0 0; }
		.nav { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
		.nav a { text-decoration:none; padding: 6px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); }
		.nav a.active { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.route { margin-top: 12px; }
		.routeHead { display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="top">
			<div>
				<h1>Tunnel Server</h1>
				<div class="muted">Configuration</div>
			</div>
			<div class="card">
				<div class="nav">
					<a href="/">Stats</a>
					<a class="active" href="/config">Config</a>
					<a href="/controls">Controls</a>
					<form method="post" action="/logout" style="display:inline; margin: 0">
						<input type="hidden" name="csrf" value="{{.CSRF}}" />
						<button type="submit">Logout</button>
					</form>
				</div>
				<div class="row"><b>Status:</b>
					{{if .Status.AgentConnected}}<span class="pill ok">Agent connected</span>{{else}}<span class="pill bad">No agent</span>{{end}}
				</div>
				<div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
				{{if .Err}}<div class="row"><b>Last server error:</b> <span class="muted">{{.Err}}</span></div>{{end}}
			</div>
		</div>

		{{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

		<form method="post" action="/config/save" class="card">
			<input type="hidden" name="csrf" value="{{.CSRF}}" />

			<h2>Listeners</h2>
			<div class="grid">
				<div>
					<label>Control listen</label>
					<div class="help">Where the agent connects for commands (e.g. <code>:7000</code>).</div>
					<input name="control" value="{{.Cfg.ControlAddr}}" />
				</div>

				<div>
					<label>Data listen</label>
					<div class="help">Used for TCP pairing and UDP relay (same port, TCP+UDP).</div>
					<input name="data" value="{{.Cfg.DataAddr}}" />
				</div>

				<div>
					<label>Insecure data listen (optional)</label>
					<div class="help">Optional plaintext TCP data listener for routes that disable tunnel TLS. Leave empty to disable (recommended).</div>
					<input name="data_insecure" value="{{.Cfg.DataAddrInsecure}}" />
				</div>

				<div>
					<label>Pair timeout</label>
					<div class="help">How long to wait for the agent to attach after a TCP client connects (e.g. <code>10s</code>).</div>
					<input name="pair_timeout" value="{{.Cfg.PairTimeout}}" />
				</div>
			</div>

			<h2>Security</h2>
			<div class="grid">
				<div>
					<label>Token (optional)</label>
					<div class="help">Shared secret the agent must provide.</div>
					<input name="token" value="{{.Cfg.Token}}" />
				</div>
				<div>
					<label>Generate token</label>
					<div class="help">Generates a new random token and restarts the server.</div>
					<div class="btns">
						<button type="submit" formmethod="post" formaction="/gen-token">Generate token + restart</button>
					</div>
				</div>
				<div>
					<label>Tunnel TLS</label>
					{{if .Cfg.DisableTLS}}
						<div class="help">TLS for agent↔server TCP is disabled.</div>
					{{else}}
						<div class="help">Regenerates the tunnel TLS certificate/private key and restarts the server. This changes the cert fingerprint (pinned agents must be updated).</div>
						<div class="help">Cert: <code>{{.Cfg.TLSCertFile}}</code><br/>Key: <code>{{.Cfg.TLSKeyFile}}</code></div>
						<div class="btns">
							<button type="submit" name="tls_regen" value="1">Regenerate TLS cert/key + restart</button>
						</div>
					{{end}}
				</div>
				<div>
					<label>Dashboard HTTPS (self-signed)</label>
					<div class="help">Serves this dashboard over HTTPS on the <code>-web</code> address. Browsers will show a warning for self-signed certs; that's expected.</div>
					<label style="font-weight: 400; display:flex; gap:8px; align-items:center">
						<input type="checkbox" name="web_https" value="1" style="width:auto" {{if .Cfg.WebHTTPS}}checked{{end}} />
						<span>Enable HTTPS for dashboard</span>
					</label>
					<div class="help" style="margin-top:8px">Cert: <code>{{.WebTLSCert}}</code><br/>Key: <code>{{.WebTLSKey}}</code>{{if .WebTLSFP}}<br/>Cert sha256: <code>{{.WebTLSFP}}</code>{{end}}</div>
					<div class="btns">
						<button type="submit" name="web_tls_regen" value="1">Regenerate dashboard cert/key</button>
					</div>
				</div>
				<div>
					<label>UDP Encryption</label>
					<div class="help">Message-layer encryption for agent↔server UDP relay.</div>
					<select name="udp_enc">
						<option value="none" {{if eq .Cfg.UDPEncryptionMode "none"}}selected{{end}}>No encryption</option>
						<option value="aes128" {{if eq .Cfg.UDPEncryptionMode "aes128"}}selected{{end}}>128-bit (AES-GCM)</option>
						<option value="aes256" {{if or (eq .Cfg.UDPEncryptionMode "aes256") (eq .Cfg.UDPEncryptionMode "")}}selected{{end}}>256-bit (AES-GCM)</option>
					</select>
					<div class="help" style="margin-top:8px">
						Current key id: <code>{{.Cfg.UDPKeyID}}</code>{{if .UDPKeyCreated}} · created: <code>{{.UDPKeyCreated}}</code>{{end}}
					</div>
				</div>
				<div>
					<label>Regenerate UDP keys</label>
					<div class="help">Forces a new UDP key and restarts the server (agents will reconnect).</div>
					<div class="btns">
						<button type="submit" name="udp_regen" value="1">Regenerate UDP keys + restart</button>
					</div>
				</div>
			</div>

			<h2>Routes</h2>
			<div class="help">Each route is a public entry. Route <b>Name</b> must match the client route name.</div>

			<input type="hidden" name="route_count" id="route_count" value="{{.RouteCount}}" />

			<div id="routes">
				{{range $i, $r := .Routes}}
					<div class="card route" data-route>
						<div class="routeHead">
							<div><b>Route</b></div>
							<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap">
								<div class="muted">#{{$i}}</div>
								<button type="button" data-remove-route>Remove</button>
							</div>
						</div>
						<input type="hidden" name="route_{{$i}}_delete" value="0" data-route-delete />
						<div class="grid" style="margin-top:10px">
							<div>
								<label>Name</label>
								<input name="route_{{$i}}_name" value="{{$r.Name}}" />
							</div>
							<div>
								<label>Protocol</label>
								<select name="route_{{$i}}_proto">
									<option value="tcp" {{if eq $r.Proto "tcp"}}selected{{end}}>tcp</option>
									<option value="udp" {{if eq $r.Proto "udp"}}selected{{end}}>udp</option>
									<option value="both" {{if eq $r.Proto "both"}}selected{{end}}>both</option>
								</select>
							</div>
							<div>
								<label>Public address</label>
								<div class="help">Listen address, e.g. <code>:25565</code> (TCP/UDP depending on protocol).</div>
								<input name="route_{{$i}}_public" value="{{$r.PublicAddr}}" />
							</div>
							<div>
								<label>Low latency</label>
								<div class="help">Enables <code>TCP_NODELAY</code> for this route (reduces small-packet latency; recommended for games).</div>
								<label style="font-weight: 400; display:flex; gap:8px; align-items:center">
									<input type="checkbox" name="route_{{$i}}_nodelay" value="1" style="width:auto" {{if $r.TCPNoDelay}}checked{{end}} />
									<span>Enable TCP_NODELAY</span>
								</label>
							</div>
							<div>
								<label>Data channel TLS</label>
								<div class="help">Encrypts the agent↔server TCP data channel for this route. Disabling reduces overhead but exposes traffic/token to the network.</div>
								<label style="font-weight: 400; display:flex; gap:8px; align-items:center">
									<input type="checkbox" name="route_{{$i}}_tls" value="1" style="width:auto" {{if $r.TunnelTLS}}checked{{end}} />
									<span>Enable TLS</span>
								</label>
							</div>
							<div>
								<label>Preconnect</label>
								<div class="help">Number of ready data connections to keep warm for this route. <code>0</code> = on-demand.</div>
								<input type="number" min="0" max="64" name="route_{{$i}}_preconnect" value="{{$r.Preconnect}}" />
							</div>
						</div>
					</div>
				{{end}}
			</div>

			<div class="btns">
				<button type="button" id="addRoute">Add route</button>
				<button type="submit" class="primary">Save + restart</button>
			</div>
		</form>
	</div>

	<template id="routeTemplate">
		<div class="card route" data-route>
			<div class="routeHead">
				<div><b>Route</b></div>
				<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap">
					<div class="muted">#IDX</div>
					<button type="button" data-remove-route>Remove</button>
				</div>
			</div>
			<input type="hidden" name="route_IDX_delete" value="0" data-route-delete />
			<div class="grid" style="margin-top:10px">
				<div>
					<label>Name</label>
					<input name="route_IDX_name" value="" />
				</div>
				<div>
					<label>Protocol</label>
					<select name="route_IDX_proto">
						<option value="tcp" selected>tcp</option>
						<option value="udp">udp</option>
						<option value="both">both</option>
					</select>
				</div>
				<div>
					<label>Public address</label>
					<div class="help">Listen address, e.g. <code>:25565</code>.</div>
					<input name="route_IDX_public" value="" />
				</div>
				<div>
					<label>Low latency</label>
					<div class="help">Enables <code>TCP_NODELAY</code> for this route.</div>
					<label style="font-weight: 400; display:flex; gap:8px; align-items:center">
						<input type="checkbox" name="route_IDX_nodelay" value="1" style="width:auto" checked />
						<span>Enable TCP_NODELAY</span>
					</label>
				</div>
				<div>
					<label>Data channel TLS</label>
					<div class="help">Encrypts the agent↔server TCP data channel for this route.</div>
					<label style="font-weight: 400; display:flex; gap:8px; align-items:center">
						<input type="checkbox" name="route_IDX_tls" value="1" style="width:auto" checked />
						<span>Enable TLS</span>
					</label>
				</div>
				<div>
					<label>Preconnect</label>
					<div class="help">Number of ready data connections to keep warm for this route. <code>0</code> = on-demand.</div>
					<input type="number" min="0" max="64" name="route_IDX_preconnect" value="4" />
				</div>
			</div>
		</div>
	</template>

	<script>
		(function(){
			var btn = document.getElementById('addRoute');
			var routes = document.getElementById('routes');
			var countEl = document.getElementById('route_count');
			var tpl = document.getElementById('routeTemplate');
			if (!btn || !routes || !countEl || !tpl) return;
			routes.addEventListener('click', function(e){
				var t = e.target;
				if (!t || !t.matches || !t.matches('[data-remove-route]')) return;
				e.preventDefault();
				var card = t.closest ? t.closest('[data-route]') : null;
				if (!card) return;
				var del = card.querySelector ? card.querySelector('[data-route-delete]') : null;
				if (del) del.value = '1';
				card.style.display = 'none';
			});
			btn.addEventListener('click', function(){
				var idx = parseInt(countEl.value || '0', 10);
				var html = tpl.innerHTML.split('IDX').join(String(idx));
				var wrap = document.createElement('div');
				wrap.innerHTML = html;
				routes.appendChild(wrap.firstElementChild);
				countEl.value = String(idx + 1);
			});
		})();
	</script>
</body>
</html>`

const serverControlsHTML = `<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Server - Controls</title>
	<style>
		:root { color-scheme: light dark; }
		body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 0; }
		.wrap { max-width: 920px; margin: 0 auto; padding: 24px 16px 56px; }
		.top { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap; }
		h1 { margin: 0 0 8px; font-size: 22px; }
		h2 { margin: 22px 0 10px; font-size: 16px; }
		.muted { opacity: .8; }
		.card { border: 1px solid rgba(127,127,127,.25); border-radius: 12px; padding: 14px; background: rgba(127,127,127,.06); }
		.grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
		@media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
		.row { margin-bottom: 10px; }
		.btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
		button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
		button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		button[disabled] { opacity: .55; cursor: not-allowed; }
		.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
		.ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
		.bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
		code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
		.flash { margin: 10px 0 0; }
		.nav { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
		.nav a { text-decoration:none; padding: 6px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); }
		.nav a.active { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		pre { white-space: pre-wrap; margin: 10px 0 0; padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); background: rgba(127,127,127,.06); max-height: 220px; overflow:auto; }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="top">
			<div>
				<h1>Tunnel Server</h1>
				<div class="muted">Server Controls</div>
			</div>
			<div class="card">
				<div class="nav">
					<a href="/">Stats</a>
					<a href="/config">Config</a>
					<a class="active" href="/controls">Controls</a>
					<form method="post" action="/logout" style="display:inline; margin: 0">
						<input type="hidden" name="csrf" value="{{.CSRF}}" />
						<button type="submit">Logout</button>
					</form>
				</div>
				<div class="row"><b>Status:</b>
					{{if .Status.AgentConnected}}<span class="pill ok">Agent connected</span>{{else}}<span class="pill bad">No agent</span>{{end}}
				</div>
				<div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
				{{if .Err}}<div class="row"><b>Last server error:</b> <span class="muted">{{.Err}}</span></div>{{end}}
			</div>
		</div>

		{{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

		<h2>Updates</h2>
		<div class="card">
			<div class="grid">
				<div>
					<div class="row"><b>Current version:</b> <code>{{.Version}}</code></div>
					<div class="row"><b>Available version:</b> <code id="availableVersion">—</code></div>
					<div class="btns">
						<button id="checkNowBtn" type="button">Check for updates</button>
						<button id="applyBtn" type="button" class="primary" disabled>Update</button>
					</div>
					<div class="row"><span class="muted" id="updateState">—</span></div>
				</div>
				<div>
					<pre id="updateLog" style="display:none"></pre>
				</div>
			</div>
		</div>

		<h2>systemd</h2>
		<div class="card">
			<div class="row"><b>Service:</b> <code>hostit-server.service</code></div>
			<div class="row"><b>State:</b> <code id="systemdState">—</code></div>
			<div class="btns">
				<button id="svcRestartBtn" type="button">Restart service</button>
				<button id="svcStopBtn" type="button">Stop service</button>
			</div>
			<div class="row"><span class="muted" id="systemdMsg">—</span></div>
		</div>
	</div>

	<script>
		var csrf = {{printf "%q" .CSRF}};

		function setUpdateStatus(st) {
			if (!st) return;
			var avail = document.getElementById('availableVersion');
			var btn = document.getElementById('applyBtn');
			var state = document.getElementById('updateState');
			var log = document.getElementById('updateLog');
			avail.textContent = st.latestVersion || '—';
			btn.disabled = !st.updateAvailable;
			state.textContent = st.updateAvailable ? 'Update available' : 'Up to date';
			if (st.job && st.job.log) {
				log.style.display = 'block';
				log.textContent = st.job.log;
			} else {
				log.style.display = 'none';
				log.textContent = '';
			}
		}

		async function refreshUpdateStatus() {
			var r = await fetch('/api/update/status', { method: 'GET', credentials: 'include' });
			setUpdateStatus(await r.json());
		}

		async function checkNow() {
			document.getElementById('updateState').textContent = 'Checking…';
			var body = new URLSearchParams();
			body.set('csrf', csrf);
			var r = await fetch('/api/update/check-now', { method: 'POST', body: body, credentials: 'include', headers: { 'X-CSRF-Token': csrf } });
			if (!r.ok) {
				var t = '';
				try { t = await r.text(); } catch (e) {}
				document.getElementById('updateState').textContent = t ? ('Check failed: ' + t) : 'Check failed';
				return;
			}
			setUpdateStatus(await r.json());
		}

		async function applyUpdate() {
			document.getElementById('updateState').textContent = 'Starting update…';
			var body = new URLSearchParams();
			body.set('csrf', csrf);
			var r = await fetch('/api/update/apply', { method: 'POST', body: body, credentials: 'include', headers: { 'X-CSRF-Token': csrf } });
			if (!r.ok) {
				var t = '';
				try { t = await r.text(); } catch (e) {}
				document.getElementById('updateState').textContent = t ? ('Update failed: ' + t) : 'Update failed to start';
				return;
			}
			document.getElementById('updateState').textContent = 'Updating…';
			await refreshUpdateStatus();
		}

		function setSystemdStatus(st) {
			if (!st) return;
			var msg = st.error ? st.error : '';
			document.getElementById('systemdState').textContent = st.available ? (st.active || 'unknown') : 'unavailable';
			document.getElementById('systemdMsg').textContent = msg || '—';
		}

		async function refreshSystemdStatus() {
			var r = await fetch('/api/systemd/status', { method: 'GET', credentials: 'include' });
			setSystemdStatus(await r.json());
		}

		async function systemdAction(path, progressText) {
			document.getElementById('systemdMsg').textContent = progressText;
			var body = new URLSearchParams();
			body.set('csrf', csrf);
			var r = await fetch(path, { method: 'POST', body: body, credentials: 'include', headers: { 'X-CSRF-Token': csrf } });
			if (!r.ok) {
				var t = '';
				try { t = await r.text(); } catch (e) {}
				document.getElementById('systemdMsg').textContent = t ? t : 'Action failed';
				return;
			}
			document.getElementById('systemdMsg').textContent = 'OK';
			await refreshSystemdStatus();
		}

		document.getElementById('checkNowBtn').addEventListener('click', function(){ checkNow(); });
		document.getElementById('applyBtn').addEventListener('click', function(){ applyUpdate(); });
		document.getElementById('svcRestartBtn').addEventListener('click', function(){ systemdAction('/api/systemd/restart', 'Restarting…'); });
		document.getElementById('svcStopBtn').addEventListener('click', function(){ systemdAction('/api/systemd/stop', 'Stopping…'); });

		refreshUpdateStatus();
		refreshSystemdStatus();
	</script>
</body>
</html>`

const loginPageHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 0; }
    .wrap { max-width: 520px; margin: 0 auto; padding: 48px 16px; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    .muted { opacity: .8; }
    .card { margin-top: 18px; border: 1px solid rgba(127,127,127,.25); border-radius: 12px; padding: 14px; background: rgba(127,127,127,.06); }
    label { font-weight: 600; display:block; margin: 0 0 4px; }
    .help { font-size: 12px; margin: 0 0 8px; opacity: .85; }
    input { width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
    .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
    button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
    button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
    .pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
    .bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Login</h1>
    <div class="muted">Sign in to manage your tunnel server.</div>
    {{if .Msg}}<div class="pill bad" style="margin-top: 12px">{{.Msg}}</div>{{end}}

    <form method="post" action="/login" class="card">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />

      <label>Username</label>
      <div class="help">Case-sensitive.</div>
      <input name="username" autocomplete="username" />

      <div style="height: 10px"></div>

      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" />

      <div class="btns">
        <button type="submit" class="primary">Login</button>
      </div>
    </form>
  </div>
</body>
</html>`

const setupPageHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>First-time Setup</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 0; }
    .wrap { max-width: 620px; margin: 0 auto; padding: 48px 16px; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    .muted { opacity: .8; }
    .card { margin-top: 18px; border: 1px solid rgba(127,127,127,.25); border-radius: 12px; padding: 14px; background: rgba(127,127,127,.06); }
    label { font-weight: 600; display:block; margin: 0 0 4px; }
    .help { font-size: 12px; margin: 0 0 8px; opacity: .85; line-height: 1.35; }
    input { width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
		.inputErr { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .10); }
    .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
    button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
    button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
		.bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>First-time Setup</h1>
    <div class="muted">Create the initial admin account for this server.</div>
		{{if .Err}}<div class="pill bad" style="margin-top: 12px">{{.Err}}</div>{{end}}

    <form method="post" action="/setup" class="card">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />

      <label>Username</label>
      <div class="help">Pick a unique username. This will be your admin login.</div>
	<input name="username" autocomplete="username" value="{{.Username}}" class="{{if .ErrUsername}}inputErr{{end}}" />

      <div style="height: 10px"></div>

      <label>Password</label>
      <div class="help">Use a long password (minimum 10 characters). Use a password manager.</div>
	<input name="password" type="password" autocomplete="new-password" class="{{if .ErrPassword}}inputErr{{end}}" />

      <div style="height: 10px"></div>

      <label>Confirm password</label>
	<input name="confirm" type="password" autocomplete="new-password" class="{{if .ErrConfirm}}inputErr{{end}}" />

      <div class="btns">
        <button type="submit" class="primary">Create account</button>
      </div>
    </form>
  </div>
	{{if .Err}}
	<script>
		(function(){
			var p = document.querySelector('input[name="password"]');
			var c = document.querySelector('input[name="confirm"]');
			if (p) p.value = '';
			if (c) c.value = '';
		})();
	</script>
	{{end}}
</body>
</html>`

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
	return &ipRateLimiter{limit: limit, window: window, byIP: map[string][]time.Time{}}
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
	// prune
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
	// Note: we deliberately do NOT trust X-Forwarded-For here.
	// If you run behind a reverse proxy, enforce auth/rate-limit there too.
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func requireAuth(store *auth.Store, cookieSecure bool, next http.HandlerFunc) http.HandlerFunc {
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
		userID, ok, err := store.GetSession(r.Context(), sid)
		if err != nil {
			http.Error(w, "auth db error", http.StatusInternalServerError)
			return
		}
		if !ok {
			clearSessionCookie(w, cookieSecure)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxUserID, userID)))
	}
}

func ensureCSRF(w http.ResponseWriter, r *http.Request, secure bool) string {
	if c, err := r.Cookie("csrf"); err == nil && c.Value != "" {
		return c.Value
	}
	tok := genToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   60 * 60 * 24 * 7,
	})
	return tok
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
	if err != nil {
		return false
	}
	return formTok != "" && c.Value != "" && subtleEq(formTok, c.Value)
}

func subtleEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

type systemdStatusResponse struct {
	Available bool   `json:"available"`
	Service   string `json:"service"`
	Active    string `json:"active"`
	Error     string `json:"error,omitempty"`
}

func systemctlAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func systemdAction(ctx context.Context, action string, service string) error {
	if !systemctlAvailable() {
		return fmt.Errorf("systemctl not found")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", action, service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s %s: %s", action, service, msg)
	}
	return nil
}

func systemdStatus(ctx context.Context, service string) systemdStatusResponse {
	resp := systemdStatusResponse{Available: systemctlAvailable(), Service: service}
	if !resp.Available {
		resp.Active = "unknown"
		return resp
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", service)
	out, err := cmd.CombinedOutput()
	resp.Active = strings.TrimSpace(string(out))
	if resp.Active == "" {
		resp.Active = "unknown"
	}
	if err != nil {
		resp.Error = strings.TrimSpace(string(out))
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}

func setSessionCookie(w http.ResponseWriter, sid string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   60 * 60 * 24 * 7,
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
