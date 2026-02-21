package main

import (
	"context"
	"crypto/rand"
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
	flag.Parse()

	// Initialize centralized logging
	serverlog.Init()
	slog := serverlog.Log

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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

	if cfg.EncryptionAlgorithm == "" {
		if !loaded {
			cfg.EncryptionAlgorithm = "aes-128"
		} else {
			cfg.EncryptionAlgorithm = "none"
		}
	}

	if strings.TrimSpace(cfg.Token) == "" {
		cfg.Token = genToken()
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

	// Enable WebHTTPS by default for new configurations and generate dashboard TLS cert
	cfgDir := filepath.Dir(configPath)
	if !cfg.WebHTTPS {
		// Check if this is a fresh config (no dashboard cert exists yet) - enable HTTPS by default
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

	runner := newServerRunner(ctx, cfg)
	runner.Start()
	slog.Info(logging.CatSystem, "server started", serverlog.F(
		"control_addr", cfg.ControlAddr,
		"data_addr", cfg.DataAddr,
		"tls_enabled", !cfg.DisableTLS,
	))

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

func (r *serverRunner) RunAgentNettest(ctx context.Context, req tunnel.AgentNettestRequest) (tunnel.AgentNettestResult, error) {
	r.mu.Lock()
	srv := r.srv
	r.mu.Unlock()
	if srv == nil {
		return tunnel.AgentNettestResult{}, fmt.Errorf("server not running")
	}
	return srv.RunAgentNettest(ctx, req)
}

// SetRouteEnabled toggles a route's enabled state at runtime.
// Returns false if the route doesn't exist.
func (r *serverRunner) SetRouteEnabled(routeName string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update the runner's config so it persists across restarts
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

// GetRouteEnabled returns the current enabled state of a route.
func (r *serverRunner) GetRouteEnabled(routeName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srv == nil {
		return true // default
	}
	return r.srv.GetRouteEnabled(routeName)
}

type ctxKey int

const (
	ctxUserID ctxKey = iota
)

func serveServerDashboard(ctx context.Context, addr string, configPath string, authDBPath string, runner *serverRunner, store *auth.Store, cookieSecure bool, sessionTTL time.Duration) error {
	tplStats := template.Must(template.New("stats").Parse(serverStatsHTML))
	tplConfig := template.Must(template.New("config").Parse(serverConfigHTML))
	tplControls := template.Must(template.New("controls").Parse(serverControlsHTML))
	tplNetwork := template.Must(template.New("network").Parse(serverNetworkTestHTML))
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
					"CSRF":        csrf,
					"Msg":         getMsg(),
					"Err":         errMsg,
					"Username":    username,
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

		// Network test page (protected)
		mux.HandleFunc("/network-test", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			csrf := ensureCSRF(w, r, cookieSecure)
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

		// Live stats API (protected)
		mux.HandleFunc("/api/stats", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			cfg, _, snap, err := runner.Dashboard(time.Now())
			type routeOut struct {
				Name       string                  `json:"name"`
				Proto      string                  `json:"proto"`
				PublicAddr string                  `json:"publicAddr"`
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
					Active:     rs.ActiveClients,
					Enabled:    runner.GetRouteEnabled(rt.Name),
					Events:     rs.Events,
				})
			}
			resp := map[string]any{
				"nowUnix":        snap.NowUnix,
				"bucketSec":      snap.BucketSec,
				"agentConnected": snap.AgentConnected,
				"activeClients":  snap.ActiveClients,
				"bytesTotal":     snap.BytesTotal,
				"udp":            snap.UDP,
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
			_ = json.NewEncoder(w).Encode(resp)
		})))

		mux.HandleFunc("/api/nettest/ping", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"serverTimeUnixMs": time.Now().UnixMilli()})
		})))

		mux.HandleFunc("/api/nettest/direct-download", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
			if sz > 64*1024*1024 {
				sz = 64 * 1024 * 1024
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

		mux.HandleFunc("/api/nettest/direct-upload", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bytes":      n,
				"durationMs": elapsed.Milliseconds(),
				"mbps":       mbps,
			})
		})))

		mux.HandleFunc("/api/nettest/agent", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
			_ = json.NewEncoder(w).Encode(result)
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
		mux.HandleFunc("/api/update/apply-local", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
				Name        string
				Proto       string
				PublicAddr  string
				IsEncrypted bool
			}
			routeViews := make([]routeView, 0, len(routes))
			for _, rt := range routes {
				routeViews = append(routeViews, routeView{Name: rt.Name, Proto: rt.Proto, PublicAddr: rt.PublicAddr, IsEncrypted: rt.IsEncrypted()})
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
			dashInterval := cfg.DashboardInterval
			if dashInterval <= 0 {
				dashInterval = 30 * time.Second
			}
			data := map[string]any{
				"Cfg":          cfg,
				"Status":       st,
				"ConfigPath":   configPath,
				"Msg":          getMsg(),
				"Err":          err,
				"CSRF":         csrf,
				"Version":      version.Current,
				"DashInterval": dashInterval.String(),
			}
			_ = tplControls.Execute(w, data)
		})))

		// UDP max payload cap update (protected)
		mux.HandleFunc("/api/udp/payload", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		})))

		// UDP performance settings update (protected)
		mux.HandleFunc("/api/udp/config", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
			// Validate pair_timeout bounds: minimum 1 second, maximum 5 minutes
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
			cfg.EncryptionAlgorithm = r.Form.Get("encryption_algorithm")
			if cfg.Token == "" {
				cfg.Token = genToken()
				addMsg("Token was empty; generated a new token")
			}
			cfg.Routes = parseServerRoutesForm(r)

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

		// Route enable/disable toggle (protected) - runtime, no restart required
		mux.HandleFunc("/api/routes/toggle", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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

			// Save the updated config to disk
			cfg, _, _ := runner.Get()
			if err := configio.Save(configPath, cfg); err != nil {
				serverlog.Log.Error(logging.CatSystem, "failed to save config after route toggle", serverlog.F("error", err))
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"route":   routeName,
				"enabled": enabled,
			})
		})))

		// Dashboard interval update (protected)
		mux.HandleFunc("/api/dashboard/interval", securityHeaders(cookieSecure, requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		if name == "" && proto == "" && pub == "" {
			continue
		}
		if name == "" {
			name = fmt.Sprintf("route-%d", i)
		}
		if proto == "" {
			proto = "tcp"
		}
		encrypted := strings.TrimSpace(r.Form.Get("route_" + strconv.Itoa(i) + "_encrypted")) == "1"
		var encPtr *bool
		if encrypted {
			encPtr = &encrypted
		}
		routes = append(routes, tunnel.RouteConfig{Name: name, Proto: proto, PublicAddr: pub, Encrypted: encPtr})
	}
	return routes
}

const serverStatsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tunnel Server</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #0f1117; --bg2: #181b25; --bg3: #1e2230;
      --surface: rgba(255,255,255,.04); --surfaceHover: rgba(255,255,255,.07);
      --border: rgba(255,255,255,.08); --borderHover: rgba(255,255,255,.14);
      --text: #e4e6ee; --textMuted: rgba(228,230,238,.55);
      --accent: #5b8def; --accentDim: rgba(91,141,239,.18); --accentBorder: rgba(91,141,239,.35);
      --green: #3fb950; --greenDim: rgba(63,185,80,.14); --greenBorder: rgba(63,185,80,.4);
      --red: #f85149; --redDim: rgba(248,81,73,.12); --redBorder: rgba(248,81,73,.4);
      --orange: #d29922; --orangeDim: rgba(210,153,34,.12); --orangeBorder: rgba(210,153,34,.4);
      --purple: #a371f7; --purpleDim: rgba(163,113,247,.12);
      --radius: 10px; --radiusLg: 14px;
      --font: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
      color-scheme: dark;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f5f6fa; --bg2: #ebedf5; --bg3: #e2e4ee;
        --surface: rgba(0,0,0,.03); --surfaceHover: rgba(0,0,0,.06);
        --border: rgba(0,0,0,.10); --borderHover: rgba(0,0,0,.18);
        --text: #1a1d28; --textMuted: rgba(26,29,40,.50);
        --accentDim: rgba(91,141,239,.12); --greenDim: rgba(63,185,80,.10);
        --redDim: rgba(248,81,73,.08); --orangeDim: rgba(210,153,34,.08);
        --purpleDim: rgba(163,113,247,.08);
        color-scheme: light;
      }
    }
    body { font-family: var(--font); margin: 0; padding: 0; background: var(--bg); color: var(--text); line-height: 1.5; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code { font-family: var(--mono); font-size: .8em; background: var(--surface); padding: 2px 6px; border-radius: 4px; }
    .wrap { max-width: 1060px; margin: 0 auto; padding: 20px 16px 60px; }
    /* Navigation */
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
    .topbar h1 { font-size: 18px; font-weight: 700; margin: 0; letter-spacing: -.02em; }
    .topbar .subtitle { font-size: 12px; color: var(--textMuted); margin-top: 2px; }
    .nav { display: flex; gap: 4px; }
    .nav a, .nav button { font-family: var(--font); font-size: 13px; padding: 7px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: transparent; color: var(--text); cursor: pointer; transition: all .15s; text-decoration: none; }
    .nav a:hover, .nav button:hover { background: var(--surfaceHover); border-color: var(--borderHover); text-decoration: none; }
    .nav a.active { background: var(--accentDim); border-color: var(--accentBorder); color: var(--accent); }
    /* Cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radiusLg); padding: 16px; transition: border-color .15s; }
    .card:hover { border-color: var(--borderHover); }
    /* Status grid */
    .statusGrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .stat { text-align: center; padding: 14px 10px; }
    .stat .label { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--textMuted); margin-bottom: 4px; }
    .stat .value { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
    /* Pills */
    .pill { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 500; border: 1px solid; }
    .pill::before { content: ''; width: 6px; height: 6px; border-radius: 50%; }
    .pill.ok { color: var(--green); border-color: var(--greenBorder); background: var(--greenDim); }
    .pill.ok::before { background: var(--green); }
    .pill.bad { color: var(--red); border-color: var(--redBorder); background: var(--redDim); }
    .pill.bad::before { background: var(--red); }
    .pill.warn { color: var(--orange); border-color: var(--orangeBorder); background: var(--orangeDim); }
    .pill.warn::before { background: var(--orange); }
    /* Grid / Flex */
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    @media (max-width: 720px) { .grid2 { grid-template-columns: 1fr; } }
    .flex { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    /* Section headers */
    .secHead { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 24px 0 10px; }
    .secHead h2 { font-size: 14px; font-weight: 600; margin: 0; text-transform: uppercase; letter-spacing: .05em; color: var(--textMuted); }
    /* Buttons */
    .btn { font-family: var(--font); font-size: 13px; padding: 7px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; transition: all .15s; }
    .btn:hover { background: var(--surfaceHover); border-color: var(--borderHover); }
    .btn.primary { background: var(--accentDim); border-color: var(--accentBorder); color: var(--accent); }
    .btn.primary:hover { background: rgba(91,141,239,.25); }
    .btn.sm { font-size: 12px; padding: 5px 10px; }
    .btn[disabled] { opacity: .4; cursor: not-allowed; }
    /* Charts */
    .chartWrap { position: relative; }
    .chartWrap canvas { width: 100%; height: 160px; display: block; border-radius: 8px; }
    .chartLabel { font-size: 11px; color: var(--textMuted); margin-top: 4px; }
    .chartControls { display: flex; gap: 4px; margin-bottom: 8px; }
    .chartControls .btn { font-size: 11px; padding: 4px 10px; }
    .chartControls .btn.active { background: var(--accentDim); border-color: var(--accentBorder); color: var(--accent); }
    /* Route cards */
    .routeCard { margin-top: 10px; }
    .routeCard summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 10px; padding: 4px 0; }
    .routeCard summary::-webkit-details-marker { display: none; }
    .routeCard summary::before { content: '▸'; font-size: 12px; color: var(--textMuted); transition: transform .15s; }
    .routeCard[open] summary::before { transform: rotate(90deg); }
    .routeCard .routeName { font-weight: 600; }
    .routeCard .routeProto { font-size: 12px; padding: 2px 8px; border-radius: 4px; background: var(--purpleDim); color: var(--purple); }
    .routeCard .routeAddr { font-family: var(--mono); font-size: 12px; color: var(--textMuted); }
    .routeCard .routeActive { margin-left: auto; font-size: 12px; }
    .routeCard .routeDisabled { opacity: 0.5; }
    .routeCard .routeDisabled .routeName { text-decoration: line-through; }
    .routeToggle { font-size: 11px; padding: 3px 8px; border-radius: 999px; border: 1px solid; cursor: pointer; margin-left: 8px; }
    .routeToggle.on { color: var(--green); border-color: var(--greenBorder); background: var(--greenDim); }
    .routeToggle.off { color: var(--red); border-color: var(--redBorder); background: var(--redDim); }
    .routeConsole { font-family: var(--mono); font-size: 11px; line-height: 1.6; white-space: pre-wrap; margin: 10px 0 0; padding: 12px; border-radius: 8px; background: var(--bg); border: 1px solid var(--border); max-height: 280px; overflow: auto; color: var(--textMuted); }
    .routeConsole .ev-connect { color: var(--green); }
    .routeConsole .ev-disconnect { color: var(--textMuted); }
    .routeConsole .ev-error { color: var(--red); }
    .routeConsole .ev-udp { color: var(--purple); }
    .routeConsole .ev-pair { color: var(--accent); }
    /* Flash messages */
    .flash { padding: 10px 14px; border-radius: var(--radius); font-size: 13px; margin-bottom: 16px; background: var(--greenDim); border: 1px solid var(--greenBorder); color: var(--green); }
    /* Live indicator */
    .liveIndicator { font-size: 11px; color: var(--textMuted); }
    .liveIndicator .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--green); margin-right: 4px; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }
    /* Update popup */
    .popup { position: fixed; right: 16px; bottom: 16px; max-width: 420px; width: calc(100% - 32px); z-index: 1000; display: none; }
    .popup pre { font-family: var(--mono); font-size: 11px; white-space: pre-wrap; margin: 8px 0 0; padding: 10px; border-radius: 8px; background: var(--bg); border: 1px solid var(--border); max-height: 200px; overflow: auto; }
    /* Tooltip */
    .tooltip { position: absolute; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 11px; pointer-events: none; z-index: 100; white-space: nowrap; opacity: 0; transition: opacity .1s; }
    .tooltip.visible { opacity: 1; }
    /* Row */
    .row { margin-bottom: 8px; }
    .row b { font-weight: 600; }
    .small { font-size: 12px; color: var(--textMuted); }
    .muted { color: var(--textMuted); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <h1>Tunnel Server</h1>
        <div class="subtitle">Forwarding public traffic to your connected agent</div>
      </div>
      <div class="flex">
        <div class="nav">
          <a class="active" href="/">Dashboard</a>
          <a href="/config">Config</a>
          <a href="/controls">Controls</a>
					<a href="/network-test">Network Test</a>
        </div>
        <form method="post" action="/logout" style="margin:0">
          <input type="hidden" name="csrf" value="{{.CSRF}}" />
          <button type="submit" class="btn sm">Logout</button>
        </form>
      </div>
    </div>

    {{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

    <div class="statusGrid">
      <div class="card stat">
        <div class="label">Agent</div>
        <div class="value"><span id="agentPill" class="pill {{if .Status.AgentConnected}}ok{{else}}bad{{end}}">{{if .Status.AgentConnected}}Connected{{else}}Disconnected{{end}}</span></div>
      </div>
      <div class="card stat">
        <div class="label">Public Clients</div>
        <div class="value" id="activeClientsVal">0</div>
      </div>
      <div class="card stat">
        <div class="label">Bandwidth <span id="bwIntervalLabel">(interval)</span></div>
        <div class="value" id="bw5mVal">—</div>
      </div>
      <div class="card stat">
        <div class="label">Total Transferred</div>
        <div class="value" id="bytesTotalVal">—</div>
      </div>
      <div class="card stat">
        <div class="label">Routes</div>
        <div class="value">{{.RouteCount}}</div>
      </div>
			<div class="card stat">
				<div class="label">UDP Loss</div>
				<div class="value" id="udpLossVal">—</div>
			</div>
			<div class="card stat">
				<div class="label">UDP Drops</div>
				<div class="value" id="udpDropsVal">—</div>
			</div>
			<div class="card stat">
				<div class="label">UDP Queues</div>
				<div class="value" id="udpQueueVal">—</div>
			</div>
    </div>

    <div class="grid2">
      <div>
        <div class="secHead">
          <h2>Bandwidth</h2>
          <div class="chartControls">
            <button class="btn sm" id="bwScale1h">1h</button>
            <button class="btn sm" id="bwScale6h">6h</button>
            <button class="btn sm" id="bwScale12h">12h</button>
            <button class="btn sm active" id="bwScale24h">24h</button>
          </div>
        </div>
        <div class="card">
          <div class="chartWrap">
            <canvas id="bwChart"></canvas>
            <div id="bwTooltip" class="tooltip"></div>
          </div>
          <div class="chartLabel" id="bwChartLabel">Bytes transferred per interval</div>
        </div>
      </div>
      <div>
        <div class="secHead">
          <h2>Connections</h2>
          <div class="chartControls">
            <button class="btn sm" id="connScale1h">1h</button>
            <button class="btn sm" id="connScale6h">6h</button>
            <button class="btn sm" id="connScale12h">12h</button>
            <button class="btn sm active" id="connScale24h">24h</button>
          </div>
        </div>
        <div class="card">
          <div class="chartWrap">
            <canvas id="connChart"></canvas>
            <div id="connTooltip" class="tooltip"></div>
          </div>
          <div class="chartLabel" id="connChartLabel">New connections per interval (TCP + UDP)</div>
        </div>
      </div>
    </div>

		<div class="secHead">
			<h2>Transport Logs</h2>
		</div>
		<div class="grid2">
			<div class="card">
				<div class="small" style="margin-bottom:6px"><b>UDP (Global)</b></div>
				<div id="udpGlobalLog" class="routeConsole">No UDP events yet.</div>
			</div>
			<div class="card">
				<div class="small" style="margin-bottom:6px"><b>TCP (Global)</b></div>
				<div id="tcpGlobalLog" class="routeConsole">No TCP events yet.</div>
			</div>
		</div>

    <div class="secHead">
      <h2>Routes</h2>
      <div class="liveIndicator"><span class="dot"></span><span id="liveText">Updating…</span></div>
    </div>

    {{if eq .RouteCount 0}}
      <div class="card">
        <div class="muted">No routes configured. <a href="/config">Add routes</a> to start accepting connections.</div>
      </div>
    {{end}}
    {{range .Routes}}
      <details class="card routeCard" data-route="{{.Name}}">
        <summary>
          <span class="routeName">{{.Name}}</span>
          <span class="routeProto">{{.Proto}}</span>
          <span class="routeAddr">{{.PublicAddr}}</span>
          <button type="button" class="routeToggle on" data-route-toggle title="Click to enable/disable route">On</button>
          <span class="routeActive"><span data-route-active>0</span> active</span>
        </summary>
        <div style="margin-top: 10px">
					<div class="small" style="margin-bottom:4px"><b>Packet Loss</b></div>
					<div data-route-loss-console class="routeConsole">No packet loss events yet.</div>
				</div>
				<div style="margin-top: 10px">
					<div class="small" style="margin-bottom:4px"><b>Route Events</b></div>
          <div data-route-console class="routeConsole">No events yet.</div>
        </div>
      </details>
    {{end}}

    <div id="errRow" class="card" style="display:none; margin-top: 16px; background: var(--redDim); border-color: var(--redBorder);">
      <b style="color:var(--red)">Error:</b> <span id="errText" class="muted"></span>
    </div>
  </div>

  <div id="updatePopup" class="card popup">
    <div style="display:flex; justify-content:space-between; align-items:center">
      <b>Update available</b>
      <span class="muted small" id="updVer"></span>
    </div>
    <div class="muted small" id="updInfo" style="margin-top: 4px">Current: <code>{{.Version}}</code></div>
    <div class="flex" style="margin-top: 10px">
      <button class="btn sm" id="updRemind">Remind later</button>
      <button class="btn sm" id="updSkip">Skip</button>
      <button class="btn sm primary" id="updApply">Update now</button>
    </div>
    <pre id="updSteps" style="display:none"></pre>
    <pre id="updLog" style="display:none"></pre>
  </div>

  <script>
  (function(){
    var csrf = "{{.CSRF}}";
    function $(id){ return document.getElementById(id); }
    function fmtBytes(n){
      n = Number(n||0); if(!isFinite(n)||n<0) n=0;
      var u=['B','KiB','MiB','GiB','TiB'], i=0;
      while(n>=1024&&i<u.length-1){ n/=1024; i++; }
      return (i===0?Math.round(n):n.toFixed(1))+' '+u[i];
    }
    function fmtNum(n){ return Number(n||0).toLocaleString(); }
    function setPill(el,ok,t){
      if(!el)return;
      el.className='pill '+(ok?'ok':'bad');
      el.textContent=t;
    }
    function sleep(ms){ return new Promise(function(r){ setTimeout(r,ms); }); }
    async function postForm(p){
      try{ return await fetch(p,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+encodeURIComponent(csrf)}); }catch(e){ return null; }
    }

    // Chart rendering
    function drawAreaChart(canvasId, tooltipId, series, scaleSec, valueKey, fmtFn, color){
      var c = $(canvasId); if(!c||!c.getContext) return;
      var tt = $(tooltipId);
      var dpr = window.devicePixelRatio || 1;
      var rect = c.getBoundingClientRect();
      c.width = rect.width * dpr;
      c.height = 160 * dpr;
      c.style.height = '160px';
      var ctx = c.getContext('2d');
      ctx.scale(dpr, dpr);
      var w = rect.width, h = 160;
      ctx.clearRect(0,0,w,h);
      if(!series||!series.length) return;

      // Slice to window
      var dt = 30;
      if(window._bucketSec) dt = window._bucketSec;
      else if(series.length>=2){ dt = Math.max(1, Number(series[1].t||0) - Number(series[0].t||0)); }
      var n = Math.max(1, Math.min(series.length, Math.floor(scaleSec/dt)));
      var data = series.slice(series.length - n);
      var max = 0;
      for(var i=0;i<data.length;i++) max = Math.max(max, Number(data[i][valueKey]||0));
      if(max<=0) max = 1;

      var padL=48, padR=8, padT=8, padB=28;
      var cw = w-padL-padR, ch = h-padT-padB;

      // Grid lines & Y labels
      ctx.strokeStyle = 'rgba(128,128,128,.12)';
      ctx.lineWidth = 1;
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--textMuted').trim() || 'rgba(128,128,128,.5)';
      ctx.font = '10px system-ui';
      ctx.textAlign = 'right';
      var gridLines = 4;
      for(var g=0;g<=gridLines;g++){
        var gy = padT + ch - (g/gridLines)*ch;
        ctx.beginPath(); ctx.moveTo(padL,gy); ctx.lineTo(w-padR,gy); ctx.stroke();
        var lbl = fmtFn(max * g / gridLines);
        ctx.fillText(lbl, padL-6, gy+3);
      }

      // X labels
      ctx.textAlign = 'center';
      var xLabels = Math.min(6, data.length);
      for(var xl=0;xl<xLabels;xl++){
        var xi = Math.floor(xl * (data.length-1) / Math.max(1,xLabels-1));
        var xp = padL + (xi/(data.length-1))*cw;
        var d = new Date(Number(data[xi].t||0)*1000);
        ctx.fillText(d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0'), xp, h-4);
      }

      // Area fill
      ctx.beginPath();
      ctx.moveTo(padL, padT+ch);
      for(var i2=0;i2<data.length;i2++){
        var x = padL + (i2/(Math.max(1,data.length-1)))*cw;
        var y = padT + ch - (Number(data[i2][valueKey]||0)/max)*ch;
        ctx.lineTo(x,y);
      }
      ctx.lineTo(padL+cw, padT+ch);
      ctx.closePath();
      var grad = ctx.createLinearGradient(0,padT,0,padT+ch);
      grad.addColorStop(0, color.replace('1)', '.25)'));
      grad.addColorStop(1, color.replace('1)', '.02)'));
      ctx.fillStyle = grad;
      ctx.fill();

      // Line
      ctx.beginPath();
      for(var i3=0;i3<data.length;i3++){
        var x2 = padL + (i3/(Math.max(1,data.length-1)))*cw;
        var y2 = padT + ch - (Number(data[i3][valueKey]||0)/max)*ch;
        if(i3===0) ctx.moveTo(x2,y2); else ctx.lineTo(x2,y2);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Tooltip on hover
      c._chartData = data; c._chartMeta = {padL:padL,cw:cw,padT:padT,ch:ch,max:max,valueKey:valueKey,fmtFn:fmtFn};
      if(!c._hasListener){
        c._hasListener = true;
        c.addEventListener('mousemove', function(e){
          var r = c.getBoundingClientRect();
          var mx = e.clientX - r.left;
          var m = c._chartMeta; var d = c._chartData;
          if(!m||!d) return;
          var idx = Math.round(((mx-m.padL)/m.cw)*(d.length-1));
          if(idx<0||idx>=d.length){ if(tt) tt.classList.remove('visible'); return; }
          var pt = d[idx];
          var dt2 = new Date(Number(pt.t||0)*1000);
          var html = dt2.toLocaleTimeString()+' — '+m.fmtFn(Number(pt[m.valueKey]||0));
          if(tt){ tt.textContent = html; tt.style.left = mx+'px'; tt.style.top = '0px'; tt.classList.add('visible'); }
        });
        c.addEventListener('mouseleave', function(){ if(tt) tt.classList.remove('visible'); });
      }
    }

    // Bandwidth chart state
    var lastSeries = null;
    var bwScaleSec = 86400, connScaleSec = 86400;
    function setBwScale(sec){
      bwScaleSec = sec;
      ['1h','6h','12h','24h'].forEach(function(k){
        var b = $('bwScale'+k.replace('h','h'));
        if(b) b.classList.remove('active');
      });
      var map = {3600:'bwScale1h',21600:'bwScale6h',43200:'bwScale12h',86400:'bwScale24h'};
      if(map[sec]) $(map[sec]).classList.add('active');
      if(lastSeries) drawAreaChart('bwChart','bwTooltip',lastSeries,bwScaleSec,'bytes',fmtBytes,'rgba(91,141,239,1)');
    }
    function setConnScale(sec){
      connScaleSec = sec;
      ['1h','6h','12h','24h'].forEach(function(k){
        var b = $('connScale'+k.replace('h','h'));
        if(b) b.classList.remove('active');
      });
      var map = {3600:'connScale1h',21600:'connScale6h',43200:'connScale12h',86400:'connScale24h'};
      if(map[sec]) $(map[sec]).classList.add('active');
      if(lastSeries) drawAreaChart('connChart','connTooltip',lastSeries,connScaleSec,'conns',fmtNum,'rgba(163,113,247,1)');
    }
    $('bwScale1h').onclick=function(){setBwScale(3600);};
    $('bwScale6h').onclick=function(){setBwScale(21600);};
    $('bwScale12h').onclick=function(){setBwScale(43200);};
    $('bwScale24h').onclick=function(){setBwScale(86400);};
    $('connScale1h').onclick=function(){setConnScale(3600);};
    $('connScale6h').onclick=function(){setConnScale(21600);};
    $('connScale12h').onclick=function(){setConnScale(43200);};
    $('connScale24h').onclick=function(){setConnScale(86400);};

    // Route console rendering
    function evClass(kind){
      if(!kind) return '';
      if(kind.indexOf('connect')>=0||kind==='paired'||kind==='udp_session') return 'ev-connect';
      if(kind.indexOf('disconnect')>=0) return 'ev-disconnect';
      if(kind.indexOf('error')>=0||kind.indexOf('reject')>=0||kind.indexOf('timeout')>=0) return 'ev-error';
      if(kind.indexOf('udp')>=0) return 'ev-udp';
      if(kind.indexOf('pair')>=0) return 'ev-pair';
      return '';
    }
    function renderRouteConsole(el, route){
      if(!el) return;
      var ev = (route && route.events) ? route.events : [];
      if(!ev.length){ el.textContent = 'No events yet.'; return; }
      el.innerHTML = '';
      for(var i=Math.min(ev.length,30)-1;i>=0;i--){
        var e = ev[ev.length-1-i]||{};
        var ts = e.t ? new Date(e.t*1000).toLocaleTimeString() : '';
        var parts = [ts, e.kind||''];
        if(e.ip) parts.push('ip='+e.ip);
        if(e.id) parts.push('id='+e.id.substring(0,8));
        if(e.bytes) parts.push(fmtBytes(e.bytes));
        if(e.durMs) parts.push(e.durMs+'ms');
        if(e.detail) parts.push(e.detail);
        var span = document.createElement('div');
        span.className = evClass(e.kind);
        span.textContent = parts.join('  ');
        el.appendChild(span);
      }
    }

		function isUDPLossKind(kind){
			kind = String(kind||'').toLowerCase();
			return kind.indexOf('loss_udp') >= 0;
		}
		function isUDPKind(kind){
			kind = String(kind||'').toLowerCase();
			return kind.indexOf('udp') >= 0 || kind.indexOf('loss_udp') >= 0;
		}
		function isTCPKind(kind){
			kind = String(kind||'').toLowerCase();
			if(isUDPKind(kind)) return false;
			return kind.indexOf('connect')>=0 || kind.indexOf('disconnect')>=0 || kind.indexOf('pair')>=0 || kind.indexOf('reject')>=0 || kind.indexOf('timeout')>=0 || kind.indexOf('error')>=0;
		}
		function renderEventList(el, events, emptyText){
			if(!el) return;
			events = events||[];
			if(!events.length){ el.textContent = emptyText; return; }
			el.innerHTML = '';
			var start = Math.max(0, events.length-40);
			for(var i=start;i<events.length;i++){
				var e = events[i]||{};
				var ts = e.t ? new Date(e.t*1000).toLocaleTimeString() : '';
				var parts = [ts, e.kind||''];
				if(e.route) parts.push('route='+e.route);
				if(e.ip) parts.push('ip='+e.ip);
				if(e.id) parts.push('id='+e.id.substring(0,8));
				if(e.detail) parts.push(e.detail);
				var row = document.createElement('div');
				row.className = evClass(e.kind);
				row.textContent = parts.join('  ');
				el.appendChild(row);
			}
		}
		function renderRouteLossConsole(el, route){
			var ev = (route && route.events) ? route.events : [];
			var loss = [];
			for(var i=0;i<ev.length;i++){
				if(isUDPLossKind(ev[i] && ev[i].kind)) loss.push(ev[i]);
			}
			renderEventList(el, loss, 'No packet loss events yet.');
		}

    function computeLastBucket(s){ return s&&s.length ? Number(s[s.length-1].bytes||0) : 0; }

    function fmtInterval(sec){
      if(sec<60) return sec+'s';
      if(sec<3600) return Math.round(sec/60)+'m';
      return Math.round(sec/3600)+'h';
    }
    function fmtIntervalLong(sec){
      if(sec<60) return sec+'-second';
      if(sec<3600){ var m=Math.round(sec/60); return m+'-minute'; }
      var h=Math.round(sec/3600); return h+'-hour';
    }

    async function poll(){
      try {
        var res = await fetch('/api/stats',{cache:'no-store'});
        if(!res.ok) throw new Error('http '+res.status);
        var j = await res.json();
        if(j.bucketSec){
          window._bucketSec = j.bucketSec;
          var il = $('bwIntervalLabel'); if(il) il.textContent = '('+fmtInterval(j.bucketSec)+')';
          var bl = $('bwChartLabel');  if(bl) bl.textContent = 'Bytes transferred per '+fmtIntervalLong(j.bucketSec)+' interval';
          var cl = $('connChartLabel'); if(cl) cl.textContent = 'New connections per '+fmtIntervalLong(j.bucketSec)+' interval (TCP + UDP)';
        }
        setPill($('agentPill'),!!j.agentConnected,j.agentConnected?'Connected':'Disconnected');
        if($('activeClientsVal')) $('activeClientsVal').textContent = fmtNum(j.activeClients);
        if($('bw5mVal')) $('bw5mVal').textContent = fmtBytes(computeLastBucket(j.series));
        if($('bytesTotalVal')) $('bytesTotalVal').textContent = fmtBytes(j.bytesTotal||0);
				var udp = j.udp || null;
				if($('udpLossVal')) $('udpLossVal').textContent = udp ? ((Number(udp.lossPercent||0)).toFixed(2)+'%') : '—';
				if($('udpDropsVal')) $('udpDropsVal').textContent = udp ? fmtNum(udp.totalDrops||0) : '—';
				if($('udpQueueVal')) {
					if(udp){
						var pq = fmtNum(udp.publicQueueDepth||0) + '/' + fmtNum(udp.publicQueueCapacity||0);
						var aq = fmtNum(udp.agentQueueDepth||0) + '/' + fmtNum(udp.agentQueueCapacity||0);
						$('udpQueueVal').textContent = 'P ' + pq + ' · A ' + aq;
					} else {
						$('udpQueueVal').textContent = '—';
					}
				}
        if(j.err){
          $('errRow').style.display='';
          $('errText').textContent=j.err;
        } else {
          $('errRow').style.display='none';
        }
        if($('liveText')) $('liveText').textContent = new Date().toLocaleTimeString();
        if(j.series){
          lastSeries = j.series;
          drawAreaChart('bwChart','bwTooltip',j.series,bwScaleSec,'bytes',fmtBytes,'rgba(91,141,239,1)');
          drawAreaChart('connChart','connTooltip',j.series,connScaleSec,'conns',fmtNum,'rgba(163,113,247,1)');
        }
        var routes = j.routes||[];
				var systemEvents = j.systemEvents||[];
				var globalUDP = [];
				var globalTCP = [];
				for(var si=0;si<systemEvents.length;si++){
					var sev = systemEvents[si]||{};
					if(isUDPKind(sev.kind)) globalUDP.push(sev);
					else if(isTCPKind(sev.kind)) globalTCP.push(sev);
				}
        for(var i=0;i<routes.length;i++){
          var rt = routes[i]||{};
					var evs = rt.events||[];
					for(var ei=0;ei<evs.length;ei++){
						var ev = evs[ei]||{};
						if(isUDPKind(ev.kind)) globalUDP.push(ev);
						else if(isTCPKind(ev.kind)) globalTCP.push(ev);
					}
          var det = document.querySelector('details[data-route="'+(rt.name||'')+'"]');
          if(!det) continue;
          var a = det.querySelector('[data-route-active]');
          if(a) a.textContent = String(rt.active==null?0:rt.active);
          var c = det.querySelector('[data-route-console]');
          renderRouteConsole(c, rt);
					var lc = det.querySelector('[data-route-loss-console]');
					renderRouteLossConsole(lc, rt);
          // Update enabled/disabled state
          var toggle = det.querySelector('[data-route-toggle]');
          if(toggle){
            var enabled = rt.enabled !== false;
            toggle.textContent = enabled ? 'On' : 'Off';
            toggle.className = 'routeToggle ' + (enabled ? 'on' : 'off');
            if(enabled){
              det.classList.remove('routeDisabled');
            } else {
              det.classList.add('routeDisabled');
            }
          }
        }
				globalUDP.sort(function(a,b){return Number(a.t||0)-Number(b.t||0);});
				globalTCP.sort(function(a,b){return Number(a.t||0)-Number(b.t||0);});
				if(udp){
					globalUDP.push({
						t: Math.floor(Date.now()/1000),
						kind: 'udp_telemetry',
						detail: 'loss='+Number(udp.lossPercent||0).toFixed(2)+'% drops='+fmtNum(udp.totalDrops||0)+' decode='+fmtNum(udp.decodeDrops||0)+' resolve='+fmtNum(udp.resolveDrops||0)+' writeErr='+(fmtNum((udp.publicWriteErrors||0)+(udp.agentWriteErrors||0)))
					});
				}
				renderEventList($('udpGlobalLog'), globalUDP, 'No UDP events yet.');
				renderEventList($('tcpGlobalLog'), globalTCP, 'No TCP events yet.');
      } catch(e){
        if($('liveText')) $('liveText').textContent = 'Offline';
      }
    }
    poll(); setInterval(poll, 2000);

    // Route toggle click handler
    document.addEventListener('click', function(e){
      var t = e.target;
      if(!t || !t.matches || !t.matches('[data-route-toggle]')) return;
      e.preventDefault();
      var det = t.closest('details[data-route]');
      if(!det) return;
      var routeName = det.getAttribute('data-route');
      if(!routeName) return;
      var curEnabled = t.textContent.trim() === 'On';
      var newEnabled = !curEnabled;
      var p = new URLSearchParams();
      p.set('csrf', csrf);
      p.set('route', routeName);
      p.set('enabled', newEnabled ? '1' : '');
      fetch('/api/routes/toggle', {method: 'POST', body: p, credentials: 'include'})
        .then(function(r){ return r.ok ? r.json() : null; })
        .then(function(d){
          if(d && d.enabled !== undefined){
            t.textContent = d.enabled ? 'On' : 'Off';
            t.className = 'routeToggle ' + (d.enabled ? 'on' : 'off');
            if(d.enabled){
              det.classList.remove('routeDisabled');
            } else {
              det.classList.add('routeDisabled');
            }
          }
        });
    });

    // Redraw charts on resize
    var resizeTimer;
    window.addEventListener('resize', function(){
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function(){
        if(lastSeries){
          drawAreaChart('bwChart','bwTooltip',lastSeries,bwScaleSec,'bytes',fmtBytes,'rgba(91,141,239,1)');
          drawAreaChart('connChart','connTooltip',lastSeries,connScaleSec,'conns',fmtNum,'rgba(163,113,247,1)');
        }
      }, 100);
    });

    // Updates
    async function fetchUpd(){ try{ var r=await fetch('/api/update/status',{cache:'no-store'}); return r.ok?await r.json():null; }catch(e){return null;} }
    function showUpd(st){
      if(!st) return;
      var show = !!st.showPopup || (st.job&&st.job.state&&st.job.state!=='idle');
      $('updatePopup').style.display = show?'':'none';
      if(!show) return;
      $('updVer').textContent = st.availableVersion ? '→ '+st.availableVersion : '';
      var info = 'Current: {{.Version}}';
      if(st.job&&st.job.state==='running') info='Updating…';
      if(st.job&&st.job.state==='success') info='Update complete. Restarting…';
      if(st.job&&st.job.state==='failed') info='Update failed.';
      $('updInfo').textContent = info;
      var log = (st.job&&st.job.log)?String(st.job.log):'';
      if(st.job&&(st.job.state==='failed'||st.job.state==='success'||st.job.state==='running')){
        $('updLog').style.display=''; $('updLog').textContent=log||'(no log)';
        // Steps
        if(st.job.state==='running'){
          var has=function(re){try{return re.test(log);}catch(e){return false;}};
          var s1=has(/Downloading:/)&&has(/Downloaded\s+\d+\s+bytes/);
          var s2=has(/Extracted source:/)&&has(/Applying into:/);
          var s3=has(/Running build\.sh/);
          var s4=has(/Build succeeded/)||has(/Build failed/);
          var s5=!!(st.job&&st.job.restarting);
          $('updSteps').style.display='';
          $('updSteps').textContent=[s1?'[x]':'[ ]', 'Download', s2?'[x]':'[ ]', 'Apply', s3?'[x]':'[ ]', 'Build', s4?'[x]':'[ ]', 'Done', s5?'[x]':'[ ]', 'Restart'].join(' ');
        } else { $('updSteps').style.display='none'; }
      } else { $('updLog').style.display='none'; $('updSteps').style.display='none'; }
      var busy = st.job&&st.job.state==='running';
      $('updApply').disabled=busy; $('updRemind').disabled=busy; $('updSkip').disabled=busy;
    }
    async function pollUpdDone(){
      for(;;){ var st=await fetchUpd(); if(st){showUpd(st);if(st.job&&st.job.state&&st.job.state!=='running')break;} await sleep(500); }
      for(var i=0;i<90;i++){ var s=await fetchUpd(); if(s){location.replace(location.pathname+'?r='+Date.now());return;} await sleep(1000); }
    }
    $('updRemind').onclick=async function(){await postForm('/api/update/remind');$('updatePopup').style.display='none';};
    $('updSkip').onclick=async function(){await postForm('/api/update/skip');$('updatePopup').style.display='none';};
    $('updApply').onclick=async function(){await postForm('/api/update/apply');pollUpdDone();};
    fetchUpd().then(showUpd);
    setInterval(function(){fetchUpd().then(showUpd);},30000);
  })();
  </script>
</body>
</html>`

const serverConfigHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Server — Config</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0;letter-spacing:-.02em}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a,.nav button{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;transition:all .15s;text-decoration:none}
		.nav a:hover,.nav button:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.card:hover{border-color:var(--borderHover)}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.secHead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:24px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn.primary:hover{background:rgba(91,141,239,.25)}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.btn.sm{font-size:12px;padding:5px 10px}
		label{font-weight:600;display:block;margin:0 0 4px;font-size:13px}
		.help{font-size:12px;margin:0 0 8px;color:var(--textMuted);line-height:1.35}
		input,select{width:100%;max-width:100%;box-sizing:border-box;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:13px}
		input:focus,select:focus{outline:none;border-color:var(--accentBorder)}
		input[type=checkbox]{width:auto}
		.row{margin-bottom:8px}
		.muted{color:var(--textMuted)}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		.routeCard{margin-top:10px}
		.routeHead{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Server</h1>
				<div class="subtitle">Configuration</div>
			</div>
			<div class="flex">
				<div class="nav">
					<a href="/">Dashboard</a>
					<a class="active" href="/config">Config</a>
					<a href="/controls">Controls</a>
					<a href="/network-test">Network Test</a>
				</div>
				<form method="post" action="/logout" style="margin:0">
					<input type="hidden" name="csrf" value="{{.CSRF}}" />
					<button type="submit" class="btn sm">Logout</button>
				</form>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<form method="post" action="/config/save" class="card">
			<input type="hidden" name="csrf" value="{{.CSRF}}" />

			<div class="secHead" style="margin-top:0"><h2>Listeners</h2></div>
			<div class="grid2">
				<div>
					<label>Control listen</label>
					<div class="help">Agent connects here for commands (e.g. <code>:7000</code>)</div>
					<input name="control" value="{{.Cfg.ControlAddr}}" />
				</div>
				<div>
					<label>Data listen</label>
					<div class="help">TCP pairing and UDP relay (same port)</div>
					<input name="data" value="{{.Cfg.DataAddr}}" />
				</div>
				<div>
					<label>Pair timeout</label>
					<div class="help">Max wait for agent to attach (e.g. <code>10s</code>)</div>
					<input name="pair_timeout" value="{{.Cfg.PairTimeout}}" />
				</div>
			</div>

			<div class="secHead"><h2>Security</h2></div>
			<div class="grid2">
				<div>
					<label>Token</label>
					<div class="help">Shared secret for agent authentication</div>
					<input name="token" value="{{.Cfg.Token}}" />
				</div>
				<div>
					<label>Actions</label>
					<div class="help">Generate a new random token</div>
					<button type="submit" class="btn" formmethod="post" formaction="/gen-token">Generate token + restart</button>
				</div>
				<div>
					<label>Tunnel TLS</label>
					{{if .Cfg.DisableTLS}}
						<div class="help">TLS for agent↔server TCP is disabled.</div>
					{{else}}
						<div class="help">Cert: <code>{{.Cfg.TLSCertFile}}</code></div>
						<button type="submit" class="btn" name="tls_regen" value="1">Regenerate TLS cert + restart</button>
					{{end}}
				</div>
				<div>
					<label>Dashboard HTTPS</label>
					<div class="help">Self-signed HTTPS for this dashboard</div>
					<label style="font-weight:400;display:flex;gap:8px;align-items:center;margin-bottom:8px">
						<input type="checkbox" name="web_https" value="1" {{if .Cfg.WebHTTPS}}checked{{end}} />
						<span>Enable HTTPS</span>
					</label>
					<div class="help">{{if .WebTLSFP}}Cert sha256: <code>{{.WebTLSFP}}</code>{{end}}</div>
					<button type="submit" class="btn sm" name="web_tls_regen" value="1">Regen dashboard cert</button>
				</div>
				<div>
					<label>Encryption Algorithm</label>
					<div class="help">Global encryption standard for tunnel traffic</div>
					<select name="encryption_algorithm">
						<option value="none" {{if eq .Cfg.EncryptionAlgorithm "none"}}selected{{end}}>None</option>
						<option value="aes-128" {{if eq .Cfg.EncryptionAlgorithm "aes-128"}}selected{{end}}>AES-128</option>
						<option value="aes-256" {{if eq .Cfg.EncryptionAlgorithm "aes-256"}}selected{{end}}>AES-256</option>
					</select>
				</div>
			</div>

			<div class="secHead"><h2>Routes</h2></div>
			<div class="help">Each route is a public listener. The agent forwards traffic to the local port.</div>

			<input type="hidden" name="route_count" id="route_count" value="{{.RouteCount}}" />

			<div id="routes">
				{{range $i, $r := .Routes}}
					<div class="card routeCard" data-route>
						<div class="routeHead">
							<b>Route #{{$i}}</b>
							<button type="button" class="btn sm warn" data-remove-route>Remove</button>
						</div>
						<input type="hidden" name="route_{{$i}}_delete" value="0" data-route-delete />
						<div class="grid2" style="margin-top:10px">
							<div>
								<label>Name (optional)</label>
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
								<label>Port (e.g. :25565)</label>
								<input name="route_{{$i}}_public" value="{{$r.PublicAddr}}" placeholder=":25565" />
							</div>
							<div>
								<label>Encryption</label>
								<label style="font-weight:400;display:flex;gap:8px;align-items:center;margin-top:8px">
									<input type="checkbox" name="route_{{$i}}_encrypted" value="1" {{if $r.IsEncrypted}}checked{{end}} />
									<span>Enable encryption for this route</span>
								</label>
							</div>
						</div>
					</div>
				{{end}}
			</div>

			<div class="flex" style="margin-top:14px">
				<button type="button" id="addRoute" class="btn">+ Add route</button>
				<button type="submit" class="btn primary">Save + restart server</button>
			</div>
		</form>
	</div>

	<template id="routeTemplate">
		<div class="card routeCard" data-route>
			<div class="routeHead">
				<b>Route #IDX</b>
				<button type="button" class="btn sm warn" data-remove-route>Remove</button>
			</div>
			<input type="hidden" name="route_IDX_delete" value="0" data-route-delete />
			<div class="grid2" style="margin-top:10px">
				<div><label>Name (optional)</label><input name="route_IDX_name" value="" /></div>
				<div><label>Protocol</label><select name="route_IDX_proto"><option value="tcp" selected>tcp</option><option value="udp">udp</option><option value="both">both</option></select></div>
				<div><label>Port (e.g. :25565)</label><input name="route_IDX_public" value="" placeholder=":25565" /></div>
				<div>
					<label>Encryption</label>
					<label style="font-weight:400;display:flex;gap:8px;align-items:center;margin-top:8px">
						<input type="checkbox" name="route_IDX_encrypted" value="1" />
						<span>Enable encryption for this route</span>
					</label>
				</div>
			</div>
		</div>
	</template>

	<script>
	(function(){
		var btn=document.getElementById('addRoute'),routes=document.getElementById('routes'),cnt=document.getElementById('route_count'),tpl=document.getElementById('routeTemplate');
		if(!btn||!routes||!cnt||!tpl)return;
		routes.addEventListener('click',function(e){
			var t=e.target;if(!t||!t.matches||!t.matches('[data-remove-route]'))return;
			e.preventDefault();var c=t.closest('[data-route]');if(!c)return;
			var d=c.querySelector('[data-route-delete]');if(d)d.value='1';c.style.display='none';
		});
		btn.addEventListener('click',function(){
			var i=parseInt(cnt.value||'0',10);
			var html=tpl.innerHTML.split('IDX').join(String(i));
			var w=document.createElement('div');w.innerHTML=html;
			routes.appendChild(w.firstElementChild);cnt.value=String(i+1);
		});
	})();
	</script>
</body>
</html>`
const serverControlsHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Server — Controls</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a,.nav button{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;transition:all .15s;text-decoration:none}
		.nav a:hover,.nav button:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.secHead{margin:24px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn[disabled]{opacity:.4;cursor:not-allowed}
		.btn.sm{font-size:12px;padding:5px 10px}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.row{margin-bottom:8px}
		.muted{color:var(--textMuted)}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		pre{font-family:var(--mono);font-size:11px;white-space:pre-wrap;margin:8px 0 0;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);max-height:200px;overflow:auto}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Server</h1>
				<div class="subtitle">Server Controls</div>
			</div>
			<div class="flex">
				<div class="nav">
					<a href="/">Dashboard</a>
					<a href="/config">Config</a>
					<a class="active" href="/controls">Controls</a>
					<a href="/network-test">Network Test</a>
				</div>
				<form method="post" action="/logout" style="margin:0">
					<input type="hidden" name="csrf" value="{{.CSRF}}" />
					<button type="submit" class="btn sm">Logout</button>
				</form>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<div class="grid2">
			<div>
				<div class="secHead"><h2>Dashboard</h2></div>
				<div class="card">
					<div class="row"><b>Stats Interval:</b> <code id="curInterval">{{.DashInterval}}</code></div>
					<div class="muted" style="margin-bottom:8px;font-size:12px">Bucket width for bandwidth &amp; connection charts. Smaller = higher resolution but more memory. Requires restart.</div>
					<form method="post" action="/api/dashboard/interval" style="margin:0">
						<input type="hidden" name="csrf" value="{{.CSRF}}" />
						<div class="flex">
							<select name="interval" class="btn sm" style="appearance:auto;padding:5px 8px">
								<option value="5s"{{if eq .DashInterval "5s"}} selected{{end}}>5 seconds</option>
								<option value="10s"{{if eq .DashInterval "10s"}} selected{{end}}>10 seconds</option>
								<option value="30s"{{if eq .DashInterval "30s"}} selected{{end}}>30 seconds</option>
								<option value="1m0s"{{if eq .DashInterval "1m0s"}} selected{{end}}>1 minute</option>
								<option value="2m0s"{{if eq .DashInterval "2m0s"}} selected{{end}}>2 minutes</option>
								<option value="5m0s"{{if eq .DashInterval "5m0s"}} selected{{end}}>5 minutes</option>
								<option value="10m0s"{{if eq .DashInterval "10m0s"}} selected{{end}}>10 minutes</option>
							</select>
							<button type="submit" class="btn sm primary">Apply &amp; Restart</button>
						</div>
					</form>
				</div>

				<div class="secHead"><h2>Updates</h2></div>
				<div class="card">
					<div class="row"><b>Current:</b> <code>{{.Version}}</code></div>
					<div class="row"><b>Available:</b> <code id="availableVersion">—</code></div>
					<div class="row muted" id="updateState">—</div>
					<div class="flex" style="margin-top:8px">
						<button class="btn sm" id="checkNowBtn">Check now</button>
						<button class="btn sm primary" id="applyBtn" disabled>Update</button>
					</div>
					<div style="margin-top:10px">
						<div class="muted" style="font-size:12px;margin-bottom:6px">Local update (.zip)</div>
						<div class="grid2" style="gap:8px">
							<input type="file" id="localComponentZip" accept=".zip" />
							<input type="file" id="localSharedZip" accept=".zip" />
						</div>
						<div class="muted" style="font-size:11px;margin-top:4px">Left: server.zip (required), right: shared.zip (optional).</div>
						<div class="flex" style="margin-top:8px">
							<button class="btn sm" id="applyLocalBtn">Apply local update</button>
						</div>
					</div>
					<pre id="updateLog" style="display:none"></pre>
				</div>
			</div>
			<div>
				<div class="secHead"><h2>systemd</h2></div>
				<div class="card">
					<div class="row"><b>Service:</b> <code>hostit-server.service</code></div>
					<div class="row"><b>State:</b> <code id="systemdState">—</code></div>
					<div class="row muted" id="systemdMsg">—</div>
					<div class="flex" style="margin-top:8px">
						<button class="btn sm" id="svcRestartBtn">Restart</button>
						<button class="btn sm warn" id="svcStopBtn">Stop</button>
					</div>
				</div>

				<div class="secHead"><h2>Process</h2></div>
				<div class="card">
					<div class="muted" style="margin-bottom:8px;font-size:12px">Direct process control. Under systemd it will restart automatically.</div>
					<div class="flex">
						<button class="btn sm" id="procRestart">Restart process</button>
						<button class="btn sm warn" id="procExit">Exit process</button>
					</div>
				</div>
			</div>
		</div>
	</div>

	<script>
	var csrf = {{printf "%q" .CSRF}};
	function body(){var b=new URLSearchParams();b.set('csrf',csrf);return b;}
	function setUpd(st){
		if(!st)return;
		document.getElementById('availableVersion').textContent=st.latestVersion||st.availableVersion||'—';
		document.getElementById('applyBtn').disabled=!st.updateAvailable;
		document.getElementById('updateState').textContent=st.updateAvailable?'Update available':'Up to date';
		var log=document.getElementById('updateLog');
		if(st.job&&st.job.log){log.style.display='block';log.textContent=st.job.log;}else{log.style.display='none';}
	}
	async function refreshUpd(){var r=await fetch('/api/update/status',{credentials:'include'});if(r.ok)setUpd(await r.json());}
	async function checkNow(){
		document.getElementById('updateState').textContent='Checking…';
		var r=await fetch('/api/update/check-now',{method:'POST',body:body(),credentials:'include'});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){}return;}
		setUpd(await r.json());
	}
	async function applyUpd(){
		document.getElementById('updateState').textContent='Starting…';
		await fetch('/api/update/apply',{method:'POST',body:body(),credentials:'include'});
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	async function applyLocalUpd(){
		var comp=document.getElementById('localComponentZip');
		var shared=document.getElementById('localSharedZip');
		if(!comp||!comp.files||!comp.files.length){document.getElementById('updateState').textContent='Pick server.zip first';return;}
		var fd=new FormData();
		fd.append('csrf',csrf);
		fd.append('componentZip', comp.files[0]);
		if(shared&&shared.files&&shared.files.length){fd.append('sharedZip', shared.files[0]);}
		document.getElementById('updateState').textContent='Uploading…';
		var r=await fetch('/api/update/apply-local',{method:'POST',body:fd,credentials:'include'});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){document.getElementById('updateState').textContent='Failed';}return;}
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	function setSys(st){
		if(!st)return;
		document.getElementById('systemdState').textContent=st.available?(st.active||'unknown'):'unavailable';
		document.getElementById('systemdMsg').textContent=st.error||'—';
	}
	async function refreshSys(){var r=await fetch('/api/systemd/status',{credentials:'include'});if(r.ok)setSys(await r.json());}
	async function sysAction(p,t){
		document.getElementById('systemdMsg').textContent=t;
		var r=await fetch(p,{method:'POST',body:body(),credentials:'include'});
		if(!r.ok){try{var txt=await r.text();document.getElementById('systemdMsg').textContent=txt;}catch(e){}return;}
		document.getElementById('systemdMsg').textContent='OK';
		await refreshSys();
	}
	document.getElementById('checkNowBtn').onclick=checkNow;
	document.getElementById('applyBtn').onclick=applyUpd;
	document.getElementById('applyLocalBtn').onclick=applyLocalUpd;
	document.getElementById('svcRestartBtn').onclick=function(){sysAction('/api/systemd/restart','Restarting…');};
	document.getElementById('svcStopBtn').onclick=function(){sysAction('/api/systemd/stop','Stopping…');};
	document.getElementById('procRestart').onclick=async function(){
		await fetch('/api/process/restart',{method:'POST',body:body(),credentials:'include'});
		setTimeout(function(){location.reload();},1000);
	};
	document.getElementById('procExit').onclick=async function(){
		await fetch('/api/process/exit',{method:'POST',body:body(),credentials:'include'});
		setTimeout(function(){location.reload();},1000);
	};
	refreshUpd();refreshSys();
	</script>
</body>
</html>`

const serverNetworkTestHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Server — Network Test</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;background:var(--bg);color:var(--text)}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 40px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{margin:0;font-size:18px}
		.subtitle{font-size:12px;color:var(--textMuted)}
		.nav{display:flex;gap:4px}
		.nav a,.nav button{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;margin-bottom:14px}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:900px){.grid2{grid-template-columns:1fr}}
		.btn{font-size:13px;padding:8px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn[disabled]{opacity:.5;cursor:not-allowed}
		.kv{display:grid;grid-template-columns:170px 1fr;gap:6px 12px;font-size:13px}
		.k{color:var(--textMuted)}
		.v{font-variant-numeric:tabular-nums}
		.muted{color:var(--textMuted);font-size:12px}
		.ok{color:var(--green)}
		.bad{color:var(--red)}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Server</h1>
				<div class="subtitle">Network Test — direct and server↔agent path diagnostics</div>
			</div>
			<div class="nav">
				<a href="/">Dashboard</a>
				<a href="/config">Config</a>
				<a href="/controls">Controls</a>
				<a class="active" href="/network-test">Network Test</a>
			</div>
		</div>

		<div class="grid2">
			<div class="card">
				<h3 style="margin:0 0 8px">Browser ↔ Server</h3>
				<div class="muted" style="margin-bottom:12px">Measures from this browser to the dashboard server over HTTPS.</div>
				<button id="runDirect" class="btn primary">Run Direct Test</button>
				<div id="directStatus" class="muted" style="margin-top:8px">Idle</div>
				<div class="kv" style="margin-top:12px">
					<div class="k">Latency (avg)</div><div class="v" id="dLatency">—</div>
					<div class="k">Packet loss</div><div class="v" id="dLoss">—</div>
					<div class="k">Download speed</div><div class="v" id="dDown">—</div>
					<div class="k">Upload speed</div><div class="v" id="dUp">—</div>
				</div>
			</div>

			<div class="card">
				<h3 style="margin:0 0 8px">Server ↔ Agent</h3>
				<div class="muted" style="margin-bottom:12px">Control-channel ping/throughput test between tunnel server and connected agent.</div>
				<button id="runAgent" class="btn primary">Run Agent Path Test</button>
				<div id="agentStatus" class="muted" style="margin-top:8px">Idle</div>
				<div class="kv" style="margin-top:12px">
					<div class="k">Latency (avg/min/max)</div><div class="v" id="aLatency">—</div>
					<div class="k">Jitter</div><div class="v" id="aJitter">—</div>
					<div class="k">Packet loss</div><div class="v" id="aLoss">—</div>
					<div class="k">Download speed</div><div class="v" id="aDown">—</div>
					<div class="k">Upload speed</div><div class="v" id="aUp">—</div>
				</div>
			</div>
		</div>
	</div>

	<script>
	(function(){
		var csrf = "{{.CSRF}}";
		function $(id){ return document.getElementById(id); }
		function fmtMs(v){ return (Number(v)||0).toFixed(2)+' ms'; }
		function fmtPct(v){ return (Number(v)||0).toFixed(2)+'%'; }
		function fmtMbps(v){ return (Number(v)||0).toFixed(2)+' Mbps'; }

		async function pingOnce(timeoutMs){
			var c = new AbortController();
			var t = setTimeout(function(){ c.abort(); }, timeoutMs);
			var s = performance.now();
			try {
				var r = await fetch('/api/nettest/ping', {cache:'no-store', signal:c.signal});
				if(!r.ok) throw new Error('http '+r.status);
				return performance.now()-s;
			} finally {
				clearTimeout(t);
			}
		}

		async function runDirect(){
			$('runDirect').disabled = true;
			$('directStatus').textContent = 'Running latency and packet loss test...';
			var total = 20, ok = 0, sum = 0;
			for(var i=0;i<total;i++){
				try { var ms = await pingOnce(2000); ok++; sum += ms; } catch(e) {}
			}
			var loss = total-ok;
			var lossPct = total>0 ? (loss*100/total) : 0;
			var avg = ok>0 ? (sum/ok) : 0;
			$('dLatency').textContent = ok>0 ? fmtMs(avg) : 'timeout';
			$('dLoss').textContent = fmtPct(lossPct)+' ('+loss+'/'+total+')';

			$('directStatus').textContent = 'Running download speed test...';
			var dlBytes = 16*1024*1024;
			var ds = performance.now();
			var dr = await fetch('/api/nettest/direct-download?bytes='+dlBytes, {cache:'no-store'});
			if(!dr.ok) throw new Error('download http '+dr.status);
			await dr.arrayBuffer();
			var dt = (performance.now()-ds)/1000;
			var dMbps = (dlBytes*8)/(dt*1e6);
			$('dDown').textContent = fmtMbps(dMbps);

			$('directStatus').textContent = 'Running upload speed test...';
			var ulBytes = 8*1024*1024;
			var payload = new Uint8Array(ulBytes);
			for(var p=0; p<ulBytes; p+=65536){
				var chunk = payload.subarray(p, Math.min(ulBytes, p+65536));
				crypto.getRandomValues(chunk);
			}
			var us = performance.now();
			var ur = await fetch('/api/nettest/direct-upload', {
				method:'POST',
				headers:{'Content-Type':'application/octet-stream'},
				body: payload
			});
			if(!ur.ok) throw new Error('upload http '+ur.status);
			var uj = await ur.json();
			var ut = (performance.now()-us)/1000;
			var uMbps = uj && uj.mbps ? Number(uj.mbps) : (ulBytes*8)/(ut*1e6);
			$('dUp').textContent = fmtMbps(uMbps);

			$('directStatus').textContent = 'Complete';
			$('runDirect').disabled = false;
		}

		async function runAgent(){
			$('runAgent').disabled = true;
			$('agentStatus').textContent = 'Running server↔agent test...';
			var form = new URLSearchParams();
			form.set('csrf', csrf);
			form.set('count', '60');
			form.set('payload_bytes', '1024');
			form.set('timeout_ms', '1500');
			var r = await fetch('/api/nettest/agent', {method:'POST', body: form});
			if(!r.ok){
				var txt = await r.text();
				throw new Error(txt || ('http '+r.status));
			}
			var j = await r.json();
			$('aLatency').textContent = fmtMs(j.avgLatencyMs)+' / '+fmtMs(j.minLatencyMs)+' / '+fmtMs(j.maxLatencyMs);
			$('aJitter').textContent = fmtMs(j.jitterMs);
			$('aLoss').textContent = fmtPct(j.lossPercent)+' ('+j.lostPackets+'/'+j.sentPackets+')';
			$('aDown').textContent = fmtMbps(j.downloadMbps);
			$('aUp').textContent = fmtMbps(j.uploadMbps);
			$('agentStatus').textContent = 'Complete ('+j.durationMs+' ms)';
			$('runAgent').disabled = false;
		}

		$('runDirect').addEventListener('click', function(){
			runDirect().catch(function(err){
				$('directStatus').textContent = 'Failed: '+(err && err.message ? err.message : 'unknown');
				$('runDirect').disabled = false;
			});
		});
		$('runAgent').addEventListener('click', function(){
			runAgent().catch(function(err){
				$('agentStatus').textContent = 'Failed: '+(err && err.message ? err.message : 'unknown');
				$('runAgent').disabled = false;
			});
		});
	})();
	</script>
</body>
</html>`

const loginPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login — Tunnel Server</title>
  <style>
    *,*::before,*::after{box-sizing:border-box}
    :root{--bg:#0f1117;--bg2:#181b25;--surface:rgba(255,255,255,.04);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color-scheme:dark}
    @media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--surface:rgba(0,0,0,.03);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--redDim:rgba(248,81,73,.08);color-scheme:light}}
    body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .wrap{width:100%;max-width:400px;padding:16px}
    h1{margin:0 0 4px;font-size:20px;font-weight:700}
    .sub{font-size:13px;color:var(--textMuted);margin-bottom:20px}
    .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:20px}
    label{font-size:12px;font-weight:600;display:block;margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
    input{width:100%;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:14px;transition:border-color .15s}
    input:focus{outline:none;border-color:var(--accent)}
    .gap{height:14px}
    .btn{display:inline-flex;align-items:center;justify-content:center;width:100%;padding:10px;border-radius:var(--radius);border:1px solid var(--accentBorder);background:var(--accentDim);color:var(--accent);font-family:var(--font);font-size:14px;font-weight:600;cursor:pointer;transition:all .15s;margin-top:16px}
    .btn:hover{background:rgba(91,141,239,.28)}
    .err{padding:8px 12px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red)}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Tunnel Server</h1>
    <div class="sub">Sign in to manage your server.</div>
    {{if .Msg}}<div class="err">{{.Msg}}</div>{{end}}
    <form method="post" action="/login" class="card">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />
      <label>Username</label>
      <input name="username" autocomplete="username" autofocus />
      <div class="gap"></div>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" />
      <button type="submit" class="btn">Sign in</button>
    </form>
  </div>
</body>
</html>`

const setupPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>First-time Setup — Tunnel Server</title>
  <style>
    *,*::before,*::after{box-sizing:border-box}
    :root{--bg:#0f1117;--bg2:#181b25;--surface:rgba(255,255,255,.04);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color-scheme:dark}
    @media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--surface:rgba(0,0,0,.03);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--redDim:rgba(248,81,73,.08);color-scheme:light}}
    body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .wrap{width:100%;max-width:440px;padding:16px}
    h1{margin:0 0 4px;font-size:20px;font-weight:700}
    .sub{font-size:13px;color:var(--textMuted);margin-bottom:20px}
    .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:20px}
    label{font-size:12px;font-weight:600;display:block;margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
    .help{font-size:11px;color:var(--textMuted);margin:0 0 6px;line-height:1.4}
    input{width:100%;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:14px;transition:border-color .15s}
    input:focus{outline:none;border-color:var(--accent)}
    input.inputErr{border-color:var(--red);background:var(--redDim)}
    .gap{height:14px}
    .btn{display:inline-flex;align-items:center;justify-content:center;width:100%;padding:10px;border-radius:var(--radius);border:1px solid var(--accentBorder);background:var(--accentDim);color:var(--accent);font-family:var(--font);font-size:14px;font-weight:600;cursor:pointer;transition:all .15s;margin-top:16px}
    .btn:hover{background:rgba(91,141,239,.28)}
    .err{padding:8px 12px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red)}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>First-time Setup</h1>
    <div class="sub">Create the initial admin account for this server.</div>
    {{if .Err}}<div class="err">{{.Err}}</div>{{end}}
    <form method="post" action="/setup" class="card">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />
      <label>Username</label>
      <div class="help">Pick a unique username for the admin login.</div>
      <input name="username" autocomplete="username" value="{{.Username}}" class="{{if .ErrUsername}}inputErr{{end}}" autofocus />
      <div class="gap"></div>
      <label>Password</label>
      <div class="help">Minimum 10 characters. Use a password manager.</div>
      <input name="password" type="password" autocomplete="new-password" class="{{if .ErrPassword}}inputErr{{end}}" />
      <div class="gap"></div>
      <label>Confirm password</label>
      <input name="confirm" type="password" autocomplete="new-password" class="{{if .ErrConfirm}}inputErr{{end}}" />
      <button type="submit" class="btn">Create account</button>
    </form>
  </div>
  {{if .Err}}
  <script>
    (function(){
      var p=document.querySelector('input[name="password"]');
      var c=document.querySelector('input[name="confirm"]');
      if(p)p.value='';if(c)c.value='';
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

// Rate limiter for auth session lookups (prevents session brute-forcing)
var authSessionLimiter = newIPRateLimiter(60, 1*time.Minute) // 60 requests per minute per IP

func requireAuth(store *auth.Store, cookieSecure bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limit session validation attempts
		if !authSessionLimiter.Allow(clientIP(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

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
