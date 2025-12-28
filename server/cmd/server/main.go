package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"playit-prototype/server/internal/auth"
	"playit-prototype/server/internal/configio"
	"playit-prototype/server/internal/tlsutil"
	"playit-prototype/server/internal/tunnel"
)

func main() {
	var controlAddr string
	var dataAddr string
	var publicAddr string
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
	flag.StringVar(&publicAddr, "public", ":7777", "public listen address")
	flag.StringVar(&token, "token", "", "shared token (optional)")
	flag.BoolVar(&disableTLS, "disable-tls", false, "disable TLS for agent<->server control/data TCP")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate PEM path (default: alongside config)")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key PEM path (default: alongside config)")
	flag.BoolVar(&disableUDPEnc, "disable-udp-encryption", false, "disable application-layer encryption for agent<->server UDP data (deprecated; use server config: UDP Encryption = none)")
	flag.DurationVar(&pairTimeout, "pair-timeout", 10*time.Second, "max wait for agent to attach")
	flag.StringVar(&webAddr, "web", ":7002", "web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "server.json", "path to server config JSON")
	flag.StringVar(&authDBPath, "auth-db", "auth.db", "sqlite auth db path")
	flag.BoolVar(&cookieSecure, "cookie-secure", false, "set Secure on cookies (recommended behind HTTPS)")
	flag.DurationVar(&sessionTTL, "session-ttl", 7*24*time.Hour, "session lifetime")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := tunnel.ServerConfig{
		ControlAddr:          controlAddr,
		DataAddr:             dataAddr,
		PublicAddr:           publicAddr,
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
		log.Printf("server token was empty; generated a new one")
	}

	// Normalize/ensure UDP encryption settings + key material.
	if changed := tunnel.EnsureUDPKeys(&cfg, time.Now()); changed {
		_ = configio.Save(configPath, cfg)
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
			log.Fatalf("tls setup: %v", err)
		}
		_ = configio.Save(configPath, cfg)
		log.Printf("tunnel tls enabled; cert sha256=%s", fp)
	}

	runner := newServerRunner(ctx, cfg)
	runner.Start()

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
				log.Printf("udp key rotation save error: %v", err)
				continue
			}
			runner.Restart(cfg)
			log.Printf("udp keys rotated; new key id=%d", cfg.UDPKeyID)
		}
	}()

	if webAddr != "" {
		go func() {
			store, err := auth.Open(authDBPath)
			if err != nil {
				log.Printf("auth db open error: %v", err)
				return
			}
			defer store.Close()

			log.Printf("server web: http://%s", webAddr)
			if err := serveServerDashboard(ctx, webAddr, configPath, runner, store, cookieSecure, sessionTTL); err != nil {
				log.Printf("server web error: %v", err)
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

type ctxKey int

const (
	ctxUserID ctxKey = iota
)

func serveServerDashboard(ctx context.Context, addr string, configPath string, runner *serverRunner, store *auth.Store, cookieSecure bool, sessionTTL time.Duration) error {
	tplStats := template.Must(template.New("stats").Parse(serverStatsHTML))
	tplConfig := template.Must(template.New("config").Parse(serverConfigHTML))
	tplLogin := template.Must(template.New("login").Parse(loginPageHTML))
	tplSetup := template.Must(template.New("setup").Parse(setupPageHTML))

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

	mux := http.NewServeMux()

	// Setup: only available if no users exist.
	mux.HandleFunc("/setup", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		hasUsers, err := store.HasAnyUsers(r.Context())
		if err != nil {
			http.Error(w, "auth db error", http.StatusInternalServerError)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
		if hasUsers {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		switch r.Method {
		case http.MethodGet:
			_ = tplSetup.Execute(w, map[string]any{"CSRF": csrf, "Msg": getMsg()})
			return
		case http.MethodPost:
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
			confirm := r.Form.Get("confirm")
			if username == "" || len(password) < 10 || password != confirm {
				http.Error(w, "invalid input (password must be >= 10 chars and match)", http.StatusBadRequest)
				return
			}
			if err := store.CreateUser(r.Context(), username, password); err != nil {
				http.Error(w, "create user failed", http.StatusBadRequest)
				return
			}
			userID, ok, err := store.Authenticate(r.Context(), username, password)
			if err != nil || !ok {
				http.Error(w, "login failed", http.StatusInternalServerError)
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
	mux.HandleFunc("/login", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/logout", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
	mux.HandleFunc("/", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
		cfg, st, err := runner.Get()
		routes := effectiveServerRoutes(cfg)
		data := map[string]any{
			"Cfg":        cfg,
			"Status":     st,
			"ConfigPath": configPath,
			"Msg":        getMsg(),
			"Err":        err,
			"CSRF":       csrf,
			"Routes":     routes,
			"RouteCount": len(routes),
		}
		_ = tplStats.Execute(w, data)
	})))

	// Config (protected)
	mux.HandleFunc("/config", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		csrf := ensureCSRF(w, r, cookieSecure)
		cfg, st, err := runner.Get()
		routes := effectiveServerRoutes(cfg)
		type routeView struct {
			Name       string
			Proto      string
			PublicAddr string
			TCPNoDelay bool
		}
		routeViews := make([]routeView, 0, len(routes))
		for _, rt := range routes {
			noDelay := true
			if rt.TCPNoDelay != nil {
				noDelay = *rt.TCPNoDelay
			}
			routeViews = append(routeViews, routeView{Name: rt.Name, Proto: rt.Proto, PublicAddr: rt.PublicAddr, TCPNoDelay: noDelay})
		}
		data := map[string]any{
			"Cfg":        cfg,
			"Status":     st,
			"ConfigPath": configPath,
			"Msg":        getMsg(),
			"Err":        err,
			"CSRF":       csrf,
			"Routes":     routeViews,
			"RouteCount": len(routeViews),
			"UDPKeyCreated": func() string {
				if cfg.UDPKeyCreatedUnix == 0 {
					return ""
				}
				return time.Unix(cfg.UDPKeyCreatedUnix, 0).Format(time.RFC3339)
			}(),
		}
		_ = tplConfig.Execute(w, data)
	})))

	mux.HandleFunc("/config/save", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
		cfg := tunnel.ServerConfig{
			// Preserve non-UI fields by starting from current config.
		}
		old, _, _ := runner.Get()
		cfg = old
		oldEnc := strings.TrimSpace(cfg.UDPEncryptionMode)
		cfg.ControlAddr = r.Form.Get("control")
		cfg.DataAddr = r.Form.Get("data")
		cfg.PublicAddr = r.Form.Get("public")
		cfg.Token = strings.TrimSpace(r.Form.Get("token"))
		cfg.PairTimeout = pt
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
		if err := configio.Save(configPath, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		runner.Restart(cfg)
		addMsg("Saved + restarted")
		setMsg(strings.Join(msgs, " · "))
		http.Redirect(w, r, "/config", http.StatusSeeOther)
	})))

	// Back-compat: old save endpoint
	mux.HandleFunc("/save", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/config", http.StatusSeeOther)
	})))

	mux.HandleFunc("/gen-token", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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

	h := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx2)
	}()

	err := h.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func genToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func effectiveServerRoutes(cfg tunnel.ServerConfig) []tunnel.RouteConfig {
	if len(cfg.Routes) == 0 {
		if strings.TrimSpace(cfg.PublicAddr) != "" {
			return []tunnel.RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: cfg.PublicAddr}}
		}
		return []tunnel.RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: ":7777"}}
	}
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
		if name == "" && proto == "" && pub == "" {
			continue
		}
		if name == "" {
			name = "default"
		}
		if proto == "" {
			proto = "tcp"
		}
		routes = append(routes, tunnel.RouteConfig{Name: name, Proto: proto, PublicAddr: pub, TCPNoDelay: &nodelay})
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
				<div class="row"><b>Routes:</b> {{.RouteCount}}</div>
				<div class="row"><b>Control:</b> <code>{{.Cfg.ControlAddr}}</code></div>
				<div class="row"><b>Data:</b> <code>{{.Cfg.DataAddr}}</code></div>
			</div>
			<div class="card">
				<div class="muted">Edit server settings on the <a href="/config">Config</a> page.</div>
			</div>
		</div>

		<h2>Routes</h2>
		<div class="card">
			{{range .Routes}}
				<div class="row"><b>{{.Name}}</b> <span class="muted">({{.Proto}})</span> — <code>{{.PublicAddr}}</code></div>
			{{end}}
		</div>
  </div>
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
					<label>Public listen (legacy single TCP)</label>
					<div class="help">If Routes are empty, a single TCP route named <code>default</code> is created from this value.</div>
					<input name="public" value="{{.Cfg.PublicAddr}}" />
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
    .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
    button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
    button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>First-time Setup</h1>
    <div class="muted">Create the initial admin account for this server.</div>

    <form method="post" action="/setup" class="card">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />

      <label>Username</label>
      <div class="help">Pick a unique username. This will be your admin login.</div>
      <input name="username" autocomplete="username" />

      <div style="height: 10px"></div>

      <label>Password</label>
      <div class="help">Use a long password (minimum 10 characters). Use a password manager.</div>
      <input name="password" type="password" autocomplete="new-password" />

      <div style="height: 10px"></div>

      <label>Confirm password</label>
      <input name="confirm" type="password" autocomplete="new-password" />

      <div class="btns">
        <button type="submit" class="primary">Create account</button>
      </div>
    </form>
  </div>
</body>
</html>`

func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next(w, r)
	}
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
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   60 * 60 * 24 * 7,
	})
	return tok
}

func checkCSRF(r *http.Request) bool {
	formTok := r.Form.Get("csrf")
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

func setSessionCookie(w http.ResponseWriter, sid string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
		SameSite: http.SameSiteLaxMode,
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
