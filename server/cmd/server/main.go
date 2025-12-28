package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"strings"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"playit-prototype/server/internal/auth"
	"playit-prototype/server/internal/configio"
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

	flag.StringVar(&controlAddr, "control", ":7000", "control listen address")
	flag.StringVar(&dataAddr, "data", ":7001", "data listen address")
	flag.StringVar(&publicAddr, "public", ":7777", "public listen address")
	flag.StringVar(&token, "token", "", "shared token (optional)")
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
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		PublicAddr:  publicAddr,
		Token:       token,
		PairTimeout: pairTimeout,
	}
	_, _ = configio.Load(configPath, &cfg)

	runner := newServerRunner(ctx, cfg)
	runner.Start()

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
	go func(s *tunnel.Server) {
		err := s.Run(ctx)
		r.mu.Lock()
		r.err = err
		if r.cancel != nil {
			r.cancel = nil
		}
		r.mu.Unlock()
	}(r.srv)
}

func (r *serverRunner) Restart(cfg tunnel.ServerConfig) {
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.cfg = cfg
	r.mu.Unlock()

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
	tplServer := template.Must(template.New("server").Parse(serverPageHTML))
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

	// Dashboard (protected)
	mux.HandleFunc("/", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
		csrf := ensureCSRF(w, r, cookieSecure)
		cfg, st, err := runner.Get()
		routes := cfg.Routes
		if len(routes) == 0 && strings.TrimSpace(cfg.PublicAddr) != "" {
			routes = []tunnel.RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: cfg.PublicAddr}}
		}
		routesJSON := ""
		if b, jerr := json.MarshalIndent(routes, "", "  "); jerr == nil {
			routesJSON = string(b)
		}
		data := map[string]any{
			"Cfg":        cfg,
			"Status":     st,
			"ConfigPath": configPath,
			"Msg":        getMsg(),
			"Err":        err,
			"CSRF":       csrf,
			"RoutesJSON": routesJSON,
		}
		_ = tplServer.Execute(w, data)
	})))

	mux.HandleFunc("/save", securityHeaders(requireAuth(store, cookieSecure, func(w http.ResponseWriter, r *http.Request) {
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
		cfg := tunnel.ServerConfig{
			ControlAddr: r.Form.Get("control"),
			DataAddr:    r.Form.Get("data"),
			PublicAddr:  r.Form.Get("public"),
			Token:       r.Form.Get("token"),
			PairTimeout: pt,
		}
		routesJSON := strings.TrimSpace(r.Form.Get("routes_json"))
		if routesJSON != "" {
			var routes []tunnel.RouteConfig
			if err := json.Unmarshal([]byte(routesJSON), &routes); err != nil {
				http.Error(w, "invalid routes JSON", http.StatusBadRequest)
				return
			}
			cfg.Routes = routes
		}
		if err := configio.Save(configPath, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		runner.Restart(cfg)
		setMsg("Saved + restarted")
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

const serverPageHTML = `<!doctype html>
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
    label { font-weight: 600; display:block; margin: 0 0 4px; }
    .help { font-size: 12px; margin: 0 0 8px; opacity: .85; line-height: 1.35; }
	input, textarea { width: 100%; max-width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
	textarea { min-height: 140px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .row { margin-bottom: 10px; }
    .btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
    button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
    button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
    .pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
    .ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
    .bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
    .flash { margin: 10px 0 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>Tunnel Server</h1>
        <div class="muted">Public TCP listeners that forward to one connected agent.</div>
      </div>
      <div class="card">
				<form method="post" action="/logout" style="float:right; margin: 0">
					<input type="hidden" name="csrf" value="{{.CSRF}}" />
					<button type="submit">Logout</button>
				</form>
        <div class="row"><b>Status:</b>
          {{if .Status.AgentConnected}}<span class="pill ok">Agent connected</span>{{else}}<span class="pill bad">No agent</span>{{end}}
        </div>
        <div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
        {{if .Err}}<div class="row"><b>Last server error:</b> <span class="muted">{{.Err}}</span></div>{{end}}
      </div>
    </div>

    {{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

    <h2>How this works</h2>
    <div class="card">
      <div class="muted">Clients connect to <b>Public listen</b>. The server notifies the agent over <b>Control</b>, then pairs the connection over <b>Data</b>. If you change ports here, the server will restart the listeners.</div>
    </div>

    <h2>Config</h2>
    <form method="post" action="/save" class="card">
			<input type="hidden" name="csrf" value="{{.CSRF}}" />
      <div class="grid">
        <div>
          <label>Control listen</label>
          <div class="help">Where the agent connects for commands (e.g. <code>:7000</code> or <code>0.0.0.0:7000</code>).</div>
          <input name="control" value="{{.Cfg.ControlAddr}}" />
        </div>

        <div>
          <label>Data listen</label>
          <div class="help">Where the agent connects to attach a specific proxied connection (e.g. <code>:7001</code>).</div>
          <input name="data" value="{{.Cfg.DataAddr}}" />
        </div>

				<div>
					<label>Public listen (legacy single TCP)</label>
					<div class="help">Backwards-compatible: if <b>Routes</b> is empty, a single TCP route named <code>default</code> is created from this value.</div>
					<input name="public" value="{{.Cfg.PublicAddr}}" />
				</div>

        <div>
          <label>Pair timeout</label>
          <div class="help">How long to wait for the agent to attach after a public client connects (e.g. <code>10s</code>, <code>2s</code>).</div>
          <input name="pair_timeout" value="{{.Cfg.PairTimeout}}" />
        </div>
      </div>

      <div style="margin-top: 12px">
        <label>Token (optional)</label>
        <div class="help">Shared secret the agent must provide. Leave blank to allow any agent to connect.</div>
        <input name="token" value="{{.Cfg.Token}}" />
      </div>

			<div style="margin-top: 12px">
				<label>Routes (JSON)</label>
				<div class="help">Define multiple public entry ports and protocols. Each route uses the same <b>PublicAddr</b> for TCP and/or UDP, depending on <code>Proto</code> (<code>tcp</code>, <code>udp</code>, <code>both</code>). Route <code>Name</code> must match the client’s route name.</div>
				<textarea name="routes_json">{{.RoutesJSON}}</textarea>
			</div>

      <div class="btns">
        <button type="submit" class="primary">Save + restart</button>
      </div>
    </form>

    <form method="post" action="/gen-token" class="card" style="margin-top: 12px">
      <input type="hidden" name="csrf" value="{{.CSRF}}" />
      <div class="help">Generates a new random token, saves it to <code>{{.ConfigPath}}</code>, and restarts the server. Update your agent to use the same token.</div>
      <div class="btns">
        <button type="submit">Generate token + restart</button>
      </div>
    </form>
  </div>
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
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
