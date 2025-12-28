package main

import (
	"context"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"playit-prototype/client/internal/agent"
	"playit-prototype/client/internal/configio"
)

func main() {
	var serverHost string
	var token string
	var webAddr string
	var configPath string
	var autostart bool

	flag.StringVar(&serverHost, "server", "", "tunnel server host/IP (optionally include control port, e.g. host:7000)")
	flag.StringVar(&token, "token", "", "shared token (required)")
	flag.StringVar(&webAddr, "web", ":7003", "agent web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "agent.json", "path to agent config JSON")
	flag.BoolVar(&autostart, "autostart", true, "start agent automatically")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := agent.Config{}
	loaded, _ := configio.Load(configPath, &cfg)
	if !loaded && strings.TrimSpace(cfg.Server) == "" {
		// First-run convenience: if no config file exists, default to localhost.
		cfg.Server = "127.0.0.1"
	}
	if strings.TrimSpace(token) != "" {
		cfg.Token = token
	}
	if strings.TrimSpace(serverHost) != "" {
		cfg.Server = serverHost
	}

	if strings.TrimSpace(cfg.Server) == "" {
		if webAddr == "" {
			log.Fatalf("agent server is required (set -server or agent.json Server)")
		}
		autostart = false
		log.Printf("agent server not set; web UI is available to configure it")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		if webAddr == "" {
			log.Fatalf("agent token is required (set -token or agent.json Token)")
		}
		autostart = false
		log.Printf("agent token not set; web UI is available to configure it")
	}

	ctrl := newAgentController(ctx, cfg)
	if autostart {
		ctrl.Start()
	}

	if webAddr != "" {
		go func() {
			display := webAddr
			if strings.HasPrefix(display, ":") {
				display = "127.0.0.1" + display
			}
			log.Printf("agent web: http://%s", display)
			if err := serveAgentDashboard(ctx, webAddr, configPath, ctrl); err != nil {
				log.Printf("agent web error: %v", err)
			}
		}()
	}

	<-ctx.Done()
}

type agentController struct {
	root context.Context

	mu        sync.Mutex
	cfg       agent.Config
	running   bool
	connected bool
	lastErr   string
	routes    []agent.RemoteRoute
	cancel    context.CancelFunc
	done      chan struct{}
	runID     uint64
}

func newAgentController(root context.Context, cfg agent.Config) *agentController {
	return &agentController{root: root, cfg: cfg}
}

func (a *agentController) Get() (agent.Config, bool, bool, string, []agent.RemoteRoute) {
	a.mu.Lock()
	defer a.mu.Unlock()
	routes := append([]agent.RemoteRoute(nil), a.routes...)
	return a.cfg, a.running, a.connected, a.lastErr, routes
}

func (a *agentController) SetConfig(cfg agent.Config) {
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
}

func (a *agentController) Start() {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return
	}
	a.runID++
	rid := a.runID
	cfg := a.cfg
	if strings.TrimSpace(cfg.Server) == "" || strings.TrimSpace(cfg.Token) == "" {
		a.running = false
		a.connected = false
		a.lastErr = "missing server and/or token (set them on /)"
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(a.root)
	a.cancel = cancel
	done := make(chan struct{})
	a.done = done
	a.running = true
	a.connected = false
	a.lastErr = ""
	a.mu.Unlock()

	hooks := &agent.Hooks{
		OnConnected: func() {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.connected = true
			a.lastErr = ""
			a.mu.Unlock()
		},
		OnRoutes: func(routes []agent.RemoteRoute) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.routes = append([]agent.RemoteRoute(nil), routes...)
			a.mu.Unlock()
		},
		OnDisconnected: func(err error) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.connected = false
			if err != nil {
				a.lastErr = err.Error()
			}
			a.mu.Unlock()
		},
		OnError: func(err error) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.connected = false
			if err != nil {
				a.lastErr = err.Error()
			}
			a.mu.Unlock()
		},
	}

	go func() {
		defer close(done)
		err := agent.RunWithHooks(ctx, cfg, hooks)
		a.mu.Lock()
		if a.runID == rid {
			a.connected = false
			a.running = false
			a.cancel = nil
			a.done = nil
			if err != nil && a.lastErr == "" {
				a.lastErr = err.Error()
			}
		}
		a.mu.Unlock()
	}()
}

func (a *agentController) Stop() {
	a.mu.Lock()
	a.runID++
	cancel := a.cancel
	done := a.done
	a.cancel = nil
	a.running = false
	a.connected = false
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func serveAgentDashboard(ctx context.Context, addr string, configPath string, ctrl *agentController) error {
	tplHome := template.Must(template.New("home").Parse(agentHomeHTML))

	type routeView struct {
		Name        string
		Proto       string
		PublicAddr  string
		LocalTarget string
	}
	makeRouteViews := func(routes []agent.RemoteRoute) []routeView {
		out := make([]routeView, 0, len(routes))
		for _, rt := range routes {
			out = append(out, routeView{
				Name:        rt.Name,
				Proto:       rt.Proto,
				PublicAddr:  rt.PublicAddr,
				LocalTarget: localTargetFromPublicAddr(rt.PublicAddr),
			})
		}
		return out
	}

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

	// Single page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		data := map[string]any{
			"Cfg":        cfg,
			"Running":    running,
			"Connected":  connected,
			"HasToken":   strings.TrimSpace(cfg.Token) != "",
			"LastErr":    lastErr,
			"ConfigPath": configPath,
			"Msg":        getMsg(),
			"RoutesView": makeRouteViews(routes),
		}
		_ = tplHome.Execute(w, data)
	})

	// Back-compat: old config page
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	saveHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		old, _, _, _, _ := ctrl.Get()
		cfg := old
		cfg.Server = strings.TrimSpace(r.Form.Get("server"))
		cfg.Token = strings.TrimSpace(r.Form.Get("token"))
		if cfg.Server == "" {
			http.Error(w, "server is required", http.StatusBadRequest)
			return
		}
		if cfg.Token == "" {
			http.Error(w, "token is required", http.StatusBadRequest)
			return
		}
		if err := configio.Save(configPath, cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Apply immediately.
		ctrl.Stop()
		ctrl.SetConfig(cfg)
		ctrl.Start()
		setMsg("Saved + restarted")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	// Save endpoint (and back-compat path)
	mux.HandleFunc("/save", saveHandler)
	mux.HandleFunc("/config/save", saveHandler)

	// No start/stop controls: agent runs as a service.

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

func localTargetFromPublicAddr(publicAddr string) string {
	if strings.TrimSpace(publicAddr) == "" {
		return "127.0.0.1"
	}
	if strings.HasPrefix(publicAddr, ":") {
		port := strings.TrimPrefix(publicAddr, ":")
		if port == "" {
			return "127.0.0.1"
		}
		return net.JoinHostPort("127.0.0.1", port)
	}

	_, port, err := net.SplitHostPort(publicAddr)
	if err == nil {
		return net.JoinHostPort("127.0.0.1", port)
	}

	if idx := strings.LastIndex(publicAddr, ":"); idx != -1 && idx+1 < len(publicAddr) {
		port = publicAddr[idx+1:]
		if port != "" {
			return net.JoinHostPort("127.0.0.1", port)
		}
	}
	return "127.0.0.1"
}

const agentHomeHTML = `<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Agent</title>
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
		input { width: 100%; max-width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
		.btns { display:flex; gap:10px; flex-wrap:wrap; margin-top: 10px; }
		button { padding: 9px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.12); cursor: pointer; }
		button.primary { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
		.ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
		.bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
		code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
		.flash { margin: 10px 0 0; }
		.row { margin-bottom: 10px; }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="top">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="muted">Connects outbound to your tunnel server and forwards based on server configuration.</div>
			</div>
			<div class="card">
				<div class="row"><b>Status:</b>
					{{if .Running}}<span class="pill ok">Running</span>{{else}}<span class="pill bad">Stopped</span>{{end}}
					{{if .Connected}}<span class="pill ok">Connected</span>{{else}}<span class="pill bad">Disconnected</span>{{end}}
				</div>
				<div class="row"><b>Server:</b> <code>{{.Cfg.Server}}</code></div>
				<div class="row"><b>Token:</b> {{if .HasToken}}<span class="pill ok">Set</span>{{else}}<span class="pill bad">Missing</span>{{end}}</div>
				<div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
				{{if .LastErr}}<div class="row"><b>Last error:</b> <span class="muted">{{.LastErr}}</span></div>{{end}}
			</div>
		</div>

		{{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

		<form method="post" action="/save" class="card">
			<h2>Connection</h2>
			<div class="grid">
				<div>
					<label>Server</label>
					<div class="help">Tunnel server host/IP (defaults to ports 7000/7001).</div>
					<input name="server" value="{{.Cfg.Server}}" />
				</div>
				<div>
					<label>Token</label>
					<div class="help">Required. Must match the server token.</div>
					<input name="token" value="{{.Cfg.Token}}" />
				</div>
			</div>
			<div style="margin-top:12px" class="muted">This agent does not configure routes. Routes come from the server, and the agent forwards to <code>127.0.0.1:&lt;publicPort&gt;</code> on this machine.</div>
			<div class="btns">
				<button type="submit" class="primary">Save + restart agent</button>
			</div>
		</form>

		<h2>Routes</h2>
		<div class="card">
			{{if not .Connected}}
				<div class="muted">Routes appear after the agent connects to the server.</div>
			{{end}}
			{{range .RoutesView}}
				<div class="row"><b>{{.Name}}</b> <span class="muted">({{.Proto}})</span> public: <code>{{.PublicAddr}}</code> local: <code>{{.LocalTarget}}</code></div>
			{{end}}
		</div>
	</div>
</body>
</html>`
