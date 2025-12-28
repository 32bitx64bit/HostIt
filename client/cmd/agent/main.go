package main

import (
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"log"
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
	var controlAddr string
	var dataAddr string
	var token string
	var localAddr string
	var webAddr string
	var configPath string
	var autostart bool

	flag.StringVar(&controlAddr, "control", "127.0.0.1:7000", "server control address")
	flag.StringVar(&dataAddr, "data", "127.0.0.1:7001", "server data address")
	flag.StringVar(&token, "token", "", "shared token (optional)")
	flag.StringVar(&localAddr, "local", "127.0.0.1:8080", "local target address")
	flag.StringVar(&webAddr, "web", "127.0.0.1:7070", "agent web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "agent.json", "path to agent config JSON")
	flag.BoolVar(&autostart, "autostart", true, "start agent automatically")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := agent.Config{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       token,
		LocalAddr:   localAddr,
	}
	_, _ = configio.Load(configPath, &cfg)

	ctrl := newAgentController(ctx, cfg)
	if autostart {
		ctrl.Start()
	}

	if webAddr != "" {
		go func() {
			log.Printf("agent web: http://%s", webAddr)
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
	cancel    context.CancelFunc
}

func newAgentController(root context.Context, cfg agent.Config) *agentController {
	return &agentController{root: root, cfg: cfg}
}

func (a *agentController) Get() (agent.Config, bool, bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg, a.running, a.connected, a.lastErr
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
	ctx, cancel := context.WithCancel(a.root)
	a.cancel = cancel
	a.running = true
	a.connected = false
	a.lastErr = ""
	cfg := a.cfg
	a.mu.Unlock()

	hooks := &agent.Hooks{
		OnConnected: func() {
			a.mu.Lock()
			a.connected = true
			a.lastErr = ""
			a.mu.Unlock()
		},
		OnDisconnected: func(err error) {
			a.mu.Lock()
			a.connected = false
			if err != nil {
				a.lastErr = err.Error()
			}
			a.mu.Unlock()
		},
		OnError: func(err error) {
			a.mu.Lock()
			a.connected = false
			if err != nil {
				a.lastErr = err.Error()
			}
			a.mu.Unlock()
		},
	}

	go func() {
		err := agent.RunWithHooks(ctx, cfg, hooks)
		a.mu.Lock()
		a.connected = false
		a.running = false
		a.cancel = nil
		if err != nil && a.lastErr == "" {
			a.lastErr = err.Error()
		}
		a.mu.Unlock()
	}()
}

func (a *agentController) Stop() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.running = false
	a.connected = false
	a.mu.Unlock()
}

func serveAgentDashboard(ctx context.Context, addr string, configPath string, ctrl *agentController) error {
	tpl := template.Must(template.New("agent").Parse(agentPageHTML))

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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cfg, running, connected, lastErr := ctrl.Get()
		routes := cfg.Routes
		if len(routes) == 0 && strings.TrimSpace(cfg.LocalAddr) != "" {
			routes = []agent.RouteConfig{{Name: "default", Proto: "tcp", LocalTCPAddr: cfg.LocalAddr}}
		}
		routesJSON := ""
		if b, jerr := json.MarshalIndent(routes, "", "  "); jerr == nil {
			routesJSON = string(b)
		}
		data := map[string]any{
			"Cfg":        cfg,
			"Running":    running,
			"Connected":  connected,
			"LastErr":    lastErr,
			"ConfigPath": configPath,
			"Msg":        getMsg(),
			"RoutesJSON": routesJSON,
		}
		_ = tpl.Execute(w, data)
	})

	mux.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg := agent.Config{
			ControlAddr: r.Form.Get("control"),
			DataAddr:    r.Form.Get("data"),
			Token:       r.Form.Get("token"),
			LocalAddr:   r.Form.Get("local"),
		}
		routesJSON := strings.TrimSpace(r.Form.Get("routes_json"))
		if routesJSON != "" {
			var routes []agent.RouteConfig
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
		ctrl.SetConfig(cfg)
		setMsg("Saved")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctrl.Start()
		setMsg("Starting")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctrl.Stop()
		setMsg("Stopped")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

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

const agentPageHTML = `<!doctype html>
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
		input, textarea { width: 100%; max-width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); }
		textarea { min-height: 160px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
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
				<h1>Tunnel Agent</h1>
				<div class="muted">Runs near your private service and connects outbound to your tunnel server.</div>
			</div>
			<div class="card">
				<div><b>Status:</b>
					{{if .Running}}<span class="pill ok">Running</span>{{else}}<span class="pill bad">Stopped</span>{{end}}
					{{if .Connected}}<span class="pill ok">Connected</span>{{else}}<span class="pill bad">Disconnected</span>{{end}}
				</div>
				<div style="margin-top:8px"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
				{{if .LastErr}}<div style="margin-top:8px"><b>Last error:</b> <span class="muted">{{.LastErr}}</span></div>{{end}}
			</div>
		</div>

		{{if .Msg}}<div class="flash pill ok">{{.Msg}}</div>{{end}}

		<h2>How this works</h2>
		<div class="card">
			<div class="muted">When the server gets a public connection, it tells this agent to attach. The agent then dials <b>Local target</b> and pipes bytes both ways. Start/Stop here only affects the agent connection; your local service keeps running.</div>
		</div>

		<h2>Config</h2>
		<form method="post" action="/save" class="card">
			<div class="grid">
				<div>
					<label>Server control</label>
					<div class="help">Tunnel server control address (e.g. <code>your-vps:7000</code>).</div>
					<input name="control" value="{{.Cfg.ControlAddr}}" />
				</div>

				<div>
					<label>Server data</label>
					<div class="help">Tunnel server data address (e.g. <code>your-vps:7001</code>).</div>
					<input name="data" value="{{.Cfg.DataAddr}}" />
				</div>

				<div>
					<label>Local target (legacy single TCP)</label>
					<div class="help">Backwards-compatible: if <b>Routes</b> is empty, a single TCP route named <code>default</code> is created from this value.</div>
					<input name="local" value="{{.Cfg.LocalAddr}}" />
				</div>

				<div>
					<label>Token (optional)</label>
					<div class="help">Must match the server token if set. Leave blank if the server has no token.</div>
					<input name="token" value="{{.Cfg.Token}}" />
				</div>
			</div>

			<div style="margin-top: 12px">
				<label>Routes (JSON)</label>
				<div class="help">Define multiple internal targets. Route <code>Name</code> must match the server’s route name. Use <code>Proto</code> = <code>tcp</code>, <code>udp</code>, or <code>both</code> and set <code>LocalTCPAddr</code>/<code>LocalUDPAddr</code> accordingly.</div>
				<textarea name="routes_json">{{.RoutesJSON}}</textarea>
			</div>

			<div class="btns">
				<button type="submit" class="primary">Save</button>
			</div>
		</form>

		<h2>Control</h2>
		<div class="card">
			<div class="help">If you changed config above, click <b>Save</b> first. If the agent is running, you may need to Stop then Start to reconnect using new settings.</div>
			<div class="btns">
				<form method="post" action="/start" style="display:inline">
					<button type="submit" class="primary">Start</button>
				</form>
				<form method="post" action="/stop" style="display:inline">
					<button type="submit">Stop</button>
				</form>
			</div>
		</div>
	</div>
</body>
</html>`
