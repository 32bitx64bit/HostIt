package main

import (
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"hostit/client/internal/agent"
	"hostit/client/internal/configio"
	"hostit/shared/updater"
	"hostit/shared/version"
)

func main() {
	var serverHost string
	var token string
	var webAddr string
	var configPath string
	var autostart bool

	flag.StringVar(&serverHost, "server", "", "tunnel server host/IP (optionally include control port, e.g. host:7000)")
	flag.StringVar(&token, "token", "", "shared token (required)")
	flag.StringVar(&webAddr, "web", "127.0.0.1:7003", "agent web dashboard listen address (empty to disable)")
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
				display = "0.0.0.0" + display
				log.Printf("WARNING: agent web UI is unauthenticated; binding to all interfaces")
			} else if h, _, err := net.SplitHostPort(display); err == nil {
				h = strings.TrimSpace(h)
				if h == "" || h == "0.0.0.0" || h == "::" {
					log.Printf("WARNING: agent web UI is unauthenticated; binding to all interfaces")
				}
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
	tplControls := template.Must(template.New("controls").Parse(agentControlsHTML))

	absCfg := configPath
	if p, err := filepath.Abs(configPath); err == nil {
		absCfg = p
	}
	updStatePath := filepath.Join(filepath.Dir(absCfg), "update_state_client.json")
	moduleDir := detectModuleDir(absCfg)
	upd := updater.NewManager("32bitx64bit/HostIt", updater.ComponentClient, "client.zip", moduleDir, updStatePath)
	upd.PreservePaths = []string{absCfg}
	upd.Restart = func() error {
		ctrl.Stop()
		bin := upd.BuiltBinaryPath()
		if _, err := os.Stat(bin); err != nil {
			return err
		}
		// If we're running under systemd, restart the service (or exit and let systemd restart).
		if runningUnderSystemd() {
			if systemctlAvailable() {
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "systemctl", "restart", "--no-block", "hostit-agent.service")
				out, err := cmd.CombinedOutput()
				if err == nil {
					return nil
				}
				_ = out
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			return nil
		}
		return updater.ExecReplace(bin, os.Args[1:])
	}
	upd.Start(ctx)

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

	// Live status API
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		type routeView struct {
			Name        string `json:"name"`
			Proto       string `json:"proto"`
			PublicAddr  string `json:"publicAddr"`
			LocalTarget string `json:"localTarget"`
		}
		outRoutes := make([]routeView, 0, len(routes))
		for _, rt := range routes {
			outRoutes = append(outRoutes, routeView{Name: rt.Name, Proto: rt.Proto, PublicAddr: rt.PublicAddr, LocalTarget: localTargetFromPublicAddr(rt.PublicAddr)})
		}
		resp := map[string]any{
			"running":     running,
			"connected":   connected,
			"lastErr":     lastErr,
			"server":      cfg.Server,
			"tokenSet":    strings.TrimSpace(cfg.Token) != "",
			"configPath":  configPath,
			"nowUnix":     time.Now().Unix(),
			"routes":      outRoutes,
			"routeCount":  len(outRoutes),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Update APIs
	mux.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		upd.CheckIfDue(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(upd.Status())
	})
	mux.HandleFunc("/api/update/check-now", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = upd.CheckNow(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(upd.Status())
	})

	// systemd controls (best-effort; typically works when agent runs as a service).
	mux.HandleFunc("/api/systemd/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st := systemdStatus(r.Context(), "hostit-agent.service")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("/api/systemd/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := systemdAction(r.Context(), "restart", "hostit-agent.service"); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/systemd/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := systemdAction(r.Context(), "stop", "hostit-agent.service"); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Process control: exits the whole agent process.
	mux.HandleFunc("/api/process/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	})
	mux.HandleFunc("/api/process/exit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	})
	mux.HandleFunc("/api/update/remind", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = upd.RemindLater(24 * time.Hour)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/update/skip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = upd.SkipAvailableVersion()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/update/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	})

	// Service controls
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctrl.Start()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctrl.Stop()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctrl.Stop()
		ctrl.Start()
		w.WriteHeader(http.StatusNoContent)
	})

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
			"Version":    version.Current,
			"Msg":        getMsg(),
			"RoutesView": makeRouteViews(routes),
		}
		_ = tplHome.Execute(w, data)
	})

	// Controls page
	mux.HandleFunc("/controls", func(w http.ResponseWriter, r *http.Request) {
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
			"Version":    version.Current,
			"Msg":        getMsg(),
			"RoutesView": makeRouteViews(routes),
		}
		_ = tplControls.Execute(w, data)
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

	// Agent also supports explicit start/stop/restart via /start,/stop,/restart.

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

func detectModuleDir(configPath string) string {
	if wd, err := os.Getwd(); err == nil && wd != "" {
		if fileExists(filepath.Join(wd, "build.sh")) {
			return wd
		}
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		if filepath.Base(exeDir) == "bin" {
			parent := filepath.Dir(exeDir)
			if fileExists(filepath.Join(parent, "build.sh")) {
				return parent
			}
		}
	}
	if strings.TrimSpace(configPath) != "" {
		return filepath.Dir(configPath)
	}
	return "."
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
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
		button.warn { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .10); }
		.pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); background: rgba(127,127,127,.10); font-size: 12px; }
		.ok { border-color: rgba(46, 160, 67, .55); background: rgba(46, 160, 67, .18); }
		.bad { border-color: rgba(248, 81, 73, .55); background: rgba(248, 81, 73, .16); }
		code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }
		.flash { margin: 10px 0 0; }
		.row { margin-bottom: 10px; }
		.small { font-size: 12px; opacity: .85; }
		.nav { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
		.nav a { text-decoration:none; padding: 6px 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); }
		.nav a.active { border-color: rgba(46, 125, 255, .55); background: rgba(46, 125, 255, .18); }
		.updatePopup { position: fixed; right: 16px; bottom: 16px; max-width: 520px; width: calc(100% - 32px); z-index: 1000; display:none; }
		.updatePopup pre { white-space: pre-wrap; margin: 10px 0 0; padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); background: rgba(127,127,127,.06); max-height: 220px; overflow:auto; }
		.procPopup { position: fixed; right: 16px; bottom: 162px; max-width: 360px; width: calc(100% - 32px); z-index: 1000; }
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
				<div class="nav" style="margin-bottom:10px">
					<a class="active" href="/">Home</a>
					<a href="/controls">Controls</a>
				</div>
				<div class="row"><b>Service:</b>
					<span id="svcPill" class="pill {{if .Running}}ok{{else}}bad{{end}}">{{if .Running}}Running{{else}}Stopped{{end}}</span>
				</div>
				<div class="row"><b>Control:</b>
					<span id="ctlPill" class="pill {{if .Connected}}ok{{else}}bad{{end}}">{{if .Connected}}Connected{{else}}Disconnected{{end}}</span>
				</div>
				<div class="row"><b>Server:</b> <code id="serverVal">{{.Cfg.Server}}</code></div>
				<div class="row"><b>Token:</b> <span id="tokenPill" class="pill {{if .HasToken}}ok{{else}}bad{{end}}">{{if .HasToken}}Set{{else}}Missing{{end}}</span></div>
				<div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
				<div class="btns">
					<button id="btnStart" type="button" class="primary">Start</button>
					<button id="btnStop" type="button" class="warn">Stop</button>
					<button id="btnRestart" type="button">Restart</button>
				</div>
				<div class="row small"><b>Live:</b> <span id="liveText">Updating…</span></div>
				<div class="row" id="errRow" style="display:none"><b>Last error:</b> <span class="muted" id="errText"></span></div>
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
			<div id="routesEmpty" class="muted" {{if .Connected}}style="display:none"{{end}}>Routes appear after the agent connects to the server.</div>
			<div id="routesList">
				{{range .RoutesView}}
					<div class="row"><b>{{.Name}}</b> <span class="muted">({{.Proto}})</span> public: <code>{{.PublicAddr}}</code> local: <code>{{.LocalTarget}}</code></div>
				{{end}}
			</div>
		</div>
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
	<div id="procPopup" class="card procPopup">
		<div class="row"><b>Process</b> <span class="muted">(agent)</span></div>
		<div class="btns" style="margin-top:0">
			<button type="button" id="procRestart">Restart</button>
			<button type="button" id="procExit">Exit</button>
		</div>
		<div class="muted" style="margin-top:8px">If running under systemd, it will restart automatically.</div>
	</div>
	<script>
		(function(){
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
			async function postUpdate(path){
				try { await fetch(path, {method:'POST'}); } catch (_) {}
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
				if(!st) return;
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
						if(st.job && st.job.state && st.job.state !== 'running') break;
					}
					await sleep(500);
				}
				for (var i=0;i<90;i++){
					var st2 = await fetchUpdateStatus();
					if(st2){ location.replace(location.pathname + '?r=' + Date.now()); return; }
					await sleep(1000);
				}
			}

			if (updRemind) updRemind.addEventListener('click', async function(){
				await postUpdate('/api/update/remind');
				setPopupVisible(false);
			});
			if (updSkip) updSkip.addEventListener('click', async function(){
				await postUpdate('/api/update/skip');
				setPopupVisible(false);
			});
			if (updApply) updApply.addEventListener('click', async function(){
				await postUpdate('/api/update/apply');
				pollUpdateUntilDone();
			});

			fetchUpdateStatus().then(renderUpdate);
			setInterval(function(){ fetchUpdateStatus().then(renderUpdate); }, 30000);

			function setPill(el, ok, text){
				if(!el) return;
				el.classList.remove('ok');
				el.classList.remove('bad');
				el.classList.add(ok ? 'ok' : 'bad');
				el.textContent = text;
			}
			function escapeText(s){
				return (s == null) ? '' : String(s);
			}
			var svcPill = document.getElementById('svcPill');
			var ctlPill = document.getElementById('ctlPill');
			var tokenPill = document.getElementById('tokenPill');
			var serverVal = document.getElementById('serverVal');
			var liveText = document.getElementById('liveText');
			var errRow = document.getElementById('errRow');
			var errText = document.getElementById('errText');
			var routesEmpty = document.getElementById('routesEmpty');
			var routesList = document.getElementById('routesList');
			var btnStart = document.getElementById('btnStart');
			var btnStop = document.getElementById('btnStop');
			var btnRestart = document.getElementById('btnRestart');

			async function post(path){
				try {
					await fetch(path, {method:'POST'});
				} catch (_) {}
				await pollOnce();
			}
			if (procRestart) procRestart.addEventListener('click', async function(){
				await post('/api/process/restart');
				setTimeout(function(){ location.replace(location.pathname + '?r=' + Date.now()); }, 1000);
			});
			if (procExit) procExit.addEventListener('click', async function(){
				await post('/api/process/exit');
				setTimeout(function(){ location.replace(location.pathname + '?r=' + Date.now()); }, 1000);
			});

			if (btnStart) btnStart.addEventListener('click', function(){ post('/start'); });
			if (btnStop) btnStop.addEventListener('click', function(){ post('/stop'); });
			if (btnRestart) btnRestart.addEventListener('click', function(){ post('/restart'); });

			function renderRoutes(routes){
				if(!routesList) return;
				routesList.innerHTML = '';
				if(!routes || !routes.length){
					if (routesEmpty) routesEmpty.style.display = '';
					return;
				}
				if (routesEmpty) routesEmpty.style.display = 'none';
				for (var i=0;i<routes.length;i++){
					var rt = routes[i] || {};
					var row = document.createElement('div');
					row.className = 'row';
					var b = document.createElement('b');
					b.textContent = escapeText(rt.name);
					row.appendChild(b);
					var sp = document.createElement('span');
					sp.className = 'muted';
					sp.textContent = ' (' + escapeText(rt.proto) + ') ';
					row.appendChild(document.createTextNode(' '));
					row.appendChild(sp);
					row.appendChild(document.createTextNode(' public: '));
					var c1 = document.createElement('code');
					c1.textContent = escapeText(rt.publicAddr);
					row.appendChild(c1);
					row.appendChild(document.createTextNode(' local: '));
					var c2 = document.createElement('code');
					c2.textContent = escapeText(rt.localTarget);
					row.appendChild(c2);
					routesList.appendChild(row);
				}
			}

			async function pollOnce(){
				try {
					var res = await fetch('/api/status', {cache:'no-store'});
					if(!res.ok) throw new Error('http ' + res.status);
					var j = await res.json();
					setPill(svcPill, !!j.running, j.running ? 'Running' : 'Stopped');
					setPill(ctlPill, !!j.connected, j.connected ? 'Connected' : 'Disconnected');
					setPill(tokenPill, !!j.tokenSet, j.tokenSet ? 'Set' : 'Missing');
					if(serverVal) serverVal.textContent = escapeText(j.server);
					if(errRow && errText){
						if(j.lastErr){
							errRow.style.display = '';
							errText.textContent = escapeText(j.lastErr);
						} else {
							errRow.style.display = 'none';
							errText.textContent = '';
						}
					}
					renderRoutes(j.routes);
					if(liveText) liveText.textContent = 'Last update: ' + new Date().toLocaleTimeString();
				} catch (e) {
					if(liveText) liveText.textContent = 'Offline (' + (e && e.message ? e.message : 'error') + ')';
				}
			}

			pollOnce();
			setInterval(pollOnce, 2000);
		})();
	</script>
</body>
</html>`

const agentControlsHTML = `<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Agent - Controls</title>
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
				<h1>Tunnel Agent</h1>
				<div class="muted">Controls</div>
			</div>
			<div class="card">
				<div class="nav">
					<a href="/">Home</a>
					<a class="active" href="/controls">Controls</a>
				</div>
				<div class="row"><b>Service:</b>
					<span class="pill {{if .Running}}ok{{else}}bad{{end}}">{{if .Running}}Running{{else}}Stopped{{end}}</span>
				</div>
				<div class="row"><b>Control:</b>
					<span class="pill {{if .Connected}}ok{{else}}bad{{end}}">{{if .Connected}}Connected{{else}}Disconnected{{end}}</span>
				</div>
				<div class="row"><b>Server:</b> <code>{{.Cfg.Server}}</code></div>
				<div class="row"><b>Config:</b> <code>{{.ConfigPath}}</code></div>
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
			<div class="row"><b>Service:</b> <code>hostit-agent.service</code></div>
			<div class="row"><b>State:</b> <code id="systemdState">—</code></div>
			<div class="btns">
				<button id="svcRestartBtn" type="button">Restart service</button>
				<button id="svcStopBtn" type="button">Stop service</button>
			</div>
			<div class="row"><span class="muted" id="systemdMsg">—</span></div>
		</div>
	</div>

	<script>
		function setUpdateStatus(st) {
			if (!st) return;
			var avail = document.getElementById('availableVersion');
			var btn = document.getElementById('applyBtn');
			var state = document.getElementById('updateState');
			var log = document.getElementById('updateLog');
			avail.textContent = st.availableVersion || '—';
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
			var r = await fetch('/api/update/status', { method: 'GET', cache: 'no-store' });
			if (!r.ok) return;
			setUpdateStatus(await r.json());
		}

		async function checkNow() {
			document.getElementById('updateState').textContent = 'Checking…';
			var r = await fetch('/api/update/check-now', { method: 'POST' });
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
			var r = await fetch('/api/update/apply', { method: 'POST' });
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
			var r = await fetch('/api/systemd/status', { method: 'GET', cache: 'no-store' });
			if (!r.ok) return;
			setSystemdStatus(await r.json());
		}

		async function systemdAction(path, progressText) {
			document.getElementById('systemdMsg').textContent = progressText;
			var r = await fetch(path, { method: 'POST' });
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
