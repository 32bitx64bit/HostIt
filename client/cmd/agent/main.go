package main

import (
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"io"
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

// ShutdownTimeout is the maximum time to wait for graceful shutdown.
// Can be overridden via the HOSTIT_SHUTDOWN_TIMEOUT environment variable.
var shutdownTimeout = 5 * time.Second

func init() {
	if v := os.Getenv("HOSTIT_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			shutdownTimeout = d
		}
	}
}

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

	// Log configuration status
	if loaded {
		log.Printf("Loaded configuration from: %s", configPath)
	} else {
		log.Printf("No configuration file found at: %s (will create on save)", configPath)
	}

	// First-run convenience: if no config file exists, default to localhost.
	if !loaded && strings.TrimSpace(cfg.Server) == "" {
		cfg.Server = "127.0.0.1"
		log.Printf("First run: using default server: %s", cfg.Server)
	}

	// Override with command-line arguments
	if strings.TrimSpace(token) != "" {
		cfg.Token = token
		log.Printf("Using token from command-line argument")
	}
	if strings.TrimSpace(serverHost) != "" {
		cfg.Server = serverHost
		log.Printf("Using server from command-line argument: %s", serverHost)
	}

	// Validate configuration
	if strings.TrimSpace(cfg.Server) == "" {
		if webAddr == "" {
			log.Fatalf("ERROR: agent server is required (set -server or agent.json Server)")
		}
		autostart = false
		log.Printf("WARNING: agent server not configured; web UI is available to configure it")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		if webAddr == "" {
			log.Fatalf("ERROR: agent token is required (set -token or agent.json Token)")
		}
		autostart = false
		log.Printf("WARNING: agent token not configured; web UI is available to configure it")
	}

	ctrl := newAgentController(ctx, cfg)
	if autostart {
		log.Printf("=== Auto-starting agent ===")
		log.Printf("Server: %s", cfg.Server)
		log.Printf("Control address: %s", cfg.ControlAddr())
		log.Printf("Data address: %s", cfg.DataAddr())
		log.Printf("TLS enabled: %v", !cfg.DisableTLS)
		ctrl.Start()
	} else {
		log.Printf("=== Agent not auto-started ===")
		log.Printf("Reason: server or token not configured")
		if webAddr != "" {
			log.Printf("Configure via web UI at: http://%s", webAddr)
		}
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
		case <-time.After(shutdownTimeout):
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
		log.Printf("=== Update complete, restarting agent ===")
		ctrl.Stop()
		bin := upd.BuiltBinaryPath()
		if _, err := os.Stat(bin); err != nil {
			log.Printf("ERROR: Built binary not found: %s", bin)
			return err
		}
		log.Printf("Built binary: %s", bin)

		// If we're running under systemd, restart the service (or exit and let systemd restart).
		if runningUnderSystemd() {
			log.Printf("Running under systemd - restarting service")
			if systemctlAvailable() {
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "systemctl", "restart", "--no-block", "hostit-agent.service")
				out, err := cmd.CombinedOutput()
				if err == nil {
					log.Printf("Systemd restart command sent successfully")
					return nil
				}
				log.Printf("Systemctl restart failed: %v, output: %s", err, string(out))
			}
			log.Printf("Sending SIGTERM to let systemd restart")
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			return nil
		}

		log.Printf("Not running under systemd - executing binary replacement")
		log.Printf("Agent will auto-reconnect using configuration from: %s", configPath)
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
			"running":    running,
			"connected":  connected,
			"lastErr":    lastErr,
			"server":     cfg.Server,
			"tokenSet":   strings.TrimSpace(cfg.Token) != "",
			"configPath": configPath,
			"nowUnix":    time.Now().Unix(),
			"routes":     outRoutes,
			"routeCount": len(outRoutes),
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
	mux.HandleFunc("/api/update/apply-local", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
		if err := r.ParseMultipartForm(512 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		componentZipPath, hasComponent, err := writeUploadedZipTemp(r, "componentZip", "hostit-client-component-*.zip")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !hasComponent {
			http.Error(w, "component zip is required", http.StatusBadRequest)
			return
		}
		defer os.Remove(componentZipPath)

		sharedZipPath, hasShared, err := writeUploadedZipTemp(r, "sharedZip", "hostit-client-shared-*.zip")
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
		ctx2, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
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

const agentHomeHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Agent</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--orange:#d29922;--orangeDim:rgba(210,153,34,.12);--orangeBorder:rgba(210,153,34,.4);--purple:#a371f7;--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);--orangeDim:rgba(210,153,34,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.statusGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px}
		.sCard{padding:12px;border-radius:var(--radiusLg);border:1px solid var(--border);background:var(--surface);text-align:center}
		.sCard .label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted);margin-bottom:4px}
		.sCard .val{font-size:15px;font-weight:600}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.pill.warn{color:var(--orange);border-color:var(--orangeBorder);background:var(--orangeDim)}.pill.warn::before{background:var(--orange)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
		.secHead{margin:20px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		label{font-size:12px;font-weight:600;display:block;margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.help{font-size:11px;color:var(--textMuted);margin:0 0 6px;line-height:1.4}
		input[type="text"],input:not([type]){width:100%;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:14px;transition:border-color .15s}
		input:focus{outline:none;border-color:var(--accent)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.btn.sm{font-size:12px;padding:5px 10px}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.muted{color:var(--textMuted)}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		.errBox{font-size:12px;padding:8px 10px;margin-top:8px;border-radius:8px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red);word-break:break-all}
		.routeRow{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}
		.routeRow:last-child{border-bottom:none}
		.routeRow .rName{font-weight:600;min-width:80px}
		.routeRow .rProto{font-size:11px;padding:2px 6px;border-radius:4px;text-transform:uppercase;font-weight:500}
		.routeRow .rProto.tcp{background:var(--accentDim);color:var(--accent)}
		.routeRow .rProto.udp{background:rgba(163,113,247,.14);color:var(--purple)}
		.routeRow .rAddrs{font-size:12px;color:var(--textMuted)}
		.updatePopup{position:fixed;right:16px;bottom:16px;max-width:460px;width:calc(100% - 32px);z-index:1000;display:none;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
		.updatePopup pre{font-family:var(--mono);font-size:11px;white-space:pre-wrap;margin:8px 0 0;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);max-height:180px;overflow:auto}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Connects to your tunnel server and forwards traffic locally</div>
			</div>
			<div class="nav">
				<a class="active" href="/">Home</a>
				<a href="/controls">Controls</a>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<div class="statusGrid">
			<div class="sCard">
				<div class="label">Service</div>
				<div class="val"><span id="svcPill" class="pill {{if .Running}}ok{{else}}bad{{end}}">{{if .Running}}Running{{else}}Stopped{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Connection</div>
				<div class="val"><span id="ctlPill" class="pill {{if .Connected}}ok{{else}}bad{{end}}">{{if .Connected}}Connected{{else}}Disconnected{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Token</div>
				<div class="val"><span id="tokenPill" class="pill {{if .HasToken}}ok{{else}}bad{{end}}">{{if .HasToken}}Set{{else}}Missing{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Server</div>
				<div class="val" style="font-size:12px"><code id="serverVal">{{.Cfg.Server}}</code></div>
			</div>
		</div>

		<div class="flex" style="margin-bottom:16px">
			<button class="btn sm primary" id="btnStart">Start</button>
			<button class="btn sm warn" id="btnStop">Stop</button>
			<button class="btn sm" id="btnRestart">Restart</button>
			<span class="muted" style="font-size:11px" id="liveText">Updating…</span>
		</div>
		<div id="errRow" style="display:none" class="errBox"><b>Last error:</b> <span id="errText"></span></div>

		<div class="secHead"><h2>Connection</h2></div>
		<form method="post" action="/save" class="card">
			<div class="grid2">
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
			<div style="margin-top:10px" class="muted" style="font-size:12px">Routes come from the server. The agent forwards to <code>127.0.0.1:&lt;publicPort&gt;</code>.</div>
			<div class="flex" style="margin-top:12px">
				<button type="submit" class="btn primary">Save &amp; restart</button>
			</div>
		</form>

		<div class="secHead"><h2>Routes</h2></div>
		<div class="card">
			<div id="routesEmpty" class="muted" {{if .Connected}}style="display:none"{{end}}>Routes appear after the agent connects to the server.</div>
			<div id="routesList">
				{{range .RoutesView}}
				<div class="routeRow">
					<span class="rName">{{.Name}}</span>
					<span class="rProto {{.Proto}}">{{.Proto}}</span>
					<span class="rAddrs"><code>{{.PublicAddr}}</code> &rarr; <code>{{.LocalTarget}}</code></span>
				</div>
				{{end}}
			</div>
		</div>
	</div>

	<div id="updatePopup" class="updatePopup">
		<div style="margin-bottom:8px"><b>Update available</b> <span class="muted" id="updVer">—</span></div>
		<div class="muted" style="font-size:12px;margin-bottom:8px" id="updInfo">Current: <code>{{.Version}}</code></div>
		<div class="flex">
			<button type="button" class="btn sm" id="updRemind">Later</button>
			<button type="button" class="btn sm" id="updSkip">Skip</button>
			<button type="button" class="btn sm primary" id="updApply">Update</button>
		</div>
		<pre id="updSteps" style="display:none"></pre>
		<pre id="updLog" style="display:none"></pre>
	</div>

	<script>
	(function(){
		var updPopup=document.getElementById('updatePopup');
		var updVer=document.getElementById('updVer');
		var updInfo=document.getElementById('updInfo');
		var updSteps=document.getElementById('updSteps');
		var updLog=document.getElementById('updLog');
		function sleep(ms){return new Promise(function(r){setTimeout(r,ms)});}
		async function postU(p){try{await fetch(p,{method:'POST'});}catch(_){}}
		async function fetchUpd(){try{var r=await fetch('/api/update/status',{cache:'no-store'});if(!r.ok)return null;return await r.json();}catch(e){return null;}}
		function setVis(v){if(updPopup)updPopup.style.display=v?'':'none';}
		function renderSteps(st){
			if(!updSteps)return;
			var running=!!(st&&st.job&&st.job.state==='running');
			var log=(st&&st.job&&st.job.log)?String(st.job.log):'';
			if(!running){updSteps.style.display='none';return;}
			var has=function(re){try{return re.test(log);}catch(e){return false;}};
			var s1=has(/Downloading:/)&&has(/Downloaded\s+\d+\s+bytes/);
			var s2=has(/Extracted source:/)&&has(/Applying into:/);
			var s3=has(/Running build\.sh/);
			var s4=has(/Build succeeded/)||has(/Build failed/);
			var s5=!!(st&&st.job&&st.job.restarting);
			var fmt=function(d,l){return(d?'[x] ':'[ ] ')+l;};
			updSteps.textContent=[fmt(s1,'Download'),fmt(s2,'Apply files'),fmt(s3,'Build'),fmt(s4,'Build finished'),fmt(s5,'Restart')].join('\n');
			updSteps.style.display='';
		}
		function renderUpd(st){
			if(!st)return;
			var show=!!st.showPopup||(st.job&&st.job.state&&st.job.state!=='idle');
			setVis(show);if(!show)return;
			if(updVer)updVer.textContent=st.availableVersion?('v'+st.availableVersion):'';
			if(updInfo){
				var s='Current: {{.Version}}';
				if(st.job&&st.job.state==='running')s='Updating…';
				if(st.job&&st.job.state==='success')s='Done. Restarting…';
				if(st.job&&st.job.state==='failed')s='Update failed.';
				updInfo.textContent=s;
			}
			renderSteps(st);
			if(updLog){
				var l=(st.job&&st.job.log)?String(st.job.log):'';
				if(st.job&&(st.job.state==='failed'||st.job.state==='success'||st.job.state==='running')){updLog.style.display='';updLog.textContent=l||'(no log)';}
				else{updLog.style.display='none';}
			}
			var busy=st.job&&st.job.state==='running';
			var a=document.getElementById('updApply');if(a)a.disabled=busy;
		}
		async function pollDone(){
			for(;;){var st=await fetchUpd();if(st){renderUpd(st);if(st.job&&st.job.state&&st.job.state!=='running')break;}await sleep(500);}
			for(var i=0;i<90;i++){var s=await fetchUpd();if(s){location.replace('/?r='+Date.now());return;}await sleep(1000);}
		}
		document.getElementById('updRemind').onclick=async function(){await postU('/api/update/remind');setVis(false);};
		document.getElementById('updSkip').onclick=async function(){await postU('/api/update/skip');setVis(false);};
		document.getElementById('updApply').onclick=async function(){await postU('/api/update/apply');pollDone();};
		fetchUpd().then(renderUpd);
		setInterval(function(){fetchUpd().then(renderUpd);},30000);

		function setPill(el,ok,t){if(!el)return;el.classList.remove('ok','bad');el.classList.add(ok?'ok':'bad');el.textContent=t;}
		function esc(s){return s==null?'':String(s);}
		var svcPill=document.getElementById('svcPill');
		var ctlPill=document.getElementById('ctlPill');
		var tokenPill=document.getElementById('tokenPill');
		var serverVal=document.getElementById('serverVal');
		var liveText=document.getElementById('liveText');
		var errRow=document.getElementById('errRow');
		var errText=document.getElementById('errText');
		var routesEmpty=document.getElementById('routesEmpty');
		var routesList=document.getElementById('routesList');

		async function post(p){try{await fetch(p,{method:'POST'});}catch(_){}await pollOnce();}
		document.getElementById('btnStart').onclick=function(){post('/start');};
		document.getElementById('btnStop').onclick=function(){post('/stop');};
		document.getElementById('btnRestart').onclick=function(){post('/restart');};

		function renderRoutes(routes){
			if(!routesList)return;
			routesList.innerHTML='';
			if(!routes||!routes.length){if(routesEmpty)routesEmpty.style.display='';return;}
			if(routesEmpty)routesEmpty.style.display='none';
			for(var i=0;i<routes.length;i++){
				var rt=routes[i]||{};
				var row=document.createElement('div');row.className='routeRow';
				var nm=document.createElement('span');nm.className='rName';nm.textContent=esc(rt.name);row.appendChild(nm);
				var pr=document.createElement('span');pr.className='rProto '+(esc(rt.proto).toLowerCase());pr.textContent=esc(rt.proto);row.appendChild(pr);
				var ad=document.createElement('span');ad.className='rAddrs';
				var c1=document.createElement('code');c1.textContent=esc(rt.publicAddr);ad.appendChild(c1);
				ad.appendChild(document.createTextNode(' \u2192 '));
				var c2=document.createElement('code');c2.textContent=esc(rt.localTarget);ad.appendChild(c2);
				row.appendChild(ad);
				routesList.appendChild(row);
			}
		}

		async function pollOnce(){
			try{
				var res=await fetch('/api/status',{cache:'no-store'});
				if(!res.ok)throw new Error('http '+res.status);
				var j=await res.json();
				setPill(svcPill,!!j.running,j.running?'Running':'Stopped');
				setPill(ctlPill,!!j.connected,j.connected?'Connected':'Disconnected');
				setPill(tokenPill,!!j.tokenSet,j.tokenSet?'Set':'Missing');
				if(serverVal)serverVal.textContent=esc(j.server);
				if(errRow&&errText){if(j.lastErr){errRow.style.display='';errText.textContent=esc(j.lastErr);}else{errRow.style.display='none';}}
				renderRoutes(j.routes);
				if(liveText)liveText.textContent='Updated '+new Date().toLocaleTimeString();
			}catch(e){if(liveText)liveText.textContent='Offline';}
		}
		pollOnce();setInterval(pollOnce,2000);
	})();
	</script>
</body>
</html>`

const agentControlsHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<title>Tunnel Agent — Controls</title>
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
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
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
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		pre{font-family:var(--mono);font-size:11px;white-space:pre-wrap;margin:8px 0 0;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);max-height:200px;overflow:auto}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Agent Controls</div>
			</div>
			<div class="nav">
				<a href="/">Home</a>
				<a class="active" href="/controls">Controls</a>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<div class="grid2">
			<div>
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
						<div class="muted" style="font-size:11px;margin-top:4px">Left: client.zip (required), right: shared.zip (optional).</div>
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
					<div class="row"><b>Service:</b> <code>hostit-agent.service</code></div>
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
	function setUpd(st){
		if(!st)return;
		document.getElementById('availableVersion').textContent=st.availableVersion||'—';
		document.getElementById('applyBtn').disabled=!st.updateAvailable;
		document.getElementById('updateState').textContent=st.updateAvailable?'Update available':'Up to date';
		var log=document.getElementById('updateLog');
		if(st.job&&st.job.log){log.style.display='block';log.textContent=st.job.log;}else{log.style.display='none';}
	}
	async function refreshUpd(){var r=await fetch('/api/update/status',{cache:'no-store'});if(r.ok)setUpd(await r.json());}
	async function checkNow(){
		document.getElementById('updateState').textContent='Checking…';
		var r=await fetch('/api/update/check-now',{method:'POST'});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){}return;}
		setUpd(await r.json());
	}
	async function applyUpd(){
		document.getElementById('updateState').textContent='Starting…';
		await fetch('/api/update/apply',{method:'POST'});
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	async function applyLocalUpd(){
		var comp=document.getElementById('localComponentZip');
		var shared=document.getElementById('localSharedZip');
		if(!comp||!comp.files||!comp.files.length){document.getElementById('updateState').textContent='Pick client.zip first';return;}
		var fd=new FormData();
		fd.append('componentZip', comp.files[0]);
		if(shared&&shared.files&&shared.files.length){fd.append('sharedZip', shared.files[0]);}
		document.getElementById('updateState').textContent='Uploading…';
		var r=await fetch('/api/update/apply-local',{method:'POST',body:fd});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){document.getElementById('updateState').textContent='Failed';}return;}
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	function setSys(st){
		if(!st)return;
		document.getElementById('systemdState').textContent=st.available?(st.active||'unknown'):'unavailable';
		document.getElementById('systemdMsg').textContent=st.error||'—';
	}
	async function refreshSys(){var r=await fetch('/api/systemd/status',{cache:'no-store'});if(r.ok)setSys(await r.json());}
	async function sysAction(p,t){
		document.getElementById('systemdMsg').textContent=t;
		var r=await fetch(p,{method:'POST'});
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
		await fetch('/api/process/restart',{method:'POST'});
		setTimeout(function(){location.reload();},1000);
	};
	document.getElementById('procExit').onclick=async function(){
		await fetch('/api/process/exit',{method:'POST'});
		setTimeout(function(){location.reload();},1000);
	};
	refreshUpd();refreshSys();
	</script>
</body>
</html>`
