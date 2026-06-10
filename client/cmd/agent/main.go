package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hostit/client/internal/agent"
	"hostit/client/internal/agentlog"
	"hostit/client/internal/mail"
	"hostit/shared/apitypes"
	"hostit/shared/configio"
	"hostit/shared/emailcfg"
	"hostit/shared/logging"
	"hostit/shared/protocol"
)

var shutdownTimeout = 5 * time.Second
var startTime = time.Now()

const (
	defaultWebAddr          = "127.0.0.1:7003"
	defaultServerHost       = "127.0.0.1"
	agentSystemdServiceName = "hostit-agent.service"
	agentSystemdUnitPath    = "/etc/systemd/system/hostit-agent.service"
	agentSystemdEnvPath     = "/etc/hostit/agent.env"
)

type ctxKey string

func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func isLocalhost(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func requireLocalHost(next http.Handler, bindAddr string) http.Handler {
	host, port, _ := net.SplitHostPort(bindAddr)
	allowed := map[string]bool{
		"127.0.0.1:" + port: true,
		"localhost:" + port:  true,
		"[::1]:" + port:      true,
		"127.0.0.1":          true,
		"localhost":          true,
		"[::1]":              true,
	}
	host = strings.TrimSpace(host)
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		allowed[strings.ToLower(host+":"+port)] = true
		allowed[strings.ToLower(host)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireLocalAddr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !isLocalhost(r.RemoteAddr) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func init() {
	if v := os.Getenv("HOSTIT_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			shutdownTimeout = d
		}
	}
}

func main() {
	agentlog.Init()
	log.SetOutput(io.MultiWriter(os.Stderr, agentlog.NewUILogWriter("stdio", agentlog.UILogs)))

	var serverHost string
	var token string
	var webAddr string
	var configPath string
	var autostart bool
	var shutdownTimeoutFlag time.Duration

	flag.StringVar(&serverHost, "server", "", "tunnel server host/IP (optionally include control port, e.g. host:7000)")
	flag.StringVar(&token, "token", "", "shared token (required)")
	flag.StringVar(&webAddr, "web", defaultWebAddr, "agent web dashboard listen address (empty to disable)")
	flag.StringVar(&configPath, "config", "agent.json", "path to agent config JSON")
	flag.BoolVar(&autostart, "autostart", true, "start agent automatically")
	flag.DurationVar(&shutdownTimeoutFlag, "shutdown-timeout", 0, "graceful shutdown timeout (e.g. 10s, 1m)")
	flag.Parse()

	if shutdownTimeoutFlag > 0 {
		shutdownTimeout = shutdownTimeoutFlag
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := agent.Config{}
	loaded, _ := configio.Load(configPath, &cfg)

	if loaded {
		agentlog.Log.Infof(logging.CatSystem, "Loaded configuration from: %s", configPath)
	} else {
		agentlog.Log.Infof(logging.CatSystem, "No configuration file found at: %s (will create on save)", configPath)
	}

	if !loaded && strings.TrimSpace(cfg.Server) == "" {
		cfg.Server = "127.0.0.1"
		agentlog.Log.Infof(logging.CatSystem, "First run: using default server: %s", cfg.Server)
	}

	if strings.TrimSpace(token) != "" {
		cfg.Token = token
		agentlog.Log.Infof(logging.CatSystem, "Using token from command-line argument")
	}
	if strings.TrimSpace(serverHost) != "" {
		cfg.Server = serverHost
		agentlog.Log.Infof(logging.CatSystem, "Using server from command-line argument: %s", serverHost)
	}

	if strings.TrimSpace(cfg.Server) == "" {
		if webAddr == "" {
			agentlog.Log.Fatal(logging.CatSystem, "ERROR: agent server is required (set -server or agent.json Server)")
		}
		autostart = false
		agentlog.Log.Infof(logging.CatSystem, "WARNING: agent server not configured; web UI is available to configure it")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		if webAddr == "" {
			agentlog.Log.Fatal(logging.CatSystem, "ERROR: agent token is required (set -token or agent.json Token)")
		}
		autostart = false
		agentlog.Log.Infof(logging.CatSystem, "WARNING: agent token not configured; web UI is available to configure it")
	}

	ctrl := newAgentController(ctx, cfg)
	absCfg := configPath
	if p, err := filepath.Abs(configPath); err == nil {
		absCfg = p
	}
	appsConfigPath := filepath.Join(filepath.Dir(absCfg), "apps.json")
	appsCfg := apitypes.AppsConfig{}
	if loaded, _ := configio.Load(appsConfigPath, &appsCfg); loaded && len(appsCfg.Apps) > 0 {
		agentlog.Log.Infof(logging.CatSystem, "Loaded %d app configs from %s", len(appsCfg.Apps), appsConfigPath)
	}
	ctrl.appsCfg = appsCfg
	ctrl.appsPath = appsConfigPath
	mailSvc, err := mail.NewService(filepath.Join(filepath.Dir(absCfg), "mail"))
	if err != nil {
		agentlog.Log.Infof(logging.CatSystem, "mail service init failed: %v", err)
	} else {
		if err := mailSvc.Start(ctx); err != nil {
			agentlog.Log.Infof(logging.CatSystem, "mail service start failed: %v", err)
		}
		mailSvc.SetOutboundDialer(func(callCtx context.Context, remoteAddr string) (net.Conn, error) {
			cfg, _, connected, _, _ := ctrl.Get()
			if !connected {
				return nil, fmt.Errorf("agent is not connected to the server")
			}
			return agent.DialMailOutboundTCP(callCtx, cfg, remoteAddr)
		})
		defer mailSvc.Close()
		ctrl.onEmailConfig = func(cfg emailcfg.Config) {
			if err := mailSvc.ApplyConfig(cfg); err != nil {
				agentlog.Log.Infof(logging.CatSystem, "mail config apply failed: %v", err)
			}
		}
		ctrl.onEmailProbe = func(callCtx context.Context, req protocol.EmailProbeRequest) (protocol.EmailProbeResult, error) {
			return mailSvc.RunProbe(callCtx, req)
		}
	}
	ctrl.onTLSPinDiscovered = func(pin string) {
		cfg, _, _, _, _ := ctrl.Get()
		cfg.TLSPinSHA256 = pin
		ctrl.SetConfig(cfg)
		if err := configio.Save(configPath, cfg); err != nil {
			agentlog.Log.Infof(logging.CatSystem, "failed to save auto-pinned TLS config: %v", err)
		} else {
			agentlog.Log.Infof(logging.CatSystem, "Saved auto-pinned TLS certificate to config")
		}
	}
	if autostart {
		agentlog.Log.Infof(logging.CatSystem, "=== Auto-starting agent ===")
		agentlog.Log.Infof(logging.CatSystem, "Server: %s", cfg.Server)
		agentlog.Log.Infof(logging.CatSystem, "Control address: %s", cfg.ControlAddr())
		agentlog.Log.Infof(logging.CatSystem, "Data address: %s", cfg.DataAddr())
		agentlog.Log.Infof(logging.CatSystem, "TLS enabled: %v", !cfg.DisableTLS)
		ctrl.Start()
	} else {
		agentlog.Log.Infof(logging.CatSystem, "=== Agent not auto-started ===")
		agentlog.Log.Infof(logging.CatSystem, "Reason: server or token not configured")
		if webAddr != "" {
			agentlog.Log.Infof(logging.CatSystem, "Configure via web UI at: http://%s", webAddr)
		}
	}

	if webAddr != "" {
		go func() {
			display := webAddr
			if h, _, err := net.SplitHostPort(display); err == nil {
				h = strings.TrimSpace(h)
				if h == "" || h == "0.0.0.0" || h == "::" || h == "[::]" || h == "0:0:0:0:0:0:0:0" {
					agentlog.Log.Infof(logging.CatSystem, "WARNING: agent web UI is unauthenticated; binding to all interfaces")
				}
			}
			agentlog.Log.Infof(logging.CatSystem, "agent web: http://%s", display)
			if err := serveAgentDashboard(ctx, webAddr, configPath, ctrl, mailSvc); err != nil {
				agentlog.Log.Infof(logging.CatSystem, "agent web error: %v", err)
			}
		}()
	}

	<-ctx.Done()
}

type agentController struct {
	root context.Context

	mu                 sync.Mutex
	cfg                agent.Config
	agentInst          *agent.Agent
	running            bool
	connected          bool
	lastErr            string
	routes             []agent.RemoteRoute
	emailCfg           emailcfg.Config
	cancel             context.CancelFunc
	done               chan struct{}
	runID              uint64
	onEmailConfig      func(emailcfg.Config)
	onEmailProbe       func(context.Context, protocol.EmailProbeRequest) (protocol.EmailProbeResult, error)
	onTLSPinDiscovered func(pin string)

	eventSubs []*eventSubscriber
	appsCfg   apitypes.AppsConfig
	appsPath  string
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

func (a *agentController) GetAgent() *agent.Agent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentInst
}

func (a *agentController) RequestRoute(ctx context.Context, req apitypes.RouteRequest) (*apitypes.RouteResponse, error) {
	a.mu.Lock()
	ag := a.agentInst
	a.mu.Unlock()
	if ag == nil {
		return nil, fmt.Errorf("agent not running")
	}
	return ag.SendRouteRequest(ctx, req)
}

func (a *agentController) ConfirmRoute(ctx context.Context, confirm apitypes.RouteConfirm) (*apitypes.RouteAck, error) {
	a.mu.Lock()
	ag := a.agentInst
	a.mu.Unlock()
	if ag == nil {
		return nil, fmt.Errorf("agent not running")
	}
	return ag.SendRouteConfirm(ctx, confirm)
}

func (a *agentController) RemoveRoute(ctx context.Context, remove apitypes.RouteRemove) (*apitypes.RouteRemoveAck, error) {
	a.mu.Lock()
	ag := a.agentInst
	a.mu.Unlock()
	if ag == nil {
		return nil, fmt.Errorf("agent not running")
	}
	return ag.SendRouteRemove(ctx, remove)
}

func (a *agentController) UpdateRoute(ctx context.Context, update apitypes.RouteUpdate) (*apitypes.RouteUpdateAck, error) {
	a.mu.Lock()
	ag := a.agentInst
	a.mu.Unlock()
	if ag == nil {
		return nil, fmt.Errorf("agent not running")
	}
	return ag.SendRouteUpdate(ctx, update)
}

type eventSubscriber struct {
	ch chan apitypes.AppEvent
}

func (a *agentController) SubscribeEvents() *eventSubscriber {
	sub := &eventSubscriber{ch: make(chan apitypes.AppEvent, 100)}
	a.mu.Lock()
	a.eventSubs = append(a.eventSubs, sub)
	a.mu.Unlock()
	return sub
}

func (a *agentController) UnsubscribeEvents(sub *eventSubscriber) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, s := range a.eventSubs {
		if s == sub {
			a.eventSubs = append(a.eventSubs[:i], a.eventSubs[i+1:]...)
			return
		}
	}
}

func (a *agentController) pushEvent(event apitypes.AppEvent) {
	a.mu.Lock()
	subs := append([]*eventSubscriber(nil), a.eventSubs...)
	a.mu.Unlock()
	for _, sub := range subs {
		select {
		case sub.ch <- event:
		default:
		}
	}
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
			a.pushEvent(apitypes.AppEvent{Type: "connected", Timestamp: time.Now().UnixMilli()})
			go registerAppsFromConfig(a.root, a, a.appsCfg.Apps)
		},
		OnRoutes: func(routes []agent.RemoteRoute) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.routes = append([]agent.RemoteRoute(nil), routes...)
			a.mu.Unlock()
			a.pushEvent(apitypes.AppEvent{Type: "routes_updated", Timestamp: time.Now().UnixMilli()})
		},
		OnEmailConfig: func(cfg emailcfg.Config) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.emailCfg = cfg
			onEmailConfig := a.onEmailConfig
			a.mu.Unlock()
			if onEmailConfig != nil {
				onEmailConfig(cfg)
			}
		},
		OnEmailProbe: func(callCtx context.Context, req protocol.EmailProbeRequest) (protocol.EmailProbeResult, error) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return protocol.EmailProbeResult{}, fmt.Errorf("stale agent run")
			}
			onEmailProbe := a.onEmailProbe
			a.mu.Unlock()
			if onEmailProbe == nil {
				return protocol.EmailProbeResult{}, fmt.Errorf("email probe handler not configured")
			}
			return onEmailProbe(callCtx, req)
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
			a.pushEvent(apitypes.AppEvent{Type: "disconnected", Timestamp: time.Now().UnixMilli(), Detail: err.Error()})
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
		OnTLSPinDiscovered: func(pin string) {
			a.mu.Lock()
			if a.runID != rid {
				a.mu.Unlock()
				return
			}
			a.cfg.TLSPinSHA256 = pin
			onTLSPinDiscovered := a.onTLSPinDiscovered
			a.mu.Unlock()
			if onTLSPinDiscovered != nil {
				onTLSPinDiscovered(pin)
			}
		},
	}

	ag := agent.NewAgent(cfg)
	ag.SetHooks(hooks)
	a.mu.Lock()
	a.agentInst = ag
	a.mu.Unlock()

	go func() {
		defer close(done)
		err := ag.Run(ctx)
		a.mu.Lock()
		if a.runID == rid {
			a.agentInst = nil
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
	a.agentInst = nil
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

func maskToken(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

// mergeToken decides which token to persist when the config form is saved.
// The form never pre-fills the real token, so a blank submission means
// "keep the current token"; a "****"-prefixed value is treated the same
// way for backward compatibility with older cached dashboard pages that
// still submitted the masked placeholder. Any other value replaces the
// stored token.
func mergeToken(oldToken, submitted string) string {
	submitted = strings.TrimSpace(submitted)
	if submitted == "" || strings.HasPrefix(submitted, "****") {
		return oldToken
	}
	return submitted
}

func registerAppsFromConfig(ctx context.Context, ctrl *agentController, apps []apitypes.AppConfig) {
	for _, app := range apps {
		if !app.AutoStart {
			continue
		}
		localHost := "127.0.0.1"
		if app.LocalHost != "" {
			localHost = app.LocalHost
		}
		localAddr := net.JoinHostPort(localHost, strconv.Itoa(app.LocalPort))
		req := apitypes.RouteRequest{
			RequestID:  generateToken(),
			Name:       app.Name,
			Proto:      app.Proto,
			LocalAddr:  localAddr,
			PublicPort: app.PublicPort,
			Domain:     app.Domain,
			Encrypted:  app.Encrypted,
			Source:     "apps.json",
		}
		resp, err := ctrl.RequestRoute(ctx, req)
		if err != nil {
			agentlog.Log.Infof(logging.CatSystem, "auto-register app %q failed: %v", app.Name, err)
			continue
		}
		if resp.Status == "active" {
			agentlog.Log.Infof(logging.CatSystem, "auto-registered app %q on %s", app.Name, resp.PublicAddr)
		} else if resp.Status == "pending_domain" {
			agentlog.Log.Infof(logging.CatSystem, "auto-registered app %q pending domain selection", app.Name)
		} else if resp.Status == "failed" {
			agentlog.Log.Infof(logging.CatSystem, "auto-register app %q rejected: %s", app.Name, resp.Error)
		}
	}
}
