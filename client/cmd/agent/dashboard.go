package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	"hostit/shared/logging"
	"hostit/shared/module"
	"hostit/shared/systemdutil"
	"hostit/shared/updater"
	"hostit/shared/version"
)

type routeView struct {
	Name        string `json:"name"`
	Proto       string `json:"proto"`
	PublicAddr  string `json:"publicAddr"`
	LocalTarget string `json:"localTarget"`
}

type apitypesRoute struct {
	Name       string `json:"name"`
	Proto      string `json:"proto"`
	PublicAddr string `json:"public_addr"`
	LocalAddr  string `json:"local_addr"`
}

func serveAgentDashboard(ctx context.Context, addr string, configPath string, ctrl *agentController, mailSvc *mail.Service) error {
	tplHome := template.Must(template.New("home").Parse(agentHomeHTML))
	tplControls := template.Must(template.New("controls").Parse(agentControlsHTML))
	tplApps := template.Must(template.New("apps").Parse(agentAppsHTML))

	absCfg := configPath
	if p, err := filepath.Abs(configPath); err == nil {
		absCfg = p
	}
	updStatePath := filepath.Join(filepath.Dir(absCfg), "update_state_client.json")
	moduleDir := module.DetectModuleDir(absCfg)
	upd := updater.NewManager("32bitx64bit/HostIt", updater.ComponentClient, "client.zip", moduleDir, updStatePath)
	upd.PreservePaths = []string{absCfg, filepath.Join(filepath.Dir(absCfg), "mail")}
	upd.Restart = func() error {
		agentlog.Log.Infof(logging.CatSystem, "=== Update complete, restarting agent ===")
		ctrl.Stop()
		bin := upd.BuiltBinaryPath()
		if _, err := os.Stat(bin); err != nil {
			agentlog.Log.Infof(logging.CatSystem, "ERROR: Built binary not found: %s", bin)
			return err
		}
		agentlog.Log.Infof(logging.CatSystem, "Built binary: %s", bin)

		if systemdutil.RunningUnderSystemd() {
			agentlog.Log.Infof(logging.CatSystem, "Running under systemd - restarting service")
			if systemdutil.SystemctlAvailable() {
				if err := syncInstalledAgentSystemdUnit(moduleDir); err != nil {
					agentlog.Log.Infof(logging.CatSystem, "Failed to refresh installed systemd unit: %v", err)
				}
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx2, "systemctl", "restart", "--no-block", agentSystemdServiceName)
				out, err := cmd.CombinedOutput()
				if err == nil {
					agentlog.Log.Infof(logging.CatSystem, "Systemd restart command sent successfully")
					return nil
				}
				agentlog.Log.Infof(logging.CatSystem, "Systemctl restart failed: %v, output: %s", err, string(out))
			}
			agentlog.Log.Infof(logging.CatSystem, "Sending SIGTERM to let systemd restart")
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			return nil
		}

		agentlog.Log.Infof(logging.CatSystem, "Not running under systemd - executing binary replacement")
		agentlog.Log.Infof(logging.CatSystem, "Agent will auto-reconnect using configuration from: %s", configPath)
		return updater.ExecReplace(bin, os.Args)
	}
	upd.Start(ctx)

	makeRouteViews := func(routes []agent.RemoteRoute) []routeView {
		out := make([]routeView, 0, len(routes))
		for _, rt := range routes {
			out = append(out, routeView{
				Name:        rt.Name,
				Proto:       rt.Proto,
				PublicAddr:  rt.PublicAddr,
				LocalTarget: rt.EffectiveLocalAddr(),
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

	// Generate a CSRF token for the session.
	csrfToken := generateToken()

	buildTemplateData := func(cfg agent.Config, running, connected bool, lastErr string, routes []agent.RemoteRoute) map[string]any {
		hasToken := strings.TrimSpace(cfg.Token) != ""
		tokenPlaceholder := "Enter token (required)"
		if hasToken {
			tokenPlaceholder = "Leave blank to keep current token (" + maskToken(cfg.Token) + ")"
		}
		data := map[string]any{
			"Cfg":              cfg,
			"Running":          running,
			"Connected":        connected,
			"HasToken":         hasToken,
			"TokenPlaceholder": tokenPlaceholder,
			"LastErr":          lastErr,
			"ConfigPath":       configPath,
			"Version":          version.Current,
			"Msg":              getMsg(),
			"RoutesView":       makeRouteViews(routes),
			"CSRFToken":        csrfToken,
		}
		if mailSvc != nil {
			data["EmailStatus"] = mailSvc.Status()
		}
		return data
	}

	requireCSRF := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next(w, r)
				return
			}
			submitted := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
			if submitted == "" {
				submitted = strings.TrimSpace(r.PostFormValue("csrf_token"))
			}
			if subtle.ConstantTimeCompare([]byte(submitted), []byte(csrfToken)) != 1 {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}

	mux := http.NewServeMux()

	writeOK := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"status": "ok"}
		if data != nil {
			out["data"] = data
		}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			agentlog.Log.Infof(logging.CatSystem, "json encode: %v", err)
		}
	}
	writeError := func(w http.ResponseWriter, status int, message string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]any{"status": "error", "message": message}); err != nil {
			agentlog.Log.Infof(logging.CatSystem, "json encode error: %v", err)
		}
	}

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		outRoutes := makeRouteViews(routes)
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
		if mailSvc != nil {
			resp["email"] = mailSvc.Status()
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, resp)
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		entries := []agentlog.UILogEntry{}
		if agentlog.UILogs != nil {
			stats = agentlog.UILogs.Stats()
			entries = agentlog.UILogs.Entries(level, limit)
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, map[string]any{
			"level":   level,
			"limit":   limit,
			"stats":   stats,
			"entries": entries,
		})
	})

	mux.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		upd.CheckIfDue(r.Context())
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, upd.Status())
	})
	mux.HandleFunc("/api/update/check-now", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_ = upd.CheckNow(r.Context())
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, upd.Status())
	}))

	mux.HandleFunc("/api/systemd/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		st := systemdutil.Status(r.Context(), agentSystemdServiceName)
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, st)
	})
	mux.HandleFunc("/api/systemd/restart", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := syncInstalledAgentSystemdUnit(moduleDir); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := systemdutil.Action(r.Context(), "restart", agentSystemdServiceName); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/systemd/stop", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := systemdutil.Action(r.Context(), "stop", agentSystemdServiceName); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("/api/process/restart", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	}))
	mux.HandleFunc("/api/process/exit", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			time.Sleep(250 * time.Millisecond)
			os.Exit(0)
		}()
	}))
	mux.HandleFunc("/api/update/remind", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_ = upd.RemindLater(24 * time.Hour)
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/update/skip", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_ = upd.SkipAvailableVersion()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/update/apply", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		started, err := upd.Apply(r.Context())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !started {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	mux.HandleFunc("/api/update/apply-local", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
		if err := r.ParseMultipartForm(512 << 20); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		componentZipPath, hasComponent, err := writeUploadedZipTemp(r, "componentZip", "hostit-client-component-*.zip")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !hasComponent {
			writeError(w, http.StatusBadRequest, "component zip is required")
			return
		}
		defer os.Remove(componentZipPath)

		sharedZipPath, hasShared, err := writeUploadedZipTemp(r, "sharedZip", "hostit-client-shared-*.zip")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if hasShared {
			defer os.Remove(sharedZipPath)
		}

		started, err := upd.ApplyLocal(r.Context(), componentZipPath, sharedZipPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !started {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	mux.HandleFunc("/start", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		ctrl.Start()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/stop", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		ctrl.Stop()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/restart", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		ctrl.Stop()
		ctrl.Start()
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		_ = tplHome.Execute(w, buildTemplateData(cfg, running, connected, lastErr, routes))
	})

	mux.HandleFunc("/controls", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		_ = tplControls.Execute(w, buildTemplateData(cfg, running, connected, lastErr, routes))
	})

	mux.HandleFunc("/apps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, _, connected, lastErr, routes := ctrl.Get()
		apiRoutes := []apitypesRoute{}
		for _, rt := range routes {
			apiRoutes = append(apiRoutes, apitypesRoute{
				Name:       rt.Name,
				Proto:      rt.Proto,
				PublicAddr: rt.PublicAddr,
				LocalAddr:  rt.EffectiveLocalAddr(),
			})
		}
		data := map[string]any{
			"Cfg":        cfg,
			"Connected":  connected,
			"LastErr":    lastErr,
			"RoutesView": apiRoutes,
			"CSRFToken":  csrfToken,
			"Version":    version.Current,
		}
		_ = tplApps.Execute(w, data)
	})

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	saveHandler := requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		old, _, _, _, _ := ctrl.Get()
		cfg := old
		cfg.Server = strings.TrimSpace(r.Form.Get("server"))
		cfg.Token = mergeToken(old.Token, r.Form.Get("token"))
		cfg.TLSPinSHA256 = strings.TrimSpace(r.Form.Get("tls_pin_sha256"))
		if cfg.Server == "" {
			writeError(w, http.StatusBadRequest, "server is required")
			return
		}
		if cfg.Token == "" {
			writeError(w, http.StatusBadRequest, "token is required")
			return
		}
		if err := cfg.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := configio.Save(configPath, cfg); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctrl.Stop()
		ctrl.SetConfig(cfg)
		ctrl.Start()
		setMsg("Saved + restarted")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/save", saveHandler)
	mux.HandleFunc("/config/save", saveHandler)

	// ── Mail viewer API ─────────────────────────────────────────────
	tplMail := template.Must(template.New("mail").Parse(agentMailHTML))

	mux.HandleFunc("/api/mail/accounts", func(w http.ResponseWriter, r *http.Request) {
		if mailSvc == nil {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				writeOK(w, []mail.WebAccount{})
				return
			}
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			accts, err := mailSvc.ListAccounts()
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if accts == nil {
				accts = []mail.WebAccount{}
			}
			w.Header().Set("Content-Type", "application/json")
			writeOK(w, accts)
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "bad request")
				return
			}
			acct, err := mailSvc.CreateAccount(req.Username, req.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			writeOK(w, acct)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})

	mux.HandleFunc("/api/mail/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		username := strings.TrimPrefix(r.URL.Path, "/api/mail/accounts/")
		if username == "" {
			writeError(w, http.StatusBadRequest, "username required")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			var req struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "bad request")
				return
			}
			if err := mailSvc.UpdateAccountPassword(username, req.Password); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if err := mailSvc.DeleteAccount(username); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})

	mux.HandleFunc("/api/mail/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		addr, err := mailSvc.Authenticate(req.Username, req.Password)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, map[string]string{"username": req.Username, "address": addr})
	})

	mux.HandleFunc("/api/mail/inbox", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if _, err := mailSvc.Authenticate(req.Username, req.Password); err != nil {
			writeError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		msgs, err := mailSvc.ListInbox(req.Username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if msgs == nil {
			msgs = []mail.WebMessage{}
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, msgs)
	})

	mux.HandleFunc("/api/mail/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			MessageID int64  `json:"messageId"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if _, err := mailSvc.Authenticate(req.Username, req.Password); err != nil {
			writeError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		msg, err := mailSvc.GetMessage(req.Username, req.MessageID)
		if err != nil {
			writeError(w, http.StatusNotFound, "message not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, msg)
	})

	mux.HandleFunc("/api/mail/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			MessageID int64  `json:"messageId"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if _, err := mailSvc.Authenticate(req.Username, req.Password); err != nil {
			writeError(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		if err := mailSvc.DeleteMessage(req.Username, req.MessageID); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/mail/lock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if mailSvc == nil {
			writeError(w, http.StatusServiceUnavailable, "mail service unavailable")
			return
		}
		var req struct {
			Locked bool `json:"locked"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := mailSvc.SetSDKLock(req.Locked); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, map[string]any{"locked": req.Locked, "enabled": mailSvc.Config().Enabled})
	})

	mux.HandleFunc("/mail", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_ = tplMail.Execute(w, nil)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, _, _ := ctrl.Get()
		writeOK(w, map[string]any{
			"status":    "ok",
			"running":   running,
			"connected": connected,
			"version":   version.Current,
			"server":    cfg.Server,
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, lastErr, routes := ctrl.Get()
		writeOK(w, map[string]any{
			"uptime_seconds":  time.Since(startTime).Seconds(),
			"running":         running,
			"connected":       connected,
			"routes_count":    len(routes),
			"last_error":      lastErr,
			"version":         version.Current,
			"server":          cfg.Server,
		})
	})

	mux.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req apitypes.RegisterRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		if req.Proto == "" {
			req.Proto = "tcp"
		}
		if req.Proto != "tcp" && req.Proto != "udp" && req.Proto != "both" {
			writeError(w, http.StatusBadRequest, "proto must be tcp, udp, or both")
			return
		}
		if req.LocalPort <= 0 || req.LocalPort > 65535 {
			writeError(w, http.StatusBadRequest, "local_port must be 1-65535")
			return
		}

		localHost := "127.0.0.1"
		if req.LocalHost != "" {
			localHost = req.LocalHost
		}
		localAddr := net.JoinHostPort(localHost, strconv.Itoa(req.LocalPort))

		_, running, connected, lastErr, _ := ctrl.Get()
		if !running || !connected {
			writeError(w, http.StatusServiceUnavailable, "agent not connected: "+lastErr)
			return
		}

		reqID := generateToken()
		protoReq := apitypes.RouteRequest{
			RequestID:  reqID,
			Name:       req.Name,
			Proto:      req.Proto,
			LocalAddr:  localAddr,
			PublicPort: req.PublicPort,
			Domain:     req.Domain,
			Encrypted:  req.Encrypted,
			Source:     "api",
		}

		resp, err := ctrl.RequestRoute(r.Context(), protoReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "route request failed: "+err.Error())
			return
		}

		if resp.Status == "failed" {
			writeError(w, http.StatusBadRequest, "route request rejected: "+resp.Error)
			return
		}

		apiResp := apitypes.RegisterResponse{
			Status:           resp.Status,
			RequestID:        resp.RequestID,
			RouteName:        resp.Name,
			PublicAddr:       resp.PublicAddr,
			LocalAddr:        resp.LocalAddr,
			Proto:            resp.Proto,
			Domain:           resp.Domain,
			AvailableDomains: resp.AvailableDomains,
		}

		w.Header().Set("Content-Type", "application/json")
		writeOK(w, apiResp)
	})

	mux.HandleFunc("/api/v1/routes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_, _, _, _, routes := ctrl.Get()
		out := make([]apitypesRoute, 0, len(routes))
		for _, rt := range routes {
			out = append(out, apitypesRoute{
				Name:       rt.Name,
				Proto:      rt.Proto,
				PublicAddr: rt.PublicAddr,
				LocalAddr:  rt.EffectiveLocalAddr(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, out)
	})

	mux.HandleFunc("/api/v1/routes/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/routes/")
		if name == "" {
			writeError(w, http.StatusBadRequest, "route name required")
			return
		}
		_, running, connected, lastErr, _ := ctrl.Get()
		if !running || !connected {
			writeError(w, http.StatusServiceUnavailable, "agent not connected: "+lastErr)
			return
		}
		ack, err := ctrl.RemoveRoute(r.Context(), apitypes.RouteRemove{Name: name, Source: "api"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "route remove failed: "+err.Error())
			return
		}
		if !ack.OK {
			writeError(w, http.StatusBadRequest, "route remove rejected: "+ack.Error)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/v1/domains", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		_, _, connected, lastErr, _ := ctrl.Get()
		if !connected {
			writeError(w, http.StatusServiceUnavailable, "agent not connected: "+lastErr)
			return
		}
		protoReq := apitypes.RouteRequest{
			RequestID:  generateToken(),
			Name:       "_domain_query",
			Proto:      "tcp",
			LocalAddr:  "127.0.0.1:1",
			PublicPort: 0,
			Domain:     "_query",
			Source:     "api",
		}
		resp, err := ctrl.RequestRoute(r.Context(), protoReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "domain query failed: "+err.Error())
			return
		}
		result := apitypes.DomainsResponse{
			Base:      resp.Domain,
			Available: resp.AvailableDomains,
		}
		if result.Available == nil {
			result.Available = []apitypes.DomainOption{}
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, result)
	})

	mux.HandleFunc("/api/v1/domains/select", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req apitypes.DomainSelectRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if req.RequestID == "" || req.Domain == "" || req.RouteName == "" {
			writeError(w, http.StatusBadRequest, "request_id, route_name, and domain are required")
			return
		}
		_, _, connected, lastErr, _ := ctrl.Get()
		if !connected {
			writeError(w, http.StatusServiceUnavailable, "agent not connected: "+lastErr)
			return
		}
		ack, err := ctrl.ConfirmRoute(r.Context(), apitypes.RouteConfirm{
			RequestID: req.RequestID,
			Name:      req.RouteName,
			Domain:    req.Domain,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "domain confirm failed: "+err.Error())
			return
		}
		if ack.Status == "failed" {
			writeError(w, http.StatusBadRequest, "domain confirm rejected: "+ack.Error)
			return
		}
		apiResp := apitypes.RegisterResponse{
			Status:     "active",
			RequestID:  ack.RequestID,
			RouteName:  ack.Name,
			Domain:     ack.Domain,
			PublicAddr: ack.PublicAddr,
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, apiResp)
	})

	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cfg, running, connected, _, routes := ctrl.Get()
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, apitypes.StatusResponse{
			Connected:   running && connected,
			Server:      cfg.Server,
			Version:     version.Current,
			RoutesCount: len(routes),
		})
	})

	mux.HandleFunc("/api/v1/routes/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch && r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Name       string `json:"name"`
			LocalPort  int    `json:"local_port,omitempty"`
			LocalHost  string `json:"local_host,omitempty"`
			PublicPort int    `json:"public_port,omitempty"`
			Domain     string `json:"domain,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		_, _, connected, lastErr, _ := ctrl.Get()
		if !connected {
			writeError(w, http.StatusServiceUnavailable, "agent not connected: "+lastErr)
			return
		}
		update := apitypes.RouteUpdate{
			RequestID: generateToken(),
			Name:      req.Name,
		}
		if req.LocalPort > 0 {
			localHost := "127.0.0.1"
			if req.LocalHost != "" {
				localHost = req.LocalHost
			}
			update.LocalAddr = net.JoinHostPort(localHost, strconv.Itoa(req.LocalPort))
		}
		if req.PublicPort > 0 {
			update.PublicPort = req.PublicPort
		}
		if req.Domain != "" {
			update.Domain = req.Domain
		}
		ack, err := ctrl.UpdateRoute(r.Context(), update)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "route update failed: "+err.Error())
			return
		}
		if ack.Status == "failed" {
			writeError(w, http.StatusBadRequest, "route update rejected: "+ack.Error)
			return
		}
		ctrl.pushEvent(apitypes.AppEvent{Type: "route_updated", Timestamp: time.Now().UnixMilli(), RouteName: req.Name})
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, map[string]any{
			"status":     "updated",
			"route_name": ack.Name,
		})
	})

	mux.HandleFunc("/api/v1/route/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, "name query parameter required")
			return
		}
		_, _, connected, _, routes := ctrl.Get()
		var found *agent.RemoteRoute
		for _, rt := range routes {
			if rt.Name == name {
				found = &rt
				break
			}
		}
		if found == nil {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		stats := apitypes.RouteStats{
			Name:       found.Name,
			Proto:      found.Proto,
			PublicAddr: found.PublicAddr,
			LocalAddr:  found.EffectiveLocalAddr(),
			Connected:  connected,
			Source:     "dynamic",
		}
		w.Header().Set("Content-Type", "application/json")
		writeOK(w, stats)
	})

	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "streaming not supported")
			return
		}
		flusher.Flush()

		sub := ctrl.SubscribeEvents()
		defer ctrl.UnsubscribeEvents(sub)

		for {
			select {
			case event := <-sub.ch:
				data, err := json.Marshal(event)
				if err != nil {
					continue
				}
				_, err = w.Write([]byte("data: " + string(data) + "\n\n"))
				if err != nil {
					return
				}
				flusher.Flush()
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Minute):
				return
			}
		}
	})

	mux.HandleFunc("/api/v1/apps/register-all", requireCSRF(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		appsCfg := apitypes.AppsConfig{}
		configio.Load(ctrl.appsPath, &appsCfg)
		ctrl.mu.Lock()
		ctrl.appsCfg = appsCfg
		ctrl.mu.Unlock()
		registerAppsFromConfig(r.Context(), ctrl, appsCfg.Apps)
		w.WriteHeader(http.StatusNoContent)
	}))

	h := &http.Server{
		Addr:              addr,
		Handler:           requireLocalAddr(requireLocalHost(mux, addr)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
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
