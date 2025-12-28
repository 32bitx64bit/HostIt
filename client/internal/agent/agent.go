package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"playit-prototype/client/internal/lineproto"
)

type Hooks struct {
	OnConnected    func()
	OnRoutes       func(routes []RemoteRoute)
	OnDisconnected func(err error)
	OnError        func(err error)
}

func Run(ctx context.Context, cfg Config) error {
	return RunWithHooks(ctx, cfg, nil)
}

func RunWithHooks(ctx context.Context, cfg Config, hooks *Hooks) error {
	for {
		err := runOnce(ctx, cfg, hooks)
		if ctx.Err() != nil {
			return nil
		}
		t := time.NewTimer(1 * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		_ = err
	}
}

func runOnce(ctx context.Context, cfg Config, hooks *Hooks) error {
	if strings.TrimSpace(cfg.Token) == "" {
		return fmt.Errorf("token is required")
	}
	controlAddr := cfg.ControlAddr()
	dataAddr := cfg.DataAddr()

	controlConn, err := dialTCP(cfg, controlAddr, true)
	if err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("dial control: %w", err)
	}
	defer controlConn.Close()
	setTCPKeepAlive(controlConn, 30*time.Second)

	rw := lineproto.New(controlConn, controlConn)
	if err := rw.WriteLinef("HELLO %s", cfg.Token); err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("hello: %w", err)
	}
	line, err := rw.ReadLine()
	if err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("read hello reply: %w", err)
	}
	cmd, _ := lineproto.Split2(line)
	if cmd != "OK" {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(fmt.Errorf("server rejected: %s", line))
		}
		return fmt.Errorf("server rejected: %s", line)
	}
	// Read server-pushed routes before marking connected.
	routesByName := map[string]RemoteRoute{}
	routesList := make([]RemoteRoute, 0, 8)
	udpSec := newUDPSecurityState()
	for {
		_ = controlConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		ln, err := rw.ReadLine()
		if err != nil {
			if hooks != nil && hooks.OnError != nil {
				hooks.OnError(err)
			}
			return err
		}
		c, rest := lineproto.Split2(ln)
		switch c {
		case "READY":
			goto ready
		case "ROUTE":
			f := strings.Fields(rest)
			if len(f) < 3 {
				continue
			}
			nd := true
			for _, tok := range f[3:] {
				k, v, ok := strings.Cut(tok, "=")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "nodelay", "tcp_nodelay":
					v = strings.ToLower(strings.TrimSpace(v))
					nd = !(v == "0" || v == "false" || v == "off" || v == "no")
				}
			}
			rt := RemoteRoute{Name: f[0], Proto: f[1], PublicAddr: f[2], TCPNoDelay: nd}
			routesByName[rt.Name] = rt
			routesList = append(routesList, rt)
		case "PING":
			_ = rw.WriteLinef("PONG %s", rest)
		case "UDPSEC":
			if !cfg.DisableUDPEncryption {
				udpSec.UpdateFromLine(cfg.Token, rest)
			}
		default:
			// Ignore anything else during handshake.
		}
	}

ready:
	if hooks != nil && hooks.OnRoutes != nil {
		hooks.OnRoutes(routesList)
	}
	if hooks != nil && hooks.OnConnected != nil {
		hooks.OnConnected()
	}
	udpCtx, udpCancel := context.WithCancel(ctx)
	defer udpCancel()
	if cfg.DisableUDPEncryption {
		udpSec.ForceNone()
	}
	go runUDP(udpCtx, dataAddr, cfg.Token, udpSec, routesByName)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_ = controlConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		line, err := rw.ReadLine()
		if err != nil {
			if hooks != nil && hooks.OnDisconnected != nil {
				hooks.OnDisconnected(err)
			}
			if errors.Is(err, lineproto.ErrClosed) {
				return err
			}
			return err
		}
		cmd, rest := lineproto.Split2(line)
		switch cmd {
		case "NEW":
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			id := fields[0]
			routeName := "default"
			if len(fields) >= 2 {
				routeName = fields[1]
			}
			go handleOne(ctx, cfg, dataAddr, routesByName, id, routeName)
		case "PING":
			_ = rw.WriteLinef("PONG %s", rest)
		case "UDPSEC":
			if !cfg.DisableUDPEncryption {
				udpSec.UpdateFromLine(cfg.Token, rest)
			}
		default:
		}
	}
}

func dialTCP(cfg Config, addr string, noDelay bool) (net.Conn, error) {
	if cfg.DisableTLS {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		if noDelay {
			setTCPNoDelay(c, true)
		}
		return c, nil
	}
	host, _ := splitHostPortOrDefault(addr, "")
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if noDelay {
		setTCPNoDelay(raw, true)
	}
	conn := tls.Client(raw, tlsCfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if pin := strings.TrimSpace(cfg.TLSPinSHA256); pin != "" {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			_ = conn.Close()
			return nil, fmt.Errorf("tls pin requested but server did not present a certificate")
		}
		der := state.PeerCertificates[0].Raw
		sum := sha256.Sum256(der)
		got := fmt.Sprintf("%x", sum[:])
		if !strings.EqualFold(got, pin) {
			_ = conn.Close()
			return nil, fmt.Errorf("tls cert pin mismatch: got %s", got)
		}
	}
	return conn, nil
}

func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}

func handleOne(ctx context.Context, cfg Config, dataAddr string, routesByName map[string]RemoteRoute, id string, routeName string) {
	rt, ok := routesByName[routeName]
	if !ok || !routeHasTCP(rt.Proto) {
		return
	}
	dataConn, err := dialTCP(cfg, dataAddr, rt.TCPNoDelay)
	if err != nil {
		return
	}
	defer dataConn.Close()

	rw := lineproto.New(dataConn, dataConn)
	if err := rw.WriteLinef("CONN %s", id); err != nil {
		return
	}

	localAddr, ok := localTargetFromPublicAddr(rt.PublicAddr)
	if !ok {
		return
	}
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	if rt.TCPNoDelay {
		setTCPNoDelay(localConn, true)
	}
	defer localConn.Close()

	bidirPipe(localConn, dataConn)
}

func setTCPNoDelay(conn net.Conn, on bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(on)
}
