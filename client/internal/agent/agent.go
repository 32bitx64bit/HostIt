package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"hostit/client/internal/lineproto"
)

var warnTLSPinOnce sync.Once

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

func debugEnabled() bool {
	v := strings.TrimSpace(os.Getenv("HOSTIT_DEBUG"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PLAYIT_DEBUG"))
	}
	if v == "" || v == "0" {
		return false
	}
	return true
}

func debugf(format string, args ...any) {
	if !debugEnabled() {
		return
	}
	log.Printf(format, args...)
}

func runOnce(ctx context.Context, cfg Config, hooks *Hooks) error {
	if strings.TrimSpace(cfg.Token) == "" {
		return fmt.Errorf("token is required")
	}
	onceCtx, onceCancel := context.WithCancel(ctx)
	defer onceCancel()
	controlAddr := cfg.ControlAddr()
	dataAddrTLS := cfg.DataAddr()
	var dataAddrInsecure string

	controlConn, err := dialTCP(cfg, controlAddr, true, !cfg.DisableTLS)
	if err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("dial control: %w", err)
	}
	defer controlConn.Close()
	setTCPKeepAlive(controlConn, 30*time.Second)
	remoteHost := hostFromRemoteAddr(controlConn.RemoteAddr())

	rw := lineproto.New(controlConn, controlConn)
	if err := rw.WriteLinef("HELLO %s", cfg.Token); err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("hello: %w", err)
	}
	_ = controlConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := rw.ReadLine()
	_ = controlConn.SetReadDeadline(time.Time{})
	if err != nil {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(err)
		}
		return fmt.Errorf("read hello reply: %w", err)
	}
	cmd, rest := lineproto.Split2(line)
	if cmd != "OK" {
		if hooks != nil && hooks.OnError != nil {
			hooks.OnError(fmt.Errorf("server rejected: %s", line))
		}
		return fmt.Errorf("server rejected: %s", line)
	}
	if strings.TrimSpace(rest) != "" {
		serverHost, _ := splitHostPortOrDefault(controlAddr, "")
		if strings.TrimSpace(remoteHost) != "" {
			serverHost = remoteHost
		}
		f := strings.Fields(rest)
		if len(f) >= 1 {
			dataAddrTLS = normalizeAdvertisedAddr(serverHost, strings.TrimSpace(f[0]), dataAddrTLS)
		}
		if len(f) >= 2 {
			v := strings.TrimSpace(f[1])
			if v != "" && v != "-" {
				dataAddrInsecure = normalizeAdvertisedAddr(serverHost, v, "")
			}
		}
	}
	debugf("agent: server OK; dataTLS=%s dataInsecure=%s", dataAddrTLS, dataAddrInsecure)
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
			tlsOn := true
			pc := 0
			for _, tok := range f[3:] {
				k, v, ok := strings.Cut(tok, "=")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "nodelay", "tcp_nodelay":
					v = strings.ToLower(strings.TrimSpace(v))
					nd = !(v == "0" || v == "false" || v == "off" || v == "no")
				case "tls", "tunneltls":
					v = strings.ToLower(strings.TrimSpace(v))
					tlsOn = !(v == "0" || v == "false" || v == "off" || v == "no")
				case "preconnect":
					v = strings.TrimSpace(v)
					if v == "" {
						continue
					}
					if n, err := strconv.Atoi(v); err == nil {
						if n < 0 {
							n = 0
						}
						pc = n
					}
				}
			}
			rt := RemoteRoute{Name: f[0], Proto: f[1], PublicAddr: f[2], TCPNoDelay: nd, TunnelTLS: tlsOn, Preconnect: pc}
			routesByName[rt.Name] = rt
			routesList = append(routesList, rt)
			debugf("agent: route name=%s proto=%s public=%s nodelay=%v tls=%v preconnect=%d", rt.Name, rt.Proto, rt.PublicAddr, rt.TCPNoDelay, rt.TunnelTLS, rt.Preconnect)
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
	udpCtx, udpCancel := context.WithCancel(onceCtx)
	defer udpCancel()
	if cfg.DisableUDPEncryption {
		udpSec.ForceNone()
	}
	go runUDP(udpCtx, dataAddrTLS, cfg.Token, udpSec, routesByName)
	pools := startDataPools(onceCtx, cfg, routesByName, dataAddrTLS, dataAddrInsecure)

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
			go handleOne(ctx, cfg, dataAddrTLS, dataAddrInsecure, pools, routesByName, id, routeName)
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

func hostFromRemoteAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ta, ok := addr.(*net.TCPAddr); ok {
		if ta.IP != nil {
			return ta.IP.String()
		}
		return ""
	}
	// Fallback for custom Addr implementations.
	h, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(h)
}

func dialTCP(cfg Config, addr string, noDelay bool, useTLS bool) (net.Conn, error) {
	// Keep dial/handshake bounded so a missing/blocked data listener can't stall
	// until the server-side PairTimeout closes the public connection.
	const dialTimeout = 2 * time.Second
	const tlsHandshakeTimeout = 2 * time.Second

	if !useTLS {
		d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		setTCPKeepAlive(c, 30*time.Second)
		if noDelay {
			setTCPNoDelay(c, true)
			setTCPQuickACK(c, true)
		}
		return c, nil
	}

	if strings.TrimSpace(cfg.TLSPinSHA256) == "" {
		warnTLSPinOnce.Do(func() {
			log.Printf("WARNING: agent TLS is not verifying the server certificate (MITM risk). Set TLSPinSHA256 to pin the server cert fingerprint.")
		})
	}
	host, _ := splitHostPortOrDefault(addr, "")
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	setTCPKeepAlive(raw, 30*time.Second)
	if noDelay {
		setTCPNoDelay(raw, true)
		setTCPQuickACK(raw, true)
	}
	conn := tls.Client(raw, tlsCfg)
	_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
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

func normalizeAdvertisedAddr(serverHost string, adv string, fallback string) string {
	adv = strings.TrimSpace(adv)
	if adv == "" || adv == "-" {
		return fallback
	}
	h, p, err := net.SplitHostPort(adv)
	if err != nil {
		return fallback
	}
	sh := strings.TrimSpace(serverHost)
	if strings.TrimSpace(p) == "" {
		return fallback
	}
	h = strings.TrimSpace(h)
	if h == "" || h == "0.0.0.0" || h == "::" {
		if sh == "" {
			return net.JoinHostPort("127.0.0.1", p)
		}
		return net.JoinHostPort(sh, p)
	}
	return net.JoinHostPort(h, p)
}

func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc := unwrapTCPConn(conn)
	if tc == nil {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}

func unwrapTCPConn(conn net.Conn) *net.TCPConn {
	if conn == nil {
		return nil
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc
	}
	if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return unwrapTCPConn(nc.NetConn())
	}
	return nil
}

func handleOne(ctx context.Context, cfg Config, dataAddrTLS string, dataAddrInsecure string, pools map[string]*dataConnPool, routesByName map[string]RemoteRoute, id string, routeName string) {
	debugf("agent: NEW id=%s route=%s", id, routeName)
	rt, ok := routesByName[routeName]
	if !ok {
		debugf("agent: NEW id=%s route=%s -> unknown route (dropping)", id, routeName)
		return
	}
	if !routeHasTCP(rt.Proto) {
		debugf("agent: NEW id=%s route=%s -> non-tcp proto=%s (dropping)", id, routeName, rt.Proto)
		return
	}
	// Per-route TLS disable is best-effort: if the server isn't advertising an insecure
	// data address, fall back to the normal data address.
	primaryUseTLS := !cfg.DisableTLS && (rt.TunnelTLS || strings.TrimSpace(dataAddrInsecure) == "")
	primaryAddr := dataAddrTLS
	if !primaryUseTLS {
		primaryAddr = dataAddrInsecure
	}
	// If insecure attach fails (listener missing/firewalled), fall back to TLS.
	type candidate struct {
		addr   string
		useTLS bool
	}
	cands := []candidate{{addr: primaryAddr, useTLS: primaryUseTLS}}
	if !primaryUseTLS && strings.TrimSpace(dataAddrTLS) != "" {
		cands = append(cands, candidate{addr: dataAddrTLS, useTLS: true})
	}
	var dataConn net.Conn
	for _, cand := range cands {
		for attempt := 0; attempt < 2; attempt++ {
			var (
				c        net.Conn
				err      error
				fromPool bool
			)
			if attempt == 0 {
				if p := pools[routeName]; p != nil && p.addr == cand.addr && p.useTLS == cand.useTLS {
					fromPool = true
					c, err = p.getOrDial(ctx, cfg)
				} else {
					c, err = dialTCP(cfg, cand.addr, rt.TCPNoDelay, cand.useTLS)
				}
			} else {
				c, err = dialTCP(cfg, cand.addr, rt.TCPNoDelay, cand.useTLS)
			}
			if err != nil {
				debugf("agent: attach dial failed id=%s route=%s addr=%s tls=%v pool=%v err=%v", id, routeName, cand.addr, cand.useTLS, fromPool, err)
				continue
			}

			rw := lineproto.New(c, c)
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err = rw.WriteLinef("CONN %s", id)
			_ = c.SetWriteDeadline(time.Time{})
			if err != nil {
				debugf("agent: attach CONN write failed id=%s route=%s addr=%s tls=%v pool=%v err=%v", id, routeName, cand.addr, cand.useTLS, fromPool, err)
				_ = c.Close()
				continue
			}
			dataConn = c
			break
		}
		if dataConn != nil {
			break
		}
	}
	if dataConn == nil {
		return
	}
	defer dataConn.Close()

	localAddr, ok := localTargetFromPublicAddr(rt.PublicAddr)
	if !ok {
		return
	}
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	setTCPKeepAlive(localConn, 30*time.Second)
	if rt.TCPNoDelay {
		setTCPNoDelay(localConn, true)
		setTCPQuickACK(localConn, true)
	}
	defer localConn.Close()

	bidirPipe(localConn, dataConn)
}

func setTCPNoDelay(conn net.Conn, on bool) {
	tc := unwrapTCPConn(conn)
	if tc == nil {
		return
	}
	_ = tc.SetNoDelay(on)
}
