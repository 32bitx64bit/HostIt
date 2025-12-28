package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"playit-prototype/client/internal/lineproto"
)

type Hooks struct {
	OnConnected    func()
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
	normalizeRoutes(&cfg)
	routesByName := map[string]RouteConfig{}
	for _, rt := range cfg.Routes {
		routesByName[rt.Name] = rt
	}

	controlConn, err := net.Dial("tcp", cfg.ControlAddr)
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
	if hooks != nil && hooks.OnConnected != nil {
		hooks.OnConnected()
	}
	udpCtx, udpCancel := context.WithCancel(ctx)
	defer udpCancel()
	go runUDP(udpCtx, cfg, routesByName)

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
			go handleOne(ctx, cfg, routesByName, id, routeName)
		case "PING":
			_ = rw.WriteLinef("PONG %s", rest)
		default:
		}
	}
}

func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}

func handleOne(ctx context.Context, cfg Config, routesByName map[string]RouteConfig, id string, routeName string) {
	dataConn, err := net.Dial("tcp", cfg.DataAddr)
	if err != nil {
		return
	}
	defer dataConn.Close()

	rw := lineproto.New(dataConn, dataConn)
	if err := rw.WriteLinef("CONN %s", id); err != nil {
		return
	}

	localAddr := cfg.LocalAddr
	if rt, ok := routesByName[routeName]; ok {
		if routeHasTCP(rt.Proto) && strings.TrimSpace(rt.LocalTCPAddr) != "" {
			localAddr = rt.LocalTCPAddr
		}
	}
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer localConn.Close()

	bidirPipe(localConn, dataConn)
}
