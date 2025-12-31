package agent

import (
	"context"
	"net"
	"strings"
	"time"
)

type dataConnPool struct {
	addr    string
	useTLS  bool
	noDelay bool
	ch      chan net.Conn
}

func startDataPools(ctx context.Context, cfg Config, routesByName map[string]RemoteRoute, dataAddrTLS string, dataAddrInsecure string) map[string]*dataConnPool {
	pools := map[string]*dataConnPool{}
	for name, rt := range routesByName {
		if !routeHasTCP(rt.Proto) {
			continue
		}
		if rt.Preconnect <= 0 {
			continue
		}
		pc := rt.Preconnect
		if pc > 64 {
			pc = 64
		}
		useTLS := !cfg.DisableTLS && (rt.TunnelTLS || strings.TrimSpace(dataAddrInsecure) == "")
		addr := dataAddrTLS
		if !useTLS {
			addr = dataAddrInsecure
		}
		p := &dataConnPool{addr: addr, useTLS: useTLS, noDelay: rt.TCPNoDelay, ch: make(chan net.Conn, pc)}
		pools[name] = p
		go p.fillLoop(ctx, cfg)
	}
	return pools
}

func (p *dataConnPool) tryGet() net.Conn {
	select {
	case c := <-p.ch:
		return c
	default:
		return nil
	}
}

func (p *dataConnPool) getOrDial(ctx context.Context, cfg Config) (net.Conn, error) {
	if c := p.tryGet(); c != nil {
		return c, nil
	}
	return dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
}

func (p *dataConnPool) fillLoop(ctx context.Context, cfg Config) {
	defer func() {
		for {
			select {
			case c := <-p.ch:
				_ = c.Close()
				continue
			default:
				return
			}
		}
	}()

	backoff := 50 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		// If the pool is full, wait a bit.
		if len(p.ch) >= cap(p.ch) {
			t := time.NewTimer(150 * time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}

		c, err := dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
		if err != nil {
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if backoff < 1*time.Second {
				backoff *= 2
				if backoff > 1*time.Second {
					backoff = 1 * time.Second
				}
			}
			continue
		}
		backoff = 50 * time.Millisecond

		select {
		case p.ch <- c:
			continue
		case <-ctx.Done():
			_ = c.Close()
			return
		}
	}
}
