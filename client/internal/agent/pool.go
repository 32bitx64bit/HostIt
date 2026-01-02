package agent

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dataConnPool struct {
	addr      string
	useTLS    bool
	noDelay   bool
	ch        chan net.Conn
	capacity  int32
	size      atomic.Int32 // Track current pool size for smarter refill
	createdAt sync.Map     // Track when each connection was created
}

const poolConnMaxAge = 30 * time.Second // Connections older than this are considered stale

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
		p := &dataConnPool{addr: addr, useTLS: useTLS, noDelay: rt.TCPNoDelay, ch: make(chan net.Conn, pc), capacity: int32(pc)}
		pools[name] = p
		// Warmup pool in parallel for faster startup
		go p.warmup(ctx, cfg, pc)
		go p.fillLoop(ctx, cfg)
	}
	return pools
}

func (p *dataConnPool) warmup(ctx context.Context, cfg Config, count int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16) // Allow 16 concurrent handshakes
	
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			
			c, err := dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
			if err == nil {
				select {
				case p.ch <- c:
					p.createdAt.Store(c, time.Now())
					p.size.Add(1)
				case <-ctx.Done():
					_ = c.Close()
				default:
					_ = c.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func (p *dataConnPool) isStale(c net.Conn) bool {
	if created, ok := p.createdAt.Load(c); ok {
		if time.Since(created.(time.Time)) > poolConnMaxAge {
			return true
		}
	}
	return false
}

func (p *dataConnPool) tryGet() net.Conn {
	for {
		select {
		case c := <-p.ch:
			p.size.Add(-1)
			// Check staleness before deleting tracking metadata.
			stale := p.isStale(c)
			p.createdAt.Delete(c)
			if stale {
				_ = c.Close()
				continue // Try to get another
			}
			return c
		default:
			return nil
		}
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

	backoff := 25 * time.Millisecond // Start with lower backoff for faster refill
	for {
		if ctx.Err() != nil {
			return
		}

		// Only fill if pool is below half capacity for more aggressive refill
		currentSize := p.size.Load()
		if currentSize >= p.capacity {
			// Pool is full, wait a bit before checking again
			t := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}

		// Determine how many connections to create in parallel
		missing := int(p.capacity - currentSize)
		if missing > 4 {
			missing = 4 // Limit parallel dials
		}
		
		var wg sync.WaitGroup
		for i := 0; i < missing; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
				if err != nil {
					return
				}
				select {
				case p.ch <- c:
					p.createdAt.Store(c, time.Now())
					p.size.Add(1)
				case <-ctx.Done():
					_ = c.Close()
				default:
					_ = c.Close()
				}
			}()
		}
		wg.Wait()
		
		// Check if we successfully added any connections
		if p.size.Load() < p.capacity {
			// Still not full, backoff
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if backoff < 500*time.Millisecond {
				backoff *= 2
				if backoff > 500*time.Millisecond {
					backoff = 500 * time.Millisecond
				}
			}
		} else {
			backoff = 25 * time.Millisecond // Reset backoff on success
		}
	}
}
