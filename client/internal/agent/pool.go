package agent

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/connutil"
	"hostit/shared/logging"
)

type dataConnPool struct {
	addr      string
	useTLS    bool
	noDelay   bool
	ch        chan net.Conn
	capacity  int32
	size      atomic.Int32 // Track current pool size for smarter refill
	createdAt sync.Map     // Track when each connection was created

	// Health metrics
	totalCreated   atomic.Int64 // Total connections created
	totalReused    atomic.Int64 // Connections reused from pool
	totalStale     atomic.Int64 // Connections discarded as stale
	totalDialFails atomic.Int64 // Failed dial attempts
}

// PoolStats returns current pool statistics for monitoring.
type PoolStats struct {
	Addr         string `json:"addr"`
	UseTLS       bool   `json:"use_tls"`
	Capacity     int32  `json:"capacity"`
	CurrentSize  int32  `json:"current_size"`
	TotalCreated int64  `json:"total_created"`
	TotalReused  int64  `json:"total_reused"`
	TotalStale   int64  `json:"total_stale"`
	TotalDialFails int64 `json:"total_dial_fails"`
	HitRate      float64 `json:"hit_rate"` // Percentage of requests served from pool
}

func (p *dataConnPool) Stats() PoolStats {
	created := p.totalCreated.Load()
	reused := p.totalReused.Load()
	total := created + reused
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(reused) / float64(total) * 100
	}
	return PoolStats{
		Addr:         p.addr,
		UseTLS:       p.useTLS,
		Capacity:     p.capacity,
		CurrentSize:  p.size.Load(),
		TotalCreated: created,
		TotalReused:  reused,
		TotalStale:   p.totalStale.Load(),
		TotalDialFails: p.totalDialFails.Load(),
		HitRate:      hitRate,
	}
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
			if err != nil {
				p.totalDialFails.Add(1)
				return
			}
			p.totalCreated.Add(1)
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
}

func (p *dataConnPool) isStale(c net.Conn) bool {
	if created, ok := p.createdAt.Load(c); ok {
		if time.Since(created.(time.Time)) > poolConnMaxAge {
			return true
		}
	}
	return false
}

// connectionValidator is used to check if pooled connections are still healthy.
var connectionValidator = connutil.NewValidator(5 * time.Millisecond)

func (p *dataConnPool) tryGet() net.Conn {
	for {
		select {
		case c := <-p.ch:
			p.size.Add(-1)
			// Check staleness before deleting tracking metadata.
			stale := p.isStale(c)
			p.createdAt.Delete(c)
			if stale {
				p.totalStale.Add(1)
				log.Debugf(logging.CatData, "pool %s: discarding stale connection", p.addr)
				_ = c.Close()
				continue // Try to get another
			}
			// Validate the connection is still alive before reusing
			if !connectionValidator.IsAlive(c) {
				p.totalStale.Add(1)
				log.Debugf(logging.CatData, "pool %s: discarding dead connection", p.addr)
				_ = c.Close()
				continue // Try to get another
			}
			p.totalReused.Add(1)
			return c
		default:
			return nil
		}
	}
}

func (p *dataConnPool) getOrDial(ctx context.Context, cfg Config) (net.Conn, error) {
	if c := p.tryGet(); c != nil {
		log.Debugf(logging.CatData, "pool %s: reused connection (size=%d)", p.addr, p.size.Load())
		return c, nil
	}
	log.Debugf(logging.CatData, "pool %s: dialing new connection", p.addr)
	c, err := dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
	if err != nil {
		p.totalDialFails.Add(1)
		log.Warnf(logging.CatData, "pool %s: dial failed: %v", p.addr, err)
		return nil, err
	}
	p.totalCreated.Add(1)
	return c, nil
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
		dialFailures := int32(0)
		for i := 0; i < missing; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := dialTCPData(ctx, cfg, p.addr, p.noDelay, p.useTLS)
				if err != nil {
					atomic.AddInt32(&dialFailures, 1)
					p.totalDialFails.Add(1)
					return
				}
				p.totalCreated.Add(1)
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
