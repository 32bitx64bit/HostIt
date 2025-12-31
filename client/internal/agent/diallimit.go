package agent

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var dataDialLimiterOnce sync.Once
var dataDialLimiter chan struct{}

func initDataDialLimiter() {
	dataDialLimiterOnce.Do(func() {
		// A burst of TLS handshakes (from Preconnect across many routes) can make the
		// agent feel slow/laggy. Limit concurrent data dials to keep connect smooth.
		//
		// Tuning: set HOSTIT_DATA_DIAL_CONCURRENCY (or PLAYIT_DATA_DIAL_CONCURRENCY).
		// Default increased to 16 for better handling of connection bursts.
		n := 16
		// Precedence: PLAYIT_ overrides HOSTIT_.
		v := strings.TrimSpace(os.Getenv("HOSTIT_DATA_DIAL_CONCURRENCY"))
		if vp := strings.TrimSpace(os.Getenv("PLAYIT_DATA_DIAL_CONCURRENCY")); vp != "" {
			v = vp
		}
		if v != "" {
			if x, err := strconv.Atoi(v); err == nil {
				if x < 1 {
					x = 1
				}
				if x > 128 {
					x = 128
				}
				n = x
			}
		}
		dataDialLimiter = make(chan struct{}, n)
	})
}

func acquireDataDialSlot(ctx context.Context) bool {
	initDataDialLimiter()
	select {
	case dataDialLimiter <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseDataDialSlot() {
	select {
	case <-dataDialLimiter:
	default:
	}
}

func dialTCPData(ctx context.Context, cfg Config, addr string, noDelay bool, useTLS bool) (net.Conn, error) {
	if !acquireDataDialSlot(ctx) {
		return nil, context.Canceled
	}
	defer releaseDataDialSlot()
	return dialTCP(cfg, addr, noDelay, useTLS)
}
