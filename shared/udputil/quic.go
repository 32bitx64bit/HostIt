package udputil

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// QUIC support for improved UDP transport reliability.
// This is opt-in and disabled by default.

var (
	// ErrQUICNotEnabled is returned when QUIC operations are attempted but QUIC is disabled.
	ErrQUICNotEnabled = errors.New("QUIC protocol not enabled")

	// ErrQUICConfigInvalid is returned when QUIC configuration is invalid.
	ErrQUICConfigInvalid = errors.New("invalid QUIC configuration")
)

// QUICConfig contains configuration for QUIC transport.
type QUICConfig struct {
	// Enabled controls whether QUIC is used (default: false).
	Enabled bool `json:"enabled"`

	// MaxIdleTimeout is the maximum duration a connection can be idle.
	MaxIdleTimeout time.Duration `json:"max_idle_timeout"`

	// MaxStreams is the maximum number of concurrent streams per connection.
	MaxStreams int64 `json:"max_streams"`

	// KeepAlivePeriod is the interval between keep-alive packets.
	KeepAlivePeriod time.Duration `json:"keep_alive_period"`

	// InitialStreamReceiveWindow is the initial stream receive window.
	InitialStreamReceiveWindow uint64 `json:"initial_stream_receive_window"`

	// InitialConnectionReceiveWindow is the initial connection receive window.
	InitialConnectionReceiveWindow uint64 `json:"initial_connection_receive_window"`
}

// DefaultQUICConfig returns the default QUIC configuration.
func DefaultQUICConfig() *QUICConfig {
	return &QUICConfig{
		Enabled:                        false, // Off by default
		MaxIdleTimeout:                 30 * time.Second,
		MaxStreams:                     100,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     1 * 1024 * 1024, // 1 MB
		InitialConnectionReceiveWindow: 2 * 1024 * 1024, // 2 MB
	}
}

// Validate validates the QUIC configuration.
func (c *QUICConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.MaxIdleTimeout < 0 {
		return errors.New("max_idle_timeout must be non-negative")
	}
	if c.MaxStreams < 0 {
		return errors.New("max_streams must be non-negative")
	}
	if c.KeepAlivePeriod < 0 {
		return errors.New("keep_alive_period must be non-negative")
	}
	if c.InitialStreamReceiveWindow < 1024 {
		return errors.New("initial_stream_receive_window must be at least 1024")
	}
	if c.InitialConnectionReceiveWindow < 1024 {
		return errors.New("initial_connection_receive_window must be at least 1024")
	}

	return nil
}

// QUICListener is a stub for QUIC listener functionality.
// When QUIC is fully implemented with quic-go, this will be a real listener.
type QUICListener struct {
	config    *QUICConfig
	tlsConfig *tls.Config
	addr      net.Addr
	mu        sync.Mutex
	closed    bool
}

// NewQUICListener creates a new QUIC listener stub.
// This is a placeholder that returns ErrQUICNotEnabled until quic-go is added.
func NewQUICListener(addr string, config *QUICConfig, tlsConfig *tls.Config) (*QUICListener, error) {
	if config == nil || !config.Enabled {
		return nil, ErrQUICNotEnabled
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	return &QUICListener{
		config:    config,
		tlsConfig: tlsConfig,
		addr:      udpAddr,
	}, nil
}

// Accept waits for and returns the next connection.
// This is a stub that blocks until the listener is closed.
func (l *QUICListener) Accept(ctx context.Context) (net.Conn, error) {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}

	// Block until context is done or listener is closed
	<-ctx.Done()
	return nil, ctx.Err()
}

// Close closes the listener.
func (l *QUICListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// Addr returns the listener's network address.
func (l *QUICListener) Addr() net.Addr {
	return l.addr
}

// QUICDialer is a stub for QUIC dialer functionality.
type QUICDialer struct {
	config    *QUICConfig
	tlsConfig *tls.Config
}

// NewQUICDialer creates a new QUIC dialer stub.
func NewQUICDialer(config *QUICConfig, tlsConfig *tls.Config) (*QUICDialer, error) {
	if config == nil || !config.Enabled {
		return nil, ErrQUICNotEnabled
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &QUICDialer{
		config:    config,
		tlsConfig: tlsConfig,
	}, nil
}

// Dial establishes a QUIC connection to the given address.
// This is a stub that returns ErrQUICNotEnabled.
func (d *QUICDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, ErrQUICNotEnabled
}

// QUICConn is a stub for QUIC connection.
type QUICConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
}

// Read reads data from the connection.
func (c *QUICConn) Read(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}

// Write writes data to the connection.
func (c *QUICConn) Write(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}

// Close closes the connection.
func (c *QUICConn) Close() error {
	c.closed = true
	return nil
}

// LocalAddr returns the local network address.
func (c *QUICConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address.
func (c *QUICConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *QUICConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *QUICConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *QUICConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// IsQUICAvailable returns true if QUIC support is compiled in.
// Currently returns false as quic-go is not a dependency.
func IsQUICAvailable() bool {
	return false
}

// Note: To fully implement QUIC support, add quic-go as a dependency:
//
// go get github.com/quic-go/quic-go
//
// Then implement the real listener and dialer using quic-go's API.
// The stub implementations above allow the code to compile and run
// without QUIC, while providing a clear path for future implementation.
