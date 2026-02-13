package udputil

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
)

// PacketHandler processes a UDP packet. The handler takes ownership of the buffer
// and must return it to the pool via bufPtr when done.
type PacketHandler func(data []byte, n int, addr net.Addr, bufPtr *[]byte)

// MultiReaderConfig configures the multi-reader UDP packet processor.
type MultiReaderConfig struct {
	// Address to listen on
	Addr string

	// Number of reader goroutines (default: GOMAXPROCS)
	Readers int

	// Buffer size for each reader's queue (default: 4096)
	QueueSize int

	// UDP buffer size (default: 8MB)
	UDPBufSize int

	// Whether to use SO_REUSEPORT for true parallel reads
	UseReusePort bool
}

// MultiReaderStats holds statistics for the multi-reader.
type MultiReaderStats struct {
	PacketsReceived atomic.Uint64
	PacketsDropped  atomic.Uint64
	BytesReceived   atomic.Uint64
	ReadersActive   atomic.Int32
}

// MultiReaderUDP processes UDP packets using multiple parallel readers.
// On Linux with SO_REUSEPORT, each reader gets its own socket bound to the
// same port, allowing the kernel to distribute packets across them.
// On other platforms, a single reader distributes to worker goroutines.
type MultiReaderUDP struct {
	cfg    MultiReaderConfig
	stats  MultiReaderStats
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	conns  []*net.UDPConn
}

// NewMultiReaderUDP creates a new multi-reader UDP processor.
func NewMultiReaderUDP(ctx context.Context, cfg MultiReaderConfig) (*MultiReaderUDP, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Apply defaults
	if cfg.Readers <= 0 {
		cfg.Readers = runtime.GOMAXPROCS(0)
		if cfg.Readers < 2 {
			cfg.Readers = 2
		}
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.UDPBufSize <= 0 {
		cfg.UDPBufSize = 8 * 1024 * 1024 // 8MB
	}

	mr := &MultiReaderUDP{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		conns:  make([]*net.UDPConn, 0, cfg.Readers),
	}

	return mr, nil
}

// Start begins processing packets with the given handler.
// The handler takes ownership of the buffer and must call ReturnBuffer(bufPtr).
func (mr *MultiReaderUDP) Start(handler PacketHandler) error {
	// On Linux with UseReusePort, create multiple sockets
	// On other platforms, create one socket and distribute to workers
	numSockets := 1
	if mr.cfg.UseReusePort {
		numSockets = mr.cfg.Readers
	}

	// Create sockets
	for i := 0; i < numSockets; i++ {
		var conn *net.UDPConn
		var err error

		if mr.cfg.UseReusePort {
			conn, err = ListenUDPWithReusePort("udp", mr.cfg.Addr)
		} else {
			var udpAddr *net.UDPAddr
			udpAddr, err = net.ResolveUDPAddr("udp", mr.cfg.Addr)
			if err == nil {
				conn, err = net.ListenUDP("udp", udpAddr)
			}
		}

		if err != nil {
			mr.Stop()
			return err
		}

		// Set buffer sizes
		_ = conn.SetReadBuffer(mr.cfg.UDPBufSize)
		_ = conn.SetWriteBuffer(mr.cfg.UDPBufSize)

		mr.conns = append(mr.conns, conn)
	}

	// Start readers
	for i, conn := range mr.conns {
		mr.wg.Add(1)
		mr.stats.ReadersActive.Add(1)

		go mr.readerLoop(i, conn, handler)
	}

	return nil
}

// readerLoop reads packets from a single connection.
func (mr *MultiReaderUDP) readerLoop(readerID int, conn *net.UDPConn, handler PacketHandler) {
	defer mr.wg.Done()
	defer mr.stats.ReadersActive.Add(-1)

	// Use a local buffer pool for this reader
	localPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}

	for {
		select {
		case <-mr.ctx.Done():
			return
		default:
		}

		// Get buffer from pool
		bufPtr := localPool.Get().(*[]byte)
		buf := *bufPtr

		// Read packet
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Return buffer on error
			localPool.Put(bufPtr)

			if mr.ctx.Err() != nil {
				return // Context cancelled
			}

			// Log error but continue
			continue
		}

		// Update stats
		mr.stats.PacketsReceived.Add(1)
		mr.stats.BytesReceived.Add(uint64(n))

		// Call handler - handler takes ownership of buffer
		handler(buf[:n], n, addr, bufPtr)
	}
}

// Stats returns current statistics.
func (mr *MultiReaderUDP) Stats() *MultiReaderStats {
	return &mr.stats
}

// Stop gracefully shuts down the reader.
func (mr *MultiReaderUDP) Stop() {
	mr.cancel()

	// Close all connections
	for _, conn := range mr.conns {
		if conn != nil {
			_ = conn.Close()
		}
	}

	mr.wg.Wait()
}

// DialerUDP creates a connected UDP socket for sending/receiving to a specific peer.
// This is used by the client side which connects to a server.
type DialerUDP struct {
	conn       *net.UDPConn
	stats      MultiReaderStats
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	readers    int
	queueSize  int
	udpBufSize int
}

// NewDialerUDP creates a connected UDP socket.
func NewDialerUDP(ctx context.Context, localAddr, remoteAddr string, readers, queueSize, udpBufSize int) (*DialerUDP, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Apply defaults
	if readers <= 0 {
		readers = runtime.GOMAXPROCS(0)
		if readers < 2 {
			readers = 2
		}
	}
	if queueSize <= 0 {
		queueSize = 8192
	}
	if udpBufSize <= 0 {
		udpBufSize = 8 * 1024 * 1024
	}

	// Resolve addresses
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	// Create connected socket
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		cancel()
		return nil, err
	}

	// Set buffer sizes
	_ = conn.SetReadBuffer(udpBufSize)
	_ = conn.SetWriteBuffer(udpBufSize)

	return &DialerUDP{
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
		readers:    readers,
		queueSize:  queueSize,
		udpBufSize: udpBufSize,
	}, nil
}

// Conn returns the underlying UDP connection for writing.
func (d *DialerUDP) Conn() *net.UDPConn {
	return d.conn
}

// StartReaders starts multiple reader goroutines that process incoming packets.
// For connected UDP sockets, we can't use SO_REUSEPORT, so we use a single reader
// that distributes to multiple workers.
func (d *DialerUDP) StartReaders(handler PacketHandler) {
	// Create job queue
	type job struct {
		data   []byte
		n      int
		addr   net.Addr
		bufPtr *[]byte
	}
	jobs := make(chan job, d.queueSize)

	// Start workers
	for i := 0; i < d.readers; i++ {
		d.wg.Add(1)
		d.stats.ReadersActive.Add(1)

		go func() {
			defer d.wg.Done()
			defer d.stats.ReadersActive.Add(-1)

			for j := range jobs {
				handler(j.data, j.n, j.addr, j.bufPtr)
			}
		}()
	}

	// Start single reader that distributes to workers
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer close(jobs)

		localPool := &sync.Pool{
			New: func() any {
				b := make([]byte, 64*1024)
				return &b
			},
		}

		for {
			select {
			case <-d.ctx.Done():
				return
			default:
			}

			bufPtr := localPool.Get().(*[]byte)
			buf := *bufPtr

			n, addr, err := d.conn.ReadFromUDP(buf)
			if err != nil {
				localPool.Put(bufPtr)
				if d.ctx.Err() != nil {
					return
				}
				continue
			}

			d.stats.PacketsReceived.Add(1)
			d.stats.BytesReceived.Add(uint64(n))

			// Try to dispatch to worker
			select {
			case jobs <- job{data: buf[:n], n: n, addr: addr, bufPtr: bufPtr}:
				// Dispatched successfully
			default:
				// Queue full - drop packet
				d.stats.PacketsDropped.Add(1)
				localPool.Put(bufPtr)
			}
		}
	}()
}

// Stats returns current statistics.
func (d *DialerUDP) Stats() *MultiReaderStats {
	return &d.stats
}

// Stop gracefully shuts down the dialer.
func (d *DialerUDP) Stop() {
	d.cancel()
	if d.conn != nil {
		_ = d.conn.Close()
	}
	d.wg.Wait()
}
