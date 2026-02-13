package agent

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/udputil"
)

// PacketPriority represents the priority level of a packet.
type PacketPriority int

const (
	// PriorityControl is for control packets (registration, keepalives).
	// These are sent first and should never be dropped.
	PriorityControl PacketPriority = iota
	// PriorityData is for regular data packets.
	// These are sent after control packets and may be dropped under pressure.
	PriorityData
)

// priorityPacket wraps a packet with its priority and metadata.
type priorityPacket struct {
	data     []byte
	bufPtr   *[]byte
	priority PacketPriority
	addr     string // For logging/debugging
	enqueue  time.Time
}

// PriorityWriteQueue is a write queue that prioritizes control packets over data packets.
// It maintains separate queues for each priority level and always drains the control
// queue before the data queue.
type PriorityWriteQueue struct {
	// Separate queues for each priority level
	controlQueue chan priorityPacket
	dataQueue    chan priorityPacket

	// Stats
	stats        *udputil.Stats
	depth        atomic.Int32
	controlDepth atomic.Int32
	dataDepth    atomic.Int32
	capacity     int
	drops        atomic.Uint64
	avgLatency   atomic.Int64

	// Congestion control
	congestionMode    atomic.Bool
	lastDropTime      atomic.Int64
	congestionBackoff atomic.Int64

	// Wait signal for data queue when control queue has items
	controlPending atomic.Bool
	dataWaiters    atomic.Int32
}

// NewPriorityWriteQueue creates a new priority write queue.
func NewPriorityWriteQueue(capacity int, stats *udputil.Stats) *PriorityWriteQueue {
	// Split capacity between control and data queues
	// Control queue is smaller since control packets are rare
	controlCap := capacity / 16
	if controlCap < 64 {
		controlCap = 64
	}
	if controlCap > 1024 {
		controlCap = 1024
	}
	dataCap := capacity - controlCap

	return &PriorityWriteQueue{
		controlQueue: make(chan priorityPacket, controlCap),
		dataQueue:    make(chan priorityPacket, dataCap),
		capacity:     capacity,
		stats:        stats,
	}
}

// EnqueueControl enqueues a control packet with high priority.
// Control packets are never dropped - if the queue is full, it blocks.
func (q *PriorityWriteQueue) EnqueueControl(ctx context.Context, data []byte, bufPtr *[]byte) error {
	pkt := priorityPacket{
		data:     data,
		bufPtr:   bufPtr,
		priority: PriorityControl,
		enqueue:  time.Now(),
	}

	select {
	case q.controlQueue <- pkt:
		q.depth.Add(1)
		q.controlDepth.Add(1)
		q.controlPending.Store(true)
		return nil
	case <-ctx.Done():
		if bufPtr != nil {
			// Return buffer to pool on failure
		}
		return ctx.Err()
	}
}

// EnqueueData enqueues a data packet with normal priority.
// If the data queue is full, it returns an error immediately (drop).
func (q *PriorityWriteQueue) EnqueueData(data []byte, bufPtr *[]byte, timeout time.Duration) error {
	pkt := priorityPacket{
		data:     data,
		bufPtr:   bufPtr,
		priority: PriorityData,
		enqueue:  time.Now(),
	}

	// If control queue has items, data packets wait briefly
	if q.controlPending.Load() {
		// Wait for control queue to drain
		waitStart := time.Now()
		for q.controlPending.Load() && time.Since(waitStart) < timeout/2 {
			time.Sleep(10 * time.Microsecond)
		}
	}

	var timer *time.Timer
	var timerChan <-chan time.Time
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timerChan = timer.C
	}

	select {
	case q.dataQueue <- pkt:
		q.depth.Add(1)
		q.dataDepth.Add(1)
		return nil
	case <-timerChan:
		q.drops.Add(1)
		q.enterCongestionMode()
		if bufPtr != nil {
			// Return buffer to pool
		}
		return context.DeadlineExceeded
	default:
		q.drops.Add(1)
		q.enterCongestionMode()
		if bufPtr != nil {
			// Return buffer to pool
		}
		return context.DeadlineExceeded
	}
}

// Dequeue returns the next packet to send, prioritizing control packets.
// Control packets are always returned before data packets.
func (q *PriorityWriteQueue) Dequeue(ctx context.Context) (priorityPacket, bool) {
	// First, check control queue (non-blocking)
	select {
	case pkt := <-q.controlQueue:
		q.depth.Add(-1)
		q.controlDepth.Add(-1)
		if len(q.controlQueue) == 0 {
			q.controlPending.Store(false)
		}
		q.updateLatency(pkt)
		return pkt, true
	default:
	}

	// Then check data queue (non-blocking)
	select {
	case pkt := <-q.dataQueue:
		q.depth.Add(-1)
		q.dataDepth.Add(-1)
		q.updateLatency(pkt)
		return pkt, true
	default:
	}

	// Block waiting for either queue - this is the slow path
	select {
	case pkt := <-q.controlQueue:
		q.depth.Add(-1)
		q.controlDepth.Add(-1)
		if len(q.controlQueue) == 0 {
			q.controlPending.Store(false)
		}
		q.updateLatency(pkt)
		return pkt, true
	case pkt := <-q.dataQueue:
		q.depth.Add(-1)
		q.dataDepth.Add(-1)
		q.updateLatency(pkt)
		return pkt, true
	case <-ctx.Done():
		return priorityPacket{}, false
	}
}

// DequeueBatch returns up to n packets for batch sending.
// Control packets are always returned first.
func (q *PriorityWriteQueue) DequeueBatch(ctx context.Context, n int) []priorityPacket {
	if n <= 0 {
		return nil
	}

	packets := make([]priorityPacket, 0, n)

	// First, drain control queue
	for len(packets) < n {
		select {
		case pkt := <-q.controlQueue:
			q.depth.Add(-1)
			q.controlDepth.Add(-1)
			q.updateLatency(pkt)
			packets = append(packets, pkt)
		default:
			// No more control packets
			goto dataQueue
		}
	}
	q.controlPending.Store(false)

dataQueue:
	// Then, drain data queue
	for len(packets) < n {
		select {
		case pkt := <-q.dataQueue:
			q.depth.Add(-1)
			q.dataDepth.Add(-1)
			q.updateLatency(pkt)
			packets = append(packets, pkt)
		default:
			// No more data packets
			return packets
		}
	}

	return packets
}

func (q *PriorityWriteQueue) updateLatency(pkt priorityPacket) {
	if !pkt.enqueue.IsZero() {
		latency := time.Since(pkt.enqueue).Nanoseconds()
		oldAvg := q.avgLatency.Load()
		if oldAvg == 0 {
			q.avgLatency.Store(latency)
		} else {
			newAvg := oldAvg - oldAvg/10 + latency/10
			q.avgLatency.Store(newAvg)
		}
	}
}

func (q *PriorityWriteQueue) enterCongestionMode() {
	q.lastDropTime.Store(time.Now().UnixNano())
	if !q.congestionMode.Swap(true) {
		q.congestionBackoff.Store(100 * 1000) // 100 microseconds
	}
}

func (q *PriorityWriteQueue) maybeExitCongestionMode() {
	if !q.congestionMode.Load() {
		return
	}
	lastDrop := q.lastDropTime.Load()
	if time.Since(time.Unix(0, lastDrop)) > 5*time.Second {
		q.congestionMode.Store(false)
		q.congestionBackoff.Store(0)
		return
	}
	currentBackoff := q.congestionBackoff.Load()
	if currentBackoff > 1000 {
		newBackoff := currentBackoff - currentBackoff/10
		q.congestionBackoff.Store(newBackoff)
	}
}

// Stats returns queue statistics.
func (q *PriorityWriteQueue) Stats() (depth, controlDepth, dataDepth int, drops uint64, avgLatency time.Duration) {
	return int(q.depth.Load()), int(q.controlDepth.Load()), int(q.dataDepth.Load()),
		q.drops.Load(), time.Duration(q.avgLatency.Load())
}

// CongestionBackoff returns the current congestion backoff duration.
func (q *PriorityWriteQueue) CongestionBackoff() time.Duration {
	return time.Duration(q.congestionBackoff.Load())
}

// Close closes both queues.
func (q *PriorityWriteQueue) Close() {
	close(q.controlQueue)
	close(q.dataQueue)
}

// BatchWriter handles batch writing of packets using sendmmsg on Linux.
type BatchWriter struct {
	conn       *net.UDPConn
	queue      *PriorityWriteQueue
	batchSize  int
	stats      *udputil.Stats
	bufferPool *sync.Pool

	// Metrics
	batchesSent atomic.Uint64
	packetsSent atomic.Uint64
}

// NewBatchWriter creates a new batch writer.
func NewBatchWriter(conn *net.UDPConn, queue *PriorityWriteQueue, batchSize int, stats *udputil.Stats) *BatchWriter {
	if batchSize <= 0 {
		batchSize = 16 // Default batch size
	}
	if batchSize > 64 {
		batchSize = 64 // Cap at 64 to avoid excessive latency
	}

	return &BatchWriter{
		conn:      conn,
		queue:     queue,
		batchSize: batchSize,
		stats:     stats,
		bufferPool: &sync.Pool{
			New: func() any {
				b := make([]byte, 64*1024)
				return &b
			},
		},
	}
}

// Run starts the batch writer loop.
func (w *BatchWriter) Run(ctx context.Context) {
	batchTimeout := time.NewTimer(100 * time.Microsecond) // Max wait time to fill a batch
	defer batchTimeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Reset timer for batch timeout
		if !batchTimeout.Stop() {
			select {
			case <-batchTimeout.C:
			default:
			}
		}
		batchTimeout.Reset(100 * time.Microsecond)

		// Collect a batch of packets
		var packets []priorityPacket
		var batchData [][]byte

		// Wait for first packet
		pkt, ok := w.queue.Dequeue(ctx)
		if !ok {
			return
		}
		packets = append(packets, pkt)
		batchData = append(batchData, pkt.data)

		// Collect more packets up to batch size or timeout
		for len(packets) < w.batchSize {
			select {
			case pkt, ok := <-w.queue.dataQueue:
				if !ok {
					goto send
				}
				w.queue.depth.Add(-1)
				w.queue.dataDepth.Add(-1)
				w.queue.updateLatency(pkt)
				packets = append(packets, pkt)
				batchData = append(batchData, pkt.data)
			case <-batchTimeout.C:
				goto send
			default:
				// No more packets immediately available
				goto send
			}
		}

	send:
		// Send batch using sendmmsg (or fallback on non-Linux)
		if len(packets) == 0 {
			continue
		}

		// For connected socket, addrs are nil
		addrs := make([]*net.UDPAddr, len(packets))
		for i := range addrs {
			addrs[i] = nil // Use connected socket
		}

		sent, err := sendmmsg(w.conn, batchData, addrs)
		if err != nil {
			w.queue.enterCongestionMode()
		} else {
			w.queue.maybeExitCongestionMode()
		}

		w.batchesSent.Add(1)
		w.packetsSent.Add(uint64(sent))

		// Return buffers to pool
		for _, pkt := range packets {
			if pkt.bufPtr != nil {
				w.bufferPool.Put(pkt.bufPtr)
			}
		}

		// Update stats
		if w.stats != nil {
			for i := 0; i < sent; i++ {
				w.stats.RecordSend(len(packets[i].data))
			}
		}
	}
}

// Stats returns batch writer statistics.
func (w *BatchWriter) Stats() (batches, packets uint64) {
	return w.batchesSent.Load(), w.packetsSent.Load()
}
