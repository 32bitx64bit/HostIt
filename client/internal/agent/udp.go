package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/logging"
	"hostit/shared/udputil"
)

// UDPClient handles UDP tunneling from local applications to the server.
// It provides high-throughput UDP forwarding with encryption support.
type UDPClient struct {
	cfg        Config
	dataAddr   string
	routes     map[string]RemoteRoute
	keys       *udputil.KeySet
	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	// Session tracking for local UDP endpoints
	sessionsMu sync.RWMutex
	sessions   map[string]*udpSession // key: routeName:localAddr

	// Statistics
	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64
	bytesIn    atomic.Uint64
	bytesOut   atomic.Uint64

	// Worker pools
	workers int

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type udpSession struct {
	localConn *net.UDPConn
	routeName string
	lastSeen  atomic.Int64
}

// NewUDPClient creates a new UDP client for tunneling.
func NewUDPClient(cfg Config, dataAddr string, routes map[string]RemoteRoute) *UDPClient {
	workers := runtime.NumCPU() * 2
	if workers < 4 {
		workers = 4
	}
	if workers > 32 {
		workers = 32
	}
	if n := os.Getenv("HOSTIT_UDP_WORKERS"); n != "" {
		if w, err := parsePositiveInt(n, workers); err == nil && w > 0 {
			workers = w
		}
	}

	return &UDPClient{
		cfg:      cfg,
		dataAddr: dataAddr,
		routes:   routes,
		sessions: make(map[string]*udpSession),
		workers:  workers,
	}
}

// SetKeys sets the encryption keys received from the server.
func (c *UDPClient) SetKeys(mode string, keyID uint32, saltB64 string, prevKeyID uint32, prevSaltB64 string) error {
	if strings.EqualFold(strings.TrimSpace(mode), "none") {
		c.keys = &udputil.KeySet{}
		return nil
	}

	curSalt, _ := base64.RawStdEncoding.DecodeString(strings.TrimSpace(saltB64))
	prevSalt, _ := base64.RawStdEncoding.DecodeString(strings.TrimSpace(prevSaltB64))

	ks, err := udputil.NewKeySet(mode, c.cfg.Token, keyID, curSalt, prevKeyID, prevSalt)
	if err != nil {
		return err
	}
	c.keys = ks
	return nil
}

// Start begins the UDP client operations.
func (c *UDPClient) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Resolve server address
	serverHost, serverPort, err := net.SplitHostPort(c.dataAddr)
	if err != nil {
		return err
	}
	// For UDP, we connect to the data address
	c.serverAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(serverHost, serverPort))
	if err != nil {
		return err
	}

	// Create local UDP socket
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return err
	}
	c.conn, err = net.ListenUDP("udp", localAddr)
	if err != nil {
		return err
	}

	// Set buffer sizes
	if err := c.conn.SetReadBuffer(64 * 1024 * 1024); err != nil {
		log.Warnf(logging.CatUDP, "failed to set UDP read buffer: %v", err)
	}
	if err := c.conn.SetWriteBuffer(64 * 1024 * 1024); err != nil {
		log.Warnf(logging.CatUDP, "failed to set UDP write buffer: %v", err)
	}

	// Start registration loop
	c.wg.Add(1)
	go c.registrationLoop()

	// Start packet readers
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go c.readLoop()
	}

	// Start session cleaner
	c.wg.Add(1)
	go c.sessionCleaner()

	log.Infof(logging.CatUDP, "UDP client started, local=%v server=%v workers=%d", c.conn.LocalAddr(), c.serverAddr, c.workers)
	return nil
}

// Stop stops the UDP client.
func (c *UDPClient) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.wg.Wait()

	// Close all local connections
	c.sessionsMu.Lock()
	for _, s := range c.sessions {
		if s.localConn != nil {
			_ = s.localConn.Close()
		}
	}
	c.sessionsMu.Unlock()

	log.Infof(logging.CatUDP, "UDP client stopped (packets_in=%d packets_out=%d bytes_in=%d bytes_out=%d)",
		c.packetsIn.Load(), c.packetsOut.Load(), c.bytesIn.Load(), c.bytesOut.Load())
}

// registrationLoop periodically sends registration packets to the server.
func (c *UDPClient) registrationLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Send initial registration
	c.sendRegistration()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.sendRegistration()
		}
	}
}

func (c *UDPClient) sendRegistration() {
	if c.conn == nil || c.serverAddr == nil {
		return
	}

	pkt := udputil.EncodeRegister(c.cfg.Token)
	if c.keys != nil && c.keys.HasKey() {
		pkt = c.keys.Encrypt(pkt)
	}

	_, err := c.conn.WriteToUDP(pkt, c.serverAddr)
	if err != nil {
		log.Debugf(logging.CatUDP, "registration send failed: %v", err)
	}
}

// readLoop reads packets from the server and forwards to local applications.
func (c *UDPClient) readLoop() {
	defer c.wg.Done()

	bufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		bufPtr := bufPool.Get().(*[]byte)
		n, addr, err := c.conn.ReadFromUDP(*bufPtr)
		if err != nil {
			bufPool.Put(bufPtr)
			if c.ctx.Err() != nil {
				return
			}
			if isTemporaryError(err) {
				continue
			}
			log.Debugf(logging.CatUDP, "read error: %v", err)
			return
		}

		c.packetsIn.Add(1)
		c.bytesIn.Add(uint64(n))

		pkt := (*bufPtr)[:n]
		c.handleServerPacket(pkt, addr)
		bufPool.Put(bufPtr)
	}
}

func (c *UDPClient) handleServerPacket(pkt []byte, addr *net.UDPAddr) {
	// Decrypt if needed
	if c.keys != nil && c.keys.HasKey() {
		decrypted, ok := c.keys.Decrypt(pkt)
		if !ok {
			log.Debugf(logging.CatUDP, "decryption failed")
			return
		}
		pkt = decrypted
	}

	if len(pkt) == 0 {
		return
	}

	switch pkt[0] {
	case udputil.TypeData:
		route, client, payload, ok := udputil.DecodeData(pkt)
		if !ok {
			log.Debugf(logging.CatUDP, "invalid DATA packet")
			return
		}
		c.forwardToLocal(route, client, payload)
	case udputil.TypePong:
		// Handle pong for latency measurement if needed
	}
}

// forwardToLocal forwards a packet from the server to a local UDP application.
func (c *UDPClient) forwardToLocal(routeName, clientAddr string, payload []byte) {
	rt, ok := c.routes[routeName]
	if !ok {
		log.Debugf(logging.CatUDP, "unknown route: %s", routeName)
		return
	}

	// Get local target address
	localAddr, ok := localTargetFromPublicAddr(rt.PublicAddr)
	if !ok {
		return
	}

	// Resolve local address
	localUDP, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Debugf(logging.CatUDP, "resolve local addr failed: %v", err)
		return
	}

	// Get or create session
	session := c.getOrCreateSession(routeName, clientAddr, localUDP)
	if session == nil {
		return
	}

	// Forward to local application
	_, err = session.localConn.WriteToUDP(payload, localUDP)
	if err != nil {
		log.Debugf(logging.CatUDP, "write to local failed: %v", err)
		return
	}

	c.packetsOut.Add(1)
	c.bytesOut.Add(uint64(len(payload)))
}

func (c *UDPClient) getOrCreateSession(routeName, clientAddr string, localUDP *net.UDPAddr) *udpSession {
	key := routeName + ":" + clientAddr

	c.sessionsMu.RLock()
	session, ok := c.sessions[key]
	c.sessionsMu.RUnlock()

	if ok {
		session.lastSeen.Store(time.Now().UnixNano())
		return session
	}

	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()

	// Double check
	if session, ok = c.sessions[key]; ok {
		session.lastSeen.Store(time.Now().UnixNano())
		return session
	}

	// Create new local UDP connection
	localConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Debugf(logging.CatUDP, "create local UDP socket failed: %v", err)
		return nil
	}

	session = &udpSession{
		localConn: localConn,
		routeName: routeName,
	}
	session.lastSeen.Store(time.Now().UnixNano())
	c.sessions[key] = session

	// Start reading from local connection
	c.wg.Add(1)
	go c.readFromLocal(key, session)

	return session
}

// readFromLocal reads packets from a local UDP connection and forwards to server.
func (c *UDPClient) readFromLocal(key string, session *udpSession) {
	defer c.wg.Done()
	defer func() {
		c.sessionsMu.Lock()
		delete(c.sessions, key)
		c.sessionsMu.Unlock()
		_ = session.localConn.Close()
	}()

	bufPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		bufPtr := bufPool.Get().(*[]byte)
		n, _, err := session.localConn.ReadFromUDP(*bufPtr)
		if err != nil {
			bufPool.Put(bufPtr)
			if c.ctx.Err() != nil {
				return
			}
			if isTemporaryError(err) {
				continue
			}
			return
		}

		// Encode and send to server
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			bufPool.Put(bufPtr)
			continue
		}
		routeName := parts[0]
		clientAddr := parts[1]

		pkt := udputil.EncodeData(routeName, clientAddr, (*bufPtr)[:n])
		if c.keys != nil && c.keys.HasKey() {
			pkt = c.keys.Encrypt(pkt)
		}

		_, err = c.conn.WriteToUDP(pkt, c.serverAddr)
		bufPool.Put(bufPtr)

		if err != nil {
			log.Debugf(logging.CatUDP, "write to server failed: %v", err)
			continue
		}

		c.packetsOut.Add(1)
		c.bytesOut.Add(uint64(len(pkt)))
	}
}

// sessionCleaner periodically removes idle sessions.
func (c *UDPClient) sessionCleaner() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	const sessionTimeout = 5 * time.Minute

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanIdleSessions(sessionTimeout)
		}
	}
}

func (c *UDPClient) cleanIdleSessions(timeout time.Duration) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()

	now := time.Now()
	for key, session := range c.sessions {
		lastSeen := time.Unix(0, session.lastSeen.Load())
		if now.Sub(lastSeen) > timeout {
			_ = session.localConn.Close()
			delete(c.sessions, key)
		}
	}
}

// Stats returns current UDP statistics.
func (c *UDPClient) Stats() (packetsIn, packetsOut, bytesIn, bytesOut uint64) {
	return c.packetsIn.Load(), c.packetsOut.Load(), c.bytesIn.Load(), c.bytesOut.Load()
}

// Helper functions

func parsePositiveInt(s string, def int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def, err
	}
	if n < 1 {
		return def, nil
	}
	return n, nil
}

func isTemporaryError(err error) bool {
	if ne, ok := err.(interface{ Temporary() bool }); ok {
		return ne.Temporary()
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok {
		return ne.Timeout()
	}
	return false
}
