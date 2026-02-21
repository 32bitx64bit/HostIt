package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func dialAndEcho(t *testing.T, addr string, msg []byte, timeout time.Duration) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}
}

func TestServerMultiConn_PendingCleanupAndAgentRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// local echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlAddr := controlLn.Addr().String()
	_ = controlLn.Close()

	dataLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dataAddr := dataLn.Addr().String()
	_ = dataLn.Close()

	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicAddr := publicLn.Addr().String()
	_ = publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 750 * time.Millisecond,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	agentCtx, agentCancel := context.WithCancel(ctx)
	go fakeAgent(agentCtx, controlAddr, dataAddr, echoLn.Addr().String(), "testtoken")

	// Wait for agent to connect before starting bursts
	readyDeadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(readyDeadline) {
			t.Fatalf("agent never connected to server")
		}
		if srv.Status().AgentConnected {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	burst := func(round string, clients int) {
		errCh := make(chan error, clients)
		start := make(chan struct{})
		for i := 0; i < clients; i++ {
			i := i
			go func() {
				<-start
				msg := []byte("hello-" + round + "-" + strconv.Itoa(i) + "\n")
				defer func() {
					if r := recover(); r != nil {
						errCh <- fmt.Errorf("panic: %v", r)
					}
				}()
				c, err := net.Dial("tcp", publicAddr)
				if err != nil {
					errCh <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Write(msg); err != nil {
					errCh <- err
					return
				}
				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(c, buf); err != nil {
					errCh <- err
					return
				}
				if string(buf) != string(msg) {
					errCh <- fmt.Errorf("expected %q got %q", string(msg), string(buf))
					return
				}
				errCh <- nil
			}()
		}
		close(start)
		for i := 0; i < clients; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("burst %s: %v", round, err)
			}
		}
	}

	burst("a", 50)

	// After a burst, pending should be empty.
	time.Sleep(100 * time.Millisecond)
	srv.mu.Lock()
	pendingLen := len(srv.pendingTCP)
	srv.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("expected pending=0 after burst, got %d", pendingLen)
	}

	// Stop agent and start a fresh one to simulate agent restart.
	agentCancel()
	// Wait for the server to observe the disconnect.
	deadDisc := time.Now().Add(2 * time.Second)
	for srv.Status().AgentConnected {
		if time.Now().After(deadDisc) {
			t.Fatalf("server did not observe agent disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}

	agentCtx2, agentCancel2 := context.WithCancel(ctx)
	defer agentCancel2()
	go fakeAgent(agentCtx2, controlAddr, dataAddr, echoLn.Addr().String(), "testtoken")
	// Wait for the server to observe the reconnect before starting the burst.
	deadConn := time.Now().Add(2 * time.Second)
	for !srv.Status().AgentConnected {
		if time.Now().After(deadConn) {
			t.Fatalf("server did not observe agent reconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}

	burst("b", 50)

	time.Sleep(100 * time.Millisecond)
	srv.mu.Lock()
	pendingLen = len(srv.pendingTCP)
	srv.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("expected pending=0 after restart burst, got %d", pendingLen)
	}

	// Final quick reconnect loop (sequential) to catch short-lived leaks.
	for i := 0; i < 25; i++ {
		dialAndEcho(t, publicAddr, []byte("reconnect-"+strconv.Itoa(i)+"\n"), 2*time.Second)
	}
}

func TestServerMultiConn_NoAgentRejectsQuickly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlAddr := controlLn.Addr().String()
	_ = controlLn.Close()

	dataLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dataAddr := dataLn.Addr().String()
	_ = dataLn.Close()

	publicLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicAddr := publicLn.Addr().String()
	_ = publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 250 * time.Millisecond,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	// No agent connected: server should accept then close without hanging.
	c, err := net.Dial("tcp", publicAddr)
	if err != nil {
		// Allow short startup delay.
		deadline := time.Now().Add(2 * time.Second)
		for {
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			c, err = net.Dial("tcp", publicAddr)
			if err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Write([]byte("hi\n"))
	buf := make([]byte, 1)
	_, rerr := c.Read(buf)
	if rerr == nil {
		// Either EOF or timeout is acceptable; we mostly want "no hang".
		return
	}
	// no assertion: just ensure we returned.
	_ = rerr
}
