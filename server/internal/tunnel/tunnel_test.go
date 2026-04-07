package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func startEcho(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln, ln.Addr().String()
}

func startPrefixedEcho(t *testing.T, prefix string) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(append([]byte(prefix+":"), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln, ln.Addr().String()
}

func waitEchoReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel %s never became ready", addr)
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("ready\n")
		if _, werr := c.Write(msg); werr != nil {
			_ = c.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(msg))
		_, rerr := io.ReadFull(c, buf)
		_ = c.Close()
		if rerr != nil || string(buf) != string(msg) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return
	}
}

func waitPrefixedEchoReady(t *testing.T, addr, prefix string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel %s never became ready", addr)
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("ready\n")
		if _, werr := c.Write(msg); werr != nil {
			_ = c.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(prefix)+len(msg))
		_, rerr := io.ReadFull(c, buf)
		_ = c.Close()
		if rerr != nil || string(buf) != prefix+string(msg) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return
	}
}

func TestEndToEndTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEcho(t)
	defer echoLn.Close()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{ControlAddr: controlAddr, DataAddr: dataAddr, Routes: []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}}, Token: "testtoken", PairTimeout: 10 * time.Second, DisableTLS: true})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")

	waitEchoReady(t, publicAddr)

	msg := []byte("hello\n")
	c, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q got %q", string(msg), string(buf))
	}
}

func TestEndToEndTCPConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEcho(t)
	defer echoLn.Close()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{ControlAddr: controlAddr, DataAddr: dataAddr, Routes: []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}}, Token: "testtoken", PairTimeout: 10 * time.Second, DisableTLS: true})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")

	waitEchoReady(t, publicAddr)

	const clients = 10
	const rounds = 10

	for r := 0; r < rounds; r++ {
		errCh := make(chan error, clients)
		for i := 0; i < clients; i++ {
			i := i
			go func() {
				client, err := net.Dial("tcp", publicAddr)
				if err != nil {
					errCh <- err
					return
				}
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(5 * time.Second))
				msg := []byte("hello-" + strconv.Itoa(r) + "-" + strconv.Itoa(i) + "\n")
				if _, err := client.Write(msg); err != nil {
					errCh <- err
					return
				}
				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(client, buf); err != nil {
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
		for i := 0; i < clients; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("round %d: %v", r, err)
			}
		}
	}
}

func TestEndToEndTCPConcurrentMultiRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoALn, echoAAddr := startPrefixedEcho(t, "a")
	defer echoALn.Close()
	echoBLn, echoBAddr := startPrefixedEcho(t, "b")
	defer echoBLn.Close()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicALn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAAddr := publicALn.Addr().String()
	publicALn.Close()

	publicBLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicBAddr := publicBLn.Addr().String()
	publicBLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{
			{Name: "route-a", Proto: "tcp", PublicAddr: publicAAddr},
			{Name: "route-b", Proto: "tcp", PublicAddr: publicBAddr},
		},
		Token:       "testtoken",
		PairTimeout: 10 * time.Second,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{
		"route-a": echoAAddr,
		"route-b": echoBAddr,
	}, "testtoken")

	waitPrefixedEchoReady(t, publicAAddr, "a:")
	waitPrefixedEchoReady(t, publicBAddr, "b:")

	targets := []struct {
		addr   string
		prefix string
	}{
		{addr: publicAAddr, prefix: "a:"},
		{addr: publicBAddr, prefix: "b:"},
	}

	const perRoute = 10
	errCh := make(chan error, len(targets)*perRoute)
	for _, target := range targets {
		target := target
		for i := 0; i < perRoute; i++ {
			i := i
			go func() {
				c, err := net.Dial("tcp", target.addr)
				if err != nil {
					errCh <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				msg := []byte("msg-" + strconv.Itoa(i))
				if _, err := c.Write(msg); err != nil {
					errCh <- err
					return
				}
				buf := make([]byte, len(target.prefix)+len(msg))
				if _, err := io.ReadFull(c, buf); err != nil {
					errCh <- err
					return
				}
				want := target.prefix + string(msg)
				if string(buf) != want {
					errCh <- fmt.Errorf("addr %s: expected %q got %q", target.addr, want, string(buf))
					return
				}
				errCh <- nil
			}()
			time.Sleep(5 * time.Millisecond)
		}
	}

	for i := 0; i < len(targets)*perRoute; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPendingTCPKeyIncludesRoute(t *testing.T) {
	a := makePendingTCPKey("route-a", "client-1")
	b := makePendingTCPKey("route-b", "client-1")
	if a == b {
		t.Fatalf("pending TCP keys must differ across routes: %#v %#v", a, b)
	}
}

func TestHelloIncludesLocalAddr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "game",
			Proto:      "both",
			PublicAddr: publicAddr,
			LocalAddr:  "127.0.0.1:47990",
		}},
		Token:       "testtoken",
		PairTimeout: 3 * time.Second,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		conn, err = net.Dial("tcp", controlAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := crypto.AuthenticateClient(conn, "testtoken"); err != nil {
		t.Fatal(err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != protocol.TypeHello {
		t.Fatalf("first packet type = %d, want HELLO", pkt.Type)
	}

	var routes map[string]helloRoute
	if err := json.Unmarshal(pkt.Payload, &routes); err != nil {
		t.Fatal(err)
	}
	rt, ok := routes["game"]
	if !ok {
		t.Fatalf("HELLO routes missing game route: %#v", routes)
	}
	if rt.LocalAddr != "127.0.0.1:47990" {
		t.Fatalf("HELLO LocalAddr = %q, want %q", rt.LocalAddr, "127.0.0.1:47990")
	}
}

func TestNextClientIDIsCompact(t *testing.T) {
	s := &Server{}
	first := s.nextClientID()
	second := s.nextClientID()
	if first == "" || second == "" {
		t.Fatalf("nextClientID returned empty values: %q %q", first, second)
	}
	if first == second {
		t.Fatalf("nextClientID returned duplicate ids: %q", first)
	}
	if len(first) > 16 || len(second) > 16 {
		t.Fatalf("nextClientID should stay compact, got %q (%d) and %q (%d)", first, len(first), second, len(second))
	}
}

func TestServerMultiConn_PendingCleanupAndAgentRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEcho(t)
	defer echoLn.Close()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 3 * time.Second,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	agentCtx, agentCancel := context.WithCancel(ctx)
	go fakeAgent(agentCtx, controlAddr, dataAddr, echoAddr, "testtoken")

	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(readyDeadline) {
			t.Fatalf("agent never connected")
		}
		if srv.Status().AgentConnected {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	burst := func(round string, clients int) {
		errCh := make(chan error, clients)
		for i := 0; i < clients; i++ {
			i := i
			go func() {
				msg := []byte("hello-" + round + "-" + strconv.Itoa(i) + "\n")
				c, err := net.Dial("tcp", publicAddr)
				if err != nil {
					errCh <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
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
			time.Sleep(5 * time.Millisecond)
		}
		for i := 0; i < clients; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("burst %s: %v", round, err)
			}
		}
	}

	burst("a", 20)

	time.Sleep(100 * time.Millisecond)
	srv.mu.Lock()
	pendingLen := len(srv.pendingTCP)
	srv.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("expected pending=0 after burst, got %d", pendingLen)
	}

	agentCancel()
	deadDisc := time.Now().Add(2 * time.Second)
	for srv.Status().AgentConnected {
		if time.Now().After(deadDisc) {
			t.Fatalf("server did not observe agent disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}

	agentCtx2, agentCancel2 := context.WithCancel(ctx)
	defer agentCancel2()
	go fakeAgent(agentCtx2, controlAddr, dataAddr, echoAddr, "testtoken")
	deadConn := time.Now().Add(5 * time.Second)
	for !srv.Status().AgentConnected {
		if time.Now().After(deadConn) {
			t.Fatalf("server did not observe agent reconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}

	burst("b", 20)

	time.Sleep(100 * time.Millisecond)
	srv.mu.Lock()
	pendingLen = len(srv.pendingTCP)
	srv.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("expected pending=0 after restart burst, got %d", pendingLen)
	}

	for i := 0; i < 10; i++ {
		c, err := net.Dial("tcp", publicAddr)
		if err != nil {
			t.Fatalf("reconnect dial %d: %v", i, err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("reconnect-" + strconv.Itoa(i) + "\n")
		if _, err := c.Write(msg); err != nil {
			c.Close()
			t.Fatalf("reconnect write %d: %v", i, err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil {
			c.Close()
			t.Fatalf("reconnect read %d: %v", i, err)
		}
		c.Close()
		if string(buf) != string(msg) {
			t.Fatalf("reconnect %d: expected %q got %q", i, string(msg), string(buf))
		}
	}
}

func TestServerMultiConn_NoAgentRejectsQuickly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 250 * time.Millisecond,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	c, err := net.Dial("tcp", publicAddr)
	if err != nil {
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
		return
	}
}

func TestRealisticSunshineScenario(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	services := map[string]string{}
	for _, name := range []string{"rtsp", "https", "http"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		prefix := name
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					buf := make([]byte, 4096)
					for {
						n, err := conn.Read(buf)
						if n > 0 {
							resp := append([]byte(prefix+":"), buf[:n]...)
							_, _ = conn.Write(resp)
						}
						if err != nil {
							return
						}
					}
				}(c)
			}
		}()
		services[name] = ln.Addr().String()
	}

	controlLn, _ := net.Listen("tcp", "127.0.0.1:0")
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	dataLn, _ := net.Listen("tcp", "127.0.0.1:0")
	dataAddr := dataLn.Addr().String()
	dataLn.Close()

	publicAddrs := map[string]string{}
	for _, name := range []string{"rtsp", "https", "http"} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		publicAddrs[name] = ln.Addr().String()
		ln.Close()
	}

	routes := []RouteConfig{
		{Name: "rtsp", Proto: "tcp", PublicAddr: publicAddrs["rtsp"]},
		{Name: "https", Proto: "tcp", PublicAddr: publicAddrs["https"]},
		{Name: "http", Proto: "tcp", PublicAddr: publicAddrs["http"]},
	}

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      routes,
		Token:       "testtoken",
		PairTimeout: 10 * time.Second,
		DisableTLS:  true,
	})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutes(ctx, controlAddr, dataAddr, services, "testtoken")

	for _, name := range []string{"rtsp", "https", "http"} {
		waitPrefixedEchoReady(t, publicAddrs[name], name+":")
	}

	for _, name := range []string{"rtsp", "https", "http"} {
		addr := publicAddrs[name]
		prefix := name + ":"

		testConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s test dial: %v", name, err)
		}
		_ = testConn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = testConn.Write([]byte("test\n"))
		testConn.Close()

		realConn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("%s real dial: %v", name, err)
		}
		_ = realConn.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("real-data\n")
		if _, err := realConn.Write(msg); err != nil {
			realConn.Close()
			t.Fatalf("%s real write: %v", name, err)
		}
		buf := make([]byte, len(prefix)+len(msg))
		if _, err := io.ReadFull(realConn, buf); err != nil {
			realConn.Close()
			t.Fatalf("%s real read: %v", name, err)
		}
		realConn.Close()
		if string(buf) != prefix+string(msg) {
			t.Fatalf("%s: expected %q got %q", name, prefix+string(msg), string(buf))
		}
	}

	type streamResult struct {
		route string
		idx   int
		err   error
	}
	results := make(chan streamResult, 30)
	start := make(chan struct{})

	for _, name := range []string{"rtsp", "https", "http"} {
		addr := publicAddrs[name]
		prefix := name + ":"
		for i := 0; i < 10; i++ {
			name := name
			addr := addr
			prefix := prefix
			i := i
			go func() {
				<-start
				c, err := net.Dial("tcp", addr)
				if err != nil {
					results <- streamResult{route: name, idx: i, err: fmt.Errorf("dial: %v", err)}
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				msg := []byte(fmt.Sprintf("stream-%d\n", i))
				if _, err := c.Write(msg); err != nil {
					results <- streamResult{route: name, idx: i, err: fmt.Errorf("write: %v", err)}
					return
				}
				buf := make([]byte, len(prefix)+len(msg))
				if _, err := io.ReadFull(c, buf); err != nil {
					results <- streamResult{route: name, idx: i, err: fmt.Errorf("read: %v", err)}
					return
				}
				want := prefix + string(msg)
				if string(buf) != want {
					results <- streamResult{route: name, idx: i, err: fmt.Errorf("data mismatch: expected %q got %q", want, string(buf))}
					return
				}
				results <- streamResult{route: name, idx: i, err: nil}
			}()
		}
	}

	close(start)
	for i := 0; i < 30; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("route=%s idx=%d: %v", r.route, r.idx, r.err)
		}
	}

	for cycle := 0; cycle < 3; cycle++ {
		for _, name := range []string{"rtsp", "https", "http"} {
			addr := publicAddrs[name]
			prefix := name + ":"
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("cycle %d %s dial: %v", cycle, name, err)
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			msg := []byte(fmt.Sprintf("cycle-%d\n", cycle))
			if _, err := c.Write(msg); err != nil {
				c.Close()
				t.Fatalf("cycle %d %s write: %v", cycle, name, err)
			}
			buf := make([]byte, len(prefix)+len(msg))
			if _, err := io.ReadFull(c, buf); err != nil {
				c.Close()
				t.Fatalf("cycle %d %s read: %v", cycle, name, err)
			}
			c.Close()
			if string(buf) != prefix+string(msg) {
				t.Fatalf("cycle %d %s: expected %q got %q", cycle, name, prefix+string(msg), string(buf))
			}
		}
	}
}

func fakeAgent(ctx context.Context, controlAddr, dataAddr, localAddr string, token string) {
	fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{"default": localAddr}, token)
}

func fakeAgentRoutes(ctx context.Context, controlAddr, dataAddr string, localAddrs map[string]string, token string) {
	var controlConn net.Conn
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c, err := net.Dial("tcp", controlAddr)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		controlConn = c
		break
	}
	go func() {
		<-ctx.Done()
		_ = controlConn.Close()
	}()
	defer controlConn.Close()

	controlConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := crypto.AuthenticateClient(controlConn, token); err != nil {
		return
	}
	controlConn.SetDeadline(time.Time{})

	controlConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	helloPkt, err := protocol.ReadPacket(controlConn)
	controlConn.SetReadDeadline(time.Time{})
	if err != nil || helloPkt.Type != protocol.TypeHello {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		controlConn.SetReadDeadline(time.Now().Add(45 * time.Second))
		pkt, err := protocol.ReadPacket(controlConn)
		if err != nil {
			return
		}
		if pkt.Type == protocol.TypeConnect {
			routeName := pkt.Route
			clientID := pkt.Client
			go func() {
				localAddr, ok := localAddrs[routeName]
				if !ok {
					return
				}
				dataConn, err := net.Dial("tcp", dataAddr)
				if err != nil {
					return
				}
				defer dataConn.Close()

				dataConn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := crypto.AuthenticateClient(dataConn, token); err != nil {
					return
				}
				dataConn.SetDeadline(time.Time{})

				routeBytes := []byte(routeName)
				clientBytes := []byte(clientID)
				buf := make([]byte, 0, 1+len(routeBytes)+1+len(clientBytes))
				buf = append(buf, byte(len(routeBytes)))
				buf = append(buf, routeBytes...)
				buf = append(buf, byte(len(clientBytes)))
				buf = append(buf, clientBytes...)

				dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := dataConn.Write(buf); err != nil {
					return
				}
				dataConn.SetWriteDeadline(time.Time{})

				localConn, err := net.Dial("tcp", localAddr)
				if err != nil {
					return
				}
				defer localConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					io.Copy(localConn, dataConn)
				}()
				go func() {
					defer wg.Done()
					io.Copy(dataConn, localConn)
				}()
				wg.Wait()
				localConn.Close()
				dataConn.Close()
			}()
		}
	}
}
