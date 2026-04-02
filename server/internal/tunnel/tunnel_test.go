package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func TestEndToEndTCP(t *testing.T) {
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

	srv := NewServer(ServerConfig{ControlAddr: controlAddr, DataAddr: dataAddr, Routes: []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}}, Token: "testtoken", PairTimeout: 2 * time.Second, DisableTLS: true})
	go func() { _ = srv.Run(ctx) }()

	// Fake agent: connect to control; for each NEW id, connect to data and then to local echo.
	go fakeAgent(ctx, controlAddr, dataAddr, echoLn.Addr().String(), "testtoken")

	msg := []byte("hello\n")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel never became ready")
		}

		client, err := net.Dial("tcp", publicAddr)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, werr := client.Write(msg)
		if werr != nil {
			_ = client.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(msg))
		_, rerr := io.ReadFull(client, buf)
		_ = client.Close()
		if rerr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if string(buf) != string(msg) {
			t.Fatalf("expected %q got %q", string(msg), string(buf))
		}
		break
	}
}

func TestEndToEndTCPConcurrent(t *testing.T) {
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

	srv := NewServer(ServerConfig{ControlAddr: controlAddr, DataAddr: dataAddr, Routes: []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}}, Token: "testtoken", PairTimeout: 2 * time.Second, DisableTLS: true})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoLn.Addr().String(), "testtoken")

	// Wait for the public listener to become reachable.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel never became ready")
		}
		c, err := net.Dial("tcp", publicAddr)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		_ = c.Close()
		break
	}

	const clients = 10
	const rounds = 10

	for r := 0; r < rounds; r++ {
		errCh := make(chan error, clients)
		start := make(chan struct{})
		for i := 0; i < clients; i++ {
			i := i
			go func() {
				<-start
				client, err := net.Dial("tcp", publicAddr)
				if err != nil {
					errCh <- err
					return
				}
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(750 * time.Millisecond))
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
		close(start)
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

	startEcho := func(prefix string) (net.Listener, string) {
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

	echoALn, echoAAddr := startEcho("a")
	defer echoALn.Close()
	echoBLn, echoBAddr := startEcho("b")
	defer echoBLn.Close()

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

	publicALn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicAAddr := publicALn.Addr().String()
	_ = publicALn.Close()

	publicBLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicBAddr := publicBLn.Addr().String()
	_ = publicBLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{
			{Name: "route-a", Proto: "tcp", PublicAddr: publicAAddr},
			{Name: "route-b", Proto: "tcp", PublicAddr: publicBAddr},
		},
		Token:      "testtoken",
		PairTimeout: 2 * time.Second,
		DisableTLS: true,
	})
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{
		"route-a": echoAAddr,
		"route-b": echoBAddr,
	}, "testtoken")

	waitReady := func(addr string) {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if time.Now().After(deadline) {
				t.Fatalf("listener %s never became ready", addr)
			}
			c, err := net.Dial("tcp", addr)
			if err != nil {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			_ = c.Close()
			return
		}
	}

	waitReady(publicAAddr)
	waitReady(publicBAddr)

	targets := []struct {
		addr   string
		prefix string
	}{
		{addr: publicAAddr, prefix: "a:"},
		{addr: publicBAddr, prefix: "b:"},
	}

	const perRoute = 20
	errCh := make(chan error, len(targets)*perRoute)
	start := make(chan struct{})
	for _, target := range targets {
		target := target
		for i := 0; i < perRoute; i++ {
			i := i
			go func() {
				<-start
				c, err := net.Dial("tcp", target.addr)
				if err != nil {
					errCh <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
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
		}
	}
	close(start)

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
	// Ensure cancellation interrupts any blocking reads.
	go func() {
		<-ctx.Done()
		_ = controlConn.Close()
	}()
	defer controlConn.Close()

	// Mutual auth
	controlConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := crypto.AuthenticateClient(controlConn, token); err != nil {
		return
	}
	controlConn.SetDeadline(time.Time{})

	// Read HELLO
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

				// Send route/client info
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

				go func() {
					io.Copy(localConn, dataConn)
				}()
				io.Copy(dataConn, localConn)
			}()
		}
	}
}
