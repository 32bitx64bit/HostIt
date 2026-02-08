package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"hostit/server/internal/lineproto"
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

func fakeAgent(ctx context.Context, controlAddr, dataAddr, localAddr string, token string) {
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

	rw := lineproto.New(controlConn, controlConn)
	_ = rw.WriteLinef("HELLO %s", token)
	_, err := rw.ReadLine() // OK ...
	if err != nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := rw.ReadLine()
		if err != nil {
			return
		}
		cmd, rest := lineproto.Split2(line)
		if cmd != "NEW" || rest == "" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		go func() {
			dataConn, err := net.Dial("tcp", dataAddr)
			if err != nil {
				return
			}
			defer dataConn.Close()
			drw := lineproto.New(dataConn, dataConn)
			_ = drw.WriteLinef("CONN %s", id)

			// Read PAIRED acknowledgment byte-by-byte to avoid buffering
			// application data that follows.
			if err := readPairedAckRaw(dataConn, 3*time.Second); err != nil {
				return
			}

			localConn, err := net.Dial("tcp", localAddr)
			if err != nil {
				return
			}
			defer localConn.Close()

			bidirPipe(localConn, dataConn)
		}()
	}
}

// readPairedAckRaw reads the "PAIRED\n" acknowledgment one byte at a time
// so it doesn't over-buffer application data from the socket.
func readPairedAckRaw(c net.Conn, timeout time.Duration) error {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var buf [32]byte
	i := 0
	for i < len(buf) {
		_, err := c.Read(buf[i : i+1])
		if err != nil {
			return err
		}
		if buf[i] == '\n' {
			line := strings.TrimSpace(string(buf[:i]))
			if line == "PAIRED" {
				return nil
			}
			return fmt.Errorf("unexpected ack: %q", line)
		}
		i++
	}
	return fmt.Errorf("ack too long")
}
