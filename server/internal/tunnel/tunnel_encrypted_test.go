package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func fakeEncryptedAgent(ctx context.Context, controlAddr, dataAddr, localAddr, token string) {
	key, _ := crypto.DeriveKey(token, crypto.AlgAES256)
	fakeEncryptedAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{"default": localAddr}, token, key)
}

func fakeEncryptedAgentRoutes(ctx context.Context, controlAddr, dataAddr string, localAddrs map[string]string, token string, key []byte) {
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
	_, serverNonce, err := crypto.AuthenticateClient(controlConn, token)
	if err != nil {
		return
	}
	controlConn.SetDeadline(time.Time{})

	pub, sig := testIdentity(serverNonce)
	verPayload, _ := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion, PublicKey: pub, IdentitySig: sig})
	controlConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WritePacket(controlConn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}); err != nil {
		return
	}
	controlConn.SetWriteDeadline(time.Time{})
	controlConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	verPkt, err := protocol.ReadPacket(controlConn)
	controlConn.SetReadDeadline(time.Time{})
	if err != nil || verPkt.Type != protocol.TypeVersionNegotiate {
		return
	}

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
				clientNonce, serverNonce, err := crypto.AuthenticateClient(dataConn, token)
				if err != nil {
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

				dataConn, err = crypto.WrapTCP(dataConn, key, clientNonce, serverNonce, true)
				if err != nil {
					return
				}

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

func TestEndToEndTCPEncrypted(t *testing.T) {
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
		ControlAddr:         controlAddr,
		DataAddr:            dataAddr,
		Routes:              []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr, Encrypted: boolPtr(true)}},
		Token:               "testtoken",
		PairTimeout:         10 * time.Second,
		DisableTLS:          true,
		EncryptionAlgorithm: "aes-256",
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeEncryptedAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")

	waitEchoReady(t, publicAddr)

	msg := []byte("hello-encrypted\n")
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

func TestEndToEndTCPEncryptedConcurrent(t *testing.T) {
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
		ControlAddr:         controlAddr,
		DataAddr:            dataAddr,
		Routes:              []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr, Encrypted: boolPtr(true)}},
		Token:               "testtoken",
		PairTimeout:         10 * time.Second,
		DisableTLS:          true,
		EncryptionAlgorithm: "aes-256",
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeEncryptedAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")

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
				msg := []byte(fmt.Sprintf("enc-%d-%d\n", r, i))
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
					errCh <- io.ErrShortBuffer
					return
				}
				errCh <- nil
			}()
		}
		for i := 0; i < clients; i++ {
			if err := <-errCh; err != nil {
				t.Fatalf("round %d client %d: %v", r, i, err)
			}
		}
	}
}

func TestEndToEndTCPEncryptedLargeData(t *testing.T) {
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
		ControlAddr:         controlAddr,
		DataAddr:            dataAddr,
		Routes:              []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr, Encrypted: boolPtr(true)}},
		Token:               "testtoken",
		PairTimeout:         10 * time.Second,
		DisableTLS:          true,
		EncryptionAlgorithm: "aes-256",
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeEncryptedAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")

	waitEchoReady(t, publicAddr)

	for _, size := range []int{1000, 10000, 100000, 500000} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i % 256)
			}
			c, err := net.Dial("tcp", publicAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write(msg); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != string(msg) {
				t.Fatalf("data mismatch at size %d", size)
			}
		})
	}
}
