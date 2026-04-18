package crypto

import (
	"net"
	"sync"
	"testing"
)

func TestAuthenticateClientServer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	token := "shared-secret-token"

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = AuthenticateClient(client, token)
	}()
	go func() {
		defer wg.Done()
		serverErr = AuthenticateServer(server, token)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("AuthenticateClient failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("AuthenticateServer failed: %v", serverErr)
	}
}

func TestAuthenticateMismatchedTokens(t *testing.T) {
	client, server := net.Pipe()

	var clientErr, serverErr error

	done := make(chan struct{})
	go func() {
		serverErr = AuthenticateServer(server, "server-token")
		server.Close()
		close(done)
	}()

	clientErr = AuthenticateClient(client, "client-token")
	client.Close()
	<-done

	if clientErr == nil && serverErr == nil {
		t.Fatal("expected authentication to fail with mismatched tokens, but both succeeded")
	}
}

func TestAuthenticateEmptyToken(t *testing.T) {
	client, server := net.Pipe()

	var clientErr, serverErr error

	done := make(chan struct{})
	go func() {
		serverErr = AuthenticateServer(server, "")
		server.Close()
		close(done)
	}()

	clientErr = AuthenticateClient(client, "")
	client.Close()
	<-done

	if clientErr != nil {
		t.Fatalf("AuthenticateClient with empty token failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("AuthenticateServer with empty token failed: %v", serverErr)
	}

	mismatchClient, mismatchServer := net.Pipe()

	var clientErr2, serverErr2 error

	done2 := make(chan struct{})
	go func() {
		serverErr2 = AuthenticateServer(mismatchServer, "non-empty")
		mismatchServer.Close()
		close(done2)
	}()

	clientErr2 = AuthenticateClient(mismatchClient, "")
	mismatchClient.Close()
	<-done2

	if clientErr2 == nil && serverErr2 == nil {
		t.Fatal("expected auth to fail when one side uses empty token and other uses non-empty")
	}
}
