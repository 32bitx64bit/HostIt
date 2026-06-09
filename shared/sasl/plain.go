package sasl

import (
	"bytes"
	"fmt"
)

// PlainAuthenticator is the signature for a PLAIN SASL authenticator.
type PlainAuthenticator func(identity, username, password string) error

// NewPlainServer creates a new SASL PLAIN server.
func NewPlainServer(authenticate PlainAuthenticator) Server {
	return &plainServer{authenticate: authenticate}
}

type plainServer struct {
	authenticate PlainAuthenticator
	done         bool
}

func (s *plainServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if s.done {
		return nil, true, ErrUnexpectedClientResponse
	}

	// No initial response, send an empty challenge
	if response == nil {
		return []byte{}, false, nil
	}

	s.done = true

	parts := bytes.Split(response, []byte("\x00"))
	if len(parts) != 3 {
		return nil, true, fmt.Errorf("sasl: invalid PLAIN response format")
	}

	identity := string(parts[0])
	username := string(parts[1])
	password := string(parts[2])

	if authErr := s.authenticate(identity, username, password); authErr != nil {
		return nil, true, authErr
	}
	return nil, true, nil
}
