package sasl

import "errors"

// Server implements a SASL authentication server.
type Server interface {
	Next(response []byte) (challenge []byte, done bool, err error)
}

// ErrUnexpectedClientResponse is returned when the client sends an unexpected
// response during SASL authentication.
var ErrUnexpectedClientResponse = errors.New("sasl: unexpected client response")
