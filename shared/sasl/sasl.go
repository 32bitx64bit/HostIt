package sasl

import "errors"

type Server interface {
	Next(response []byte) (challenge []byte, done bool, err error)
}

var ErrUnexpectedClientResponse = errors.New("sasl: unexpected client response")
