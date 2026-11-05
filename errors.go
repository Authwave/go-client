// Package authwave connects server-side Go applications to an Authwave provider.
package authwave

import (
	"errors"
	"fmt"
)

var (
	ErrTokenReuse                   = errors.New("authwave: create a new token for a different request")
	ErrSessionNotStarted            = errors.New("authwave: session not started")
	ErrNotLoggedIn                  = errors.New("authwave: not logged in")
	ErrInsecureProtocol             = errors.New("authwave: insecure provider protocol")
	ErrInvalidUserDataSerialization = errors.New("authwave: invalid user data serialization")
	// ErrResponseCipherDecryption is retained for parity; cipher errors use ErrDecryptionFailure.
	ErrResponseCipherDecryption = errors.New("authwave: response cipher decryption")
	ErrDecryptionFailure        = errors.New("authwave: error decrypting cipher message")
	ErrEncryptionFailure        = errors.New("authwave: error encrypting cipher message")
)

// RedirectError transfers control to an HTTP adapter, which saves before responding.
type RedirectError struct {
	URI  string
	Code int
}

func (e *RedirectError) Error() string {
	return fmt.Sprintf("authwave: redirect %d to %s", e.Code, e.URI)
}

type RedirectHandler func(uri string, code int) error

func DefaultRedirectHandler(uri string, code int) error { return &RedirectError{URI: uri, Code: code} }
