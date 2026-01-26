//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/tree/v3.20.1/internal/mocks
//

package tlsstub

import (
	"crypto/tls"
	"net"

	"github.com/bassosimone/runtimex"
)

// TLSEngine is the interface implemented by [FuncTLSEngine].
//
// There is no corresponding type in the standard library but this interface
// feels like a reasonable approximation of an "engine" for instantiating
// TLS connections across multiple libraries.
type TLSEngine interface {
	Client(conn net.Conn, config *tls.Config) TLSConn
	Name() string
	Parrot() string
}

// FuncTLSEngine allows to mock any [TLSEngine] implementation.
//
// The type parameter T specifies the return type of the Client method.
// This allows FuncTLSEngine to satisfy TLSEngine interfaces from different
// packages that define their own TLSConn type.
type FuncTLSEngine[T any] struct {
	// ClientFunc builds a new client TLSConn.
	ClientFunc func(conn net.Conn, config *tls.Config) T

	// NameFunc returns the engine name.
	NameFunc func() string

	// ParrotFunc returns the configured parrot or an empty string.
	ParrotFunc func() string
}

var _ TLSEngine = &FuncTLSEngine[TLSConn]{}

// Client implements [TLSEngine].
func (fe *FuncTLSEngine[T]) Client(conn net.Conn, config *tls.Config) T {
	runtimex.Assert(fe.ClientFunc != nil)
	return fe.ClientFunc(conn, config)
}

// Name implements [TLSEngine].
func (fe *FuncTLSEngine[T]) Name() string {
	runtimex.Assert(fe.NameFunc != nil)
	return fe.NameFunc()
}

// Parrot implements [TLSEngine].
func (fe *FuncTLSEngine[T]) Parrot() string {
	runtimex.Assert(fe.ParrotFunc != nil)
	return fe.ParrotFunc()
}
