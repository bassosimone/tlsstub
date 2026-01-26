//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/tree/v3.20.1/internal/mocks
//

package tlsstub

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/runtimex"
)

// TLSConn is the interface implemented by [FuncTLSConn].
//
// This mirrors typical TLSConn interfaces to avoid circular dependencies.
type TLSConn interface {
	ConnectionState() tls.ConnectionState
	HandshakeContext(ctx context.Context) error
	net.Conn
}

// FuncTLSConn allows to mock any [TLSConn] (including [*tls.Conn]).
type FuncTLSConn struct {
	// FuncConn is embedded for [net.Conn] methods.
	*netstub.FuncConn

	// ConnectionStateFunc returns the TLS connection state.
	ConnectionStateFunc func() tls.ConnectionState

	// HandshakeContextFunc performs the TLS handshake.
	HandshakeContextFunc func(ctx context.Context) error
}

var _ TLSConn = &FuncTLSConn{}

// ConnectionState implements [TLSConn].
func (fc *FuncTLSConn) ConnectionState() tls.ConnectionState {
	runtimex.Assert(fc.ConnectionStateFunc != nil)
	return fc.ConnectionStateFunc()
}

// HandshakeContext implements [TLSConn].
func (fc *FuncTLSConn) HandshakeContext(ctx context.Context) error {
	runtimex.Assert(fc.HandshakeContextFunc != nil)
	return fc.HandshakeContextFunc(ctx)
}
