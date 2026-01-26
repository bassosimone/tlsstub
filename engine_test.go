// SPDX-License-Identifier: GPL-3.0-or-later

package tlsstub_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/tlsstub"
	"github.com/stretchr/testify/assert"
)

func TestFuncTLSEngine(t *testing.T) {
	wantName := "test-engine"
	wantParrot := "Chrome/120"

	mockConn := &tlsstub.FuncTLSConn{
		FuncConn: &netstub.FuncConn{
			CloseFunc: func() error { return nil },
			LocalAddrFunc: func() net.Addr {
				return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
			},
			RemoteAddrFunc: func() net.Addr {
				return &net.TCPAddr{IP: net.IPv4(93, 184, 216, 34)}
			},
			SetDeadlineFunc: func(time.Time) error {
				return nil
			},
			SetReadDeadFunc: func(time.Time) error {
				return nil
			},
			SetWriteDeaFunc: func(time.Time) error {
				return nil
			},
		},
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	engine := &tlsstub.FuncTLSEngine[tlsstub.TLSConn]{
		ClientFunc: func(conn net.Conn, config *tls.Config) tlsstub.TLSConn {
			return mockConn
		},
		NameFunc: func() string {
			return wantName
		},
		ParrotFunc: func() string {
			return wantParrot
		},
	}

	// Test Name
	name := engine.Name()
	assert.Equal(t, wantName, name)

	// Test Parrot
	parrot := engine.Parrot()
	assert.Equal(t, wantParrot, parrot)

	// Test Client
	stubConn := &netstub.FuncConn{}
	tlsConn := engine.Client(stubConn, &tls.Config{})
	assert.Equal(t, mockConn, tlsConn)
}

func TestFuncTLSEngineEmptyParrot(t *testing.T) {
	engine := &tlsstub.FuncTLSEngine[tlsstub.TLSConn]{
		ClientFunc: func(conn net.Conn, config *tls.Config) tlsstub.TLSConn {
			return nil
		},
		NameFunc: func() string {
			return "stdlib"
		},
		ParrotFunc: func() string {
			return ""
		},
	}

	parrot := engine.Parrot()
	assert.Equal(t, "", parrot)
}

// The following types simulate a "foreign" package that defines its own
// TLSEngine and TLSConn interfaces, structurally identical to tlsstub's
// but distinct Go types.

// foreignTLSConn is a TLSConn interface defined in a "foreign" package.
type foreignTLSConn interface {
	ConnectionState() tls.ConnectionState
	HandshakeContext(ctx context.Context) error
	net.Conn
}

// foreignTLSEngine is a TLSEngine interface defined in a "foreign" package.
type foreignTLSEngine interface {
	Client(conn net.Conn, config *tls.Config) foreignTLSConn
	Name() string
	Parrot() string
}

// foreignMockTLSConn is a mock that directly implements foreignTLSConn.
type foreignMockTLSConn struct {
	*netstub.FuncConn
	connectionState tls.ConnectionState
}

func (c *foreignMockTLSConn) ConnectionState() tls.ConnectionState {
	return c.connectionState
}

func (c *foreignMockTLSConn) HandshakeContext(ctx context.Context) error {
	return nil
}

// TestFuncTLSEngineWithForeignInterface demonstrates that FuncTLSEngine[T]
// can satisfy a TLSEngine interface from a different package by parameterizing
// it with that package's TLSConn type.
func TestFuncTLSEngineWithForeignInterface(t *testing.T) {
	mockConn := &foreignMockTLSConn{
		FuncConn: &netstub.FuncConn{
			CloseFunc:       func() error { return nil },
			LocalAddrFunc:   func() net.Addr { return &net.TCPAddr{} },
			RemoteAddrFunc:  func() net.Addr { return &net.TCPAddr{} },
			SetDeadlineFunc: func(time.Time) error { return nil },
			SetReadDeadFunc: func(time.Time) error { return nil },
			SetWriteDeaFunc: func(time.Time) error { return nil },
		},
		connectionState: tls.ConnectionState{Version: tls.VersionTLS13},
	}

	// Create a FuncTLSEngine parameterized with foreignTLSConn.
	engine := &tlsstub.FuncTLSEngine[foreignTLSConn]{
		ClientFunc: func(conn net.Conn, config *tls.Config) foreignTLSConn {
			return mockConn
		},
		NameFunc: func() string {
			return "foreign-engine"
		},
		ParrotFunc: func() string {
			return "firefox"
		},
	}

	// The key assertion: *FuncTLSEngine[foreignTLSConn] satisfies foreignTLSEngine.
	var foreignEngine foreignTLSEngine = engine

	// Verify all methods work correctly through the foreign interface.
	assert.Equal(t, "foreign-engine", foreignEngine.Name())
	assert.Equal(t, "firefox", foreignEngine.Parrot())

	tlsConn := foreignEngine.Client(&netstub.FuncConn{}, &tls.Config{})
	assert.NotNil(t, tlsConn)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConn.ConnectionState().Version)
}
