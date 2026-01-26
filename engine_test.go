// SPDX-License-Identifier: GPL-3.0-or-later

package tlsstub

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/assert"
)

func TestFuncTLSEngine(t *testing.T) {
	wantName := "test-engine"
	wantParrot := "Chrome/120"

	mockConn := &FuncTLSConn{
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

	engine := &FuncTLSEngine{
		ClientFunc: func(conn net.Conn, config *tls.Config) TLSConn {
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
	engine := &FuncTLSEngine{
		ClientFunc: func(conn net.Conn, config *tls.Config) TLSConn {
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
