// SPDX-License-Identifier: GPL-3.0-or-later

package tlsstub

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFuncTLSConn(t *testing.T) {
	wantErr := errors.New("mocked error")
	wantAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	wantState := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}

	conn := &FuncTLSConn{
		FuncConn: &netstub.FuncConn{
			ReadFunc: func([]byte) (int, error) {
				return 0, wantErr
			},
			WriteFunc: func([]byte) (int, error) {
				return 0, wantErr
			},
			CloseFunc: func() error {
				return wantErr
			},
			LocalAddrFunc: func() net.Addr {
				return wantAddr
			},
			RemoteAddrFunc: func() net.Addr {
				return wantAddr
			},
			SetDeadlineFunc: func(time.Time) error {
				return wantErr
			},
			SetReadDeadFunc: func(time.Time) error {
				return wantErr
			},
			SetWriteDeaFunc: func(time.Time) error {
				return wantErr
			},
		},
		ConnectionStateFunc: func() tls.ConnectionState {
			return wantState
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return wantErr
		},
	}

	// Test embedded FuncConn methods
	buf := make([]byte, 8)
	_, err := conn.Read(buf)
	require.ErrorIs(t, err, wantErr)

	_, err = conn.Write(buf)
	require.ErrorIs(t, err, wantErr)

	err = conn.Close()
	require.ErrorIs(t, err, wantErr)

	assert.Equal(t, wantAddr, conn.LocalAddr())
	assert.Equal(t, wantAddr, conn.RemoteAddr())

	deadline := time.Now()
	err = conn.SetDeadline(deadline)
	require.ErrorIs(t, err, wantErr)

	err = conn.SetReadDeadline(deadline)
	require.ErrorIs(t, err, wantErr)

	err = conn.SetWriteDeadline(deadline)
	require.ErrorIs(t, err, wantErr)

	// Test TLSConn-specific methods
	state := conn.ConnectionState()
	assert.Equal(t, wantState, state)

	err = conn.HandshakeContext(context.Background())
	require.ErrorIs(t, err, wantErr)
}

func TestFuncTLSConnHandshakeSuccess(t *testing.T) {
	conn := &FuncTLSConn{
		FuncConn: &netstub.FuncConn{
			CloseFunc: func() error { return nil },
		},
		ConnectionStateFunc: func() tls.ConnectionState {
			return tls.ConnectionState{}
		},
		HandshakeContextFunc: func(ctx context.Context) error {
			return nil
		},
	}

	err := conn.HandshakeContext(context.Background())
	require.NoError(t, err)
}
