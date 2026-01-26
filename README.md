# Golang Helpers for TLS Testing

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/tlsstub)](https://pkg.go.dev/github.com/bassosimone/tlsstub) [![Build Status](https://github.com/bassosimone/tlsstub/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/tlsstub/actions) [![codecov](https://codecov.io/gh/bassosimone/tlsstub/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/tlsstub)

The `tlsstub` Go package contains small helpers for testing TLS code.

For example:

```Go
import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/bassosimone/netstub"
	"github.com/bassosimone/tlsstub"
	"github.com/stretchr/testify/require"
)

// Create a TLSConn that fails on handshake.
conn := &tlsstub.FuncTLSConn{
	FuncConn: &netstub.FuncConn{...},
	HandshakeContextFunc: func(ctx context.Context) error {
		return errors.New("mocked handshake error")
	},
	ConnectionStateFunc: func() tls.ConnectionState {
		return tls.ConnectionState{}
	},
}

// Use the conn in code under test.
err := conn.HandshakeContext(context.Background())

// Verify the test.
require.Error(t, err)
```

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/tlsstub
```

## Development

To run the tests:
```sh
go test -v .
```

To measure test coverage:
```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [ooni/probe-cli](https://github.com/ooni/probe-cli/tree/v3.20.1/internal/mocks).
