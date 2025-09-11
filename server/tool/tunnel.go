package tool

import (
	"errors"
	"net"
	"sync/atomic"
)

type Dialer interface {
	DialVirtual(remote string) (net.Conn, error)
}

var lookup atomic.Value // holds: func(int) (Dialer, bool)

func SetLookup(fn func(int) (Dialer, bool)) {
	lookup.Store(fn)
}

func GetTunnelConn(id int, remote string) (net.Conn, error) {
	v := lookup.Load()
	if v == nil {
		return nil, errors.New("tunnel lookup not set")
	}
	fn := v.(func(int) (Dialer, bool))
	d, ok := fn(id)
	if !ok || d == nil {
		return nil, errors.New("tunnel not found")
	}
	return d.DialVirtual(remote)
}
