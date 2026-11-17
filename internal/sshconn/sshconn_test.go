package sshconn

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// blackholeProxy forwards TCP to dst; freeze() silently swallows what the already open connections carry.
type blackholeProxy struct {
	addr   string
	mu     sync.Mutex
	frozen []*atomic.Bool
}

func newProxy(t *testing.T, dst string) *blackholeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &blackholeProxy{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", dst)
			if err != nil {
				c.Close()
				continue
			}
			fz := &atomic.Bool{}
			p.mu.Lock()
			p.frozen = append(p.frozen, fz)
			p.mu.Unlock()
			pipe := func(a, b net.Conn) {
				buf := make([]byte, 4096)
				for {
					n, err := a.Read(buf)
					if n > 0 && !fz.Load() {
						b.Write(buf[:n])
					}
					if err != nil {
						b.Close()
						return
					}
				}
			}
			go pipe(c, up)
			go pipe(up, c)
		}
	}()
	return p
}

func (p *blackholeProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.frozen {
		f.Store(true)
	}
}

func TestClientRedialsWhenKeepaliveHangs(t *testing.T) {
	keepaliveTimeout = 200 * time.Millisecond
	t.Cleanup(func() { keepaliveTimeout = 5 * time.Second })
	addr, hk := forwardServer(t)
	px := newProxy(t, addr)
	pool := NewPool(t.TempDir() + "/kh")
	if err := Trust(pool.KnownHosts, px.addr, hk); err != nil {
		t.Fatal(err)
	}
	tg := Target{Name: "h", Addr: px.addr, User: "u", Auth: ssh.Password("x")}
	c1, err := pool.client(tg)
	if err != nil {
		t.Fatal(err)
	}
	px.freeze() // half-open: c1 now hangs forever
	start := time.Now()
	c2, err := pool.client(tg)
	if err != nil {
		t.Fatal(err)
	}
	if c2 == c1 || time.Since(start) > 3*time.Second {
		t.Fatalf("want a fresh connection quickly, got same=%v after %s", c2 == c1, time.Since(start))
	}
}

func TestHandshakeIsBounded(t *testing.T) {
	handshakeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = 20 * time.Second })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { // accepts, never speaks
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	pool := NewPool(t.TempDir() + "/kh")
	start := time.Now()
	_, err = pool.client(Target{Name: "h", Addr: ln.Addr().String(), User: "u", Auth: ssh.Password("x")})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("want a quick error, got %v after %s", err, time.Since(start))
	}
	st := pool.Check(context.Background(), Target{Name: "h", Addr: ln.Addr().String(), User: "u", Auth: ssh.Password("x")}, "")
	last := st[len(st)-1]
	if last.Stage != "hostkey" || last.OK || last.Code != "handshake-timeout" {
		t.Fatalf("stages %+v", st)
	}
}
