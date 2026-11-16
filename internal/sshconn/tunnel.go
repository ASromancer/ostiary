package sshconn

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// MaxConns is the most concurrent connections one tunnel forwards; extra ones are refused.
	MaxConns    = 32
	DialTimeout = 10 * time.Second
)

// Stats is a tunnel's traffic. BytesOut goes toward the remote target.
type Stats struct{ BytesIn, BytesOut, Conns int64 }

// Tunnel forwards connections to 127.0.0.1:<random port> to a target reachable from the SSH server.
type Tunnel struct {
	ln      net.Listener
	timer   *time.Timer
	onClose func(Stats)
	in, out atomic.Int64
	conns   atomic.Int64
	once    sync.Once
	mu      sync.Mutex
	active  map[net.Conn]struct{}
	closed  bool
	slots   chan struct{} // limits concurrent connections
}

// Closed reports whether Close has begun.
func (t *Tunnel) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *Tunnel) Addr() string { return t.ln.Addr().String() }

func (t *Tunnel) Stats() Stats {
	return Stats{BytesIn: t.in.Load(), BytesOut: t.out.Load(), Conns: t.conns.Load()}
}

// Close stops listening, drops active connections and calls onClose once.
func (t *Tunnel) Close() {
	t.once.Do(func() {
		t.ln.Close()
		t.mu.Lock()
		t.closed = true
		t.timer.Stop()
		for c := range t.active {
			c.Close()
		}
		t.mu.Unlock()
		if t.onClose != nil {
			t.onClose(t.Stats())
		}
	})
}

// Forward listens on 127.0.0.1:0 and forwards every connection to remote ("host:port" as seen
// from the SSH server) over the pooled connection. It closes itself after ttl.
func (p *Pool) Forward(tg Target, remote string, ttl time.Duration, onClose func(Stats)) (*Tunnel, error) {
	c, err := p.client(tg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t := &Tunnel{ln: ln, onClose: onClose, active: map[net.Conn]struct{}{}, slots: make(chan struct{}, MaxConns)}
	t.mu.Lock() // Close may fire at once and reads t.timer under mu
	t.timer = time.AfterFunc(ttl, t.Close)
	t.mu.Unlock()
	go func() {
		for {
			lc, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case t.slots <- struct{}{}:
			default:
				lc.Close() // too many connections
				continue
			}
			t.mu.Lock()
			if t.closed { // accepted while closing: Close has already swept t.active
				t.mu.Unlock()
				lc.Close()
				<-t.slots
				return
			}
			t.active[lc] = struct{}{}
			t.mu.Unlock()
			t.conns.Add(1)
			go func() {
				defer func() {
					lc.Close()
					t.mu.Lock()
					delete(t.active, lc)
					t.mu.Unlock()
					<-t.slots
				}()
				rc, err := dialTimeout(c, remote)
				if err != nil {
					return
				}
				defer rc.Close()
				done := make(chan struct{}, 2)
				cp := func(dst io.Writer, src io.Reader, n *atomic.Int64) {
					io.Copy(&counter{dst, n}, src)
					done <- struct{}{}
				}
				go cp(rc, lc, &t.out)
				go cp(lc, rc, &t.in)
				<-done // one side finished: close both, then the other copy ends
				lc.Close()
				rc.Close()
				<-done
			}()
		}
	}()
	return t, nil
}

// counter adds to n as bytes are written, so Stats is live.
type counter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *counter) Write(b []byte) (int, error) {
	m, err := c.w.Write(b)
	c.n.Add(int64(m))
	return m, err
}

// dialTimeout is c.Dial with a deadline, which ssh.Client lacks.
func dialTimeout(c *ssh.Client, addr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { x, err := c.Dial("tcp", addr); ch <- res{x, err} }()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(DialTimeout):
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, errors.New("dial timeout")
	}
}
