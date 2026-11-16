package sshconn

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
	t := &Tunnel{ln: ln, onClose: onClose, active: map[net.Conn]struct{}{}}
	t.mu.Lock() // Close may fire at once and reads t.timer under mu
	t.timer = time.AfterFunc(ttl, t.Close)
	t.mu.Unlock()
	go func() {
		for {
			lc, err := ln.Accept()
			if err != nil {
				return
			}
			t.mu.Lock()
			t.active[lc] = struct{}{}
			t.mu.Unlock()
			t.conns.Add(1)
			go func() {
				defer func() {
					lc.Close()
					t.mu.Lock()
					delete(t.active, lc)
					t.mu.Unlock()
				}()
				rc, err := c.Dial("tcp", remote)
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
