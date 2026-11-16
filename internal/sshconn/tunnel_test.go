package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// forwardServer is an SSH server that accepts any client and serves direct-tcpip channels.
func forwardServer(t *testing.T) (addr string, hostKey ssh.PublicKey) {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					p := nc.ExtraData()
					hl := binary.BigEndian.Uint32(p)
					dst := net.JoinHostPort(string(p[4:4+hl]), strconv.Itoa(int(binary.BigEndian.Uint32(p[4+hl:]))))
					up, err := net.Dial("tcp", dst)
					if err != nil {
						nc.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, _, _ := nc.Accept()
					go func() { io.Copy(up, ch); up.Close() }()
					go func() { io.Copy(ch, up); ch.Close() }()
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func newPoolTarget(t *testing.T) (*Pool, Target) {
	addr, hk := forwardServer(t)
	p := NewPool(t.TempDir() + "/kh")
	if err := Trust(p.KnownHosts, addr, hk); err != nil {
		t.Fatal(err)
	}
	return p, Target{Name: "h", Addr: addr, User: "u", Auth: ssh.Password("x")}
}

func TestForwardEchoAndStats(t *testing.T) {
	p, tg := newPoolTarget(t)
	closed := make(chan Stats, 1)
	tn, err := p.Forward(tg, echoServer(t), time.Minute, func(s Stats) { closed <- s })
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", tn.Addr())
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if s := tn.Stats(); s.Conns != 1 || s.BytesOut != 5 {
		t.Fatalf("stats %+v", s)
	}
	tn.Close()
	// Close drops the active connection.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("connection still open after Close")
	}
	select {
	case s := <-closed:
		if s.BytesIn != 5 || s.BytesOut != 5 || s.Conns != 1 {
			t.Fatalf("final stats %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onClose not called")
	}
	tn.Close() // idempotent
	if _, err := net.DialTimeout("tcp", tn.Addr(), time.Second); err == nil {
		t.Fatal("listener still open")
	}
}

func TestForwardTTL(t *testing.T) {
	p, tg := newPoolTarget(t)
	closed := make(chan Stats, 1)
	tn, err := p.Forward(tg, echoServer(t), 100*time.Millisecond, func(s Stats) { closed <- s })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("TTL did not close the tunnel")
	}
	if _, err := net.DialTimeout("tcp", tn.Addr(), time.Second); err == nil {
		t.Fatal("listener still open after TTL")
	}
}

func TestForwardConnCap(t *testing.T) {
	p, tg := newPoolTarget(t)
	tn, err := p.Forward(tg, echoServer(t), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	var cs []net.Conn
	for i := 0; i < MaxConns; i++ {
		c, err := net.Dial("tcp", tn.Addr())
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
		c.Write([]byte("x"))
		io.ReadFull(c, make([]byte, 1)) // wait until the slot is surely taken
	}
	extra, _ := net.Dial("tcp", tn.Addr())
	extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("extra connection not refused: %v", err)
	}
	for _, c := range cs {
		c.Close()
	}
}

// A dropped pooled client must not strand the tunnel: the next local connection re-dials.
func TestForwardSurvivesDroppedClient(t *testing.T) {
	p, tg := newPoolTarget(t)
	tn, err := p.Forward(tg, echoServer(t), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	p.Drop(tg.Name)
	c, err := net.Dial("tcp", tn.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("after Drop: %q %v", buf, err)
	}
}

// A burst of connections after a Drop shares one re-dial and all work.
func TestForwardBurstAfterDrop(t *testing.T) {
	p, tg := newPoolTarget(t)
	tn, err := p.Forward(tg, echoServer(t), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	p.Drop(tg.Name)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			c, err := net.Dial("tcp", tn.Addr())
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte("x"))
			_, err = io.ReadFull(c, make([]byte, 1))
			errs <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
