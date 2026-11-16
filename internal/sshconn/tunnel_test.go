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
