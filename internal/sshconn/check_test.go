package sshconn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// shellServer accepts the password "ok" and runs every exec request with the given exit status.
func shellServer(t *testing.T, exit uint32) (string, ssh.PublicKey) {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "ok" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
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
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							r.Reply(true, nil)
							if r.Type == "exec" {
								ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{exit}))
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func stageNames(st []Stage) (names string, last Stage) {
	for _, s := range st {
		names += s.Stage + ","
	}
	return names, st[len(st)-1]
}

func TestCheckStages(t *testing.T) {
	addr, hk := shellServer(t, 0)
	badExec, hk2 := shellServer(t, 1)
	pool := NewPool(t.TempDir() + "/kh")
	tg := Target{Name: "h", Addr: addr, User: "u", Auth: ssh.Password("ok")}

	// unknown key
	st := pool.Check(context.Background(), tg, "")
	if n, l := stageNames(st); n != "tcp,hostkey," || l.OK || l.Code != "hostkey-unknown" {
		t.Fatalf("%s %+v", n, st)
	}
	// all good, and nothing was pooled
	Trust(pool.KnownHosts, addr, hk)
	st = pool.Check(context.Background(), tg, "")
	if n, l := stageNames(st); n != "tcp,hostkey,auth,exec," || !l.OK {
		t.Fatalf("%s %+v", n, st)
	}
	if len(pool.conns) != 0 {
		t.Fatal("check must not pool a connection")
	}
	// wrong password
	bad := tg
	bad.Auth = ssh.Password("nope")
	if n, l := stageNames(pool.Check(context.Background(), bad, "")); n != "tcp,hostkey,auth," || l.Code != "auth" {
		t.Fatalf("%s %+v", n, l)
	}
	// locked vault: tcp and hostkey run, auth reports the reason
	bad.Auth = nil
	st = pool.Check(context.Background(), bad, "vault đang khóa")
	if n, l := stageNames(st); n != "tcp,hostkey,auth," || l.OK || l.Err != "vault đang khóa" {
		t.Fatalf("%s %+v", n, st)
	}
	// true exits 1
	Trust(pool.KnownHosts, badExec, hk2)
	st = pool.Check(context.Background(), Target{Name: "h", Addr: badExec, User: "u", Auth: ssh.Password("ok")}, "")
	if n, l := stageNames(st); n != "tcp,hostkey,auth,exec," || l.OK || l.Code != "exec" {
		t.Fatalf("%s %+v", n, st)
	}
	// changed key
	Trust(pool.KnownHosts, addr, hk2)
	if _, l := stageNames(pool.Check(context.Background(), tg, "")); l.Code != "hostkey-changed" {
		t.Fatalf("%+v", l)
	}
	// closed port
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if n, l := stageNames(pool.Check(context.Background(), Target{Name: "h", Addr: closed, User: "u", Auth: ssh.Password("ok")}, "")); n != "tcp," || l.Code != "refused" {
		t.Fatalf("%s %+v", n, l)
	}
}
