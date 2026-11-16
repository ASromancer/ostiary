//go:build linux || darwin

package cli

import (
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/daemon"
)

type fakeA struct {
	calls atomic.Int32
	fail  int32
}

func (f *fakeA) Exec(_ *daemon.ExecArgs, r *daemon.ExecReply) error {
	if f.calls.Add(1) <= f.fail {
		r.Code, r.Msg = daemon.CodeRestarting, "restarting"
	}
	return nil
}

func runRetry(t *testing.T, fail int32) (int32, int) {
	d, _ := os.MkdirTemp("/tmp", "ostiary-retry")
	t.Cleanup(func() { os.RemoveAll(d) })
	t.Setenv("OSTIARY_SOCKET", filepath.Join(d, "s"))
	ln, err := net.Listen("unix", filepath.Join(d, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeA{fail: fail}
	srv := rpc.NewServer()
	srv.RegisterName("A", f)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeCodec(jsonrpc.NewServerCodec(c))
		}
	}()
	old := restartWait
	restartWait = time.Millisecond
	defer func() { restartWait = old }()
	_, code := execute(daemon.ExecArgs{Kind: "run", Host: "h", Cmd: "ls"})
	return f.calls.Load(), code
}

func TestExecuteRetries103Once(t *testing.T) {
	if n, code := runRetry(t, 1); n != 2 || code != -1 {
		t.Fatalf("one 103: calls=%d code=%d", n, code)
	}
	if n, code := runRetry(t, 5); n != 2 || code != daemon.CodeRestarting {
		t.Fatalf("persistent 103: calls=%d code=%d", n, code)
	}
}
