package daemon

import (
	"context"
	"github.com/ASromancer/ostiary/internal/approval"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func unlocked(t *testing.T) *harness {
	h := setup(t)
	if err := h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDrainWaitsForRunningAndRefusesNew(t *testing.T) {
	h := unlocked(t)
	res := make(chan ExecReply, 1)
	go func() { res <- h.exec(ExecArgs{Cmd: "sleep 1"}) }()
	for i := 0; i < 100; i++ {
		var st StatusReply
		h.call("Status", &Empty{}, &st)
		if st.Running.Commands == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { h.d.Drain(context.Background(), false); close(done) }()
	time.Sleep(200 * time.Millisecond)
	if r := h.exec(ExecArgs{Cmd: "echo hi"}); r.Code != CodeRestarting || !strings.Contains(r.Msg, "restarting") {
		t.Fatalf("new exec while draining: %+v", r)
	}
	select {
	case <-done:
		t.Fatal("drain finished before the running command")
	default:
	}
	if r := <-res; r.Code != 0 || r.Exit != 0 {
		t.Fatalf("running command: %+v", r)
	}
	<-done
	if Running() {
		t.Fatal("listener still open after drain")
	}
}

func TestDrainCancelsPendingApproval(t *testing.T) {
	h := unlocked(t)
	r := h.exec(ExecArgs{Env: Env{Agent: "codex"}, Cmd: "sh -c 'exit 3'"})
	if r.Pending == 0 {
		t.Fatalf("expected a pending approval: %+v", r)
	}
	h.d.Drain(context.Background(), false)
	_, dec, done, ok := h.d.q.WaitFor(r.Pending, time.Second)
	if !ok || !done || dec.Outcome != "restart" || dec.OK {
		t.Fatalf("decision: %+v done=%v ok=%v", dec, done, ok)
	}
}

func TestDrainForceAndTwice(t *testing.T) {
	h := unlocked(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.call("Exec", &ExecArgs{Env: Env{Cwd: h.tmp, Agent: AgentClaude}, Kind: "run", Host: "web1", Cmd: "sleep 3"}, &ExecReply{})
	}()
	// The forced drain does not wait for the command, but the test must: on
	// Windows its open output file would block the temp-dir cleanup.
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		for i := 0; i < 50 && runningCommands(h.d) > 0; i++ {
			time.Sleep(100 * time.Millisecond)
		}
	})
	for i := 0; i < 100; i++ {
		if c, _, _ := h.d.runningCounts(); c == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	h.d.Drain(context.Background(), true)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("force waited %s", time.Since(start))
	}
	h.d.Drain(context.Background(), false) // second call returns, no panic
}

func TestDrainOnSignal(t *testing.T) {
	h := unlocked(t)
	sig := make(chan os.Signal, 2)
	go h.d.drainOnSignal(sig)
	sig <- syscall.SIGTERM
	for i := 0; i < 100 && Running(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if Running() || !h.d.isDraining() {
		t.Fatal("SIGTERM did not drain and close the listener")
	}
}

func TestDrainCancelsRequestAddedWhileDraining(t *testing.T) {
	h := unlocked(t)
	h.d.drainMu.Lock()
	h.d.draining = true // a drain began; its CancelAll already ran
	h.d.drainMu.Unlock()
	h.d.q.Add(approval.Request{ID: 999, Host: "web1", Cmd: "x", Kind: "run"})
	h.d.cancelIfDraining()
	if _, dec, done, ok := h.d.q.WaitFor(999, time.Second); !ok || !done || dec.Outcome != "restart" {
		t.Fatalf("%+v %v %v", dec, done, ok)
	}
}

func runningCommands(d *Daemon) int { c, _, _ := d.runningCounts(); return c }
