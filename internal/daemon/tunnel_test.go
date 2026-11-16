package daemon

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/paths"
)

func echo(t *testing.T) string {
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

// tunnelHarness allows target in web1's tunnels and reloads the config.
func tunnelHarness(t *testing.T, target string) *harness {
	h := unlocked(t)
	b, _ := os.ReadFile(paths.Hosts())
	s := strings.Replace(string(b), "agent = true\n", "agent = true\ntunnels = [\""+target+"\"]\n", 1)
	os.WriteFile(paths.Hosts(), []byte(s), 0o600)
	if err := h.d.loadConfig(); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) tunnel(a TunnelArgs) TunnelReply {
	h.t.Helper()
	a.Env = Env{Cwd: h.tmp, Agent: "codex"}
	if a.Host == "" {
		a.Host = "web1"
	}
	var r TunnelReply
	if err := h.call("TunnelOpen", &a, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) auditText() string {
	b, _ := os.ReadFile(paths.Audit())
	return string(b)
}

func TestTunnelBlockedTarget(t *testing.T) {
	h := tunnelHarness(t, echo(t))
	r := h.tunnel(TunnelArgs{Target: "127.0.0.1:9"})
	if r.Code != CodeBlocked || r.Pending != 0 || len(h.d.q.Pending()) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestTunnelApproveListCloseAudit(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	a := TunnelArgs{Target: target, TTL: 2 * time.Hour}
	r := h.tunnel(a)
	if r.Pending == 0 || r.Level != "destructive" {
		t.Fatalf("expected pending: %+v", r)
	}
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "s"}, &Empty{}); err == nil {
		t.Fatal("sticky approval accepted for a tunnel")
	}
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "y"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	a.ApprovalID = r.Pending
	r = h.tunnel(a)
	if r.Code != 0 || r.Local == "" {
		t.Fatalf("open: %+v", r)
	}
	// the same request again needs a new approval
	if r2 := h.tunnel(TunnelArgs{Target: target}); r2.Pending == 0 || r2.Pending == r.ID {
		t.Fatalf("second open: %+v", r2)
	}
	c, err := net.Dial("tcp", r.Local)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	var l []TunnelInfo
	if err := h.call("TunnelList", &Empty{}, &l); err != nil || len(l) != 1 || l[0].ID != r.ID || l[0].Target != target || l[0].BytesOut != 4 {
		t.Fatalf("list %+v %v", l, err)
	}
	if _, _, n := h.d.runningCounts(); n != 1 {
		t.Fatalf("running tunnels %d", n)
	}
	if err := h.call("TunnelClose", &TunnelArgs{ID: r.ID}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	if err := h.call("TunnelClose", &TunnelArgs{ID: r.ID}, &Empty{}); err == nil {
		t.Fatal("closing twice succeeded")
	}
	h.call("TunnelList", &Empty{}, &l)
	if len(l) != 0 {
		t.Fatalf("still listed: %+v", l)
	}
	log := h.auditText()
	if !strings.Contains(log, `"decision":"approved"`) || !strings.Contains(log, "reason=close bytes_in=4 bytes_out=4 conns=1") ||
		!strings.Contains(log, "trong 2h") {
		t.Fatalf("audit:\n%s", log)
	}
}

func TestTunnelDeny(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	r := h.tunnel(TunnelArgs{Target: target})
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "n"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	r = h.tunnel(TunnelArgs{Target: target, ApprovalID: r.Pending})
	if r.Code != CodeDenied {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(h.auditText(), `"decision":"denied"`) {
		t.Fatalf("audit:\n%s", h.auditText())
	}
}

func TestDrainClosesTunnels(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	r := h.tunnel(TunnelArgs{Target: target})
	h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "y"}, &Empty{})
	r = h.tunnel(TunnelArgs{Target: target, ApprovalID: r.Pending})
	if r.Local == "" {
		t.Fatalf("%+v", r)
	}
	h.d.Drain(t.Context(), false)
	if _, err := net.DialTimeout("tcp", r.Local, time.Second); err == nil {
		t.Fatal("tunnel still open after drain")
	}
	if _, _, c := h.d.runningCounts(); c != 0 {
		t.Fatalf("%d tunnels left", c)
	}
	if !strings.Contains(h.auditText(), "reason=restart") {
		t.Fatalf("audit:\n%s", h.auditText())
	}
	if r := h.tunnel(TunnelArgs{Target: target}); r.Code != CodeRestarting {
		t.Fatalf("open while draining: %+v", r)
	}
}

func TestFmtTTL(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "30s", 10 * time.Minute: "10m", 20 * time.Minute: "20m", time.Hour: "1h",
		90 * time.Minute: "1h30m", 8 * time.Hour: "8h", 5*time.Minute + 30*time.Second: "5m30s",
	} {
		if got := fmtTTL(d); got != want {
			t.Errorf("%s: %q want %q", d, got, want)
		}
	}
}

func TestTunnelMinTTLAndNoApprovalSteal(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	if r := h.tunnel(TunnelArgs{Target: target, TTL: time.Second}); r.Code != CodeBlocked || !strings.Contains(r.Msg, "too short") || len(h.d.q.Pending()) != 0 {
		t.Fatalf("%+v", r)
	}
	// a decided request for another command must survive a tunnel call that quotes its id
	ex := h.exec(ExecArgs{Env: Env{Agent: "codex"}, Cmd: "sh -c 'exit 3'"})
	h.call("Decide", &DecideArgs{ID: ex.Pending, Code: h.lastCode(), Choice: "y"}, &Empty{})
	if r := h.tunnel(TunnelArgs{Target: target, ApprovalID: ex.Pending}); r.Code != CodeDenied {
		t.Fatalf("%+v", r)
	}
	if r := h.exec(ExecArgs{Env: Env{Agent: "codex"}, Cmd: "sh -c 'exit 3'", ApprovalID: ex.Pending}); r.Code != 0 || r.Exit != 3 {
		t.Fatalf("approval was consumed: %+v", r)
	}
}

func openTunnel(t *testing.T, h *harness, target string) TunnelReply {
	t.Helper()
	r := h.tunnel(TunnelArgs{Target: target})
	h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "y"}, &Empty{})
	r = h.tunnel(TunnelArgs{Target: target, ApprovalID: r.Pending})
	if r.Local == "" {
		t.Fatalf("%+v", r)
	}
	return r
}

func TestTunnelClosesOnLockAndConfigChange(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	r := openTunnel(t, h, target)
	h.d.lock()
	if _, err := net.DialTimeout("tcp", r.Local, time.Second); err == nil {
		t.Fatal("tunnel still open after lock")
	}
	if !strings.Contains(h.auditText(), "reason=lock") {
		t.Fatalf("audit:\n%s", h.auditText())
	}
	// removing the target from the host closes the tunnel on the next config load
	h = tunnelHarness(t, target)
	r = openTunnel(t, h, target)
	b, _ := os.ReadFile(paths.Hosts())
	os.WriteFile(paths.Hosts(), []byte(strings.Replace(string(b), "tunnels = [\""+target+"\"]\n", "", 1)), 0o600)
	if err := h.d.loadConfig(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", r.Local, time.Second); err == nil {
		t.Fatal("tunnel still open after its target was removed")
	}
	if !strings.Contains(h.auditText(), "reason=config") {
		t.Fatalf("audit:\n%s", h.auditText())
	}
}

func TestTunnelRefusedOnReadonlyHost(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	b, _ := os.ReadFile(paths.Hosts())
	os.WriteFile(paths.Hosts(), []byte(strings.Replace(string(b), "agent = true\n", "agent = true\nprofile = \"readonly\"\n", 1)), 0o600)
	if err := h.d.loadConfig(); err != nil {
		t.Fatal(err)
	}
	if r := h.tunnel(TunnelArgs{Target: target}); r.Code != CodeBlocked || r.Pending != 0 || !strings.Contains(r.Msg, "read-only") {
		t.Fatalf("%+v", r)
	}
}

// Reload approves the files that were reviewed: swapping one between Begin and the commit is refused.
func TestReloadBoundToReviewedConfig(t *testing.T) {
	h := unlocked(t)
	hash := ConfigHash() // what the human reviewed
	var br BeginReply
	h.call("Begin", &BeginArgs{Op: "reload", Hash: hash}, &br)
	b, _ := os.ReadFile(paths.Hosts())
	os.WriteFile(paths.Hosts(), append(b, []byte("\n# swapped after review\n")...), 0o600)
	var ar AdminReply
	err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "reload"}, &ar)
	if err == nil || !strings.Contains(err.Error(), "đã thay đổi sau khi bạn xem") {
		t.Fatalf("%v", err)
	}
	h.d.mu.Lock()
	same := h.d.data.ConfigHash == hash
	h.d.mu.Unlock()
	if !same {
		t.Fatal("vault baseline changed by a refused reload")
	}
	// without a supplied hash (CLI) Begin pins the files as they are then
	h.call("Begin", &BeginArgs{Op: "reload"}, &br)
	b, _ = os.ReadFile(paths.Hosts())
	os.WriteFile(paths.Hosts(), append(b, []byte("# again\n")...), 0o600)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "reload"}, &ar); err == nil {
		t.Fatal("reload approved files that changed after Begin")
	}
	// unchanged files are approved and become the vault baseline
	h.call("Begin", &BeginArgs{Op: "reload"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "reload"}, &ar); err != nil {
		t.Fatal(err)
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	if h.d.data.ConfigHash != ConfigHash() {
		t.Fatal("baseline is not the approved bytes")
	}
}

// host-set that changes the address closes the tunnel (its connection was made for the old target).
func TestHostSetPrunesTunnels(t *testing.T) {
	target := echo(t)
	h := tunnelHarness(t, target)
	r := openTunnel(t, h, target)
	h.d.mu.Lock()
	cur := *h.d.cfg.Hosts["web1"]
	h.d.mu.Unlock()
	cur.Port = 2299
	var br BeginReply
	h.call("Begin", &BeginArgs{Op: "reload"}, &br) // approve the harness's tunnels edit first
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "reload"}, &AdminReply{}); err != nil {
		t.Fatal(err)
	}
	h.call("Begin", &BeginArgs{Op: "host-set", Name: "web1"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "host-set", Name: "web1", Host: &cur}, &AdminReply{}); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", r.Local, time.Second); err == nil {
		t.Fatal("tunnel still open after its host changed")
	}
}

func TestTgCandString(t *testing.T) {
	for c, want := range map[tgCand]string{
		{id: 7, user: "a", name: "Al"}: "@a (id 7, Al)",
		{id: 7, user: "a"}:             "@a (id 7)",
		{id: 7, name: "Al"}:            "id 7 (Al)",
		{id: 7}:                        "id 7",
	} {
		if got := c.String(); got != want {
			t.Errorf("%q want %q", got, want)
		}
	}
}
