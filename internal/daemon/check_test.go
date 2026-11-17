package daemon

import (
	"strings"
	"testing"

	"github.com/ASromancer/ostiary/internal/hosts"
)

func (h *harness) check(method, host string) CheckReply {
	h.t.Helper()
	var r CheckReply
	if err := h.call(method, &CheckArgs{Env: Env{Cwd: h.tmp, Agent: "codex"}, Host: host}, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func TestCheckAndCase(t *testing.T) {
	h := unlocked(t)
	// a different case reaches the same host, and the audit uses the configured name
	if r := h.exec(ExecArgs{Host: "WEB1", Cmd: "echo hi"}); r.Code != 0 || r.Exit != 0 {
		t.Fatalf("%+v", r)
	}
	if r := h.exec(ExecArgs{Host: "nope", Cmd: "echo hi"}); r.Code != CodeBlocked || !strings.Contains(r.Msg, "available: web1") {
		t.Fatalf("%+v", r)
	}
	var er ExplainReply
	h.call("Explain", &ExplainArgs{Env: Env{Cwd: h.tmp}, Cmd: "ls", Host: "Web1"}, &er)
	if !er.HostOK || er.Host != "web1" {
		t.Fatalf("%+v", er)
	}

	r := h.check("Check", "Web1")
	if r.Code != 0 || !r.OK || len(r.Stages) != 4 || r.Host != "web1" {
		t.Fatalf("%+v", r)
	}
	if r := h.check("Check", "hidden"); r.Code != CodeBlocked { // not visible to agents
		t.Fatalf("%+v", r)
	}
	var hl HostListReply
	h.call("HostList", &Empty{}, &hl)
	if c := hl.Checks["web1"]; !c.OK || c.At.IsZero() {
		t.Fatalf("%+v", hl.Checks)
	}
	if !strings.Contains(h.auditText(), `"kind":"check"`) {
		t.Fatal("check not audited")
	}
	// the human path works on a host agents cannot use
	if r := h.check("HostCheck", "web1"); !r.OK {
		t.Fatalf("%+v", r)
	}
	var none CheckReply
	if err := h.call("HostCheck", &CheckArgs{Host: "ghost"}, &none); err == nil {
		t.Fatal("unknown host accepted")
	}
}

func TestCheckLockedVault(t *testing.T) {
	h := setup(t) // locked
	r := h.check("Check", "web1")
	if r.OK || len(r.Stages) != 3 || r.Stages[1].Stage != "hostkey" || !r.Stages[1].OK || r.Stages[2].Err != "vault đang khóa" {
		t.Fatalf("%+v", r)
	}
}

func TestConfigChangeDropsConnection(t *testing.T) {
	h := unlocked(t)
	h.exec(ExecArgs{Cmd: "true"})
	pooled := func() bool { return h.d.pool.Has("web1") }
	if !pooled() {
		t.Fatal("no pooled connection after exec")
	}
	admin := func(op, name string, host *hosts.Host) {
		var br BeginReply
		h.call("Begin", &BeginArgs{Op: op, Name: name}, &br)
		var ar AdminReply
		if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: op, Name: name, Host: host}, &ar); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _, _, _ := h.d.snapshot()
	same := *cfg.Hosts["web1"]
	admin("host-set", "web1", &same)
	if pooled() {
		t.Fatal("host-set kept the old connection")
	}
	h.exec(ExecArgs{Cmd: "true"})
	admin("key-rm", "k1", nil)
	if pooled() {
		t.Fatal("key-rm kept the old connection")
	}
}
