package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/audit"
	"github.com/ASromancer/ostiary/internal/hosts"
	"github.com/ASromancer/ostiary/internal/sshconn"
)

const checkTimeout = 25 * time.Second

// Check tests the connection to a host an agent may use. It is read-only (it
// runs only "true"), so it needs no approval; it is audited.
func (s *Service) Check(a *CheckArgs, r *CheckReply) error {
	cfg, _, _, _ := s.d.snapshot()
	repo, err := hosts.FindRepo(a.Cwd)
	if err != nil {
		r.Code, r.Msg = CodeBlocked, err.Error()
		return nil
	}
	canon, _, msg := cfg.Pick(repo, a.Host)
	if msg != "" {
		r.Code, r.Msg = CodeBlocked, msg
		return nil
	}
	s.d.check(canon, cfg.Hosts[canon], a.Agent, r)
	return nil
}

// HostCheck tests the connection to any configured host, for the human UI.
func (s *Service) HostCheck(a *CheckArgs, r *CheckReply) error {
	cfg, _, _, _ := s.d.snapshot()
	h := cfg.Hosts[a.Host]
	if h == nil {
		return fmt.Errorf("unknown host %q", a.Host)
	}
	s.d.check(a.Host, h, "ui", r)
	return nil
}

func (d *Daemon) check(name string, h *hosts.Host, agent string, r *CheckReply) {
	r.Host = name
	if !d.beginCmd() {
		r.Code, r.Msg = CodeRestarting, restartingMsg
		return
	}
	defer d.endCmd()
	t, err := d.target(name, h)
	noAuth := ""
	if err != nil {
		t.Auth = nil
		noAuth = err.Error()
		if d.isLocked() {
			noAuth = "vault đang khóa"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	start := time.Now()
	st := d.pool.Check(ctx, t, noAuth)
	r.At, r.Stages, r.OK = time.Now(), st, st[len(st)-1].OK && len(st) == 4
	d.mu.Lock()
	d.checks[name] = r.CheckInfo
	d.mu.Unlock()
	e := audit.Entry{ID: newID(), Kind: "check", Agent: agent, Host: name, Cmd: "check " + name, Decision: "allow",
		DurationMs: time.Since(start).Milliseconds(), Note: summarize(st)}
	d.log.Write(e)
}

func (d *Daemon) isLocked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.data == nil
}

// summarize is "tcp ok, hostkey ok, auth FAIL (auth)".
func summarize(st []sshconn.Stage) string {
	var p []string
	for _, s := range st {
		if s.OK {
			p = append(p, s.Stage+" ok")
		} else {
			p = append(p, fmt.Sprintf("%s FAIL (%s) %s", s.Stage, s.Code, s.Err))
		}
	}
	return strings.Join(p, ", ")
}

// dropConns forgets what changed for the named hosts: their pooled connection, their tunnels and their last check.
func (d *Daemon) dropConns(names ...string) {
	for _, n := range names {
		d.pool.Drop(n)
	}
	d.closeTunnelsIf("config", func(e *tunnelEntry) bool { return slices.Contains(names, e.Host) })
	d.mu.Lock()
	for _, n := range names {
		delete(d.checks, n)
	}
	d.mu.Unlock()
}

// hostsUsingKey lists the hosts whose credential is the vault entry key.
func (d *Daemon) hostsUsingKey(key string) []string {
	cfg, _, _, _ := d.snapshot()
	var out []string
	for n, h := range cfg.Hosts {
		if h.Key == key {
			out = append(out, n)
		}
	}
	return out
}
