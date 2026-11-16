package daemon

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/audit"
	"github.com/ASromancer/ostiary/internal/hosts"
	"github.com/ASromancer/ostiary/internal/policy"
	"github.com/ASromancer/ostiary/internal/sshconn"
)

const (
	DefaultTunnelTTL = time.Hour
	MinTunnelTTL     = time.Minute
	MaxTunnelTTL     = 8 * time.Hour
)

type TunnelArgs struct {
	Env
	Host, Target string
	TTL          time.Duration
	ID           int           // TunnelClose
	ApprovalID   int           // second call after the request was approved
	WaitMax      time.Duration // with ApprovalID: give up waiting after this (0 = until decided)
}

type TunnelReply struct {
	ID      int
	Local   string // 127.0.0.1:<port>
	Until   time.Time
	Code    int
	Msg     string
	Pending int // approval needed: call again with ApprovalID = Pending
	Level   string
}

type TunnelInfo struct {
	ID                       int
	Host, Target, Local      string
	Until                    time.Time
	BytesIn, BytesOut, Conns int64
	Agent                    string
}

type tunnelEntry struct {
	TunnelInfo
	t      *sshconn.Tunnel
	reason atomic.Value // string: why it closed (default "ttl")
	cwd    string       // the agent's directory: its repo may cap the profile
	sig    string       // hostSig at open
}

func fmtTTL(d time.Duration) string {
	d = d.Round(time.Second)
	h, m, sec := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	var b strings.Builder
	for _, u := range []struct {
		n int
		s string
	}{{h, "h"}, {m, "m"}, {sec, "s"}} {
		if u.n > 0 {
			fmt.Fprintf(&b, "%d%s", u.n, u.s)
		}
	}
	return b.String()
}

func tunnelCmd(host, target string, ttl time.Duration) string {
	return fmt.Sprintf("mở tunnel tới %s qua %s trong %s", target, host, fmtTTL(ttl))
}

func (d *Daemon) addTunnel(e *tunnelEntry) bool {
	d.drainMu.Lock() // with draining checked under the same lock, no tunnel outlives closeTunnels
	defer d.drainMu.Unlock()
	if d.draining {
		return false
	}
	d.mu.Lock()
	d.tunnels[e.ID] = e
	if e.t.Closed() { // its timer fired before registration; onClose's delete already ran
		delete(d.tunnels, e.ID)
	}
	d.mu.Unlock()
	return true
}

// closeTunnel closes tunnel id for reason; onClose (set in TunnelOpen) logs and unregisters it.
func (d *Daemon) closeTunnel(id int, reason string) bool {
	d.mu.Lock()
	e := d.tunnels[id]
	d.mu.Unlock()
	if e == nil {
		return false
	}
	e.reason.CompareAndSwap(nil, reason)
	e.t.Close()
	return true
}

// closeTunnels closes every open tunnel (drain).
func (d *Daemon) closeTunnels() { d.closeTunnelsIf("restart", func(*tunnelEntry) bool { return true }) }

// closeTunnelsIf closes the open tunnels for which drop reports true.
func (d *Daemon) closeTunnelsIf(reason string, drop func(*tunnelEntry) bool) {
	d.mu.Lock()
	ids := make([]int, 0, len(d.tunnels))
	for id, e := range d.tunnels {
		if drop(e) {
			ids = append(ids, id)
		}
	}
	d.mu.Unlock()
	sort.Ints(ids)
	for _, id := range ids {
		d.closeTunnel(id, reason)
		log.Printf("closed tunnel %d (%s)", id, reason)
	}
}

// hostSig identifies what a tunnel's SSH connection depends on.
func hostSig(h *hosts.Host) string { return fmt.Sprintf("%s|%d|%s|%s", h.Host, h.Port, h.User, h.Key) }

// pruneTunnels closes tunnels that the config or vault no longer allows: the host
// is gone, its address, user or key changed, the target left the allow-list, agent
// access is off, the effective profile (with the repo cap) is readonly, or the key was removed.
func (d *Daemon) pruneTunnels() {
	d.mu.Lock()
	cfg := d.cfg
	var es []*tunnelEntry
	for _, e := range d.tunnels {
		es = append(es, e)
	}
	keys := map[string]bool{}
	if d.data != nil {
		for k := range d.data.Keys {
			keys[k] = true
		}
		for k := range d.data.Passwords {
			keys[k] = true
		}
	}
	haveVault := d.data != nil
	d.mu.Unlock()
	for _, e := range es {
		h := cfg.Hosts[e.Host]
		bad := h == nil || hostSig(h) != e.sig || !slices.Contains(h.Tunnels, e.Target) || (haveVault && h.Key != "" && !keys[h.Key])
		if !bad {
			repo, err := hosts.FindRepo(e.cwd)
			prof, ok := cfg.Visible(repo)[e.Host]
			bad = err != nil || !ok || prof == policy.ProfileReadonly
		}
		if bad {
			d.closeTunnel(e.ID, "config")
			log.Printf("closed tunnel %d (config)", e.ID)
		}
	}
}

func (s *Service) TunnelOpen(a *TunnelArgs, r *TunnelReply) error {
	d := s.d
	if a.ApprovalID == 0 && d.isDraining() {
		r.Code, r.Msg = CodeRestarting, restartingMsg
		return nil
	}
	cfg, _, locked, userOnly := d.snapshot()
	switch {
	case locked:
		r.Code, r.Msg = CodeNoDaemon, "vault is locked; ask the user to run 'ostiary unlock'"
		return nil
	case userOnly:
		r.Code, r.Msg = CodeBlocked, "ostiary config changed on disk and is not approved; ask the user to review it and run 'ostiary reload'"
		return nil
	}
	repo, err := hosts.FindRepo(a.Cwd)
	if err != nil {
		r.Code, r.Msg = CodeBlocked, err.Error()
		return nil
	}
	if _, ok := cfg.Visible(repo)[a.Host]; !ok {
		r.Code, r.Msg = CodeBlocked, fmt.Sprintf("host %q is not available to agents here; see 'ostiary hosts'", a.Host)
		return nil
	}
	if prof := cfg.Visible(repo)[a.Host]; prof == policy.ProfileReadonly {
		r.Code, r.Msg = CodeBlocked, fmt.Sprintf("host %q is read-only here; a tunnel could carry writes, so it is refused", a.Host)
		return nil
	}
	h := cfg.Hosts[a.Host]
	repoDir := ""
	if repo != nil {
		repoDir = repo.Dir
	}
	ttl := a.TTL
	if ttl <= 0 {
		ttl = DefaultTunnelTTL
	}
	if ttl < MinTunnelTTL {
		r.Code, r.Msg = CodeBlocked, fmt.Sprintf("ttl %s is too short; the minimum is %s", ttl, MinTunnelTTL)
		return nil
	}
	ttl = min(ttl, MaxTunnelTTL)
	target, err := hosts.NormalizeTarget(a.Target)
	if err != nil {
		r.Code, r.Msg = CodeBlocked, err.Error()
		return nil
	}
	a.Target = target
	display := tunnelCmd(a.Host, a.Target, ttl)
	r.Level = "destructive"
	e := audit.Entry{Kind: "tunnel", Agent: a.Agent, Cwd: a.Cwd, Repo: repoDir, Host: a.Host, Cmd: display, Level: r.Level}

	if !slices.Contains(h.Tunnels, a.Target) {
		e.ID, e.Decision, e.Note = newID(), "blocked", "target not in the host's tunnels allow-list"
		d.log.Write(e)
		r.Code = CodeBlocked
		r.Msg = fmt.Sprintf("blocked: %q is not an allowed tunnel target on %s; ask the user to add it to tunnels in the host settings", a.Target, a.Host)
		return nil
	}
	if a.ApprovalID == 0 { // always needs the human: no sticky, no policy shortcut
		id := newID()
		d.q.Add(approval.Request{ID: id, Time: time.Now(), Host: a.Host, User: h.User, Cwd: a.Cwd,
			Repo: repoDir, Agent: a.Agent, Kind: "tunnel", Cmd: display, Level: r.Level})
		d.cancelIfDraining()
		r.Pending, r.ID = id, id
		return nil
	}
	// check the id belongs to this request before WaitFor consumes the decision
	if p, ok := d.q.Peek(a.ApprovalID); !ok || p.Host != a.Host || p.Cmd != display || p.Kind != "tunnel" {
		r.Code, r.Msg = CodeDenied, "unknown or expired approval request; stop and ask the user"
		return nil
	}
	req, dec, done, ok := d.q.WaitFor(a.ApprovalID, a.WaitMax)
	if ok && !done && req.Host == a.Host && req.Cmd == display && req.Kind == "tunnel" {
		r.Pending, r.ID = a.ApprovalID, a.ApprovalID
		return nil
	}
	if !ok || req.Host != a.Host || req.Cmd != display || req.Kind != "tunnel" {
		r.Code, r.Msg = CodeDenied, "unknown or expired approval request; stop and ask the user"
		return nil
	}
	id := a.ApprovalID
	e.ID, e.CodeOK, e.Auth = id, &dec.CodeOK, dec.Auth
	if !dec.OK {
		e.Decision, e.Note = dec.Outcome, dec.Message
		if dec.Outcome == "restart" {
			e.Decision, e.Note = "cancelled", "restart"
		}
		d.log.Write(e)
		r.Code, r.ID = CodeDenied, id
		r.Msg = fmt.Sprintf("request #%d %s; stop and ask the user, do not retry another way", id, dec.Outcome)
		if dec.Outcome == "restart" {
			r.Msg = fmt.Sprintf("request #%d was cancelled because ostiary restarted; ask the user before retrying", id)
		}
		if dec.Message != "" {
			r.Msg += ". User says: " + dec.Message
		}
		return nil
	}
	e.Decision = "approved"
	r.ID = id
	if d.isDraining() {
		e.Decision, e.Note = "cancelled", "restart"
		d.log.Write(e)
		r.Code, r.Msg = CodeRestarting, restartingMsg
		return nil
	}
	t, err := d.target(a.Host, h)
	if err == nil {
		te := &tunnelEntry{TunnelInfo: TunnelInfo{ID: id, Host: a.Host, Target: a.Target, Agent: a.Agent, Until: time.Now().Add(ttl)}, cwd: a.Cwd, sig: hostSig(h)}
		te.t, err = d.pool.Forward(t, a.Target, ttl, func(st sshconn.Stats) {
			d.mu.Lock()
			delete(d.tunnels, id)
			d.mu.Unlock()
			reason, _ := te.reason.Load().(string)
			if reason == "" {
				reason = "ttl"
			}
			d.log.Write(audit.Entry{Kind: "tunnel", ID: id, Agent: a.Agent, Host: a.Host, Level: "destructive", Decision: "closed",
				Cmd:   fmt.Sprintf("close tunnel %d to %s", id, a.Target),
				Bytes: st.BytesIn + st.BytesOut,
				Note:  fmt.Sprintf("reason=%s bytes_in=%d bytes_out=%d conns=%d", reason, st.BytesIn, st.BytesOut, st.Conns)})
		})
		if err == nil {
			te.Local = te.t.Addr()
			if !d.addTunnel(te) { // a drain began meanwhile
				e.Note = "ostiary began restarting right after approval; tunnel closed at once"
				d.log.Write(e) // approved, then closed: keeps the log in order
				te.reason.Store("restart")
				te.t.Close()
				r.Code, r.Msg = CodeRestarting, restartingMsg
				return nil
			}
			d.log.Write(e)
			r.Local, r.Until = te.Local, te.Until
			return nil
		}
	}
	e.Decision, e.Note = "error", err.Error()
	d.log.Write(e)
	r.Code, r.Msg = CodeBlocked, err.Error()
	return nil
}

func (s *Service) TunnelList(_ *Empty, r *[]TunnelInfo) error {
	d := s.d
	d.mu.Lock()
	out := make([]TunnelInfo, 0, len(d.tunnels))
	for _, e := range d.tunnels {
		i := e.TunnelInfo
		st := e.t.Stats()
		i.BytesIn, i.BytesOut, i.Conns = st.BytesIn, st.BytesOut, st.Conns
		out = append(out, i)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	*r = out
	return nil
}

func (s *Service) TunnelClose(a *TunnelArgs, _ *Empty) error {
	if !s.d.closeTunnel(a.ID, "close") {
		return fmt.Errorf("no open tunnel %d", a.ID)
	}
	return nil
}
