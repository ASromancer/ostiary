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
	"github.com/ASromancer/ostiary/internal/sshconn"
)

const (
	DefaultTunnelTTL = time.Hour
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
}

func fmtTTL(d time.Duration) string {
	s := d.Round(time.Second).String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "0m")
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
func (d *Daemon) closeTunnels() {
	d.mu.Lock()
	ids := make([]int, 0, len(d.tunnels))
	for id := range d.tunnels {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	sort.Ints(ids)
	for _, id := range ids {
		d.closeTunnel(id, "restart")
		log.Printf("drain: closed tunnel %d", id)
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
	h := cfg.Hosts[a.Host]
	repoDir := ""
	if repo != nil {
		repoDir = repo.Dir
	}
	ttl := a.TTL
	if ttl <= 0 {
		ttl = DefaultTunnelTTL
	}
	ttl = min(ttl, MaxTunnelTTL)
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
		r.Pending, r.ID = id, id
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
		r.Code, r.Msg = CodeRestarting, restartingMsg
		return nil
	}
	t, err := d.target(a.Host, h)
	if err == nil {
		te := &tunnelEntry{TunnelInfo: TunnelInfo{ID: id, Host: a.Host, Target: a.Target, Agent: a.Agent, Until: time.Now().Add(ttl)}}
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
