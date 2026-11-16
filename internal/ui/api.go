package ui

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/ASromancer/ostiary/internal/audit"
	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/hosts"
)

const maxBody = 1 << 20

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v); err != nil {
		fail(w, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

func (s *Server) routes(mux *http.ServeMux) {
	b := s.opt.Backend
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := b.Status()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"status": st, "version": s.opt.Version})
	})
	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		p, err := b.Pending()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("POST /api/decide", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			ID                 int
			Choice, Note, Code string
		}
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Decide(daemon.DecideArgs{ID: a.ID, Choice: a.Choice, Note: a.Note, Code: a.Code}); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		h, err := b.HostList()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("POST /api/admin/begin", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Op, Name, Pass string }
		if !readJSON(w, r, &in) {
			return
		}
		a := daemon.BeginArgs{Op: in.Op, Name: in.Name}
		if in.Op == "telegram-pair" { // the bot token, for this op only
			a.Pass = []byte(in.Pass)
		}
		rep, err := b.Begin(a)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /api/admin/commit", func(w http.ResponseWriter, r *http.Request) {
		var a struct {
			Ticket                       int
			Code, Op, Name               string
			Host                         *hosts.Host
			Key, KeyPassphrase, Password string
			Pass                         string
			Force                        bool
		}
		if !readJSON(w, r, &a) {
			return
		}
		args := daemon.AdminArgs{Ticket: a.Ticket, Code: a.Code, Op: a.Op, Name: a.Name, Host: a.Host, Force: a.Force}
		if a.Key != "" {
			p, err := normalizeKey([]byte(a.Key), a.KeyPassphrase, a.Name)
			if err != nil {
				fail(w, err)
				return
			}
			args.PEM = p
		}
		if a.Password != "" {
			args.Password = []byte(a.Password)
		}
		if a.Pass != "" {
			args.Pass = []byte(a.Pass)
		}
		rep, err := b.Admin(args)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"out": rep.Out})
	})
	mux.HandleFunc("GET /api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		t, err := b.Tunnels()
		if err != nil {
			fail(w, err)
			return
		}
		if t == nil {
			t = []daemon.TunnelInfo{}
		}
		writeJSON(w, t)
	})
	mux.HandleFunc("POST /api/tunnels/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			fail(w, errors.New("bad id"))
			return
		}
		if err := b.TunnelClose(id); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/telegram", func(w http.ResponseWriter, r *http.Request) {
		t, err := b.Telegram()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, t)
	})
	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		midnight := time.Now()
		midnight = time.Date(midnight.Year(), midnight.Month(), midnight.Day(), 0, 0, 0, 0, midnight.Location())
		all, err := scanAudit(s.opt.AuditFile, func(e audit.Entry) bool {
			return !e.Time.Before(midnight) && (e.Kind == "run" || e.Kind == "job" || e.Kind == "get" || e.Kind == "put")
		})
		if err != nil {
			fail(w, err)
			return
		}
		sum := struct {
			Today       map[string]int `json:"today"` // by decision, agent commands only
			LastBlocked *audit.Entry   `json:"lastBlocked"`
			Tunnels     int            `json:"tunnels"`
			Telegram    string         `json:"telegram"` // none|pairing|paired
		}{Today: map[string]int{}}
		for i := range all {
			sum.Today[all[i].Decision]++
			if sum.LastBlocked == nil && all[i].Decision == "blocked" {
				sum.LastBlocked = &all[i]
			}
		}
		if t, err := b.Tunnels(); err == nil {
			sum.Tunnels = len(t)
		}
		sum.Telegram = "none"
		if tg, err := b.Telegram(); err == nil {
			switch {
			case tg.Paired:
				sum.Telegram = "paired"
			case tg.Pairing:
				sum.Telegram = "pairing"
			}
		}
		writeJSON(w, sum)
	})
	mux.HandleFunc("GET /api/config/diff", func(w http.ResponseWriter, r *http.Request) {
		type fileDiff struct {
			Name     string `json:"name"`
			Approved bool   `json:"approved"` // a last-approved copy exists
			Diff     string `json:"diff"`
			Error    string `json:"error,omitempty"`
		}
		out := []fileDiff{}
		// The copies are plain files an agent can write: they only count when they match what the vault approved.
		want, _ := b.ApprovedHash()
		verified := want != "" && want == daemon.HashConfigFiles(filepath.Join(s.opt.ApprovedDir, "hosts.toml"), filepath.Join(s.opt.ApprovedDir, "rules.toml"))
		for _, f := range []struct{ name, cur string }{{"hosts.toml", s.opt.HostsFile}, {"rules.toml", s.opt.RulesFile}} {
			cur, _ := os.ReadFile(f.cur)
			old, err := os.ReadFile(filepath.Join(s.opt.ApprovedDir, f.name))
			d := fileDiff{Name: f.name, Approved: err == nil}
			if err == nil && !verified {
				d.Approved, d.Error = false, "không xác minh được bản đã duyệt — xem file trực tiếp"
			} else if err == nil {
				d.Diff = unifiedDiff(string(old), string(cur))
			}
			out = append(out, d)
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /api/setup", func(w http.ResponseWriter, r *http.Request) {
		rep, err := b.Setup()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /api/setup/skip", func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Skip bool }
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.SetupSkip(a.Skip); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("POST /api/unlock", func(w http.ResponseWriter, r *http.Request) {
		var a struct{ Pass string }
		if !readJSON(w, r, &a) {
			return
		}
		if err := b.Unlock(a.Pass); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("POST /api/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := b.Lock(); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /api/keys", func(w http.ResponseWriter, r *http.Request) {
		k, err := b.Keys()
		if err != nil {
			fail(w, err)
			return
		}
		if k == nil {
			k = []string{}
		}
		writeJSON(w, k)
	})
	mux.HandleFunc("GET /api/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		entries, total, err := readAudit(s.opt.AuditFile, q.Get("host"), q.Get("decision"), q.Get("since"), q.Get("project"), limit, offset)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]any{"entries": entries, "total": total})
	})
	mux.HandleFunc("GET /api/out/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id <= 0 {
			fail(w, errors.New("bad id"))
			return
		}
		text, err := daemon.ReadOutput(id, r.URL.Query().Get("grep"), r.URL.Query().Get("range"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, map[string]string{"text": text})
	})
	mux.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		checks := []Check{}
		if s.opt.Doctor != nil {
			checks = s.opt.Doctor()
		}
		writeJSON(w, checks)
	})
	mux.HandleFunc("GET /api/knownhosts", func(w http.ResponseWriter, r *http.Request) {
		names := map[string]string{} // normalized address -> ostiary host name
		if hl, err := b.HostList(); err == nil {
			for name, h := range hl.Hosts {
				names[knownhosts.Normalize(h.Addr())] = name
			}
		}
		writeJSON(w, readKnownHosts(s.opt.KnownHostsFile, names))
	})
	mux.HandleFunc("GET /events", s.events)
}

// normalizeKey turns an uploaded private key (possibly passphrase
// protected) into the unencrypted OpenSSH PEM the vault stores, like
// 'ostiary key import' does.
func normalizeKey(b []byte, passphrase, name string) ([]byte, error) {
	raw, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, errors.New("this key is protected: enter its passphrase")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "ostiary-"+name)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// readLine returns the next line (with its newline), or nil if it is longer
// than max; an over-long line is discarded as it is read, never buffered.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if line != nil || len(chunk) > 0 {
			if len(line)+len(chunk) > max {
				line = nil
				for err == bufio.ErrBufferFull { // drop the rest of the line
					_, err = br.ReadSlice('\n')
				}
				return nil, err
			}
			line = append(line, chunk...)
		}
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

// scanAudit returns the audit entries keep accepts, newest first.
// ponytail: reads the whole file per request; index or tail-read if logs get huge.
func scanAudit(path string, keep func(audit.Entry) bool) ([]audit.Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []audit.Entry
	br := bufio.NewReader(f)
	for {
		line, err := readLine(br, 4<<20) // over-long or unparseable lines are skipped, not fatal
		if len(line) > 0 {
			var e audit.Entry
			if json.Unmarshal(line, &e) == nil && keep(e) {
				all = append(all, e)
			}
		}
		if err != nil {
			break
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })
	return all, nil
}

// readAudit returns audit entries newest first, filtered and paged.
// project matches, case-insensitively, a substring of the entry's repo or cwd.
func readAudit(path, host, decision, since, project string, limit, offset int) ([]audit.Entry, int, error) {
	project = strings.ToLower(project)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var sinceT time.Time
	if since != "" {
		t, err := time.ParseInLocation("2006-01-02", since, time.Local)
		if err != nil {
			return nil, 0, errors.New("since must be YYYY-MM-DD")
		}
		sinceT = t
	}
	all, err := scanAudit(path, func(e audit.Entry) bool {
		return !(host != "" && e.Host != host) && !(decision != "" && e.Decision != decision) && !(!sinceT.IsZero() && e.Time.Before(sinceT)) &&
			(project == "" || strings.Contains(strings.ToLower(e.Repo+"\n"+e.Cwd), project))
	})
	if err != nil {
		return nil, 0, err
	}
	total := len(all)
	offset = max(0, min(offset, total))
	end := min(offset+limit, total)
	page := all[offset:end]
	if page == nil {
		page = []audit.Entry{}
	}
	return page, total, nil
}

// events streams "update" whenever pending requests, lock state or auth
// mode change, so the page refreshes without polling.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last, idle := "", 0
	for {
		st, _ := s.opt.Backend.Status()
		p, _ := s.opt.Backend.Pending()
		ids := make([]string, len(p))
		for i, x := range p {
			ids[i] = strconv.Itoa(x.ID)
		}
		cur := fmt.Sprintf("%v|%s|%s", st.Locked, st.Auth, strings.Join(ids, ","))
		if cur != last {
			last, idle = cur, 0
			fmt.Fprintf(w, "event: update\ndata: %d\n\n", len(p))
			fl.Flush()
		} else if idle++; idle >= 15 {
			idle = 0
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

type knownHost struct {
	Host        string `json:"host"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name,omitempty"` // matching ostiary host, if any
}

const maxKnownHosts = 10000

// readKnownHosts lists known_hosts entries (public data). Unparseable lines
// and revoked/CA markers are skipped; a missing file gives an empty list.
func readKnownHosts(path string, names map[string]string) []knownHost {
	out := []knownHost{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for len(out) < maxKnownHosts {
		line, err := readLine(br, 64<<10)
		if len(line) > 0 {
			if marker, hs, key, _, _, perr := ssh.ParseKnownHosts(line); perr == nil && marker == "" {
				for _, h := range hs {
					out = append(out, knownHost{Host: h, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), Name: names[h]})
				}
			}
		}
		if err != nil {
			break
		}
	}
	return out
}
