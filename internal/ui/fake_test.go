package ui

import (
	"errors"
	"sync"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/hosts"
)

type fakeBackend struct {
	mu      sync.Mutex
	pending []approval.Request
	decided []daemon.DecideArgs
	admin   []daemon.AdminArgs
	locked  bool
	failAll bool
	setup   daemon.SetupReply
	skipped *bool
	tunnels []daemon.TunnelInfo
	closed  []int
	begun   []daemon.BeginArgs
	hash    string // the vault's approved config hash
}

func (f *fakeBackend) Status() (daemon.StatusReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return daemon.StatusReply{Locked: f.locked, Pending: len(f.pending), Auth: "os"}, nil
}
func (f *fakeBackend) Pending() ([]approval.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]approval.Request{}, f.pending...), nil
}
func (f *fakeBackend) Decide(a daemon.DecideArgs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll {
		return errors.New("not confirmed by the user")
	}
	f.decided = append(f.decided, a)
	return nil
}
func (f *fakeBackend) HostList() (daemon.HostListReply, error) {
	return daemon.HostListReply{Hosts: map[string]hosts.Host{"web1": {Host: "10.0.0.5", User: "deploy", Agent: true}},
		Trusted: map[string]bool{"web1": true}}, nil
}
func (f *fakeBackend) Begin(a daemon.BeginArgs) (daemon.BeginReply, error) {
	f.mu.Lock()
	f.begun = append(f.begun, a)
	f.mu.Unlock()
	return daemon.BeginReply{Ticket: 77, OSAuth: true, Info: "info:" + a.Op + ":" + string(a.Pass)}, nil
}
func (f *fakeBackend) Admin(a daemon.AdminArgs) (daemon.AdminReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admin = append(f.admin, a)
	return daemon.AdminReply{Out: "done " + a.Op}, nil
}
func (f *fakeBackend) Unlock(pass string) error {
	if pass != "pw" {
		return errors.New("vault: wrong master key or passphrase")
	}
	f.mu.Lock()
	f.locked = false
	f.mu.Unlock()
	return nil
}
func (f *fakeBackend) Lock() error { f.mu.Lock(); f.locked = true; f.mu.Unlock(); return nil }
func (f *fakeBackend) Keys() ([]string, error) {
	return []string{"web1-agent\tssh-ed25519 SHA256:abc"}, nil
}
func (f *fakeBackend) Setup() (daemon.SetupReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setup, nil
}
func (f *fakeBackend) SetupSkip(skip bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skipped = &skip
	return nil
}
func (f *fakeBackend) Tunnels() ([]daemon.TunnelInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]daemon.TunnelInfo{}, f.tunnels...), nil
}
func (f *fakeBackend) TunnelClose(id int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, id)
	return nil
}

func (f *fakeBackend) Telegram() (daemon.TelegramReply, error) {
	return daemon.TelegramReply{Configured: true, Paired: true, Bot: "ostiary_bot", AllowDestructive: true}, nil
}

func (f *fakeBackend) ApprovedHash() (string, error) { return f.hash, nil }
