package ui

import (
	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/daemon"
)

// Backend is what the UI needs from the daemon. ServiceBackend calls the
// daemon's RPC methods in-process, so plan A's OS authentication and every
// policy check apply exactly as for the CLI.
type Backend interface {
	Status() (daemon.StatusReply, error)
	Pending() ([]approval.Request, error)
	Decide(a daemon.DecideArgs) error
	HostList() (daemon.HostListReply, error)
	Begin(a daemon.BeginArgs) (daemon.BeginReply, error)
	Admin(a daemon.AdminArgs) (daemon.AdminReply, error)
	Unlock(pass string) error
	Lock() error
	Keys() ([]string, error)
	Setup() (daemon.SetupReply, error)
	SetupSkip(skip bool) error
	Tunnels() ([]daemon.TunnelInfo, error)
	TunnelClose(id int) error
	Telegram() (daemon.TelegramReply, error)
	ApprovedHash() (string, error) // the vault's hash of the approved config
}

type ServiceBackend struct{ S *daemon.Service }

func (b ServiceBackend) Status() (r daemon.StatusReply, err error) {
	err = b.S.Status(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Pending() (r []approval.Request, err error) {
	err = b.S.Pending(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Decide(a daemon.DecideArgs) error { return b.S.Decide(&a, &daemon.Empty{}) }
func (b ServiceBackend) HostList() (r daemon.HostListReply, err error) {
	err = b.S.HostList(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Begin(a daemon.BeginArgs) (r daemon.BeginReply, err error) {
	err = b.S.Begin(&a, &r)
	return
}
func (b ServiceBackend) Admin(a daemon.AdminArgs) (r daemon.AdminReply, err error) {
	err = b.S.Admin(&a, &r)
	return
}
func (b ServiceBackend) Unlock(pass string) error {
	return b.S.Unlock(&daemon.UnlockArgs{Pass: pass}, &daemon.Empty{})
}
func (b ServiceBackend) Lock() error { return b.S.Lock(&daemon.Empty{}, &daemon.Empty{}) }
func (b ServiceBackend) Keys() ([]string, error) {
	var r daemon.KeysReply
	err := b.S.Keys(&daemon.Empty{}, &r)
	return r.Keys, err
}
func (b ServiceBackend) Setup() (r daemon.SetupReply, err error) {
	err = b.S.Setup(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) SetupSkip(skip bool) error {
	return b.S.SetupSkip(&daemon.SetupSkipArgs{Skip: skip}, &daemon.Empty{})
}
func (b ServiceBackend) Tunnels() (r []daemon.TunnelInfo, err error) {
	err = b.S.TunnelList(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) TunnelClose(id int) error {
	return b.S.TunnelClose(&daemon.TunnelArgs{ID: id}, &daemon.Empty{})
}
func (b ServiceBackend) Telegram() (r daemon.TelegramReply, err error) {
	err = b.S.TelegramStatus(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) ApprovedHash() (string, error) {
	var r daemon.ApprovedHashReply
	err := b.S.ApprovedHash(&daemon.Empty{}, &r)
	return r.Hash, err
}
