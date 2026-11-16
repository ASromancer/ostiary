package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/audit"
	"github.com/ASromancer/ostiary/internal/policy"
	"github.com/ASromancer/ostiary/internal/telegram"
)

// Vault settings used by Telegram. The token lives only in the vault.
const (
	setTGToken  = "telegram-token"
	setTGBot    = "telegram-bot"
	setTGChat   = "telegram-chat"
	setTGUser   = "telegram-user"
	setTGDestOn = "telegram-destructive" // "off" disables; anything else is on
)

type tgState struct {
	mu     sync.Mutex
	svc    *telegram.Service
	cancel context.CancelFunc
	closed bool // draining: never start again
}

func (d *Daemon) tgService() *telegram.Service {
	d.tg.mu.Lock()
	defer d.tg.mu.Unlock()
	return d.tg.svc
}

// tgStart replaces the running service with one for token. The caller holds no lock.
func (d *Daemon) tgStart(token, bot string, chat, user int64, allow bool) (*telegram.Service, error) {
	d.tg.mu.Lock()
	defer d.tg.mu.Unlock()
	if d.tg.closed {
		return nil, errors.New("ostiary is restarting")
	}
	if d.tg.cancel != nil {
		d.tg.cancel()
		d.tg.svc.Stop()
	}
	svc := telegram.New(telegram.Options{
		Bot: &telegram.Bot{Token: token}, ChatID: chat, UserID: user, AllowDestructive: allow,
		Resolve: d.tgResolve, Pending: d.q.Get,
	})
	svc.SetBotName(bot)
	ctx, cancel := context.WithCancel(context.Background())
	d.tg.svc, d.tg.cancel = svc, cancel
	go svc.Run(ctx)
	return svc, nil
}

// tgStop stops polling and notifying. permanent (drain) also refuses later starts.
func (d *Daemon) tgStop(permanent bool) {
	d.tg.mu.Lock()
	defer d.tg.mu.Unlock()
	d.tg.closed = d.tg.closed || permanent
	if d.tg.cancel != nil {
		d.tg.cancel()
		d.tg.svc.Stop()
		if !permanent { // lock: the token must not stay in memory
			d.tg.svc, d.tg.cancel = nil, nil
		} else {
			d.tg.cancel = nil
		}
	}
}

func (d *Daemon) tgWait() {
	if svc := d.tgService(); svc != nil {
		svc.Wait(3 * time.Second)
	}
}

// tgResume starts the service from the unlocked vault when Telegram is paired.
func (d *Daemon) tgResume() {
	d.mu.Lock()
	var s map[string]string
	if d.data != nil {
		s = map[string]string{}
		for k, v := range d.data.Settings {
			s[k] = v
		}
	}
	d.mu.Unlock()
	chat, _ := strconv.ParseInt(s[setTGChat], 10, 64)
	user, _ := strconv.ParseInt(s[setTGUser], 10, 64)
	if s[setTGToken] == "" || chat == 0 || user == 0 {
		return
	}
	if _, err := d.tgStart(s[setTGToken], s[setTGBot], chat, user, s[setTGDestOn] != "off"); err != nil {
		return
	}
}

func (d *Daemon) tgNotify(r approval.Request) {
	if svc := d.tgService(); svc != nil {
		svc.Notify(r)
	}
}

func (d *Daemon) tgResolved(id int, dec approval.Decision) {
	if svc := d.tgService(); svc != nil {
		svc.Resolved(id, dec)
	}
}

// tgResolve is the only way Telegram decides anything: an agent request
// that is still pending, never a sticky approval for a destructive command
// or a tunnel.
func (d *Daemon) tgResolve(id int, choice string) error {
	if d.isDraining() {
		return errors.New("ostiary is restarting")
	}
	req, ok := d.q.Get(id)
	if !ok {
		return fmt.Errorf("no pending request #%d", id)
	}
	if choice == "s" && (req.Level == policy.Destructive.String() || req.Kind == "tunnel") {
		return errors.New("not approvable for 30 minutes")
	}
	_, err := d.q.Resolve(id, choice, "", "telegram")
	return err
}

// TelegramStatus reports the Telegram state for the UI. The token never leaves the vault.
func (s *Service) TelegramStatus(_ *Empty, r *TelegramReply) error {
	d := s.d
	d.mu.Lock()
	if d.data != nil {
		r.Configured = d.data.Settings[setTGToken] != ""
		r.Bot = d.data.Settings[setTGBot]
		r.AllowDestructive = d.data.Settings[setTGDestOn] != "off"
	}
	d.mu.Unlock()
	if svc := d.tgService(); svc != nil {
		st := svc.Status()
		r.Paired, r.Pairing, r.AllowDestructive, r.LastError = st.Paired, st.Pairing, st.AllowDestructive, st.LastError
		if st.Bot != "" {
			r.Bot = st.Bot
		}
	}
	return nil
}

// telegramAdmin runs an approved telegram-* admin op. The bot token arrives
// in a.Pass, never in a name that is shown, audited or put in a notification.
func (d *Daemon) telegramAdmin(a *AdminArgs, r *AdminReply) error {
	switch a.Op {
	case "telegram-pair":
		return d.telegramPair(string(a.Pass), r)
	case "telegram-settings":
		on := a.Name == "destructive-on"
		d.mu.Lock()
		if d.data == nil {
			d.mu.Unlock()
			return errors.New("vault is locked; run 'ostiary unlock' first")
		}
		d.data.Settings[setTGDestOn] = map[bool]string{true: "on", false: "off"}[on]
		err := d.saveVault()
		d.mu.Unlock()
		if err != nil {
			return err
		}
		if svc := d.tgService(); svc != nil {
			svc.SetAllowDestructive(on)
		}
		r.Out = map[bool]string{true: "destructive approvals over Telegram: on", false: "destructive approvals over Telegram: off"}[on]
		return nil
	}
	// telegram-unpair
	d.tgStop(false)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data == nil {
		return errors.New("vault is locked; run 'ostiary unlock' first")
	}
	for _, k := range []string{setTGToken, setTGBot, setTGChat, setTGUser} {
		delete(d.data.Settings, k)
	}
	r.Out = "telegram disconnected"
	return d.saveVault()
}

func (d *Daemon) telegramPair(token string, r *AdminReply) error {
	if token == "" {
		return errors.New("paste the bot token from @BotFather")
	}
	d.mu.Lock()
	locked := d.data == nil
	d.mu.Unlock()
	if locked {
		return errors.New("vault is locked; run 'ostiary unlock' first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	name, err := (&telegram.Bot{Token: token}).GetMe(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if d.data == nil {
		d.mu.Unlock()
		return errors.New("vault is locked; run 'ostiary unlock' first")
	}
	d.data.Settings[setTGToken], d.data.Settings[setTGBot] = token, name
	delete(d.data.Settings, setTGChat)
	delete(d.data.Settings, setTGUser)
	allow := d.data.Settings[setTGDestOn] != "off"
	err = d.saveVault()
	d.mu.Unlock()
	if err != nil {
		return err
	}
	svc, err := d.tgStart(token, name, 0, 0, allow)
	if err != nil {
		return err
	}
	p := svc.BeginPairing("")
	code := svc.PairCode()
	go d.tgFinishPairing(svc, p)
	r.Out = fmt.Sprintf("@%s %s", name, code)
	return nil
}

// tgFinishPairing stores the chat and user ids once the human has sent /pair <code>.
func (d *Daemon) tgFinishPairing(svc *telegram.Service, p *telegram.Pairing) {
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	chat, user, err := p.Result(ctx)
	if err != nil {
		svc.SetError(fmt.Errorf("Telegram: ghép đôi không thành công (%v)", err))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tgService() != svc || d.data == nil {
		return
	}
	d.data.Settings[setTGChat], d.data.Settings[setTGUser] = strconv.FormatInt(chat, 10), strconv.FormatInt(user, 10)
	if err := d.saveVault(); err != nil {
		svc.SetError(err)
		return
	}
	d.log.Write(audit.Entry{Kind: "admin", Cmd: "telegram-paired", Decision: "allow"})
}
