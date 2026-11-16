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
		d.tg.svc.Retire()
		d.tg.cancel()
		d.tg.svc.Stop()
	}
	svc := telegram.New(telegram.Options{
		Bot: &telegram.Bot{Token: token}, ChatID: chat, UserID: user, AllowDestructive: allow,
		Resolve: d.tgResolve, Pending: d.q.Get, OnPairVoid: d.tgPairVoid,
	})
	svc.SetBotName(bot)
	ctx, cancel := context.WithCancel(context.Background())
	d.tg.svc, d.tg.cancel = svc, cancel
	go svc.Run(ctx)
	return svc, nil
}

// tgTicket is what a telegram-pair ticket carries: the token checked at Begin
// and the bot it belongs to, which the human sees before approving.
type tgTicket struct{ token, bot string }

// telegramBegin trims and validates the pasted token and asks Telegram which bot it is.
func telegramBegin(pass []byte) (*tgTicket, error) {
	token, err := telegram.ValidToken(string(pass))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	name, err := (&telegram.Bot{Token: token}).GetMe(ctx)
	if err != nil {
		return nil, err
	}
	return &tgTicket{token: token, bot: name}, nil
}

// tgStop stops polling and notifying. permanent (drain) also refuses later starts.
func (d *Daemon) tgStop(permanent bool) {
	d.tg.mu.Lock()
	defer d.tg.mu.Unlock()
	d.tg.closed = d.tg.closed || permanent
	if d.tg.cancel != nil {
		if !permanent { // drain cancels the queue itself, and its edits say why
			d.tg.svc.Retire()
		}
		d.tg.cancel()
		d.tg.svc.Stop()
		if !permanent { // lock: drop the service (Go strings cannot be wiped, so the token lingers until GC)
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
	if svc, err := d.tgStart(s[setTGToken], s[setTGBot], chat, user, s[setTGDestOn] != "off"); err == nil {
		svc.SetUser(s[setTGUser+"name"])
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
func (d *Daemon) tgResolve(id int, choice string, user int64) error {
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
	dec, err := d.q.Resolve(id, choice, "", "telegram")
	if err == nil { // who pressed the button, next to the request's own audit entry
		d.log.Write(audit.Entry{Kind: "approve", ID: id, Host: req.Host, Cmd: "telegram #" + strconv.Itoa(id),
			Decision: dec.Outcome, Auth: "telegram", Note: "telegram user id " + strconv.FormatInt(user, 10)})
	}
	return err
}

// ApprovedHash returns the config hash the human approved, from the vault ("" while locked).
func (s *Service) ApprovedHash(_ *Empty, r *ApprovedHashReply) error {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	if s.d.data != nil {
		r.Hash = s.d.data.ConfigHash
	}
	return nil
}

// TelegramStatus reports the Telegram state for the UI. The token never leaves the vault.
func (s *Service) TelegramStatus(_ *Empty, r *TelegramReply) error {
	d := s.d
	d.mu.Lock()
	if d.data != nil {
		r.Configured = d.data.Settings[setTGToken] != ""
		r.Bot = d.data.Settings[setTGBot]
		r.User = d.data.Settings[setTGUser+"name"]
		r.AllowDestructive = d.data.Settings[setTGDestOn] != "off"
	}
	d.mu.Unlock()
	if svc := d.tgService(); svc != nil {
		st := svc.Status()
		r.Paired, r.Pairing, r.AllowDestructive, r.LastError = st.Paired, st.Pairing, st.AllowDestructive, st.LastError
		if c := st.Candidate; c != nil {
			r.CandUser, r.CandName, r.CandID = c.Username, c.Name, c.UserID
		}
		if !st.PairExpires.IsZero() {
			r.PairExpires = st.PairExpires.Unix()
		}
		if st.Bot != "" {
			r.Bot = st.Bot
		}
		if st.User != "" {
			r.User = st.User
		}
	}
	return nil
}

// telegramAdmin runs an approved telegram-* admin op. The bot token arrives
// in a.Pass, never in a name that is shown, audited or put in a notification.
func (d *Daemon) telegramAdmin(a *AdminArgs, data any, r *AdminReply) error {
	switch a.Op {
	case "telegram-pair":
		tk, ok := data.(*tgTicket) // the ticket's token only; Admin's Pass is ignored
		if !ok {
			return errors.New("approval ticket has no bot; start again")
		}
		return d.telegramPair(tk, r)
	case "telegram-confirm":
		c, ok := data.(*tgCand)
		if !ok {
			return errors.New("approval ticket has no account; start again")
		}
		return d.telegramConfirm(c, r)
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
	for _, k := range []string{setTGToken, setTGBot, setTGChat, setTGUser, setTGUser + "name"} {
		delete(d.data.Settings, k)
	}
	r.Out = "telegram disconnected"
	return d.saveVault()
}

func (d *Daemon) telegramPair(tk *tgTicket, r *AdminReply) error {
	d.mu.Lock()
	if d.data == nil {
		d.mu.Unlock()
		return errors.New("vault is locked; run 'ostiary unlock' first")
	}
	d.data.Settings[setTGToken], d.data.Settings[setTGBot] = tk.token, tk.bot
	for _, k := range []string{setTGChat, setTGUser, setTGUser + "name"} {
		delete(d.data.Settings, k)
	}
	allow := d.data.Settings[setTGDestOn] != "off"
	err := d.saveVault()
	d.mu.Unlock()
	if err != nil {
		return err
	}
	svc, err := d.tgStart(tk.token, tk.bot, 0, 0, allow)
	if err != nil {
		return err
	}
	svc.BeginPairing("")
	r.Out = fmt.Sprintf("@%s %s", tk.bot, svc.PairCode())
	return nil
}

// tgCand is what a telegram-confirm ticket carries: the account the human sees in the dialog.
type tgCand struct {
	id              int64
	user, name, bot string
}

// telegramConfirmBegin captures the pending candidate for a ticket.
func (d *Daemon) telegramConfirmBegin() (*tgCand, error) {
	svc := d.tgService()
	if svc == nil {
		return nil, errors.New("chưa có yêu cầu ghép nối Telegram nào")
	}
	st := svc.Status()
	if st.Candidate == nil {
		return nil, errors.New("chưa có tài khoản Telegram nào gửi mã ghép nối")
	}
	c := st.Candidate
	return &tgCand{id: c.UserID, user: c.Username, name: c.Name, bot: st.Bot}, nil
}

// String names the account: @user (id N, name), omitting what is empty.
func (c *tgCand) String() string {
	id := "id " + strconv.FormatInt(c.id, 10)
	if c.user == "" {
		if c.name == "" {
			return id
		}
		return id + " (" + c.name + ")"
	}
	if c.name == "" {
		return "@" + c.user + " (" + id + ")"
	}
	return "@" + c.user + " (" + id + ", " + c.name + ")"
}

// tgPairVoid records that two accounts sent the right code, so the pairing was cancelled.
func (d *Daemon) tgPairVoid(first, second telegram.Candidate) {
	who := func(c telegram.Candidate) string {
		return (&tgCand{id: c.UserID, user: c.Username, name: c.Name}).String()
	}
	d.log.Write(audit.Entry{Kind: "admin", Cmd: "telegram-pair-cancelled", Decision: "denied",
		Note: fmt.Sprintf("two Telegram accounts sent the pairing code: %s and %s", who(first), who(second))})
	if d.q.Notify != nil {
		_ = d.q.Notify(approval.Notice{Title: "Ostiary", Body: "Ghép nối Telegram đã bị hủy: hai tài khoản gửi cùng một mã (" + who(first) + ", " + who(second) + "). Hãy ghép lại trên máy."})
	}
}

// telegramConfirm stores the chat and user ids of the account the human approved.
func (d *Daemon) telegramConfirm(c *tgCand, r *AdminReply) error {
	svc := d.tgService()
	if svc == nil {
		return errors.New("chưa có yêu cầu ghép nối Telegram nào")
	}
	cand, err := svc.Confirm(c.id, func(cand telegram.Candidate) error { // saves first: paired only if stored
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.data == nil {
			return errors.New("vault is locked; run 'ostiary unlock' first")
		}
		d.data.Settings[setTGChat], d.data.Settings[setTGUser] = strconv.FormatInt(cand.ChatID, 10), strconv.FormatInt(cand.UserID, 10)
		d.data.Settings[setTGUser+"name"] = cand.Username
		if err := d.saveVault(); err != nil {
			delete(d.data.Settings, setTGChat)
			delete(d.data.Settings, setTGUser)
			delete(d.data.Settings, setTGUser+"name")
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	who := (&tgCand{id: cand.UserID, user: cand.Username, name: cand.Name}).String()
	d.log.Write(audit.Entry{Kind: "admin", Cmd: "telegram-paired", Decision: "allow",
		Note: fmt.Sprintf("bot @%s, telegram user %s, chat id %d", c.bot, who, cand.ChatID)})
	if d.q.Notify != nil {
		_ = d.q.Notify(approval.Notice{Title: "Ostiary", Body: fmt.Sprintf("Ostiary đã kết nối với Telegram %s qua @%s", who, c.bot)})
	}
	r.Out = "telegram paired with " + who
	return nil
}
