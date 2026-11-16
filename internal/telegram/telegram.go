// Package telegram lets the paired human approve agent requests from a
// Telegram bot. It never handles admin operations: it only sees requests
// the approval queue hands it, and answers through Options.Resolve.
package telegram

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/policy"
)

const (
	pairTTL      = 10 * time.Minute
	maxPairFails = 5
	maxCmd       = 3000
	maxReasons   = 600
)

// Bot is a minimal Bot API client. Base is empty except in tests.
type Bot struct {
	Token string
	Base  string
	HTTP  *http.Client
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
}

// call posts one Bot API method. Errors never contain the token.
func (b *Bot) call(ctx context.Context, method string, params, out any) error {
	base := b.Base
	if base == "" {
		base = defaultBase()
	}
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/bot"+b.Token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return b.scrub(err)
	}
	req.Header.Set("Content-Type", "application/json")
	c := b.HTTP
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return b.scrub(err)
	}
	defer resp.Body.Close()
	var r apiResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d, bad response", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("telegram %s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (b *Bot) scrub(err error) error {
	s := err.Error()
	if b.Token != "" {
		s = strings.ReplaceAll(s, b.Token, "***")
	}
	return errors.New(s)
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
type Message struct {
	MessageID int    `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}
type Callback struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}
type Update struct {
	UpdateID int       `json:"update_id"`
	Message  *Message  `json:"message"`
	Callback *Callback `json:"callback_query"`
}

// GetMe validates the token and returns the bot's username.
func (b *Bot) GetMe(ctx context.Context) (string, error) {
	var u User
	if err := b.call(ctx, "getMe", struct{}{}, &u); err != nil {
		return "", fmt.Errorf("token Telegram không hợp lệ hoặc không kết nối được: %w", err)
	}
	return u.Username, nil
}

func (b *Bot) updates(ctx context.Context, offset, timeout int) ([]Update, error) {
	var u []Update
	err := b.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": timeout,
		"allowed_updates": []string{"message", "callback_query"}}, &u)
	return u, err
}

type button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func (b *Bot) send(ctx context.Context, chat int64, text, parse string, kb []button) (int, error) {
	p := map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": true}
	if parse != "" {
		p["parse_mode"] = parse
	}
	if len(kb) > 0 {
		p["reply_markup"] = map[string]any{"inline_keyboard": [][]button{kb}}
	}
	var m Message
	if err := b.call(ctx, "sendMessage", p, &m); err != nil {
		return 0, err
	}
	return m.MessageID, nil
}

// edit replaces the message text and drops its buttons.
func (b *Bot) edit(ctx context.Context, chat int64, msg int, text string) error {
	return b.call(ctx, "editMessageText", map[string]any{"chat_id": chat, "message_id": msg,
		"text": text, "parse_mode": "HTML", "disable_web_page_preview": true}, nil)
}

func (b *Bot) answer(ctx context.Context, id, text string) error {
	return b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

// Options configures a Service.
type Options struct {
	Bot              *Bot
	ChatID, UserID   int64 // 0 until paired
	AllowDestructive bool
	// Resolve decides request id with choice y|s|n (auth "telegram").
	Resolve func(id int, choice string) error
	// Pending returns a request that is still undecided.
	Pending func(id int) (approval.Request, bool)
	// OnPairCode returns a new pairing code; nil means a random 6 digits.
	OnPairCode func() string
}

// Status is what the UI shows.
type Status struct {
	Paired, Pairing, AllowDestructive bool
	Bot, LastError                    string
}

type sent struct {
	nonce   string
	text    string // HTML body, without the outcome line
	level   string
	kind    string
	msgID   int
	ready   chan struct{} // closed when the send finished (msgID set or failed)
	decided bool
}

type Pairing struct {
	code    string
	expires time.Time
	fails   int
	res     chan pairResult
}

type pairResult struct {
	chat, user int64
	err        error
}

// Service sends requests to the paired chat and turns button presses into
// decisions. Create with New; Run starts the long poll.
type Service struct {
	o Options

	// Tests may change these before Run.
	Now        func() time.Time
	PollSecs   int           // long-poll timeout, default 60
	MinBackoff time.Duration // default 1s, doubling to MaxBackoff
	MaxBackoff time.Duration // default 60s

	mu       sync.Mutex
	chat     int64
	user     int64
	allow    bool
	sent     map[int]*sent
	pair     *Pairing
	lastErr  string
	botName  string
	stopped  bool
	wg       sync.WaitGroup
	offset   int
	hostname string
}

func New(o Options) *Service {
	h, _ := os.Hostname()
	return &Service{o: o, Now: time.Now, PollSecs: 60, MinBackoff: time.Second, MaxBackoff: time.Minute,
		chat: o.ChatID, user: o.UserID, allow: o.AllowDestructive, sent: map[int]*sent{}, hostname: h}
}

// SetBotName records the @name shown in Status.
func (s *Service) SetBotName(n string) { s.mu.Lock(); s.botName = n; s.mu.Unlock() }

// SetError records why Telegram is not working (shown in Status).
func (s *Service) SetError(err error) { s.setErr(err) }

func (s *Service) SetAllowDestructive(on bool) { s.mu.Lock(); s.allow = on; s.mu.Unlock() }

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Paired: s.chat != 0 && s.user != 0, Pairing: s.pair != nil, AllowDestructive: s.allow,
		Bot: s.botName, LastError: s.lastErr}
}

func (s *Service) paired() bool { return s.chat != 0 && s.user != 0 }

func (s *Service) setErr(err error) {
	s.mu.Lock()
	s.lastErr = ""
	if err != nil {
		s.lastErr = err.Error()
	}
	s.mu.Unlock()
}

// Pair starts pairing with code ("" = a new one) and blocks until the human
// sends "/pair <code>" from a private chat, five wrong codes arrive, the
// code expires, or ctx ends. Run must be running to receive the message.
func (s *Service) Pair(ctx context.Context, code string) (chatID, userID int64, err error) {
	p := s.BeginPairing(code)
	select {
	case r := <-p.res:
		return r.chat, r.user, r.err
	case <-ctx.Done():
		s.endPairing(p, ctx.Err())
		return 0, 0, ctx.Err()
	case <-time.After(pairTTL):
		s.endPairing(p, errors.New("mã ghép đôi đã hết hạn"))
		r := <-p.res
		return 0, 0, r.err
	}
}

// BeginPairing starts pairing without waiting; the result arrives on the
// returned pairing's channel (see Pair for the blocking form). A new
// pairing replaces the previous one.
func (s *Service) BeginPairing(code string) *Pairing {
	if code == "" {
		if s.o.OnPairCode != nil {
			code = s.o.OnPairCode()
		} else {
			code = randDigits(6)
		}
	}
	p := &Pairing{code: code, expires: s.Now().Add(pairTTL), res: make(chan pairResult, 1)}
	s.mu.Lock()
	old := s.pair
	s.pair = p
	s.mu.Unlock()
	if old != nil {
		old.res <- pairResult{err: errors.New("đã bắt đầu ghép đôi mới")}
	}
	return p
}

// PairCode returns the code of the pairing in progress ("" if none).
func (s *Service) PairCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pair == nil {
		return ""
	}
	return s.pair.code
}

// Result waits for the pairing outcome.
func (p *Pairing) Result(ctx context.Context) (chat, user int64, err error) {
	select {
	case r := <-p.res:
		return r.chat, r.user, r.err
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

func (s *Service) endPairing(p *Pairing, err error) {
	s.mu.Lock()
	if s.pair == p {
		s.pair = nil
		p.res <- pairResult{err: err}
	}
	s.mu.Unlock()
}

func randDigits(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = '0' + b[i]%10
	}
	return string(b)
}

// Run long-polls until ctx ends.
func (s *Service) Run(ctx context.Context) {
	backoff := s.MinBackoff
	for ctx.Err() == nil {
		ups, err := s.o.Bot.updates(ctx, s.offset, s.PollSecs)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.setErr(fmt.Errorf("Telegram: không kết nối được (%v)", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > s.MaxBackoff {
				backoff = s.MaxBackoff
			}
			continue
		}
		backoff = s.MinBackoff
		s.setErr(nil)
		for _, u := range ups {
			if u.UpdateID >= s.offset {
				s.offset = u.UpdateID + 1
			}
			switch {
			case u.Callback != nil:
				s.callback(ctx, u.Callback)
			case u.Message != nil:
				s.message(ctx, u.Message)
			}
		}
	}
}

func (s *Service) message(ctx context.Context, m *Message) {
	code, ok := strings.CutPrefix(strings.TrimSpace(m.Text), "/pair ")
	if !ok || m.Chat.Type != "private" || m.From == nil || m.From.ID != m.Chat.ID {
		return // groups and anything but /pair <code> are ignored
	}
	code = strings.TrimSpace(code)
	s.mu.Lock()
	p := s.pair
	if p == nil {
		s.mu.Unlock()
		return
	}
	var reply string
	switch {
	case s.Now().After(p.expires):
		s.pair = nil
		p.res <- pairResult{err: errors.New("mã ghép đôi đã hết hạn")}
		reply = "Mã đã hết hạn. Hãy tạo mã mới trong Ostiary."
	case subtle.ConstantTimeCompare([]byte(code), []byte(p.code)) == 1:
		s.pair = nil
		s.chat, s.user = m.Chat.ID, m.From.ID
		p.res <- pairResult{chat: s.chat, user: s.user}
		reply = "Đã kết nối với Ostiary trên " + s.hostname
	default:
		p.fails++
		reply = "Mã không đúng."
		if p.fails >= maxPairFails {
			s.pair = nil
			p.res <- pairResult{err: errors.New("nhập sai mã 5 lần; hãy bắt đầu lại")}
			reply = "Nhập sai quá nhiều lần. Hãy bắt đầu lại trong Ostiary."
		}
	}
	s.mu.Unlock()
	_, _ = s.o.Bot.send(ctx, m.Chat.ID, reply, "", nil)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func esc(s string) string { return html.EscapeString(s) }

func noButtons(allow bool, r approval.Request) bool {
	return !allow && (r.Level == policy.Destructive.String() || r.Kind == "tunnel")
}

func (s *Service) text(r approval.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ Ostiary #%d · %s · %s\n", r.ID, esc(r.Level), esc(r.Host))
	if r.Agent != "" {
		fmt.Fprintf(&b, "Agent: %s\n", esc(r.Agent))
	}
	if r.Repo != "" {
		fmt.Fprintf(&b, "Dự án: %s\n", esc(filepath.Base(r.Repo)))
	}
	fmt.Fprintf(&b, "<pre>%s</pre>\n", esc(trunc(r.Cmd, maxCmd)))
	var rs []string
	for _, x := range r.Reasons {
		rs = append(rs, x.Text)
	}
	if len(rs) > 0 {
		fmt.Fprintf(&b, "Lý do: %s\n", esc(trunc(strings.Join(rs, "; "), maxReasons)))
	}
	if !r.Expires.IsZero() {
		fmt.Fprintf(&b, "Hết hạn: %s", r.Expires.Local().Format("15:04:05"))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Notify registers r and sends it to the paired chat in the background.
// It never blocks the caller.
func (s *Service) Notify(r approval.Request) {
	s.mu.Lock()
	if s.stopped || !s.paired() {
		s.mu.Unlock()
		return
	}
	nb := make([]byte, 8)
	if _, err := rand.Read(nb); err != nil {
		panic(err)
	}
	rec := &sent{nonce: hex.EncodeToString(nb), text: s.text(r), level: r.Level, kind: r.Kind, ready: make(chan struct{})}
	s.sent[r.ID] = rec
	chat, allow := s.chat, s.allow
	s.wg.Add(1)
	s.mu.Unlock()

	text := rec.text
	var kb []button
	if noButtons(allow, r) {
		text += "\n\nChỉ thông báo: hãy duyệt trên máy."
	} else {
		data := func(c string) string { return fmt.Sprintf("%d:%s:%s", r.ID, c, rec.nonce) }
		kb = []button{{"✅ Duyệt 1 lần", data("y")}}
		if r.Level != policy.Destructive.String() && r.Kind != "tunnel" {
			kb = append(kb, button{"⏱ 30 phút", data("s")})
		}
		kb = append(kb, button{"❌ Từ chối", data("n")})
	}
	go func() {
		defer s.wg.Done()
		defer close(rec.ready)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		id, err := s.o.Bot.send(ctx, chat, text, "HTML", kb)
		if err != nil {
			s.setErr(err)
			return
		}
		s.mu.Lock()
		rec.msgID = id
		s.mu.Unlock()
	}()
}

func (s *Service) callback(ctx context.Context, c *Callback) {
	answer := func(t string) { _ = s.o.Bot.answer(ctx, c.ID, t) }
	s.mu.Lock()
	okFrom := s.paired() && c.From.ID == s.user && c.Message != nil && c.Message.Chat.ID == s.chat
	allow := s.allow
	s.mu.Unlock()
	if !okFrom {
		answer("không hợp lệ")
		return
	}
	parts := strings.Split(c.Data, ":")
	if len(parts) != 3 {
		answer("không hợp lệ")
		return
	}
	id, err := strconv.Atoi(parts[0])
	choice := parts[1]
	s.mu.Lock()
	rec := s.sent[id]
	valid := err == nil && rec != nil && subtle.ConstantTimeCompare([]byte(parts[2]), []byte(rec.nonce)) == 1 &&
		(choice == "y" || choice == "n" || (choice == "s" && rec.level != policy.Destructive.String() && rec.kind != "tunnel"))
	if valid && choice != "n" && !allow && (rec.level == policy.Destructive.String() || rec.kind == "tunnel") {
		valid = false
	}
	decided := valid && rec.decided
	s.mu.Unlock()
	switch {
	case !valid:
		answer("không hợp lệ")
		return
	case decided:
		answer("đã xử lý")
		return
	}
	if _, ok := s.o.Pending(id); !ok {
		answer("đã xử lý")
		return
	}
	if err := s.o.Resolve(id, choice); err != nil {
		if _, ok := s.o.Pending(id); !ok {
			answer("đã xử lý")
		} else {
			answer("không thực hiện được")
		}
		return
	}
	answer("đã ghi nhận")
}

// Resolved edits the request's message once it is decided, here or elsewhere.
func (s *Service) Resolved(id int, d approval.Decision) {
	s.mu.Lock()
	rec := s.sent[id]
	if rec == nil || rec.decided {
		s.mu.Unlock()
		return
	}
	rec.decided = true
	time.AfterFunc(10*time.Minute, func() { s.mu.Lock(); delete(s.sent, id); s.mu.Unlock() })
	chat := s.chat
	s.wg.Add(1)
	s.mu.Unlock()

	var line string
	at := s.Now().Local().Format("15:04")
	switch {
	case d.Auth == "telegram" && d.OK:
		line = "✅ Đã duyệt bởi bạn qua Telegram lúc " + at
	case d.Auth == "telegram":
		line = "❌ Đã từ chối bởi bạn qua Telegram lúc " + at
	case d.Outcome == "timeout":
		line = "⌛ Hết hạn lúc " + at
	case d.Outcome == "restart":
		line = "⛔ Đã hủy vì Ostiary khởi động lại"
	default:
		line = "Đã xử lý trên máy lúc " + at
	}
	go func() {
		defer s.wg.Done()
		<-rec.ready
		s.mu.Lock()
		msg, text := rec.msgID, rec.text
		s.mu.Unlock()
		if msg == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.o.Bot.edit(ctx, chat, msg, text+"\n\n"+esc(line)); err != nil {
			s.setErr(err)
		}
	}()
}

// Stop refuses new notifications. Cancel Run's context separately.
func (s *Service) Stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
}

// Wait blocks until pending sends and edits finish, or max passes.
func (s *Service) Wait(max time.Duration) {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(max):
	}
}
