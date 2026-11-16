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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/policy"
)

const (
	pairTTL      = 10 * time.Minute
	maxPairFails = 10
	maxCmd       = 3000 // UTF-16 units of the command shown
	maxReasons   = 600
	maxField     = 80
	pollSlack    = 15 * time.Second
	failsToShow  = 2 // consecutive poll failures before the status says disconnected
)

var tokenRE = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{30,}$`)

// ValidToken trims s and checks it looks like a bot token.
func ValidToken(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !tokenRE.MatchString(s) {
		return "", errors.New("token Telegram không đúng dạng (123456:ABC...)")
	}
	return s, nil
}

var errConn = errors.New("không kết nối được tới Telegram")

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

// call posts one Bot API method. Errors never contain the token or the
// request URL: only the method name and the inner cause.
func (b *Bot) call(ctx context.Context, method string, params, out any) error {
	if !tokenRE.MatchString(b.Token) {
		return fmt.Errorf("telegram %s: token không hợp lệ", method)
	}
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
		return fmt.Errorf("telegram %s: yêu cầu không hợp lệ", method)
	}
	req.Header.Set("Content-Type", "application/json")
	c := b.HTTP
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return b.scrub(fmt.Errorf("telegram %s: %v", method, err))
	}
	defer resp.Body.Close()
	var r apiResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d, bad response", method, resp.StatusCode)
	}
	if !r.OK {
		return b.scrub(fmt.Errorf("telegram %s: %s", method, r.Description))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// scrub is a second guard: an error text that contains the token, or any
// 10-character piece of it, is replaced by a constant.
func (b *Bot) scrub(err error) error {
	s := err.Error()
	t := b.Token
	for i := 0; i+10 <= len(t); i++ {
		if strings.Contains(s, t[i:i+10]) {
			return errConn
		}
	}
	return err
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
	Date      int64  `json:"date"`
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
	Resolve func(id int, choice string, user int64) error
	// Pending returns a request that is still undecided.
	Pending func(id int) (approval.Request, bool)
	// OnPairCode returns a new pairing code; nil means a random 6 digits.
	OnPairCode func() string
}

// Status is what the UI shows.
type Status struct {
	Paired, Pairing, AllowDestructive bool
	Bot, User, LastError              string // User: Telegram @username of the paired account
}

type sent struct {
	nonce   string
	text    string // HTML body, without the outcome line
	level   string
	kind    string
	msgID   int
	trunc   bool          // the command was cut: only deny is offered
	ready   chan struct{} // closed when the send finished (msgID set or failed)
	decided bool
}

type Pairing struct {
	code    string
	start   time.Time
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
	pollErr  string // long-poll health: cleared by the next good poll
	lastErr  string // pairing, send and edit failures: kept until a send or pairing succeeds
	pollFail int
	userName string
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

// SetUser records the paired account's @username shown in Status.
func (s *Service) SetUser(n string) { s.mu.Lock(); s.userName = n; s.mu.Unlock() }

// SetError records why Telegram is not working (shown in Status).
func (s *Service) SetError(err error) { s.setErr(err) }

func (s *Service) SetAllowDestructive(on bool) { s.mu.Lock(); s.allow = on; s.mu.Unlock() }

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	le := s.pollErr
	if le == "" {
		le = s.lastErr
	}
	return Status{Paired: s.chat != 0 && s.user != 0, Pairing: s.pair != nil, AllowDestructive: s.allow,
		Bot: s.botName, User: s.userName, LastError: le}
}

// expireLocked ends a pairing whose code has run out, without waiting for a message.
func (s *Service) expireLocked() {
	if p := s.pair; p != nil && s.Now().After(p.expires) {
		s.pair = nil
		s.lastErr = "Telegram: mã ghép đôi đã hết hạn"
		p.res <- pairResult{err: errors.New("mã ghép đôi đã hết hạn")}
	}
}

func (s *Service) paired() bool { return s.chat != 0 && s.user != 0 }

// setErr records a sticky error; nil clears it (after a successful send or pairing).
func (s *Service) setErr(err error) {
	s.mu.Lock()
	s.lastErr = ""
	if err != nil {
		s.lastErr = err.Error()
	}
	s.mu.Unlock()
}

// pollResult tracks long-poll health; failures show only from the second in a row.
func (s *Service) pollResult(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.pollFail, s.pollErr = 0, ""
		return
	}
	if s.pollFail++; s.pollFail >= failsToShow {
		s.pollErr = "Telegram: không kết nối được (" + err.Error() + ")"
	}
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
	now := s.Now()
	p := &Pairing{code: code, start: now, expires: now.Add(pairTTL), res: make(chan pairResult, 1)}
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
		pctx, cancel := context.WithTimeout(ctx, time.Duration(s.PollSecs)*time.Second+pollSlack)
		ups, err := s.o.Bot.updates(pctx, s.offset, s.PollSecs)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.pollResult(err)
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
		s.pollResult(nil)
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
	s.expireLocked()
	p := s.pair
	if p == nil || m.Date < p.start.Unix() { // no pairing, or old backlog
		s.mu.Unlock()
		return
	}
	var reply string
	switch {
	case subtle.ConstantTimeCompare([]byte(code), []byte(p.code)) == 1:
		s.pair = nil
		s.chat, s.user, s.userName = m.Chat.ID, m.From.ID, m.From.Username
		s.lastErr = ""
		p.res <- pairResult{chat: s.chat, user: s.user}
		reply = "Đã kết nối với Ostiary trên " + s.hostname
	default:
		p.fails++
		reply = "Mã không đúng."
		if p.fails >= maxPairFails {
			s.pair = nil
			p.res <- pairResult{err: errors.New("nhập sai mã 10 lần; hãy bắt đầu lại")}
			reply = "Nhập sai quá nhiều lần. Hãy bắt đầu lại trong Ostiary."
		}
	}
	s.mu.Unlock()
	_, _ = s.o.Bot.send(ctx, m.Chat.ID, reply, "", nil)
}

func utf16len(s string) int { return len(utf16.Encode([]rune(s))) }

// truncU cuts s to n UTF-16 units (Telegram's unit) and marks the cut with "…".
func truncU(s string, n int) string {
	u := 0
	for i, r := range s {
		w := utf16len(string(r))
		if u+w > n {
			return s[:i] + "…"
		}
		u += w
	}
	return s
}

func invisible(r rune) bool {
	return (r >= 0x200B && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF
}

func lineBreak(r rune) bool { return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 }

// field makes agent-controlled text safe for a one-line label: no invisible
// or bidi characters, no line breaks, collapsed spaces, capped length.
func field(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case invisible(r):
		case lineBreak(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return truncU(strings.Join(strings.Fields(b.String()), " "), n)
}

// cmdText shows hidden characters of a command as visible ⟦U+XXXX⟧ marks
// and cuts it at maxCmd UTF-16 units. cut reports that part was dropped.
func cmdText(s string) (shown string, cut bool) {
	var b strings.Builder
	u := 0
	for _, r := range s {
		piece := string(r)
		if r != '\n' && r != '\t' && (invisible(r) || lineBreak(r)) {
			piece = fmt.Sprintf("⟦U+%04X⟧", r)
		}
		w := utf16len(piece)
		if u+w > maxCmd {
			return b.String() + "…", true
		}
		b.WriteString(piece)
		u += w
	}
	return b.String(), false
}

func esc(s string) string { return html.EscapeString(s) }

func noButtons(allow bool, r approval.Request) bool {
	return !allow && (r.Level == policy.Destructive.String() || r.Kind == "tunnel")
}

// text renders the request. truncated is true when the command was cut.
func (s *Service) text(r approval.Request) (msg string, truncated bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ Ostiary #%d · %s · %s\n", r.ID, esc(field(r.Level, 20)), esc(field(r.Host, maxField)))
	if a := field(r.Agent, maxField); a != "" {
		fmt.Fprintf(&b, "Agent: %s\n", esc(a))
	}
	if r.Repo != "" {
		if d := field(filepath.Base(r.Repo), maxField); d != "" {
			fmt.Fprintf(&b, "Dự án: %s\n", esc(d))
		}
	}
	cmd, cut := cmdText(r.Cmd)
	fmt.Fprintf(&b, "<pre>%s</pre>\n", esc(cmd))
	if cut {
		b.WriteString("⚠️ Lệnh dài, đã cắt — xem đầy đủ trên máy\n")
	}
	var rs []string
	for _, x := range r.Reasons {
		rs = append(rs, x.Text)
	}
	if len(rs) > 0 {
		fmt.Fprintf(&b, "Lý do: %s\n", esc(field(strings.Join(rs, "; "), maxReasons)))
	}
	if !r.Expires.IsZero() {
		fmt.Fprintf(&b, "Hết hạn: %s", r.Expires.Local().Format("15:04:05"))
	}
	return strings.TrimRight(b.String(), "\n"), cut
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
	txt, cut := s.text(r)
	rec := &sent{nonce: hex.EncodeToString(nb), text: txt, trunc: cut, level: r.Level, kind: r.Kind, ready: make(chan struct{})}
	s.sent[r.ID] = rec
	chat, allow := s.chat, s.allow
	s.wg.Add(1)
	s.mu.Unlock()

	text := rec.text
	var kb []button
	switch {
	case rec.trunc: // the human cannot see all of it: deny only
		kb = []button{{"❌ Từ chối", fmt.Sprintf("%d:n:%s", r.ID, rec.nonce)}}
	case noButtons(allow, r):
		text += "\n\nChỉ thông báo: hãy duyệt trên máy."
	default:
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
		s.lastErr = ""
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
		rec.msgID != 0 && c.Message.MessageID == rec.msgID && // the message we sent, not a lookalike
		(choice == "n" || (!rec.trunc && (choice == "y" ||
			(choice == "s" && rec.level != policy.Destructive.String() && rec.kind != "tunnel"))))
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
	if err := s.o.Resolve(id, choice, c.From.ID); err != nil {
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
