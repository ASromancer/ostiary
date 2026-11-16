package telegram

import (
	"context"
	"encoding/json"
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

const tok = "123:SECRET"

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
		Resolve: func(id int, c string) error {
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
	return Update{UpdateID: 1, Message: &Message{Chat: Chat{ID: chat, Type: chatType}, From: &User{ID: user}, Text: text}}
}

func TestGetMeBadToken(t *testing.T) {
	f := newFake(t)
	_, err := (&Bot{Token: "bad", Base: f.srv.URL}).GetMe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "không hợp lệ") || strings.Contains(err.Error(), "bad:") {
		t.Fatal(err)
	}
	name, err := f.bot().GetMe(context.Background())
	if err != nil || name != "ostiary_bot" {
		t.Fatal(name, err)
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	b := &Bot{Token: tok, Base: "http://127.0.0.1:1"}
	_, err := b.GetMe(context.Background())
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestPairing(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e.f.push(pairMsg("group", -5, 7, "/pair 111111")) // ignored
	e.f.push(pairMsg("private", 7, 7, "/pair 111111"))
	chat, user, err := e.s.Pair(ctx, "111111")
	if err != nil || chat != 7 || user != 7 {
		t.Fatal(chat, user, err)
	}
	if !e.s.Status().Paired {
		t.Fatal("not paired")
	}
	m := e.f.find("sendMessage", 0)
	if m == nil || !strings.Contains(m.Body["text"].(string), "Đã kết nối với Ostiary trên") {
		t.Fatalf("%v", m)
	}
}

func TestPairingGroupIgnored(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	p := e.s.BeginPairing("222222")
	e.f.push(pairMsg("group", -5, 7, "/pair 222222"))
	time.Sleep(100 * time.Millisecond)
	if e.s.Status().Paired || e.f.count("sendMessage") != 0 {
		t.Fatal("group message was acted on")
	}
	_ = p
}

func TestPairingWrongCodesEndAfterFive(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		u := pairMsg("private", 7, 7, "/pair 000000")
		u.UpdateID = i + 1
		e.f.push(u)
	}
	_, _, err := e.s.Pair(ctx, "123456")
	if err == nil || !strings.Contains(err.Error(), "5 lần") {
		t.Fatal(err)
	}
	if e.s.Status().Pairing || e.s.Status().Paired {
		t.Fatal("state")
	}
	// the right code no longer works
	e.f.push(pairMsg("private", 7, 7, "/pair 123456"))
	time.Sleep(100 * time.Millisecond)
	if e.s.Status().Paired {
		t.Fatal("paired after pairing ended")
	}
}

func TestPairingExpires(t *testing.T) {
	e := newEnv(t, 0, 0, true)
	now := time.Now()
	e.s.mu.Lock()
	e.s.Now = func() time.Time { return now }
	e.s.mu.Unlock()
	p := e.s.BeginPairing("333333")
	now = now.Add(11 * time.Minute)
	e.f.push(pairMsg("private", 7, 7, "/pair 333333"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := p.Result(ctx)
	if err == nil || !strings.Contains(err.Error(), "hết hạn") || e.s.Status().Paired {
		t.Fatal(err)
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
		if a := answerText(t, e, i); a != "không hợp lệ" {
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
	if !strings.Contains(st.LastError, "không kết nối được") || strings.Contains(st.LastError, "SECRET") {
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
