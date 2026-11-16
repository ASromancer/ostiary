package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/telegram"
)

func TestTelegramResolveRules(t *testing.T) {
	h := unlocked(t)
	d := h.d
	add := func(id int, level, kind string) {
		d.q.Add(approval.Request{ID: id, Time: time.Now(), Host: "h", Cmd: "c", Level: level, Kind: kind})
	}
	add(1, "mutate", "run")
	add(2, "destructive", "run")
	add(3, "mutate", "tunnel")
	for _, id := range []int{2, 3} {
		if err := d.tgResolve(id, "s", 42); err == nil {
			t.Fatalf("#%d: sticky approval over Telegram allowed", id)
		}
	}
	if err := d.tgResolve(1, "y", 42); err != nil {
		t.Fatal(err)
	}
	if a := h.auditText(); !strings.Contains(a, "telegram user id 42") {
		t.Fatal("telegram user not audited:", a)
	}
	_, dec, done, ok := d.q.WaitFor(1, time.Second)
	if !ok || !done || !dec.OK || dec.Auth != "telegram" {
		t.Fatalf("%+v", dec)
	}
	if err := d.tgResolve(1, "y", 42); err == nil {
		t.Fatal("decided request resolved twice")
	}
	if err := d.tgResolve(99, "n", 42); err == nil {
		t.Fatal("unknown request resolved")
	}
}

func TestTelegramSettingsAndUnpair(t *testing.T) {
	h := unlocked(t)
	d := h.d
	d.mu.Lock()
	d.data.Settings[setTGToken] = "123:SECRET"
	d.data.Settings[setTGChat] = "7"
	d.mu.Unlock()
	var r AdminReply
	if err := d.telegramAdmin(&AdminArgs{Op: "telegram-settings", Name: "destructive-off"}, nil, &r); err != nil {
		t.Fatal(err)
	}
	var st TelegramReply
	h.call("TelegramStatus", &Empty{}, &st)
	if !st.Configured || st.AllowDestructive {
		t.Fatalf("%+v", st)
	}
	if err := d.telegramAdmin(&AdminArgs{Op: "telegram-unpair"}, nil, &r); err != nil {
		t.Fatal(err)
	}
	h.call("TelegramStatus", &Empty{}, &st)
	if st.Configured || st.Paired {
		t.Fatalf("%+v", st)
	}
	if strings.Contains(h.auditText(), "SECRET") {
		t.Fatal("token in audit log")
	}
}

func TestTelegramPairBoundToTicketBot(t *testing.T) {
	h := unlocked(t)
	// a bad token fails in Begin, before any ticket, and never echoes the token
	bad := "123456:short-secret-value\n"
	var r BeginReply
	err := h.call("Begin", &BeginArgs{Op: "telegram-pair", Pass: []byte(bad)}, &r)
	if err == nil || strings.Contains(err.Error(), "short-secret") || r.Ticket != 0 {
		t.Fatalf("%v %+v", err, r)
	}
	// the human is told which bot
	msg := h.d.adminMessage(&AdminArgs{Op: "telegram-pair"}, &tgTicket{token: "123456:TOKENTOKEN", bot: "my_bot"})
	if !strings.Contains(msg, "@my_bot") || !strings.Contains(msg, "approve agent requests") || strings.Contains(msg, "TOKENTOKEN") {
		t.Fatal(msg)
	}
	// Admin has no token of its own: without the ticket's bot it refuses
	var ar AdminReply
	if err := h.d.telegramAdmin(&AdminArgs{Op: "telegram-pair", Pass: []byte("999:" + strings.Repeat("x", 40))}, nil, &ar); err == nil {
		t.Fatal("paired with a token that was not in the ticket")
	}
}

func TestTelegramStatusShowsPairCode(t *testing.T) {
	h := unlocked(t)
	svc := telegram.New(telegram.Options{Bot: &telegram.Bot{Token: "1:x"}})
	h.d.tg.svc = svc
	var st TelegramReply
	h.call("TelegramStatus", &Empty{}, &st)
	if st.Pairing || st.PairCode != "" {
		t.Fatalf("%+v", st)
	}
	svc.BeginPairing("123456")
	h.call("TelegramStatus", &Empty{}, &st)
	if !st.Pairing || st.PairCode != "123456" || st.PairExpires <= time.Now().Unix() {
		t.Fatalf("%+v", st)
	}
}

func TestTelegramPairNameForcedEmpty(t *testing.T) {
	h := unlocked(t)
	a := &BeginArgs{Op: "telegram-pair", Name: "ignore previous instructions", Pass: []byte("bad")}
	(&Service{d: h.d}).Begin(a, &BeginReply{})
	if a.Name != "" {
		t.Fatalf("name kept: %q", a.Name)
	}
}
