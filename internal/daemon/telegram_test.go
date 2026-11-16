package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
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
		if err := d.tgResolve(id, "s"); err == nil {
			t.Fatalf("#%d: sticky approval over Telegram allowed", id)
		}
	}
	if err := d.tgResolve(1, "y"); err != nil {
		t.Fatal(err)
	}
	_, dec, done, ok := d.q.WaitFor(1, time.Second)
	if !ok || !done || !dec.OK || dec.Auth != "telegram" {
		t.Fatalf("%+v", dec)
	}
	if err := d.tgResolve(1, "y"); err == nil {
		t.Fatal("decided request resolved twice")
	}
	if err := d.tgResolve(99, "n"); err == nil {
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
	if err := d.telegramAdmin(&AdminArgs{Op: "telegram-settings", Name: "destructive-off"}, &r); err != nil {
		t.Fatal(err)
	}
	var st TelegramReply
	h.call("TelegramStatus", &Empty{}, &st)
	if !st.Configured || st.AllowDestructive {
		t.Fatalf("%+v", st)
	}
	if err := d.telegramAdmin(&AdminArgs{Op: "telegram-unpair"}, &r); err != nil {
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
