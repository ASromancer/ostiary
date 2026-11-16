package ui

import (
	"strconv"
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	if d := unifiedDiff("a\nb\n", "a\nb\n"); d != "" {
		t.Fatalf("equal input gave %q", d)
	}
	if d := unifiedDiff("a\nb\nc\n", "a\nb\nc\nd\n"); d != "@@ -1,3 +1,4 @@\n a\n b\n c\n+d\n" {
		t.Fatalf("add: %q", d)
	}
	if d := unifiedDiff("a\nb\nc\n", "a\nc\n"); d != "@@ -1,3 +1,2 @@\n a\n-b\n c\n" {
		t.Fatalf("remove: %q", d)
	}
	if d := unifiedDiff("a\nb\nc\n", "a\nB\nc\n"); d != "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n" {
		t.Fatalf("change: %q", d)
	}
	if d := unifiedDiff("", "x\n"); d != "@@ -1,0 +1,1 @@\n+x\n" {
		t.Fatalf("from empty: %q", d)
	}
}

func TestUnifiedDiffFarHunks(t *testing.T) {
	var a, b []string
	for i := 0; i < 30; i++ {
		a = append(a, "l"+strconv.Itoa(i))
		b = append(b, "l"+strconv.Itoa(i))
	}
	b[2], b[27] = "X", "Y"
	d := unifiedDiff(strings.Join(a, "\n"), strings.Join(b, "\n"))
	if strings.Count(d, "@@ -") != 2 || strings.Contains(d, "l15") {
		t.Fatalf("want two separate hunks without l15:\n%s", d)
	}
}

func TestUnifiedDiffCapped(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 5000; i++ {
		a.WriteString("a" + strconv.Itoa(i) + "\n")
		b.WriteString("b" + strconv.Itoa(i) + "\n")
	}
	d := unifiedDiff(a.String(), b.String())
	if !strings.HasSuffix(d, "…\n") || strings.Count(d, "\n") > 2*diffMaxLines+5 {
		t.Fatalf("not capped: %d lines", strings.Count(d, "\n"))
	}
}
