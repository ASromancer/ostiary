package ui

import (
	"fmt"
	"strings"
)

const (
	diffMaxLines = 2000 // per side; longer input is cut and the diff ends with "…"
	diffContext  = 3
)

// unifiedDiff returns a unified-style diff of a to b ("" when they are
// equal). Lines start with "+", "-" or " "; hunks start with "@@". It uses an
// LCS table after trimming the common head and tail, so the work is bounded
// by diffMaxLines squared.
func unifiedDiff(a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	cut := len(x) > diffMaxLines || len(y) > diffMaxLines
	if len(x) > diffMaxLines {
		x = x[:diffMaxLines]
	}
	if len(y) > diffMaxLines {
		y = y[:diffMaxLines]
	}
	type op struct {
		c byte
		s string
	}
	var ops []op
	p := 0
	for p < len(x) && p < len(y) && x[p] == y[p] {
		ops = append(ops, op{' ', x[p]})
		p++
	}
	s := 0
	for s < len(x)-p && s < len(y)-p && x[len(x)-1-s] == y[len(y)-1-s] {
		s++
	}
	mx, my := x[p:len(x)-s], y[p:len(y)-s]
	n, m := len(mx), len(my)
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if mx[i] == my[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	for i, j := 0, 0; i < n || j < m; {
		switch {
		case i < n && j < m && mx[i] == my[j]:
			ops = append(ops, op{' ', mx[i]})
			i++
			j++
		case j >= m || (i < n && t[i+1][j] >= t[i][j+1]):
			ops = append(ops, op{'-', mx[i]})
			i++
		default:
			ops = append(ops, op{'+', my[j]})
			j++
		}
	}
	for _, o := range x[len(x)-s:] {
		ops = append(ops, op{' ', o})
	}

	// keep changes plus diffContext lines around them, in hunks
	keep := make([]bool, len(ops))
	for i, o := range ops {
		if o.c != ' ' {
			for k := max(0, i-diffContext); k <= min(len(ops)-1, i+diffContext); k++ {
				keep[k] = true
			}
		}
	}
	var out strings.Builder
	ai, bi := 1, 1 // line numbers in a and b of ops[i]
	for i := 0; i < len(ops); {
		if !keep[i] {
			if ops[i].c != '+' {
				ai++
			}
			if ops[i].c != '-' {
				bi++
			}
			i++
			continue
		}
		j, na, nb := i, 0, 0
		for ; j < len(ops) && keep[j]; j++ {
			if ops[j].c != '+' {
				na++
			}
			if ops[j].c != '-' {
				nb++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", ai, na, bi, nb)
		for ; i < j; i++ {
			out.WriteByte(ops[i].c)
			out.WriteString(ops[i].s)
			out.WriteByte('\n')
			if ops[i].c != '+' {
				ai++
			}
			if ops[i].c != '-' {
				bi++
			}
		}
	}
	if cut {
		out.WriteString("…\n")
	}
	return out.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
