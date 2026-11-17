package sshconn

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Stage is the outcome of one step of a connection check.
type Stage struct {
	Stage string `json:"stage"` // tcp | hostkey | auth | exec
	OK    bool   `json:"ok"`
	Ms    int    `json:"ms"`
	Code  string `json:"code,omitempty"` // short failure code, see classify
	Err   string `json:"err,omitempty"`  // human text plus the raw error
}

// errNoAuth stops the handshake once the host key is known, when there is no credential to authenticate with.
var errNoAuth = errors.New("no credential")

// Check dials host t afresh (the pool is neither used nor changed), and reports
// tcp, hostkey, auth and exec ("true") in order, stopping at the first failure.
// noAuth is the reason to report for auth when t.Auth is nil (e.g. vault locked).
func (p *Pool) Check(ctx context.Context, t Target, noAuth string) []Stage {
	var out []Stage
	fail := func(stage string, start time.Time, err error) []Stage {
		code, msg := classify(stage, err)
		return append(out, Stage{Stage: stage, Ms: ms(start), Code: code, Err: msg})
	}
	start := time.Now()
	d := net.Dialer{Timeout: tcpTimeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return fail("tcp", start, err)
	}
	out = append(out, Stage{Stage: "tcp", OK: true, Ms: ms(start)})
	defer conn.Close() // on success the client below owns it; closing twice is harmless
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	cb, err := p.hostKeyCheck(t.Name)
	if err != nil {
		return fail("hostkey", start, err)
	}
	var keyErr error
	var keyAt time.Time
	cfg := &ssh.ClientConfig{User: t.User, HostKeyCallback: func(h string, r net.Addr, k ssh.PublicKey) error {
		keyAt, keyErr = time.Now(), cb(h, r, k)
		if keyErr == nil && t.Auth == nil {
			return errNoAuth
		}
		return keyErr
	}}
	if t.Auth != nil {
		cfg.Auth = []ssh.AuthMethod{t.Auth}
	}
	hsStart := time.Now()
	timeout := handshakeTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(dl))
	}
	c, err := handshake(conn, t.Addr, cfg, timeout)
	switch {
	case keyAt.IsZero(): // the server never got as far as presenting a key
		return fail("hostkey", hsStart, ctxErr(ctx, err))
	case keyErr != nil:
		return fail("hostkey", hsStart, keyErr)
	}
	out = append(out, Stage{Stage: "hostkey", OK: true, Ms: int(keyAt.Sub(hsStart).Milliseconds())})
	if errors.Is(err, errNoAuth) {
		return append(out, Stage{Stage: "auth", Code: "noauth", Err: noAuth})
	}
	if err != nil {
		return fail("auth", keyAt, ctxErr(ctx, err))
	}
	out = append(out, Stage{Stage: "auth", OK: true, Ms: ms(keyAt)})
	defer c.Close()
	es := time.Now()
	s, err := c.NewSession()
	if err == nil {
		defer s.Close()
		done := make(chan error, 1)
		go func() { done <- s.Run("true") }()
		select {
		case err = <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		return fail("exec", es, ctxErr(ctx, err))
	}
	return append(out, Stage{Stage: "exec", OK: true, Ms: ms(es)})
}

func ms(t time.Time) int { return int(time.Since(t).Milliseconds()) }

// ctxErr prefers the context's error when it ended the check (the closed conn reports a vaguer one).
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// classify maps an error to a short code and a message: a plain explanation, then the raw error.
func classify(stage string, err error) (code, msg string) {
	raw := err.Error()
	l := strings.ToLower(raw)
	var hk *HostKeyError
	var ne net.Error
	switch {
	case errors.As(err, &hk) && hk.Changed:
		return "hostkey-changed", "host key CHANGED (possible attack, or the server was reinstalled): " + raw
	case errors.As(err, &hk):
		return "hostkey-unknown", "host key not trusted yet: " + raw
	case strings.Contains(l, "unable to authenticate"):
		return "auth", "unable to authenticate (wrong user, key or password?): " + raw
	case strings.Contains(l, "connection refused"):
		return "refused", "connection refused (nothing listens on that port, or a firewall rejects it): " + raw
	case strings.Contains(l, "no route to host"), strings.Contains(l, "network is unreachable"):
		return "no-route", "no route to host (wrong address, VPN down?): " + raw
	case strings.Contains(l, "no such host"):
		return "dns", "name does not resolve: " + raw
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout(), strings.Contains(l, "timeout"), strings.Contains(l, "deadline exceeded"):
		if stage == "tcp" {
			return "timeout", "connection timed out (host down, or a firewall drops packets): " + raw
		}
		return "handshake-timeout", "the server accepted the connection but stalled: " + raw
	case stage == "exec":
		return "exec", "logged in, but could not run a command: " + raw
	}
	return "error", raw
}
