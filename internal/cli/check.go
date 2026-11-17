package cli

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ASromancer/ostiary/internal/daemon"
)

// checkText prints one line per stage, e.g. "tcp ok 34ms" or "auth FAIL unable to authenticate (...)".
func checkText(host string, r daemon.CheckReply) string {
	var b strings.Builder
	for _, s := range r.Stages {
		if s.OK {
			fmt.Fprintf(&b, "%s ok %dms\n", s.Stage, s.Ms)
		} else {
			fmt.Fprintf(&b, "%s FAIL %s\n", s.Stage, s.Err)
		}
	}
	if !r.OK {
		fmt.Fprintf(&b, "%s: connection check FAILED\n", host)
	}
	return b.String()
}

func checkHost(host string) (daemon.CheckReply, int) {
	var r daemon.CheckReply
	c, code := dial()
	if c == nil {
		return r, code
	}
	defer c.Close()
	if err := c.Call("A.Check", &daemon.CheckArgs{Env: env(), Host: host}, &r); err != nil {
		return r, callErr(err)
	}
	if r.Code != 0 {
		return r, agentFail(r.Code, r.Msg)
	}
	return r, -1
}

func cmdCheck(args []string) int {
	fs := newFlags("check")
	all := fs.Bool("all", false, "check every host you may use, in parallel")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if *all != (len(pos) == 0) || len(pos) > 1 {
		return errf(2, "usage: ostiary check <host> | ostiary check --all")
	}
	if !*all {
		r, code := checkHost(pos[0])
		if code >= 0 {
			return code
		}
		fmt.Print(checkText(pos[0], r))
		if !r.OK {
			return 1
		}
		return 0
	}
	c, code := dial()
	if c == nil {
		return code
	}
	var hr daemon.HostsReply
	e := env()
	err = c.Call("A.Hosts", &e, &hr)
	c.Close()
	if err != nil {
		return callErr(err)
	}
	type res struct {
		r    daemon.CheckReply
		code int
	}
	out := make([]res, len(hr.Hosts))
	var wg sync.WaitGroup
	for i, h := range hr.Hosts {
		wg.Add(1)
		go func() { defer wg.Done(); out[i].r, out[i].code = checkHost(h.Name) }()
	}
	wg.Wait()
	rc := 0
	for i, h := range hr.Hosts {
		o := out[i]
		line := "ok"
		if o.code >= 0 && o.code != 0 { // checkHost already printed why; keep the strongest code
			line, rc = fmt.Sprintf("not run (code %d)", o.code), max(rc, o.code)
		} else if !o.r.OK {
			last := o.r.Stages[len(o.r.Stages)-1]
			line, rc = fmt.Sprintf("FAIL at %s: %s", last.Stage, last.Err), max(rc, 1)
		}
		fmt.Printf("%-20s %s\n", h.Name, line)
	}
	return rc
}
