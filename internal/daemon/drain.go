package daemon

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/ASromancer/ostiary/internal/audit"
)

// DrainWait is the longest Drain waits for running commands.
const DrainWait = 60 * time.Second

const restartingMsg = "ostiary is restarting; wait about 10 seconds and retry the same command once"

// beginCmd registers a command that is about to run over SSH. It returns false while draining.
func (d *Daemon) beginCmd() bool {
	d.drainMu.Lock()
	defer d.drainMu.Unlock()
	if d.draining {
		return false
	}
	d.inflight.Add(1)
	d.running++
	return true
}

func (d *Daemon) endCmd() {
	d.drainMu.Lock()
	d.running--
	d.drainMu.Unlock()
	d.inflight.Done()
}

// cancelIfDraining finishes pending requests when a drain began while one was being added.
func (d *Daemon) cancelIfDraining() {
	if d.isDraining() {
		d.q.CancelAll("restart")
	}
}

func (d *Daemon) isDraining() bool {
	d.drainMu.Lock()
	defer d.drainMu.Unlock()
	return d.draining
}

// Drain stops the daemon gracefully: refuse new work (103), wait for running commands (up to
// DrainWait, unless force or ctx ends), cancel pending approvals, kill jobs and tunnels, close
// the listener. Safe to call again: a later call waits for the first, and force cuts its wait short.
func (d *Daemon) Drain(ctx context.Context, force bool) {
	d.drainMu.Lock()
	if force {
		d.forceOnce.Do(func() { close(d.forceCh) })
	}
	if d.draining {
		d.drainMu.Unlock()
		<-d.drained
		return
	}
	d.draining = true
	d.drainMu.Unlock()
	defer close(d.drained)
	d.q.CancelAll("restart") // nothing can be approved during the wait only to be refused

	if !force {
		done := make(chan struct{})
		go func() { d.inflight.Wait(); close(done) }()
		select {
		case <-done:
		case <-d.forceCh:
		case <-ctx.Done():
		case <-time.After(DrainWait):
		}
	}
	d.q.CancelAll("restart")

	d.mu.Lock()
	ids := make([]int, 0, len(d.jobs))
	for id := range d.jobs {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if j := d.jobs[id]; j != nil {
			if running, _ := j.Status(); running {
				j.Kill()
				log.Printf("drain: killed job %d", id)
				d.log.Write(audit.Entry{Kind: "admin", Cmd: fmt.Sprintf("kill job %d", id), Decision: "cancelled", Note: "restart"})
			}
		}
	}
	d.mu.Unlock()
	d.closeTunnels()

	d.mu.Lock()
	ln := d.ln
	d.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

// runningCounts feeds Status.Running.
func (d *Daemon) runningCounts() (cmds, jobs, tunnels int) {
	d.drainMu.Lock()
	cmds = d.running
	d.drainMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, j := range d.jobs {
		if r, _ := j.Status(); r {
			jobs++
		}
	}
	return cmds, jobs, len(d.tunnels)
}
