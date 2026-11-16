---
name: ostiary
description: Run commands and transfer files on remote servers through ostiary. Use whenever a task needs a shell on a server, logs from a host, a service restart, or a file copied to/from a host. Never use ssh/scp/rsync directly.
---

# ostiary

You never hold SSH keys. A local daemon runs commands for you, classifies each one
(read / mutate / destructive / forbidden) and asks the human when needed.

## Commands

- `ostiary hosts` — hosts you may use, their profile and description. Start here.
- `ostiary run <host> "<cmd>" [--timeout 60s]` — run one command (quote it as one argument).
  First line: `web1 exit=0 1.2s level=read id=57`, then output. Long output keeps the first and
  last 40 lines.
- `ostiary out <id> --grep <regexp>` / `--range a:b` — read the full output of an earlier run.
  Use this instead of running the command again.
- `ostiary get <host>:<remote> <local>`, `ostiary put <local> <host>:<remote>` — copy files (50 MB max).
- `ostiary job start <host> "<cmd>"`, `job tail <id> [--lines N]`, `job kill <id>` — long-running commands.
- `ostiary tunnel open <host> <host:port> [--ttl 1h]` — forward a local port (printed, on 127.0.0.1) to a
  target the user allow-listed on that host (e.g. a database). It always needs the user's approval.
  `ostiary tunnel list`, `ostiary tunnel close <id>`. You still need your own DB credentials.
- `ostiary explain "<cmd>" [--host <host>]` — see how a command is classified, without running it.

## Exit codes

- Any code from the remote command is passed through unchanged.
- `100` blocked by policy (forbidden command, profile does not allow it, host not allowed).
- `101` the user denied the request or did not answer in time.
- `102` the daemon is not running or the vault is locked. If you run inside a sandbox (Codex), the
  sandbox may be what blocks ostiary's local socket: re-run the same ostiary command outside the
  sandbox (escalated) before asking the user.
- `103` ostiary is restarting (stop, upgrade). The CLI already waits 10 s and retries once; if you
  still get 103, wait about 10 seconds and retry the same command once, then ask the user. A pending
  approval cancelled by a restart ends with 101: ask the user before retrying.
- Only errors produced by ostiary itself print a stderr line starting with `ostiary:`.

## Rules

- Never call `ssh`, `scp`, `sftp`, `rsync` to remote hosts, or `mosh` directly.
- Never run `ostiary approve`, `key`, `reload`, `host`, `init`, `unlock`, `install-hooks`, `daemon`,
  `ui`, `open`, `stop`, `upgrade`, `install-service` or `uninstall-service` (also as `ostiary-app`):
  those are for the human only.
- On `101`: stop and ask the user. Do not retry the same goal another way.
- On `100`: tell the user what you wanted to do and why; do not look for a workaround.
- Destructive commands wait for the user to approve in another terminal; just wait.
- No PTY: interactive programs (vim, top, less, watch) are refused. Use `top -bn1`, `cat`,
  `tail -n`, `journalctl --no-pager`.
- Prefer small read commands and `ostiary out --grep` over re-running heavy commands.
