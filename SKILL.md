---
name: clawhip
description: Configure and manage clawhip — the daemon-first event gateway for Discord
---

# clawhip

`clawhip` is a daemon-first notification gateway.

## Essentials

- daemon default port: `25294`
- start daemon: `clawhip` or `clawhip start`
- check health: `clawhip status`
- send event through daemon: `clawhip send --channel <id> --message "..."`
- wrapper mode: `clawhip tmux new -s <session> --channel <id> --keywords error,complete -- command`

## Config

Config file: `~/.clawhip/config.toml`

Key sections:
- `[discord]`
- `[daemon]`
- `[[routes]]`
- `[[monitors.git.repos]]`
- `[[monitors.tmux.sessions]]`

## Architecture

```text
[CLI clients / webhooks / daemon monitors] -> [clawhip daemon :25294] -> [route filters] -> [Discord REST API]
```

## Dynamic templates

Routes can opt into special dynamic tokens with `allow_dynamic_tokens = true`.

Examples:

```toml
[[routes]]
event = "tmux.*"
channel = "1468539002985644084"
allow_dynamic_tokens = true
template = "{session}\n{tmux_tail:issue-1456:20}\n{iso_time}"
```

Supported dynamic tokens:
- `{sh:...}`
- `{tmux_tail:session:lines}`
- `{file_tail:/path/to/file:lines}`
- `{env:NAME}`
- `{now}`
- `{iso_time}`

Safety:
- route-level opt-in only
- allowlisted token kinds only
- short timeout
- output capped

## Lifecycle commands

```bash
clawhip install
clawhip install --systemd
clawhip update --restart
clawhip uninstall --remove-systemd --remove-config
```

Repo helper:

```bash
./install.sh --systemd
```

## Live verification

Use the operational runbook and helper script:

- `docs/live-verification.md`
- `scripts/live-verify-default-presets.sh`
