# Changelog

## 0.3.0 - 2026-03-09

### Highlights

- introduced the typed internal event model used by the dispatcher pipeline
- generalized routing so one event can fan out to multiple deliveries
- extracted git, GitHub, and tmux monitoring into explicit event sources
- split rendering from transport and shipped the Discord sink on top of that boundary
- kept existing CLI and HTTP event ingress compatible while normalizing into the new architecture

### Upgrade notes

- crate version is now `0.3.0`
- `[providers.discord]` is the preferred config surface; legacy `[discord]` remains compatible
- routes may set `sink = "discord"`; omitting it still defaults to Discord in this release
