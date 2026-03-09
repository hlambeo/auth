use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::sync::{RwLock, mpsc};
use tokio::time::sleep;

use crate::Result;
use crate::client::DaemonClient;
use crate::config::{AppConfig, TmuxSessionMonitor};
use crate::events::{IncomingEvent, MessageFormat};
use crate::keyword_window::{PendingKeywordHits, collect_keyword_hits};
use crate::source::Source;

pub type SharedTmuxRegistry = Arc<RwLock<HashMap<String, RegisteredTmuxSession>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredTmuxSession {
    pub session: String,
    pub channel: Option<String>,
    pub mention: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_keyword_window_secs")]
    pub keyword_window_secs: u64,
    pub stale_minutes: u64,
    pub format: Option<MessageFormat>,
    #[serde(default)]
    pub active_wrapper_monitor: bool,
}

impl From<&TmuxSessionMonitor> for RegisteredTmuxSession {
    fn from(value: &TmuxSessionMonitor) -> Self {
        Self {
            session: value.session.clone(),
            channel: value.channel.clone(),
            mention: value.mention.clone(),
            keywords: value.keywords.clone(),
            keyword_window_secs: value.keyword_window_secs,
            stale_minutes: value.stale_minutes,
            format: value.format.clone(),
            active_wrapper_monitor: false,
        }
    }
}

pub struct TmuxSource {
    config: Arc<AppConfig>,
    registry: SharedTmuxRegistry,
}

impl TmuxSource {
    pub fn new(config: Arc<AppConfig>, registry: SharedTmuxRegistry) -> Self {
        Self { config, registry }
    }
}

#[async_trait::async_trait]
impl Source for TmuxSource {
    fn name(&self) -> &str {
        "tmux"
    }

    async fn run(&self, tx: mpsc::Sender<IncomingEvent>) -> Result<()> {
        let mut state = HashMap::new();

        loop {
            poll_tmux(self.config.as_ref(), &self.registry, &tx, &mut state).await?;
            sleep(Duration::from_secs(
                self.config.monitors.poll_interval_secs.max(1),
            ))
            .await;
        }
    }
}

#[async_trait::async_trait]
trait EventEmitter: Send + Sync {
    async fn emit(&self, event: IncomingEvent) -> Result<()>;
}

#[async_trait::async_trait]
impl EventEmitter for mpsc::Sender<IncomingEvent> {
    async fn emit(&self, event: IncomingEvent) -> Result<()> {
        self.send(event)
            .await
            .map_err(|error| format!("tmux source channel closed: {error}").into())
    }
}

#[async_trait::async_trait]
impl EventEmitter for DaemonClient {
    async fn emit(&self, event: IncomingEvent) -> Result<()> {
        self.send_event(&event).await
    }
}

struct TmuxPaneState {
    session: String,
    pane_name: String,
    snapshot: String,
    content_hash: u64,
    last_change: Instant,
    last_stale_notification: Option<Instant>,
    pending_keyword_hits: Option<PendingKeywordHits>,
}

struct TmuxPaneSnapshot {
    pane_id: String,
    session: String,
    pane_name: String,
    content: String,
}

pub async fn monitor_registered_session(
    registration: RegisteredTmuxSession,
    client: DaemonClient,
) -> Result<()> {
    let mut state = HashMap::new();
    let poll_interval = Duration::from_secs(1);

    loop {
        if !session_exists(&registration.session).await? {
            flush_removed_panes(
                &mut state,
                &HashSet::new(),
                &registration,
                &client,
                Instant::now(),
                true,
            )
            .await?;
            break;
        }

        let panes = snapshot_tmux_session(&registration.session).await?;
        let mut active = HashSet::new();
        let now = Instant::now();

        for pane in panes {
            active.insert(pane.pane_id.clone());
            let pane_key = pane.pane_id.clone();
            let hash = content_hash(&pane.content);
            let latest_line = last_nonempty_line(&pane.content);

            match state.get_mut(&pane_key) {
                None => {
                    state.insert(
                        pane_key,
                        TmuxPaneState {
                            session: pane.session,
                            pane_name: pane.pane_name,
                            content_hash: hash,
                            snapshot: pane.content,
                            last_change: now,
                            last_stale_notification: None,
                            pending_keyword_hits: None,
                        },
                    );
                }
                Some(existing) => {
                    flush_pending_keyword_hits(
                        existing,
                        &registration,
                        &client,
                        now,
                        Duration::from_secs(registration.keyword_window_secs.max(1)),
                        false,
                    )
                    .await?;
                    if existing.content_hash != hash {
                        let hits = collect_keyword_hits(
                            &existing.snapshot,
                            &pane.content,
                            &registration.keywords,
                        );
                        if !hits.is_empty() {
                            existing
                                .pending_keyword_hits
                                .get_or_insert_with(|| PendingKeywordHits::new(now))
                                .push(hits);
                        }

                        existing.session = pane.session;
                        existing.pane_name = pane.pane_name;
                        existing.content_hash = hash;
                        existing.snapshot = pane.content;
                        existing.last_change = now;
                        existing.last_stale_notification = None;
                    } else if should_emit_stale(existing, now, registration.stale_minutes) {
                        client
                            .emit(tmux_stale_event(
                                &registration,
                                existing.session.clone(),
                                existing.pane_name.clone(),
                                latest_line,
                            ))
                            .await?;
                        existing.last_stale_notification = Some(now);
                    }
                }
            }
        }

        flush_removed_panes(&mut state, &active, &registration, &client, now, true).await?;
        state.retain(|pane_id, _| active.contains(pane_id));
        sleep(poll_interval).await;
    }

    Ok(())
}

async fn poll_tmux(
    config: &AppConfig,
    registry: &SharedTmuxRegistry,
    tx: &mpsc::Sender<IncomingEvent>,
    state: &mut HashMap<String, TmuxPaneState>,
) -> Result<()> {
    let mut sessions: BTreeMap<String, RegisteredTmuxSession> = config
        .monitors
        .tmux
        .sessions
        .iter()
        .map(|session| {
            (
                session.session.clone(),
                RegisteredTmuxSession::from(session),
            )
        })
        .collect();
    for (session, registration) in registry.read().await.iter() {
        sessions.insert(session.clone(), registration.clone());
    }

    let mut active_panes = HashSet::new();
    let mut sessions_to_unregister = Vec::new();

    for (session_name, registration) in &sessions {
        if registration.active_wrapper_monitor {
            continue;
        }

        match session_exists(session_name).await {
            Ok(false) => {
                sessions_to_unregister.push(session_name.clone());
                let keys_to_remove = state
                    .iter()
                    .filter(|(_, pane)| pane.session == *session_name)
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                for key in keys_to_remove {
                    if let Some(mut pane) = state.remove(&key) {
                        flush_pending_keyword_hits(
                            &mut pane,
                            registration,
                            tx,
                            Instant::now(),
                            Duration::from_secs(registration.keyword_window_secs.max(1)),
                            true,
                        )
                        .await?;
                    }
                }
                continue;
            }
            Err(error) => {
                eprintln!(
                    "clawhip source tmux has-session failed for {}: {error}",
                    session_name
                );
                continue;
            }
            Ok(true) => {}
        }

        match snapshot_tmux_session(session_name).await {
            Ok(panes) => {
                for pane in panes {
                    let pane_key = format!("{}::{}", pane.session, pane.pane_id);
                    active_panes.insert(pane_key.clone());
                    let now = Instant::now();
                    let hash = content_hash(&pane.content);
                    let latest_line = last_nonempty_line(&pane.content);

                    match state.get_mut(&pane_key) {
                        None => {
                            state.insert(
                                pane_key,
                                TmuxPaneState {
                                    session: pane.session,
                                    pane_name: pane.pane_name,
                                    snapshot: pane.content,
                                    content_hash: hash,
                                    last_change: now,
                                    last_stale_notification: None,
                                    pending_keyword_hits: None,
                                },
                            );
                        }
                        Some(existing) => {
                            flush_pending_keyword_hits(
                                existing,
                                registration,
                                tx,
                                now,
                                Duration::from_secs(registration.keyword_window_secs.max(1)),
                                false,
                            )
                            .await?;
                            if existing.content_hash != hash {
                                let hits = collect_keyword_hits(
                                    &existing.snapshot,
                                    &pane.content,
                                    &registration.keywords,
                                );
                                if !hits.is_empty() {
                                    existing
                                        .pending_keyword_hits
                                        .get_or_insert_with(|| PendingKeywordHits::new(now))
                                        .push(hits);
                                }
                                existing.pane_name = pane.pane_name;
                                existing.snapshot = pane.content;
                                existing.content_hash = hash;
                                existing.last_change = now;
                                existing.last_stale_notification = None;
                            } else if should_emit_stale(existing, now, registration.stale_minutes) {
                                tx.emit(tmux_stale_event(
                                    registration,
                                    existing.session.clone(),
                                    existing.pane_name.clone(),
                                    latest_line,
                                ))
                                .await?;
                                existing.last_stale_notification = Some(now);
                            }
                        }
                    }
                }
            }
            Err(error) => eprintln!(
                "clawhip source tmux snapshot failed for {}: {error}",
                session_name
            ),
        }
    }

    let keys_to_remove = state
        .iter()
        .filter(|(key, _)| !active_panes.contains(*key))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in keys_to_remove {
        if let Some(mut pane) = state.remove(&key)
            && let Some(registration) = sessions.get(&pane.session)
        {
            flush_pending_keyword_hits(
                &mut pane,
                registration,
                tx,
                Instant::now(),
                Duration::from_secs(registration.keyword_window_secs.max(1)),
                true,
            )
            .await?;
        }
    }
    state.retain(|key, _| active_panes.contains(key));

    if !sessions_to_unregister.is_empty() {
        let mut write = registry.write().await;
        for session in sessions_to_unregister {
            write.remove(&session);
        }
    }

    Ok(())
}

fn should_emit_stale(pane: &TmuxPaneState, now: Instant, stale_minutes: u64) -> bool {
    let stale_after = Duration::from_secs(stale_minutes.max(1) * 60);
    now.duration_since(pane.last_change) >= stale_after
        && pane
            .last_stale_notification
            .map(|previous| now.duration_since(previous) >= stale_after)
            .unwrap_or(true)
}

fn tmux_keyword_event(
    registration: &RegisteredTmuxSession,
    session: String,
    hits: Vec<(String, String)>,
) -> IncomingEvent {
    IncomingEvent::tmux_keywords(session, hits, registration.channel.clone())
        .with_mention(registration.mention.clone())
        .with_format(registration.format.clone())
}

fn tmux_stale_event(
    registration: &RegisteredTmuxSession,
    session: String,
    pane: String,
    last_line: String,
) -> IncomingEvent {
    IncomingEvent::tmux_stale(
        session,
        pane,
        registration.stale_minutes,
        last_line,
        registration.channel.clone(),
    )
    .with_mention(registration.mention.clone())
    .with_format(registration.format.clone())
}

async fn flush_pending_keyword_hits<E: EventEmitter>(
    pane: &mut TmuxPaneState,
    registration: &RegisteredTmuxSession,
    emitter: &E,
    now: Instant,
    keyword_window: Duration,
    force: bool,
) -> Result<()> {
    let should_flush = pane
        .pending_keyword_hits
        .as_ref()
        .map(|pending| force || pending.ready_to_flush(now, keyword_window))
        .unwrap_or(false);
    if !should_flush {
        return Ok(());
    }

    let Some(pending) = pane.pending_keyword_hits.take() else {
        return Ok(());
    };
    let hits = pending
        .into_hits()
        .into_iter()
        .map(|hit| (hit.keyword, hit.line))
        .collect::<Vec<_>>();
    if hits.is_empty() {
        return Ok(());
    }

    emitter
        .emit(tmux_keyword_event(registration, pane.session.clone(), hits))
        .await
}

async fn flush_removed_panes<E: EventEmitter>(
    state: &mut HashMap<String, TmuxPaneState>,
    active: &HashSet<String>,
    registration: &RegisteredTmuxSession,
    emitter: &E,
    now: Instant,
    force: bool,
) -> Result<()> {
    let keys_to_remove = state
        .keys()
        .filter(|pane_id| !active.contains(*pane_id))
        .cloned()
        .collect::<Vec<_>>();
    for pane_id in keys_to_remove {
        if let Some(mut pane) = state.remove(&pane_id) {
            flush_pending_keyword_hits(
                &mut pane,
                registration,
                emitter,
                now,
                Duration::from_secs(registration.keyword_window_secs.max(1)),
                force,
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn session_exists(session: &str) -> Result<bool> {
    let output = Command::new(tmux_bin())
        .arg("has-session")
        .arg("-t")
        .arg(session)
        .output()
        .await?;
    Ok(output.status.success())
}

async fn snapshot_tmux_session(session: &str) -> Result<Vec<TmuxPaneSnapshot>> {
    let output = Command::new(tmux_bin())
        .arg("list-panes")
        .arg("-t")
        .arg(session)
        .arg("-F")
        .arg("#{pane_id}|#{session_name}|#{window_index}.#{pane_index}|#{pane_title}")
        .output()
        .await?;
    if !output.status.success() {
        return Err(tmux_stderr(&output.stderr).into());
    }

    let mut panes = Vec::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        let mut parts = line.splitn(4, '|');
        let pane_id = parts.next().unwrap_or_default().to_string();
        if pane_id.is_empty() {
            continue;
        }
        let session_name = parts.next().unwrap_or_default().to_string();
        let pane_name = parts.next().unwrap_or_default().to_string();
        let capture = Command::new(tmux_bin())
            .arg("capture-pane")
            .arg("-p")
            .arg("-t")
            .arg(&pane_id)
            .arg("-S")
            .arg("-200")
            .output()
            .await?;
        if !capture.status.success() {
            return Err(tmux_stderr(&capture.stderr).into());
        }
        panes.push(TmuxPaneSnapshot {
            pane_id,
            session: session_name,
            pane_name,
            content: String::from_utf8(capture.stdout)?,
        });
    }
    Ok(panes)
}

pub(crate) fn content_hash(content: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn last_nonempty_line(content: &str) -> String {
    content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("<no output>")
        .trim()
        .to_string()
}

pub(crate) fn tmux_bin() -> String {
    std::env::var("CLAWHIP_TMUX_BIN").unwrap_or_else(|_| "tmux".to_string())
}

fn tmux_stderr(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_string()
}

fn default_keyword_window_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyword_window::KeywordHit;

    #[test]
    fn keyword_hits_only_emit_for_new_lines() {
        let hits = collect_keyword_hits(
            "done\nall good",
            "done\nall good\nerror: failed\nPR created #7",
            &["error".into(), "PR created".into()],
        );
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].keyword, "error");
        assert_eq!(hits[1].keyword, "PR created");
    }

    #[test]
    fn tmux_keyword_event_inherits_channel_format_and_mention() {
        let registration = RegisteredTmuxSession {
            session: "issue-24".into(),
            channel: Some("alerts".into()),
            mention: Some("<@123>".into()),
            keywords: vec!["error".into()],
            keyword_window_secs: 30,
            stale_minutes: 15,
            format: Some(MessageFormat::Alert),
            active_wrapper_monitor: false,
        };

        let event = tmux_keyword_event(
            &registration,
            "issue-24".into(),
            vec![("error".into(), "boom".into())],
        );

        assert_eq!(event.channel.as_deref(), Some("alerts"));
        assert_eq!(event.mention.as_deref(), Some("<@123>"));
        assert!(matches!(event.format, Some(MessageFormat::Alert)));
        assert_eq!(event.payload["session"], "issue-24");
        assert_eq!(event.payload["keyword"], "error");
        assert_eq!(event.payload["line"], "boom");
    }

    #[test]
    fn tmux_stale_event_inherits_channel_format_and_mention() {
        let registration = RegisteredTmuxSession {
            session: "issue-24".into(),
            channel: Some("alerts".into()),
            mention: Some("<@123>".into()),
            keywords: vec!["error".into()],
            keyword_window_secs: 30,
            stale_minutes: 15,
            format: Some(MessageFormat::Inline),
            active_wrapper_monitor: false,
        };

        let event = tmux_stale_event(
            &registration,
            "issue-24".into(),
            "0.0".into(),
            "waiting".into(),
        );

        assert_eq!(event.channel.as_deref(), Some("alerts"));
        assert_eq!(event.mention.as_deref(), Some("<@123>"));
        assert!(matches!(event.format, Some(MessageFormat::Inline)));
        assert_eq!(event.payload["session"], "issue-24");
        assert_eq!(event.payload["pane"], "0.0");
        assert_eq!(event.payload["minutes"], 15);
        assert_eq!(event.payload["last_line"], "waiting");
    }

    #[tokio::test]
    async fn flush_pending_keyword_hits_aggregates_unique_hits() {
        let (tx, mut rx) = mpsc::channel(1);
        let registration = RegisteredTmuxSession {
            session: "issue-24".into(),
            channel: Some("alerts".into()),
            mention: None,
            keywords: vec!["error".into(), "complete".into()],
            keyword_window_secs: 30,
            stale_minutes: 10,
            format: Some(MessageFormat::Compact),
            active_wrapper_monitor: false,
        };
        let start = Instant::now();
        let mut pane = TmuxPaneState {
            session: "issue-24".into(),
            pane_name: "0.0".into(),
            snapshot: String::new(),
            content_hash: 0,
            last_change: start,
            last_stale_notification: None,
            pending_keyword_hits: Some({
                let mut pending = PendingKeywordHits::new(start);
                pending.push(vec![
                    KeywordHit {
                        keyword: "error".into(),
                        line: "error: failed".into(),
                    },
                    KeywordHit {
                        keyword: "error".into(),
                        line: "error: failed".into(),
                    },
                    KeywordHit {
                        keyword: "complete".into(),
                        line: "complete".into(),
                    },
                ]);
                pending
            }),
        };

        flush_pending_keyword_hits(
            &mut pane,
            &registration,
            &tx,
            start + Duration::from_secs(30),
            Duration::from_secs(30),
            false,
        )
        .await
        .unwrap();

        assert!(pane.pending_keyword_hits.is_none());
        let event = rx.recv().await.unwrap();
        assert_eq!(event.canonical_kind(), "tmux.keyword");
        assert_eq!(event.payload["hit_count"], 2);
    }

    #[tokio::test]
    async fn flush_pending_keyword_hits_clears_window_after_send_attempt() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let registration = RegisteredTmuxSession {
            session: "issue-24".into(),
            channel: Some("alerts".into()),
            mention: None,
            keywords: vec!["error".into(), "complete".into()],
            keyword_window_secs: 30,
            stale_minutes: 15,
            format: Some(MessageFormat::Compact),
            active_wrapper_monitor: false,
        };
        let start = Instant::now();
        let mut pane = TmuxPaneState {
            session: "issue-24".into(),
            pane_name: "0.0".into(),
            snapshot: String::new(),
            content_hash: 0,
            last_change: start,
            last_stale_notification: None,
            pending_keyword_hits: Some({
                let mut pending = PendingKeywordHits::new(start);
                pending.push(vec![KeywordHit {
                    keyword: "error".into(),
                    line: "boom".into(),
                }]);
                pending
            }),
        };

        let result = flush_pending_keyword_hits(
            &mut pane,
            &registration,
            &tx,
            start + Duration::from_secs(30),
            Duration::from_secs(30),
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(pane.pending_keyword_hits.is_none());
    }
}
