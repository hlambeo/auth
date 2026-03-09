use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::Result;
use crate::config::{AppConfig, GitRepoMonitor};
use crate::events::IncomingEvent;
use crate::source::Source;
use crate::source::git::{GitSnapshot, snapshot_git_repo};

pub struct GitHubSource {
    config: Arc<AppConfig>,
}

impl GitHubSource {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Source for GitHubSource {
    fn name(&self) -> &str {
        "github"
    }

    async fn run(&self, tx: mpsc::Sender<IncomingEvent>) -> Result<()> {
        let github_client = match build_github_client(self.config.monitor_github_token()) {
            Ok(client) => Some(client),
            Err(error) => {
                eprintln!("clawhip source github: failed to build GitHub client: {error}");
                None
            }
        };
        let mut state = HashMap::new();

        loop {
            poll_github(
                self.config.as_ref(),
                github_client.as_ref(),
                &tx,
                &mut state,
            )
            .await?;
            sleep(Duration::from_secs(
                self.config.monitors.poll_interval_secs.max(1),
            ))
            .await;
        }
    }
}

struct GitHubRepoState {
    issues: HashMap<u64, IssueSnapshot>,
    prs: HashMap<u64, PullRequestSnapshot>,
}

#[derive(Clone)]
struct IssueSnapshot {
    title: String,
    state: String,
    comments: u64,
}

#[derive(Clone)]
struct PullRequestSnapshot {
    title: String,
    status: String,
    url: String,
}

async fn poll_github(
    config: &AppConfig,
    github_client: Option<&reqwest::Client>,
    tx: &mpsc::Sender<IncomingEvent>,
    state: &mut HashMap<String, GitHubRepoState>,
) -> Result<()> {
    for repo in &config.monitors.git.repos {
        if !repo.emit_issue_opened && !repo.emit_pr_status {
            continue;
        }

        let snapshot = match snapshot_git_repo(repo).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!(
                    "clawhip source github snapshot failed for {}: {error}",
                    repo.path
                );
                continue;
            }
        };

        let previous = state.get(&repo.path);
        let issues = poll_issues(config, github_client, repo, &snapshot, previous, tx).await?;
        let prs = poll_pull_requests(config, github_client, repo, &snapshot, previous, tx).await?;

        state.insert(repo.path.clone(), GitHubRepoState { issues, prs });
    }

    Ok(())
}

async fn poll_issues(
    config: &AppConfig,
    github_client: Option<&reqwest::Client>,
    repo: &GitRepoMonitor,
    snapshot: &GitSnapshot,
    previous: Option<&GitHubRepoState>,
    tx: &mpsc::Sender<IncomingEvent>,
) -> Result<HashMap<u64, IssueSnapshot>> {
    if !repo.emit_issue_opened {
        return Ok(previous
            .map(|entry| entry.issues.clone())
            .unwrap_or_default());
    }

    let Some(client) = github_client else {
        return Ok(previous
            .map(|entry| entry.issues.clone())
            .unwrap_or_default());
    };

    match fetch_issues(client, &config.monitors.github_api_base, repo, snapshot).await {
        Ok(issues) => {
            if let Some(previous) = previous {
                for event in
                    collect_issue_events(repo, &snapshot.repo_name, &previous.issues, &issues)
                {
                    send_event(tx, event).await?;
                }
            }
            Ok(issues)
        }
        Err(error) => {
            eprintln!(
                "clawhip source GitHub issue polling failed for {}: {error}",
                repo.path
            );
            Ok(previous
                .map(|entry| entry.issues.clone())
                .unwrap_or_default())
        }
    }
}

async fn poll_pull_requests(
    config: &AppConfig,
    github_client: Option<&reqwest::Client>,
    repo: &GitRepoMonitor,
    snapshot: &GitSnapshot,
    previous: Option<&GitHubRepoState>,
    tx: &mpsc::Sender<IncomingEvent>,
) -> Result<HashMap<u64, PullRequestSnapshot>> {
    if !repo.emit_pr_status {
        return Ok(previous.map(|entry| entry.prs.clone()).unwrap_or_default());
    }

    let Some(client) = github_client else {
        return Ok(previous.map(|entry| entry.prs.clone()).unwrap_or_default());
    };

    match fetch_pull_requests(client, &config.monitors.github_api_base, repo, snapshot).await {
        Ok(prs) => {
            if let Some(previous) = previous {
                for (number, pr) in &prs {
                    match previous.prs.get(number) {
                        Some(old) if old.status == pr.status => {}
                        old => {
                            send_event(
                                tx,
                                IncomingEvent::github_pr_status_changed(
                                    snapshot.repo_name.clone(),
                                    *number,
                                    pr.title.clone(),
                                    old.map(|value| value.status.clone())
                                        .unwrap_or_else(|| "<new>".to_string()),
                                    pr.status.clone(),
                                    pr.url.clone(),
                                    repo.channel.clone(),
                                )
                                .with_mention(repo.mention.clone())
                                .with_format(repo.format.clone()),
                            )
                            .await?;
                        }
                    }
                }
            }
            Ok(prs)
        }
        Err(error) => {
            eprintln!(
                "clawhip source GitHub polling failed for {}: {error}",
                repo.path
            );
            Ok(previous.map(|entry| entry.prs.clone()).unwrap_or_default())
        }
    }
}

async fn send_event(tx: &mpsc::Sender<IncomingEvent>, event: IncomingEvent) -> Result<()> {
    tx.send(event)
        .await
        .map_err(|error| format!("github source channel closed: {error}").into())
}

fn collect_issue_events(
    repo: &GitRepoMonitor,
    repo_name: &str,
    previous: &HashMap<u64, IssueSnapshot>,
    current: &HashMap<u64, IssueSnapshot>,
) -> Vec<IncomingEvent> {
    let mut events = Vec::new();
    for (number, issue) in current {
        match previous.get(number) {
            None => events.push(
                IncomingEvent::github_issue_opened(
                    repo_name.to_string(),
                    *number,
                    issue.title.clone(),
                    repo.channel.clone(),
                )
                .with_mention(repo.mention.clone())
                .with_format(repo.format.clone()),
            ),
            Some(old) => {
                if old.state != issue.state && issue.state == "closed" {
                    events.push(
                        IncomingEvent::github_issue_closed(
                            repo_name.to_string(),
                            *number,
                            issue.title.clone(),
                            repo.channel.clone(),
                        )
                        .with_mention(repo.mention.clone())
                        .with_format(repo.format.clone()),
                    );
                }
                if issue.comments > old.comments {
                    events.push(
                        IncomingEvent::github_issue_commented(
                            repo_name.to_string(),
                            *number,
                            issue.title.clone(),
                            issue.comments,
                            repo.channel.clone(),
                        )
                        .with_mention(repo.mention.clone())
                        .with_format(repo.format.clone()),
                    );
                }
            }
        }
    }
    events
}

async fn fetch_issues(
    client: &reqwest::Client,
    api_base: &str,
    repo: &GitRepoMonitor,
    snapshot: &GitSnapshot,
) -> Result<HashMap<u64, IssueSnapshot>> {
    let github_repo = snapshot
        .github_repo
        .clone()
        .ok_or_else(|| format!("no GitHub repo configured or inferred for {}", repo.path))?;
    let response = client
        .get(format!(
            "{}/repos/{}/issues",
            api_base.trim_end_matches('/'),
            github_repo
        ))
        .query(&[("state", "all"), ("per_page", "100")])
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("GitHub API request failed with {status}: {body}").into());
    }
    let issues: Vec<GitHubIssue> = response.json().await?;
    Ok(issues
        .into_iter()
        .filter(|issue| !issue.is_pull_request())
        .map(|issue| {
            (
                issue.number,
                IssueSnapshot {
                    title: issue.title,
                    state: issue.state,
                    comments: issue.comments,
                },
            )
        })
        .collect())
}

async fn fetch_pull_requests(
    client: &reqwest::Client,
    api_base: &str,
    repo: &GitRepoMonitor,
    snapshot: &GitSnapshot,
) -> Result<HashMap<u64, PullRequestSnapshot>> {
    let github_repo = snapshot
        .github_repo
        .clone()
        .ok_or_else(|| format!("no GitHub repo configured or inferred for {}", repo.path))?;
    let response = client
        .get(format!(
            "{}/repos/{}/pulls",
            api_base.trim_end_matches('/'),
            github_repo
        ))
        .query(&[("state", "all"), ("per_page", "100")])
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("GitHub API request failed with {status}: {body}").into());
    }
    let pulls: Vec<GitHubPullRequest> = response.json().await?;
    Ok(pulls
        .into_iter()
        .map(|pull| {
            let status = if pull.merged_at.is_some() {
                "merged".to_string()
            } else {
                pull.state
            };
            (
                pull.number,
                PullRequestSnapshot {
                    title: pull.title,
                    status,
                    url: pull.html_url,
                },
            )
        })
        .collect())
}

fn build_github_client(token: Option<String>) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("clawhip/0.1"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    if let Some(token) = token {
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
    }
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

#[derive(Deserialize)]
struct GitHubIssue {
    number: u64,
    title: String,
    state: String,
    comments: u64,
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
}

impl GitHubIssue {
    fn is_pull_request(&self) -> bool {
        self.pull_request.is_some()
    }
}

#[derive(Deserialize)]
struct GitHubPullRequest {
    number: u64,
    title: String,
    state: String,
    html_url: String,
    merged_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::config::{DefaultsConfig, RouteRule};
    use crate::events::MessageFormat;
    use crate::router::Router;

    #[tokio::test]
    async fn new_issue_events_match_repo_filter_and_route_mention() {
        let repo = GitRepoMonitor {
            path: "/tmp/clawhip".into(),
            name: Some("clawhip".into()),
            channel: Some("dev-channel".into()),
            ..GitRepoMonitor::default()
        };
        let previous = HashMap::new();
        let current = [(
            2_u64,
            IssueSnapshot {
                title: "live issue".into(),
                state: "open".into(),
                comments: 0,
            },
        )]
        .into_iter()
        .collect();
        let events = collect_issue_events(&repo, "clawhip", &previous, &current);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].canonical_kind(), "github.issue-opened");
        assert_eq!(events[0].payload["repo"], "clawhip");

        let config = AppConfig {
            defaults: DefaultsConfig {
                channel: Some("fallback".into()),
                format: MessageFormat::Compact,
            },
            routes: vec![RouteRule {
                event: "github.*".into(),
                sink: "discord".into(),
                filter: [("repo".to_string(), "clawhip".to_string())]
                    .into_iter()
                    .collect(),
                channel: Some("route-channel".into()),
                webhook: None,
                mention: Some("<@1465264645320474637>".into()),
                allow_dynamic_tokens: false,
                format: Some(MessageFormat::Alert),
                template: None,
            }],
            ..AppConfig::default()
        };
        let router = Router::new(Arc::new(config));
        let (channel, _, content) = router.preview(&events[0]).await.unwrap();
        assert_eq!(channel, "dev-channel");
        assert!(content.starts_with("<@1465264645320474637> "));
        assert!(content.contains("live issue"));
    }

    #[test]
    fn issue_comment_and_close_events_are_emitted() {
        let repo = GitRepoMonitor {
            path: "/tmp/clawhip".into(),
            name: Some("clawhip".into()),
            ..GitRepoMonitor::default()
        };
        let previous = [(
            2_u64,
            IssueSnapshot {
                title: "live issue".into(),
                state: "open".into(),
                comments: 0,
            },
        )]
        .into_iter()
        .collect();
        let current = [(
            2_u64,
            IssueSnapshot {
                title: "live issue".into(),
                state: "closed".into(),
                comments: 1,
            },
        )]
        .into_iter()
        .collect();
        let events = collect_issue_events(&repo, "clawhip", &previous, &current);
        assert!(
            events
                .iter()
                .any(|event| event.canonical_kind() == "github.issue-commented")
        );
        assert!(
            events
                .iter()
                .any(|event| event.canonical_kind() == "github.issue-closed")
        );
    }

    #[tokio::test]
    async fn github_client_includes_bearer_auth_when_token_configured() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n[]")
                .await
                .unwrap();
            req
        });

        let client = build_github_client(Some("secret-token".into())).unwrap();
        let _ = client
            .get(format!("http://{}/repos/x/y/pulls", addr))
            .send()
            .await
            .unwrap();
        let req = server.await.unwrap();
        assert!(
            req.contains("Authorization: Bearer secret-token")
                || req.contains("authorization: Bearer secret-token")
        );
    }
}
