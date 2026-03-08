use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::events::MessageFormat;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub discord: DiscordConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub monitors: MonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscordConfig {
    #[serde(alias = "token")]
    pub bot_token: Option<String>,
    #[serde(alias = "default_channel")]
    pub legacy_default_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_bind_host")]
    pub bind_host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind_host: default_bind_host(),
            port: default_port(),
            base_url: default_base_url(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    pub channel: Option<String>,
    #[serde(default)]
    pub format: MessageFormat,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            channel: None,
            format: MessageFormat::Compact,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteRule {
    pub event: String,
    #[serde(default)]
    pub filter: BTreeMap<String, String>,
    pub channel: Option<String>,
    pub mention: Option<String>,
    #[serde(default)]
    pub allow_dynamic_tokens: bool,
    pub format: Option<MessageFormat>,
    pub template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    pub github_token: Option<String>,
    #[serde(default = "default_github_api_base")]
    pub github_api_base: String,
    #[serde(default)]
    pub git: GitMonitorConfig,
    #[serde(default)]
    pub tmux: TmuxMonitorConfig,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
            github_token: None,
            github_api_base: default_github_api_base(),
            git: GitMonitorConfig::default(),
            tmux: TmuxMonitorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitMonitorConfig {
    #[serde(default)]
    pub repos: Vec<GitRepoMonitor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TmuxMonitorConfig {
    #[serde(default)]
    pub sessions: Vec<TmuxSessionMonitor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRepoMonitor {
    pub path: String,
    pub name: Option<String>,
    #[serde(default = "default_remote")]
    pub remote: String,
    pub github_repo: Option<String>,
    #[serde(default = "default_true")]
    pub emit_commits: bool,
    #[serde(default = "default_true")]
    pub emit_branch_changes: bool,
    #[serde(default = "default_true")]
    pub emit_issue_opened: bool,
    #[serde(default)]
    pub emit_pr_status: bool,
    pub channel: Option<String>,
    pub mention: Option<String>,
    pub format: Option<MessageFormat>,
}

impl Default for GitRepoMonitor {
    fn default() -> Self {
        Self {
            path: String::new(),
            name: None,
            remote: default_remote(),
            github_repo: None,
            emit_commits: true,
            emit_branch_changes: true,
            emit_issue_opened: true,
            emit_pr_status: false,
            channel: None,
            mention: None,
            format: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmuxSessionMonitor {
    pub session: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_stale_minutes")]
    pub stale_minutes: u64,
    pub channel: Option<String>,
    pub mention: Option<String>,
    pub format: Option<MessageFormat>,
}

impl Default for TmuxSessionMonitor {
    fn default() -> Self {
        Self {
            session: String::new(),
            keywords: Vec::new(),
            stale_minutes: default_stale_minutes(),
            channel: None,
            mention: None,
            format: None,
        }
    }
}

pub fn default_config_path() -> PathBuf {
    if let Ok(override_path) = env::var("CLAWHIP_CONFIG") {
        return PathBuf::from(override_path);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".clawhip").join("config.toml")
}

fn default_bind_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    25294
}
fn default_base_url() -> String {
    format!("http://127.0.0.1:{}", default_port())
}
fn default_poll_interval() -> u64 {
    5
}
fn default_github_api_base() -> String {
    "https://api.github.com".to_string()
}
fn default_remote() -> String {
    "origin".to_string()
}
fn default_stale_minutes() -> u64 {
    10
}
fn default_true() -> bool {
    true
}

impl AppConfig {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&raw)?;
        if config.defaults.channel.is_none() {
            config.defaults.channel = config.discord.legacy_default_channel.clone();
        }
        Ok(config)
    }

    pub fn to_pretty_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_pretty_toml()?)?;
        Ok(())
    }

    pub fn effective_token(&self) -> Option<String> {
        env::var("CLAWHIP_DISCORD_BOT_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.discord.bot_token.clone())
    }

    pub fn daemon_base_url(&self) -> String {
        env::var("CLAWHIP_DAEMON_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.daemon.base_url.clone())
    }

    pub fn monitor_github_token(&self) -> Option<String> {
        env::var("CLAWHIP_GITHUB_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.monitors.github_token.clone())
    }

    pub fn run_interactive_editor(&mut self, path: &Path) -> Result<()> {
        println!("clawhip config editor");
        println!("Path: {}", path.display());
        println!();
        loop {
            self.print_summary();
            println!("Choose an action:");
            println!("  1) Set Discord bot token");
            println!("  2) Set daemon base URL");
            println!("  3) Set default channel");
            println!("  4) Set default format");
            println!("  5) Save and exit");
            println!("  6) Exit without saving");
            println!("  7) Print config template hint");
            match prompt("Selection")?.trim() {
                "1" => self.discord.bot_token = empty_to_none(prompt("Bot token")?),
                "2" => {
                    self.daemon.base_url =
                        prompt_with_default("Daemon base URL", Some(&self.daemon.base_url))?
                }
                "3" => self.defaults.channel = empty_to_none(prompt("Default channel")?),
                "4" => self.defaults.format = prompt_format(Some(self.defaults.format.clone()))?,
                "5" => {
                    self.save(path)?;
                    println!("Saved {}", path.display());
                    break;
                }
                "6" => {
                    println!("Discarded changes.");
                    break;
                }
                "7" => self.print_template_hint(),
                _ => println!("Unknown selection."),
            }
            println!();
        }
        Ok(())
    }

    fn print_summary(&self) {
        let token_status = if self
            .discord
            .bot_token
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            "missing"
        } else {
            "configured"
        };
        println!("Current config summary:");
        println!("  Discord token: {token_status}");
        println!("  Daemon base URL: {}", self.daemon.base_url);
        println!(
            "  Bind host/port: {}:{}",
            self.daemon.bind_host, self.daemon.port
        );
        println!(
            "  Default channel: {}",
            self.defaults.channel.as_deref().unwrap_or("<unset>")
        );
        println!("  Default format: {}", self.defaults.format.as_str());
        println!("  Routes: {}", self.routes.len());
        println!("  Git monitors: {}", self.monitors.git.repos.len());
        println!("  Tmux monitors: {}", self.monitors.tmux.sessions.len());
    }

    fn print_template_hint(&self) {
        println!("Edit the config file directly for routes and monitor definitions.");
        println!(
            "Sections: [daemon], [[routes]], [[monitors.git.repos]], [[monitors.tmux.sessions]]"
        );
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end().to_string())
}

fn prompt_with_default(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(default) => prompt(&format!("{label} [{default}]")),
        None => prompt(label),
    }
}

fn prompt_format(default: Option<MessageFormat>) -> Result<MessageFormat> {
    let default_value = default.unwrap_or(MessageFormat::Compact);
    let input = prompt(&format!(
        "Format [{}] (compact/alert/inline/raw)",
        default_value.as_str()
    ))?;
    if input.trim().is_empty() {
        return Ok(default_value);
    }
    MessageFormat::from_label(input.trim())
}

fn empty_to_none(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
