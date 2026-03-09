use tokio::sync::mpsc;

use crate::Result;
use crate::events::IncomingEvent;

pub mod git;
pub mod github;
pub mod tmux;

pub use git::GitSource;
pub use github::GitHubSource;
pub use tmux::{RegisteredTmuxSession, SharedTmuxRegistry, TmuxSource};

#[async_trait::async_trait]
pub trait Source: Send + Sync {
    fn name(&self) -> &str;

    async fn run(&self, tx: mpsc::Sender<IncomingEvent>) -> Result<()>;
}
