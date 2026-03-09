pub mod discord;

use async_trait::async_trait;

use crate::Result;

pub use discord::DiscordSink;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkTarget {
    DiscordChannel(String),
    DiscordWebhook(String),
}

#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, target: &SinkTarget, content: &str) -> Result<()>;
}
