use anyhow::{Context, Result};
use futures_util::SinkExt;
use protocol::status::AgentMessage;
use protocol::PROTOCOL_VERSION;
use tokio::signal::unix::{signal, SignalKind};
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

#[tokio::main]

async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    info!(version = env!("CARGO_PKG_VERSION"), "init");

    let url = std::env::var("AGENT_SERVER_URL").context("missing variable")?;

    let (mut ws, _response) = tokio_tungstenite::connect_async(url.as_str())
    .await
        .with_context(|| format!("error connecting to {url}"))?;
    info!(%url, "connected to server");

    let hello= AgentMessage::Hello {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: PROTOCOL_VERSION,
    };
    ws.send(Message::text(serde_json::to_string(&hello)?)).await?;
    info!("hello sent");

    let mut sifterm = signal(SignalKind::terminate())?;
    tokio::select!{
        res = tokio::signal::ctrl_c() => res?,
        _ = sifterm.recv() => {}
    }

    info!("received SIGTERM");
    ws.close(None).await?;
    Ok(())
}