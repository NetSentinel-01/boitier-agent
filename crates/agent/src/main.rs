use anyhow::Result;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    info!(version = env!("CARGO_PKG_VERSION"), "crate agent setup");

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => res?,
        _ = sigterm.recv() => {}
    }

    info!("received SIGTERM");
    Ok(())
}