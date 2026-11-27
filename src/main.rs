//! latrix — a small, self-managing cluster in a single binary.

mod agent;
mod api_types;
mod cli;
mod config;
mod state;
mod util;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let is_agent = matches!(cli.cmd, cli::Cmd::Agent(cli::AgentCmd::Run { .. }) | cli::Cmd::Dev { .. });
    let default = if is_agent { "info" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("{default},hyper=warn,reqwest=warn"))),
        )
        .with_target(false)
        .init();
    if let Err(e) = cli::commands::run(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
