//! latrix — a small, self-managing cluster in a single binary.

mod agent;
mod api_types;
mod cli;
mod config;
mod fluxer;
mod state;
mod util;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let is_agent = matches!(cli.cmd, cli::Cmd::Agent(cli::AgentCmd::Run { .. }) | cli::Cmd::Dev { .. });
    if !is_agent {
        // Behave like other CLI tools when piped into `head` etc. (exit quietly
        // instead of panicking on a closed pipe). The agent keeps Rust's default.
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    let default = if is_agent { "info" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("{default},hyper=warn,reqwest=warn"))),
        )
        .with_target(false)
        .init();
    if let Err(e) = Box::pin(cli::commands::run(cli)).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
