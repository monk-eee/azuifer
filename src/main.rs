mod auth;
mod checksum;
// Foundations awaiting their first service consumers (ADR-0011, ADR-0012); drop these allows when used.
#[allow(dead_code)]
mod clock;
mod config;
mod conformance;
mod dfs;
mod domain;
mod files;
mod protocol;
mod queue;
#[allow(dead_code)]
mod sas;
mod server;
mod store;
mod table;
mod wire;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use config::{Config, Options};

#[derive(Parser)]
#[command(
    name = "azuifer",
    version,
    about = "Local Azure Storage data-plane emulator"
)]
struct Cli {
    #[command(flatten)]
    options: Options,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        /// Gracefully stop when the supervising process closes standard input.
        #[arg(long)]
        shutdown_on_stdin_eof: bool,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Conformance {
        #[command(subcommand)]
        command: ConformanceCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
}

#[derive(Subcommand)]
enum ConformanceCommand {
    Export {
        #[arg(long, value_enum, default_value = "json")]
        format: conformance::Format,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            shutdown_on_stdin_eof,
        } => {
            tracing_subscriber::fmt()
                .json()
                .with_writer(std::io::stderr)
                .try_init()
                .map_err(anyhow::Error::from_boxed)
                .context("could not initialize local diagnostics")?;
            server::serve(Config::load(cli.options)?, shutdown_on_stdin_eof).await
        }
        Command::Config {
            command: ConfigCommand::Validate,
        } => {
            Config::load(cli.options)?;
            println!("Configuration is valid.");
            Ok(())
        }
        Command::Conformance {
            command: ConformanceCommand::Export { format },
        } => conformance::export(format),
    }
}
