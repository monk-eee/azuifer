mod auth;
mod checksum;
mod config;
mod domain;
mod protocol;
mod server;
mod store;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use config::{CONFORMANCE, Config, Options};

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
    Export,
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
            command: ConformanceCommand::Export,
        } => {
            print!("{CONFORMANCE}");
            Ok(())
        }
    }
}
