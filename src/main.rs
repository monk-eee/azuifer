mod acl;
mod address;
mod auth;
mod blob_auth;
mod blob_copy;
mod blob_cors;
mod blob_exec;
mod blob_sas;
mod checksum;
mod clock;
mod conditions;
mod config;
mod conformance;
mod dfs;
mod domain;
mod files;
mod lease;
mod protocol;
mod queue;
// The range map awaits its Blob and DFS consumers (ADR-0015); drop this allow when used.
#[allow(dead_code)]
mod ranges;
mod respond;
mod sas;
mod server;
mod service_props;
mod store;
mod table;
mod wire;
mod xml_tree;

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
