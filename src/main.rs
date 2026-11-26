mod acl;
mod address;
mod admin;
mod auth;
mod blob_auth;
mod blob_batch;
mod blob_copy;
mod blob_cors;
mod blob_exec;
mod blob_expiry;
mod blob_external;
mod blob_immutability;
mod blob_lifecycle;
mod blob_page;
mod blob_sas;
mod blob_snapshot;
mod blob_tags;
mod checksum;
mod clock;
mod commands;
mod conditions;
mod config;
mod conformance;
mod delegation;
mod dfs;
mod domain;
mod files;
mod jwt;
mod lease;
mod metrics;
mod oauth;
mod posix;
mod protocol;
mod queue;
mod ranges;
mod redact;
mod respond;
mod sas;
mod server;
mod service_props;
mod stamp;
mod store;
mod table;
mod telemetry;
mod tls;
mod wire;
mod xml_tree;

use anyhow::Result;
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
    /// Show the status of a running instance.
    Status {
        #[arg(
            long,
            env = "AZUIFER_ADMIN_URL",
            default_value = "http://127.0.0.1:10005"
        )]
        admin_url: String,
        /// Print the raw JSON from the admin `/status` endpoint.
        #[arg(long, conflicts_with = "ready")]
        json: bool,
        /// Exit successfully only when the readiness endpoint reports ready; prints nothing.
        #[arg(long)]
        ready: bool,
    },
    /// Diagnose configuration, ports, and the data directory.
    Doctor,
    /// Delete all emulator state under the storage location.
    Reset {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
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
        } => server::serve(Config::load(cli.options)?, shutdown_on_stdin_eof).await,
        Command::Status {
            admin_url,
            json,
            ready,
        } => commands::status(&admin_url, json, ready),
        Command::Doctor => commands::doctor(cli.options),
        Command::Reset { yes } => commands::reset(&Config::load(cli.options)?, yes),
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
