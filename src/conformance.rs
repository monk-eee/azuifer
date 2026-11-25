use crate::{
    config::{CONFORMANCE, Service},
    domain::ApiVersion,
};
use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum Format {
    Json,
    Markdown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    service: String,
    api_version: String,
    operations: Vec<Operation>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    name: String,
    state: State,
    authorization: Vec<Authorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum State {
    Exact,
    Compatible,
    KnownDifference,
    Unsupported,
    NotApplicable,
}

impl State {
    fn implemented(self) -> bool {
        matches!(self, Self::Exact | Self::Compatible | Self::KnownDifference)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Compatible => "compatible",
            Self::KnownDifference => "known-difference",
            Self::Unsupported => "unsupported",
            Self::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
enum Authorization {
    SharedKey,
    SharedKeyLite,
    #[serde(rename = "AccountSAS")]
    AccountSas,
    #[serde(rename = "ServiceSAS")]
    ServiceSas,
    #[serde(rename = "UserDelegationSAS")]
    UserDelegationSas,
    Bearer,
    Anonymous,
}

impl Authorization {
    fn label(self) -> &'static str {
        match self {
            Self::SharedKey => "SharedKey",
            Self::SharedKeyLite => "SharedKeyLite",
            Self::AccountSas => "AccountSAS",
            Self::ServiceSas => "ServiceSAS",
            Self::UserDelegationSas => "UserDelegationSAS",
            Self::Bearer => "Bearer",
            Self::Anonymous => "Anonymous",
        }
    }
}

type Catalog = BTreeMap<&'static str, Manifest>;

fn load(service: Service, data: &str) -> Result<Manifest> {
    let name = service.name();
    let manifest: Manifest = serde_json::from_str(data)
        .with_context(|| format!("invalid {name} conformance manifest"))?;
    ensure!(
        manifest.service == name,
        "expected {name} conformance manifest"
    );
    ensure!(
        ApiVersion::parse(&manifest.api_version).is_ok(),
        "invalid {name} API version"
    );
    ensure!(!manifest.operations.is_empty(), "{name} manifest is empty");
    let mut names = BTreeSet::new();
    for operation in &manifest.operations {
        let label = &operation.name;
        ensure!(
            !label.trim().is_empty() && label.trim() == label && names.insert(label),
            "duplicate, blank, or untrimmed operation in {name}: {label:?}"
        );
        ensure!(
            operation.state != State::Exact,
            "{name}/{label}: exact requires verified Azure differential evidence; none is recorded by this build"
        );
        let modes: BTreeSet<_> = operation.authorization.iter().collect();
        ensure!(
            modes.len() == operation.authorization.len()
                && operation.state.implemented() == !modes.is_empty(),
            "{name}/{label}: authorization must name each working mode once, only for implemented operations"
        );
        if operation.state != State::Unsupported {
            ensure!(
                operation
                    .notes
                    .as_ref()
                    .is_some_and(|notes| !notes.trim().is_empty()),
                "{name}/{label}: explain the evidence, difference, or exclusion in notes"
            );
        }
    }
    Ok(manifest)
}

fn catalog() -> Result<Catalog> {
    Service::ALL
        .into_iter()
        .map(|service| {
            let data = match service {
                Service::Blob => CONFORMANCE,
                Service::Dfs => include_str!("../specs/conformance/dfs.json"),
                Service::File => include_str!("../specs/conformance/file.json"),
                Service::Queue => include_str!("../specs/conformance/queue.json"),
                Service::Table => include_str!("../specs/conformance/table.json"),
            };
            Ok((service.name(), load(service, data)?))
        })
        .collect()
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    service: &'a str,
    api_version: &'a str,
    authorization: Authorization,
    azure_differential_verified: bool,
    unsupported_by_default: bool,
    implemented_locally: Vec<&'a str>,
    other_services: BTreeMap<&'static str, &'static str>,
    services: &'a Catalog,
}

fn json_report(catalog: &Catalog) -> Result<JsonReport<'_>> {
    let blob = catalog
        .get(Service::Blob.name())
        .context("Blob manifest missing")?;
    Ok(JsonReport {
        schema_version: 1,
        service: &blob.service,
        api_version: &blob.api_version,
        authorization: Authorization::SharedKey,
        azure_differential_verified: false,
        unsupported_by_default: true,
        implemented_locally: blob
            .operations
            .iter()
            .filter(|operation| operation.state.implemented())
            .map(|operation| operation.name.as_str())
            .collect(),
        other_services: catalog
            .iter()
            .filter(|&(&service, _)| service != Service::Blob.name())
            .map(|(&service, manifest)| {
                let state = if manifest
                    .operations
                    .iter()
                    .any(|operation| operation.state.implemented())
                {
                    "partial"
                } else {
                    "unsupported"
                };
                (service, state)
            })
            .collect(),
        services: catalog,
    })
}

fn markdown_report(output: &mut impl Write, catalog: &Catalog) -> io::Result<()> {
    fn cell(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace(['\r', '\n'], " ")
    }

    writeln!(
        output,
        "# Azuifer conformance\n\nOperation inventory. Local tests are not Azure differential evidence."
    )?;
    for (service, manifest) in catalog {
        writeln!(output, "\n## {service} (`{}`)\n", manifest.api_version)?;
        writeln!(
            output,
            "| Operation | State | Authorization | Notes |\n| --- | --- | --- | --- |"
        )?;
        for operation in &manifest.operations {
            let modes = operation
                .authorization
                .iter()
                .map(|mode| mode.label())
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(
                output,
                "| {} | {} | {} | {} |",
                cell(&operation.name),
                operation.state.label(),
                if modes.is_empty() { "-" } else { &modes },
                cell(operation.notes.as_deref().unwrap_or("-")),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn export(format: Format) -> Result<()> {
    let catalog = catalog()?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut output, &json_report(&catalog)?)?;
            writeln!(output)?;
        }
        Format::Markdown => markdown_report(&mut output, &catalog)?,
    }
    output.flush().context("could not write conformance report")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_manifest_cannot_assert_exact_azure_behavior() {
        let error = load(
            Service::Blob,
            r#"{"service":"blob","api_version":"2023-11-03","operations":[
                {"name":"Get Blob","state":"exact","authorization":["SharedKey"],"notes":"Local HTTP test passed"}
            ]}"#,
        )
        .err()
        .expect("exact without Azure differential evidence must fail validation");
        assert!(
            error
                .to_string()
                .contains("exact requires verified Azure differential evidence")
        );
    }

    #[test]
    fn a_manifest_cannot_advertise_authorization_for_an_unsupported_operation() {
        let error = load(
            Service::Queue,
            r#"{"service":"queue","api_version":"2023-11-03","operations":[
                {"name":"Put Message","state":"unsupported","authorization":["SharedKey"]}
            ]}"#,
        )
        .err()
        .expect("unsupported operations cannot claim working authorization");
        assert!(
            error
                .to_string()
                .contains("only for implemented operations")
        );
    }
}
