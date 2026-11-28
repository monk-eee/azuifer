use crate::{
    compat,
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
    live_azure_evidence: ServiceEvidence,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceEvidence {
    cassettes: usize,
    target_exchanges: usize,
    recorded_exchanges: usize,
    matched_exchanges: usize,
    matched_operation_auth: BTreeMap<String, BTreeMap<Authorization, String>>,
    matched_unsupported_boundaries: BTreeMap<String, String>,
    wire_discrepancies: usize,
}

impl ServiceEvidence {
    fn matched_auth_pairs(&self) -> usize {
        self.matched_operation_auth
            .values()
            .map(BTreeMap::len)
            .sum()
    }

    fn annotation(&self, operation: &str) -> String {
        if let Some(modes) = self.matched_operation_auth.get(operation) {
            modes
                .iter()
                .map(|(auth, row)| format!("{} ({row})", auth.label()))
                .collect::<Vec<_>>()
                .join(", ")
        } else if let Some(row) = self.matched_unsupported_boundaries.get(operation) {
            format!("Unsupported boundary ({row})")
        } else {
            "-".to_owned()
        }
    }
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
    const ALL: [Self; 5] = [
        Self::Exact,
        Self::Compatible,
        Self::KnownDifference,
        Self::Unsupported,
        Self::NotApplicable,
    ];

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
    let evidence = &manifest.live_azure_evidence;
    ensure!(
        evidence.matched_exchanges <= evidence.recorded_exchanges
            && evidence.recorded_exchanges <= evidence.target_exchanges
            && evidence.cassettes <= evidence.recorded_exchanges,
        "{name}: invalid live Azure exchange counts"
    );
    let mut names = BTreeSet::new();
    for operation in &manifest.operations {
        let label = &operation.name;
        ensure!(
            !label.trim().is_empty() && label.trim() == label && names.insert(label),
            "duplicate, blank, or untrimmed operation in {name}: {label:?}"
        );
        ensure!(
            operation.state != State::Exact,
            "{name}/{label}: exact requires full-scope Azure differential evidence, not individual scenario matches"
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
        if let Some(matched) = evidence.matched_operation_auth.get(label) {
            ensure!(
                !matched.is_empty() && matched.keys().all(|mode| modes.contains(mode)),
                "{name}/{label}: matched auth must be advertised by an implemented operation"
            );
        }
        if evidence.matched_unsupported_boundaries.contains_key(label) {
            ensure!(
                operation.state == State::Unsupported,
                "{name}/{label}: boundary evidence must name an unsupported operation"
            );
        }
    }
    ensure!(
        evidence
            .matched_operation_auth
            .keys()
            .chain(evidence.matched_unsupported_boundaries.keys())
            .all(|label| names.contains(label)),
        "{name}: live evidence names an unknown operation"
    );
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
struct OperationSummary {
    recognized: usize,
    implemented: usize,
    states: BTreeMap<&'static str, usize>,
}

#[derive(Default, Serialize)]
struct EvidenceSummary {
    cassettes: usize,
    target_exchanges: usize,
    recorded_exchanges: usize,
    matched_exchanges: usize,
    operations_with_matched_evidence: usize,
    operation_auth_pairs_with_matched_evidence: usize,
    advertised_operation_auth_pairs: usize,
    matched_unsupported_boundaries: usize,
    wire_discrepancies: usize,
}

fn summaries(catalog: &Catalog) -> (OperationSummary, EvidenceSummary) {
    let mut operations = OperationSummary {
        recognized: 0,
        implemented: 0,
        states: State::ALL
            .into_iter()
            .map(|state| (state.label(), 0))
            .collect(),
    };
    let mut evidence = EvidenceSummary::default();
    for manifest in catalog.values() {
        let service = &manifest.live_azure_evidence;
        evidence.cassettes += service.cassettes;
        evidence.target_exchanges += service.target_exchanges;
        evidence.recorded_exchanges += service.recorded_exchanges;
        evidence.matched_exchanges += service.matched_exchanges;
        evidence.operations_with_matched_evidence += service.matched_operation_auth.len();
        evidence.operation_auth_pairs_with_matched_evidence += service.matched_auth_pairs();
        evidence.matched_unsupported_boundaries += service.matched_unsupported_boundaries.len();
        evidence.wire_discrepancies += service.wire_discrepancies;
        for operation in &manifest.operations {
            operations.recognized += 1;
            operations.implemented += usize::from(operation.state.implemented());
            *operations
                .states
                .entry(operation.state.label())
                .or_default() += 1;
            evidence.advertised_operation_auth_pairs += operation.authorization.len();
        }
    }
    (operations, evidence)
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
    operation_summary: OperationSummary,
    live_azure_evidence: EvidenceSummary,
    compatibility: compat::Description,
}

fn json_report<'a>(catalog: &'a Catalog, policy: &compat::Policy) -> Result<JsonReport<'a>> {
    let blob = catalog
        .get(Service::Blob.name())
        .context("Blob manifest missing")?;
    let (operation_summary, live_azure_evidence) = summaries(catalog);
    Ok(JsonReport {
        schema_version: 1,
        service: &blob.service,
        api_version: &blob.api_version,
        authorization: Authorization::SharedKey,
        // Legacy whole-contract Blob/SharedKey flag, not a count of matched scenarios.
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
        operation_summary,
        live_azure_evidence,
        compatibility: policy.description(),
    })
}

fn markdown_report(
    output: &mut impl Write,
    catalog: &Catalog,
    policy: &compat::Policy,
) -> io::Result<()> {
    fn cell(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace(['\r', '\n'], " ")
    }

    let (operations, evidence) = summaries(catalog);
    let states = operations
        .states
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(output, "# Azuifer conformance\n")?;
    writeln!(
        output,
        "**{}/{} operations implemented locally.** States: {states}.",
        operations.implemented, operations.recognized
    )?;
    writeln!(output, "\n## Live Azure evidence\n")?;
    writeln!(
        output,
        "**{}/{} planned exchanges matched**, with {} recorded across {} reviewed cassettes.",
        evidence.matched_exchanges,
        evidence.target_exchanges,
        evidence.recorded_exchanges,
        evidence.cassettes
    )?;
    writeln!(
        output,
        "Explicit matches cover {} operations and {}/{} advertised operation/auth pairs, plus {} unsupported boundaries. The wire ledger has {} discrepancy entries.",
        evidence.operations_with_matched_evidence,
        evidence.operation_auth_pairs_with_matched_evidence,
        evidence.advertised_operation_auth_pairs,
        evidence.matched_unsupported_boundaries,
        evidence.wire_discrepancies
    )?;
    writeln!(
        output,
        "\nMatched cassettes cover only the recorded scenario and auth mode, including rejection cases. They do not imply `exact` or count local-only SDK tests."
    )?;
    writeln!(
        output,
        "\n| Service | Cassettes | Recorded | Matched / target | Operations with a match |\n| --- | ---: | ---: | ---: | ---: |"
    )?;
    for (service, manifest) in catalog {
        let coverage = &manifest.live_azure_evidence;
        writeln!(
            output,
            "| {service} | {} | {} | {} / {} | {} |",
            coverage.cassettes,
            coverage.recorded_exchanges,
            coverage.matched_exchanges,
            coverage.target_exchanges,
            coverage.matched_operation_auth.len()
        )?;
    }
    policy.description().write_markdown(output)?;
    for (service, manifest) in catalog {
        writeln!(output, "\n## {service} (`{}`)\n", manifest.api_version)?;
        writeln!(
            output,
            "| Operation | State | Authorization | Matched Azure evidence (plan row) | Notes |\n| --- | --- | --- | --- | --- |"
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
                "| {} | {} | {} | {} | {} |",
                cell(&operation.name),
                operation.state.label(),
                if modes.is_empty() { "-" } else { &modes },
                cell(&manifest.live_azure_evidence.annotation(&operation.name)),
                cell(operation.notes.as_deref().unwrap_or("-")),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn export(format: Format, policy: &compat::Policy) -> Result<()> {
    let catalog = catalog()?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut output, &json_report(&catalog, policy)?)?;
            writeln!(output)?;
        }
        Format::Markdown => markdown_report(&mut output, &catalog, policy)?,
    }
    output.flush().context("could not write conformance report")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_one(service: Service, operation: serde_json::Value) -> Result<Manifest> {
        let data = serde_json::json!({
            "service": service.name(), "api_version": "2023-11-03",
            "operations": [operation],
            "live_azure_evidence": {
                "target_exchanges": 1, "recorded_exchanges": 0, "matched_exchanges": 0,
                "cassettes": 0, "wire_discrepancies": 0,
                "matched_operation_auth": {}, "matched_unsupported_boundaries": {}
            }
        });
        load(service, &data.to_string())
    }

    #[test]
    fn a_local_manifest_cannot_assert_exact_azure_behavior() {
        let error = load_one(
            Service::Blob,
            serde_json::json!({"name":"Get Blob","state":"exact","authorization":["SharedKey"],"notes":"Local HTTP test passed"}),
        )
        .err()
        .expect("exact without Azure differential evidence must fail validation");
        assert!(
            error
                .to_string()
                .contains("exact requires full-scope Azure differential evidence")
        );
    }

    #[test]
    fn a_manifest_cannot_advertise_authorization_for_an_unsupported_operation() {
        let error = load_one(
            Service::Queue,
            serde_json::json!({"name":"Put Message","state":"unsupported","authorization":["SharedKey"]}),
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
