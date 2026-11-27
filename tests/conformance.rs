use serde_json::Value;
use std::{fs, path::Path, process::Command};

fn export(args: &[&str]) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_azuifer"));
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("AZUIFER_")
        {
            command.env_remove(name);
        }
    }
    let output = command
        .args(["conformance", "export"])
        .args(args)
        .output()
        .expect("run the conformance export");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 conformance report")
}

#[test]
fn json_export_adds_all_services_without_breaking_blob_clients() {
    let report: Value = serde_json::from_str(&export(&[])).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["service"], "blob");
    assert_eq!(report["authorization"], "SharedKey");
    assert_eq!(report["unsupported_by_default"], true);
    assert_eq!(report["azure_differential_verified"], false);
    let services = report["services"].as_object().expect("per-service reports");
    assert_eq!(
        services.keys().map(String::as_str).collect::<Vec<_>>(),
        ["blob", "dfs", "file", "queue", "table"]
    );
    assert_eq!(report["api_version"], services["blob"]["api_version"]);
    assert!(
        report["implemented_locally"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation == "Put Block List")
    );
    for (service, manifest) in services {
        assert_eq!(&manifest["service"], service);
        let operations = manifest["operations"].as_array().unwrap();
        assert!(!operations.is_empty(), "{service}");
        for operation in operations {
            assert_ne!(operation["state"], "exact", "{service}: {operation}");
            if operation["state"] == "unsupported" {
                assert!(operation["authorization"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn json_export_counts_reviewed_cassettes_without_upgrading_operations() {
    let report: Value = serde_json::from_str(&export(&[])).unwrap();
    let service = &report["services"]["blob"]["live_azure_evidence"];
    assert_eq!(
        service["matched_operation_auth"]["Get Blob"],
        serde_json::json!({"Bearer": "B-06", "UserDelegationSAS": "B-03"})
    );
    assert_eq!(
        service["matched_unsupported_boundaries"]["Rename Container"],
        "B-40"
    );
    assert!(service["matched_operation_auth"]["Rename Container"].is_null());
    let operations = report["services"]["blob"]["operations"].as_array().unwrap();
    assert!(
        operations
            .iter()
            .any(|op| { op["name"] == "Abort Copy Blob" && op["state"] == "known-difference" })
    );
    assert_eq!(
        service["matched_operation_auth"]["Abort Copy Blob"]["Bearer"],
        "B-22"
    );

    let cassettes = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/contracts/cassettes");
    let mut recorded = 0;
    let mut count = 0;
    for entry in fs::read_dir(cassettes).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let fixture: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            recorded += fixture["exchanges"]
                .as_array()
                .or_else(|| fixture["responses"].as_array())
                .map_or_else(|| usize::from(!fixture["response"].is_null()), Vec::len);
            count += 1;
        }
    }
    let ledger: Value = serde_json::from_str(include_str!(
        "../docs/compatibility/wire-discrepancies.json"
    ))
    .unwrap();
    let evidence = &report["live_azure_evidence"];
    assert_eq!(evidence["cassettes"], count);
    assert_eq!(evidence["recorded_exchanges"], recorded);
    assert_eq!(
        evidence["wire_discrepancies"],
        ledger["entries"].as_array().unwrap().len()
    );
}

#[test]
fn markdown_export_shows_the_same_verified_and_unsupported_operations() {
    let markdown = export(&["--format", "markdown"]);
    assert!(markdown.contains("## Live Azure evidence"));
    let report: Value = serde_json::from_str(&export(&[])).unwrap();
    let evidence = &report["live_azure_evidence"];
    assert!(markdown.contains(&format!(
        "{}/{} planned exchanges matched",
        evidence["matched_exchanges"], evidence["target_exchanges"]
    )));
    assert!(
        markdown.contains("Bearer (B-06), UserDelegationSAS (B-03)")
            || markdown.contains("UserDelegationSAS (B-03), Bearer (B-06)")
    );
    assert!(markdown.contains("## blob (`2023-11-03`)"));
    assert!(markdown.contains("| Put Block List | known-difference | SharedKey, SharedKeyLite, AccountSAS, ServiceSAS, UserDelegationSAS, Bearer |"));
    assert!(markdown.contains("## queue (`2023-11-03`)"));
    assert!(markdown.contains(
        "| Put Message | compatible | SharedKey, SharedKeyLite, AccountSAS, ServiceSAS, Bearer |"
    ));
    assert!(markdown.contains("## dfs (`2023-11-03`)"));
    assert!(markdown.contains("| Rename Path | known-difference |"));
    assert!(markdown.contains("| Query Blob Contents | known-difference |"));
    assert!(
        markdown.contains("| Rename Container | unsupported | - | Unsupported boundary (B-40) |")
    );
    assert!(!markdown.contains("| exact |"));
}
