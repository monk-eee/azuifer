use serde_json::Value;
use std::process::Command;

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
fn markdown_export_shows_the_same_verified_and_unsupported_operations() {
    let markdown = export(&["--format", "markdown"]);
    assert!(markdown.contains("## blob (`2023-11-03`)"));
    assert!(markdown.contains("| Put Block List | known-difference | SharedKey, SharedKeyLite, AccountSAS, ServiceSAS, UserDelegationSAS, Bearer |"));
    assert!(markdown.contains("## queue (`2023-11-03`)"));
    assert!(markdown.contains(
        "| Put Message | compatible | SharedKey, SharedKeyLite, AccountSAS, ServiceSAS, Bearer |"
    ));
    assert!(markdown.contains("## dfs (`2023-11-03`)"));
    assert!(markdown.contains("| Rename Path | known-difference |"));
    assert!(markdown.contains("| Query Blob Contents | unsupported | - |"));
    assert!(!markdown.contains("| exact |"));
}
