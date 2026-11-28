//! Named compatibility mode (ADR-0038) from the command line and configuration.

use super::*;

fn export_with(configure: impl FnOnce(&mut Command)) -> serde_json::Value {
    let mut command = azuifer();
    command.args(["conformance", "export"]);
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["compatibility"].clone()
}

fn names(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect()
}

#[test]
fn compatibility_mode_is_strict_by_default_and_follows_the_precedence_rules() {
    let dir = tempfile::tempdir().unwrap();
    let count = std::cell::Cell::new(0);
    let toml = |text: &str| {
        count.set(count.get() + 1);
        let file = dir.path().join(format!("config-{}.toml", count.get()));
        std::fs::write(&file, text).unwrap();
        file
    };
    let lenient_file = toml("compatibility_mode = \"lenient\"\n");
    let strict_file = toml("compatibility_mode = \"strict\"\n");

    let default = export_with(|_| {});
    assert_eq!(default["mode"], "strict");
    assert!(names(&default["ignored_headers"]).is_empty());
    assert!(names(&default["ignored_query_parameters"]).is_empty());
    assert!(
        names(&default["never_relaxed"])
            .iter()
            .any(|area| area.contains("authentication, SAS")),
        "the export says what is never relaxed"
    );

    let lenient = export_with(|command| {
        command.env("AZUIFER_COMPATIBILITY_MODE", "lenient");
    });
    assert_eq!(lenient["mode"], "lenient");
    assert_eq!(names(&lenient["ignored_headers"]), ["x-ms-useragent"]);

    let from_file = export_with(|command| {
        command.args(["--config", path(&lenient_file)]);
    });
    assert_eq!(from_file["mode"], "lenient");

    let env_over_file = export_with(|command| {
        command
            .env("AZUIFER_COMPATIBILITY_MODE", "strict")
            .args(["--config", path(&lenient_file)]);
    });
    assert_eq!(env_over_file["mode"], "strict");
    let file_under_env = export_with(|command| {
        command
            .env("AZUIFER_COMPATIBILITY_MODE", "lenient")
            .args(["--config", path(&strict_file)]);
    });
    assert_eq!(file_under_env["mode"], "lenient");
    let flag_over_env = export_with(|command| {
        command
            .env("AZUIFER_COMPATIBILITY_MODE", "lenient")
            .args(["--compatibility-mode", "strict"]);
    });
    assert_eq!(flag_over_env["mode"], "strict");

    let listed = export_with(|command| {
        command.args([
            "--compatibility-mode",
            "lenient",
            "--compatibility-allow",
            "x-ms-trace-hint,cachebust",
        ]);
    });
    assert_eq!(
        names(&listed["ignored_headers"]),
        ["x-ms-trace-hint", "x-ms-useragent"]
    );
    assert_eq!(names(&listed["ignored_query_parameters"]), ["cachebust"]);
    let allow_file =
        toml("compatibility_mode = \"lenient\"\ncompatibility_allow = \"cachebust\"\n");
    let from_file = export_with(|command| {
        command.args(["--config", path(&allow_file)]);
    });
    assert_eq!(names(&from_file["ignored_query_parameters"]), ["cachebust"]);

    let markdown = run(&[
        "--compatibility-mode",
        "lenient",
        "conformance",
        "export",
        "--format",
        "markdown",
    ]);
    let text = stdout(&markdown);
    assert!(text.contains("## Compatibility mode"), "{text}");
    assert!(text.contains("**Active mode: `lenient`.**"), "{text}");
    assert!(
        text.contains("- Ignored headers: `x-ms-useragent`"),
        "{text}"
    );
    assert!(text.contains("`lenient` never relaxes:"), "{text}");
    assert!(
        stdout(&run(&["conformance", "export", "--format", "markdown"]))
            .contains("**Active mode: `strict`.**")
    );
}

#[test]
fn compatibility_mode_rejects_unknown_modes_and_names_that_carry_protocol_meaning() {
    let dir = tempfile::tempdir().unwrap();
    let bad_file = dir.path().join("bad.toml");
    std::fs::write(&bad_file, "compatibility_mode = \"loose\"\n").unwrap();

    let valid = run(&["config", "validate", "--compatibility-mode", "lenient"]);
    assert!(valid.status.success(), "{}", stderr(&valid));
    assert_eq!(stdout(&valid).trim(), "Configuration is valid.");

    let flag = run(&["config", "validate", "--compatibility-mode", "loose"]);
    assert!(!flag.status.success());
    assert!(
        stderr(&flag).contains("strict") && stderr(&flag).contains("lenient"),
        "{}",
        stderr(&flag)
    );
    let env = azuifer()
        .args(["config", "validate"])
        .env("AZUIFER_COMPATIBILITY_MODE", "loose")
        .output()
        .unwrap();
    assert!(!env.status.success());
    let file = run(&["config", "validate", "--config", path(&bad_file)]);
    assert!(!file.status.success());
    assert!(
        stderr(&file).contains("invalid configuration TOML"),
        "{}",
        stderr(&file)
    );

    let without_mode = run(&[
        "config",
        "validate",
        "--compatibility-allow",
        "x-ms-trace-hint",
    ]);
    assert!(!without_mode.status.success());
    assert!(
        stderr(&without_mode).contains("needs compatibility-mode lenient"),
        "{}",
        stderr(&without_mode)
    );
    for (name, why) in [
        ("x-ms-encryption-scope", "encryption"),
        ("x-ms-lease-id", "a lease"),
        ("x-ms-content-crc64", "a checksum"),
        ("x-ms-if-match", "a conditional"),
        ("x-ms-vendor-token", "a credential"),
        ("sig", "a parameter of the protocol"),
        ("snapshot", "a parameter of the protocol"),
        ("comp", "a parameter of the protocol"),
    ] {
        for command in [["config", "validate"], ["conformance", "export"]] {
            let output = run(&[
                &command[..],
                &[
                    "--compatibility-mode",
                    "lenient",
                    "--compatibility-allow",
                    name,
                ],
            ]
            .concat());
            assert!(!output.status.success(), "{name} {command:?}");
            let message = stderr(&output);
            assert!(
                message.contains(name)
                    && message.contains("cannot be relaxed")
                    && message.contains(why),
                "{name}: {message}"
            );
        }
    }
}

#[test]
fn status_reports_the_compatibility_mode_and_the_names_it_ignores() {
    let server = Server::start(&[
        "--in-memory",
        "--services",
        "queue",
        "--compatibility-mode",
        "lenient",
        "--compatibility-allow",
        "cachebust",
    ]);
    let output = run(&["status", "--admin-url", &server.admin]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("Compat:    lenient (ignores unknown x-ms-useragent, cachebust)"),
        "{}",
        stdout(&output)
    );
    let output = run(&["status", "--admin-url", &server.admin, "--json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["compatibility"]["mode"], "lenient");
}
