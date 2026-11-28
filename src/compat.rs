//! Named compatibility mode (ADR-0038): which unknown request names Blob and DFS tolerate.
//!
//! `strict` rejects an `x-ms-*` header or query parameter an operation does not implement,
//! as it always has. `lenient` ignores only the names on an explicit list: a short built-in
//! one, plus names the operator spells out. Every name ignored is logged, by name only.
//! Nothing here touches authentication, SAS, encryption, checksums, conditional headers,
//! leases, immutability, or a known operation: a name that belongs to one of those cannot
//! be put on the list.

use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Headers sent by real clients that carry no protocol meaning.
const BUILTIN_HEADERS: &[&str] = &[
    // The browser and React Native builds of `@azure/core-rest-pipeline` put their user-agent
    // string here, because a browser may not set `User-Agent`.
    "x-ms-useragent",
];
const BUILTIN_QUERY: &[&str] = &[];

const MAX_NAME: usize = 64;

/// Header families that give a request meaning. A name that starts with one of these is
/// protocol, not noise, so an operator cannot relax it.
const SEMANTIC_PREFIXES: &[(&str, &str)] = &[
    ("x-ms-encryption", "encryption"),
    ("x-ms-default-encryption", "encryption"),
    ("x-ms-deny-encryption", "encryption"),
    ("x-ms-if-", "a conditional"),
    ("x-ms-blob-condition", "a conditional"),
    ("x-ms-source-", "a copy source"),
    ("x-ms-copy", "a copy source"),
    ("x-ms-requires", "a copy"),
    ("x-ms-lease", "a lease"),
    ("x-ms-proposed-lease", "a lease"),
    ("x-ms-immut", "immutability"),
    ("x-ms-legal-hold", "immutability"),
    ("x-ms-tags", "blob tags"),
    ("x-ms-meta", "metadata"),
    ("x-ms-blob-", "a blob property"),
    ("x-ms-content-", "a content property"),
    ("x-ms-range", "a range"),
    ("x-ms-access-tier", "a tier"),
    ("x-ms-rehydrate", "a tier"),
    ("x-ms-seal", "sealing"),
    ("x-ms-expiry", "expiry"),
    ("x-ms-page", "a page blob"),
    ("x-ms-sequence", "a page blob"),
    ("x-ms-delete", "deletion"),
    ("x-ms-snapshot", "a snapshot"),
    ("x-ms-version", "the API version"),
    ("x-ms-date", "the request date"),
    ("x-ms-client-request-id", "request correlation"),
    ("x-ms-return-client", "request correlation"),
    ("x-ms-file-", "Azure Files"),
    ("x-ms-rename", "a rename"),
    ("x-ms-owner", "POSIX ownership"),
    ("x-ms-group", "POSIX ownership"),
    ("x-ms-permissions", "POSIX permissions"),
    ("x-ms-umask", "POSIX permissions"),
    ("x-ms-acl", "access control"),
    ("x-ms-properties", "path properties"),
    ("x-ms-namespace", "the namespace"),
    ("x-ms-resource", "a resource type"),
    ("x-ms-is-", "state"),
    ("x-ms-enable", "a feature"),
];

/// Fragments that mark a credential or a checksum wherever they appear in a name.
const SENSITIVE_PARTS: &[(&str, &str)] = &[
    ("auth", "authorization"),
    ("sas", "a shared access signature"),
    ("sig", "a signature"),
    ("token", "a credential"),
    ("key", "a key"),
    ("secret", "a credential"),
    ("password", "a credential"),
    ("credential", "a credential"),
    ("md5", "a checksum"),
    ("crc", "a checksum"),
    ("checksum", "a checksum"),
    ("hash", "a checksum"),
];

/// Query parameters the Blob and DFS parsers know. A relaxed name must not be one of these,
/// or ignoring it would change what the request does. SAS parameters are refused separately.
const RESERVED_QUERY: &[&str] = &[
    "action",
    "blockid",
    "blocklisttype",
    "close",
    "comp",
    "continuation",
    "copyid",
    "delimiter",
    "directory",
    "forceflag",
    "include",
    "marker",
    "maxrecords",
    "maxresults",
    "mode",
    "paginated",
    "position",
    "prefix",
    "prevsnapshot",
    "recursive",
    "resource",
    "restype",
    "retainuncommitteddata",
    "snapshot",
    "timeout",
    "upn",
    "versionid",
    "where",
];

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    /// Reject every name an operation does not implement.
    #[default]
    Strict,
    /// Also ignore the names on the compatibility list, and log each one.
    Lenient,
}

impl Mode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Lenient => "lenient",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Header,
    Query,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Query => "query",
        }
    }
}

/// The resolved mode and the names it ignores. Strict, the default, ignores none.
#[derive(Clone, Debug, Default)]
pub(crate) struct Policy {
    mode: Mode,
    headers: BTreeSet<String>,
    query: BTreeSet<String>,
}

impl Policy {
    /// `allow` is the operator's comma-separated list: `x-ms-*` names are headers and any
    /// other name is a query parameter. It needs `lenient`, and refuses a name that belongs
    /// to a protected area.
    pub(crate) fn resolve(mode: Option<Mode>, allow: Option<&str>) -> Result<Self> {
        let mode = mode.unwrap_or_default();
        let extra: Vec<String> = allow
            .into_iter()
            .flat_map(|list| list.split(','))
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        if mode == Mode::Strict {
            ensure!(
                extra.is_empty(),
                "compatibility-allow needs compatibility-mode lenient"
            );
            return Ok(Self::default());
        }
        let mut policy = Self {
            mode,
            headers: BUILTIN_HEADERS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            query: BUILTIN_QUERY
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        };
        for name in extra {
            if name.starts_with("x-ms-") {
                validate_header(&name)?;
                policy.headers.insert(name);
            } else {
                validate_query(&name)?;
                policy.query.insert(name);
            }
        }
        Ok(policy)
    }

    /// The names ignored, headers first: empty in strict mode.
    pub(crate) fn names(&self) -> impl Iterator<Item = (Kind, &str)> {
        self.headers
            .iter()
            .map(|name| (Kind::Header, name.as_str()))
            .chain(self.query.iter().map(|name| (Kind::Query, name.as_str())))
    }

    /// The query parameters ignored, whose values the redactor must mask.
    pub(crate) fn query_names(&self) -> impl Iterator<Item = &str> {
        self.query.iter().map(String::as_str)
    }

    fn admits(&self, kind: Kind, name: &str) -> bool {
        match kind {
            Kind::Header => self.headers.contains(name),
            Kind::Query => self.query.contains(name),
        }
    }
}

fn well_formed(name: &str, extra: &[char]) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_NAME
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c)),
        "`{name}` is not a valid name to relax (lowercase letters, digits and `{}`, at most {MAX_NAME} characters)",
        extra.iter().collect::<String>()
    );
    Ok(())
}

fn protected(name: &str) -> Option<&'static str> {
    SENSITIVE_PARTS
        .iter()
        .find(|(part, _)| name.contains(part))
        .map(|(_, what)| *what)
}

fn validate_header(name: &str) -> Result<()> {
    well_formed(name, &['-'])?;
    // A credential or a checksum is named as such even when its prefix is a property family.
    let family = SEMANTIC_PREFIXES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, what)| *what);
    if let Some(what) = protected(name).or(family) {
        bail!("`{name}` cannot be relaxed: it names {what}");
    }
    Ok(())
}

fn validate_query(name: &str) -> Result<()> {
    well_formed(name, &['-', '_', '.'])?;
    if RESERVED_QUERY.contains(&name) || crate::blob_sas::is_sas_param(name) {
        bail!("`{name}` cannot be relaxed: it is a parameter of the protocol");
    }
    if let Some(what) = protected(name) {
        bail!("`{name}` cannot be relaxed: it names {what}");
    }
    Ok(())
}

/// What one request needs to ask whether a name may be ignored, and to say so when it is.
pub(crate) struct Relax<'a> {
    policy: &'a Policy,
    service: &'static str,
    request_id: &'a str,
}

impl<'a> Relax<'a> {
    pub(crate) fn new(policy: &'a Policy, service: &'static str, request_id: &'a str) -> Self {
        Self {
            policy,
            service,
            request_id,
        }
    }

    pub(crate) fn header(&self, name: &str) -> bool {
        self.admit(Kind::Header, name)
    }

    pub(crate) fn query(&self, name: &str) -> bool {
        self.admit(Kind::Query, name)
    }

    /// The log record names the service, request, and name, never a value: a value may be
    /// a credential, and a name that is not on the list is never logged at all.
    fn admit(&self, kind: Kind, name: &str) -> bool {
        if !self.policy.admits(kind, name) {
            return false;
        }
        tracing::warn!(
            service = self.service,
            request_id = self.request_id,
            kind = kind.label(),
            name,
            compatibility_mode = self.policy.mode.name(),
            "compatibility mode ignored an unknown request name"
        );
        true
    }
}

/// The `compatibility` object of `/status` and of the conformance export.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Report {
    pub(crate) mode: String,
    pub(crate) ignored_headers: Vec<String>,
    pub(crate) ignored_query_parameters: Vec<String>,
}

impl Policy {
    pub(crate) fn report(&self) -> Report {
        let names = |wanted| {
            self.names()
                .filter(|(kind, _)| *kind == wanted)
                .map(|(_, name)| name.to_owned())
                .collect()
        };
        Report {
            mode: self.mode.name().to_owned(),
            ignored_headers: names(Kind::Header),
            ignored_query_parameters: names(Kind::Query),
        }
    }
}

/// What the conformance export says about the mode: the active policy, and what it can
/// never relax.
#[derive(Serialize)]
pub(crate) struct Description {
    #[serde(flatten)]
    report: Report,
    never_relaxed: &'static [&'static str],
}

impl Policy {
    pub(crate) fn description(&self) -> Description {
        Description {
            report: self.report(),
            never_relaxed: NEVER_RELAXED,
        }
    }
}

impl Description {
    pub(crate) fn write_markdown(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(output, "\n## Compatibility mode\n")?;
        writeln!(
            output,
            "**Active mode: `{}`.** `strict`, the default, rejects every query parameter and `x-ms-*` header an operation does not implement. `lenient` also ignores the names listed here and logs each one by service, request ID and name, never its value. The mode applies to Blob and DFS, the services that reject unknown names; Queue, Table and Files already ignore them in both modes. It changes no operation state in the tables below.",
            self.report.mode
        )?;
        let list = |names: &[String]| {
            if names.is_empty() {
                "none".to_owned()
            } else {
                names
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        writeln!(
            output,
            "\n- Ignored headers: {}",
            list(&self.report.ignored_headers)
        )?;
        writeln!(
            output,
            "- Ignored query parameters: {}",
            list(&self.report.ignored_query_parameters)
        )?;
        writeln!(output, "\n`lenient` never relaxes:\n")?;
        for area in self.never_relaxed {
            writeln!(output, "- {area}")?;
        }
        Ok(())
    }
}

/// What `lenient` never relaxes. One list for the export; the checks above enforce it.
const NEVER_RELAXED: &[&str] = &[
    "authentication, SAS and shared keys",
    "encryption, customer-provided keys and encryption scopes",
    "checksums (`Content-MD5`, `x-ms-content-crc64` and every `*-md5` or `*-crc64` header)",
    "conditional headers (`If-*`, `x-ms-if-*`, `x-ms-blob-condition-*`)",
    "leases",
    "immutability policies and legal holds",
    "copy sources",
    "every query parameter the protocol defines, and the SAS parameters",
    "operations Azuifer recognizes as unsupported (for example `comp=rename`)",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn lenient(allow: &str) -> Result<Policy> {
        Policy::resolve(Some(Mode::Lenient), Some(allow))
    }

    #[test]
    fn strict_is_the_default_and_ignores_nothing() {
        let policy = Policy::resolve(None, None).unwrap();
        assert_eq!(policy.report().mode, "strict");
        assert_eq!(policy.names().count(), 0);
        assert!(!policy.admits(Kind::Header, "x-ms-useragent"));
    }

    #[test]
    fn lenient_ignores_the_builtin_list_and_what_the_operator_names() {
        let policy = lenient("X-Ms-Trace-Hint, cachebust ,").unwrap();
        assert!(policy.admits(Kind::Header, "x-ms-useragent"));
        assert!(policy.admits(Kind::Header, "x-ms-trace-hint"));
        assert!(policy.admits(Kind::Query, "cachebust"));
        assert!(!policy.admits(Kind::Header, "x-ms-other"));
        assert!(!policy.admits(Kind::Query, "other"));
        let report = policy.report();
        assert_eq!(report.mode, "lenient");
        assert_eq!(
            report.ignored_headers,
            ["x-ms-trace-hint", "x-ms-useragent"]
        );
        assert_eq!(report.ignored_query_parameters, ["cachebust"]);
    }

    #[test]
    fn an_operator_list_needs_lenient_mode() {
        let error = Policy::resolve(None, Some("x-ms-trace-hint")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("needs compatibility-mode lenient")
        );
        assert!(Policy::resolve(Some(Mode::Strict), Some("")).is_ok());
    }

    #[test]
    fn names_that_carry_protocol_meaning_cannot_be_relaxed() {
        for name in [
            "x-ms-encryption-scope",
            "x-ms-encryption-key",
            "x-ms-default-encryption-scope",
            "x-ms-if-tags",
            "x-ms-blob-condition-appendpos",
            "x-ms-source-if-match",
            "x-ms-copy-source",
            "x-ms-lease-id",
            "x-ms-immutability-policy-mode",
            "x-ms-legal-hold",
            "x-ms-blob-content-md5",
            "x-ms-content-crc64",
            "x-ms-range-get-content-md5",
            "x-ms-meta-anything",
            "x-ms-version",
            "x-ms-access-tier",
            "x-ms-vendor-token",
            "x-ms-vendor-authorization",
            "x-ms-vendor-sas",
            "x-ms-vendor-checksum",
            "x-ms-vendor-secret",
        ] {
            let error = lenient(name).unwrap_err().to_string();
            assert!(error.contains("cannot be relaxed"), "{name}: {error}");
        }
        for name in [
            "comp",
            "restype",
            "snapshot",
            "versionid",
            "timeout",
            "sig",
            "sv",
            "se",
            "sp",
            "skoid",
            "marker",
            "resource",
            "mytoken",
            "api-key",
            "md5",
        ] {
            let error = lenient(name).unwrap_err().to_string();
            assert!(error.contains("cannot be relaxed"), "{name}: {error}");
        }
    }

    #[test]
    fn malformed_names_are_refused() {
        for name in ["x-ms-Has Space", "x-ms-a/b", "a=b", &"x".repeat(65)] {
            assert!(lenient(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_builtin_list_obeys_its_own_rules() {
        for name in BUILTIN_HEADERS {
            assert!(validate_header(name).is_ok(), "{name}");
        }
        for name in BUILTIN_QUERY {
            assert!(validate_query(name).is_ok(), "{name}");
        }
    }
}
