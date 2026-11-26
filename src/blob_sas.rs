//! Blob SAS strings-to-sign and token interpretation for signed versions
//! 2015-04-05 through 2023-11-03 (ADR-0011). Account, service, and user-delegation
//! tokens are recognised here; user-delegation signing keys live in [`crate::delegation`].

use crate::{
    auth::Query,
    delegation::{self, Keys},
    domain::{AccountName, Error, Result, SignedIdentifier},
    sas::{self, Sas},
};
use std::net::IpAddr;
use std::time::SystemTime;

/// Query parameters that belong to a SAS rather than to the operation.
const SAS_PARAMS: [&str; 30] = [
    "sv",
    "ss",
    "srt",
    "sp",
    "st",
    "se",
    "sip",
    "spr",
    "sig",
    "sr",
    "si",
    "ses",
    "sst",
    "rscc",
    "rscd",
    "rsce",
    "rscl",
    "rsct",
    "skoid",
    "sktid",
    "skt",
    "ske",
    "sks",
    "skv",
    "saoid",
    "suoid",
    "scid",
    "sdd",
    "sdddd",
    "snapshot-time",
];

pub(crate) fn is_sas_param(name: &str) -> bool {
    SAS_PARAMS.contains(&name)
}

/// Response header overrides a service SAS may impose on Get Blob.
#[derive(Clone, Debug, Default)]
pub(crate) struct Overrides {
    pub(crate) cache_control: Option<String>,
    pub(crate) disposition: Option<String>,
    pub(crate) encoding: Option<String>,
    pub(crate) language: Option<String>,
    pub(crate) content_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    Blob,
    Container,
    /// A DFS directory (`sr=d`); `sdd` is the depth of the signed directory.
    Directory,
}

#[derive(Clone, Debug)]
pub(crate) enum Kind {
    Account,
    Service { identifier: Option<String> },
}

pub(crate) struct Token {
    pub(crate) kind: Kind,
    sas: Sas,
    pub(crate) overrides: Overrides,
    /// The lifetime of the user delegation key that signed the token, if any.
    key_window: Option<(SystemTime, SystemTime)>,
}

/// What an operation asks of a SAS or of anonymous access.
pub(crate) struct Need {
    /// Any of these service-SAS permission letters; `None` means a service SAS cannot do it.
    pub(crate) service: Option<&'static str>,
    /// The account-SAS resource type (`s`, `c`, `o`) and any of its permission letters.
    pub(crate) account: Option<(char, &'static str)>,
    pub(crate) public: Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Public {
    Never,
    /// Allowed when the container is public at `blob` or `container` level.
    Blob,
    /// Allowed only when the container is public at `container` level.
    Container,
}

/// The resource a request addresses, as the string-to-sign needs it.
pub(crate) struct Resource<'a> {
    pub(crate) account: &'a AccountName,
    pub(crate) container: Option<&'a str>,
    pub(crate) blob: Option<&'a str>,
}

/// Facts about the connection the token is presented on.
pub(crate) struct Connection {
    pub(crate) now: SystemTime,
    pub(crate) client_ip: Option<IpAddr>,
    pub(crate) https: bool,
}

impl Token {
    /// Parses and signature-checks a SAS. The time window, permissions, source
    /// address, and protocol are checked later by [`Token::authorize`], once
    /// any stored access policy has been loaded. A user-delegation SAS (`skoid`)
    /// is signed with a key issued by Get User Delegation Key rather than an account key.
    pub(crate) fn verify(
        query: &Query,
        resource: &Resource<'_>,
        keys: &[Vec<u8>],
        delegation: &Keys,
    ) -> Result<Option<Self>> {
        let Some(sas) = Sas::from_query(query)? else {
            return Ok(None);
        };
        if !sas.has("sv") {
            return Err(Error::AuthenticationFailed);
        }
        let version = sas.field("sv");
        if version < "2015-04-05" {
            return Err(Error::AuthenticationFailed);
        }
        let delegated = sas.has("skoid") || sas.has("sktid");
        let (kind, string_to_sign) = if sas.has("ss") && sas.has("srt") {
            if delegated {
                return Err(Error::AuthenticationFailed);
            }
            (Kind::Account, account_string(&sas, resource.account))
        } else {
            let scope = match sas.field("sr") {
                "b" => Scope::Blob,
                "c" => Scope::Container,
                "d" if version >= "2020-02-10" => Scope::Directory,
                "bs" | "bv" if version >= "2018-11-09" => Scope::Blob,
                _ if version < "2018-11-09" => {
                    if resource.blob.is_some() {
                        Scope::Blob
                    } else {
                        Scope::Container
                    }
                }
                _ => return Err(Error::AuthenticationFailed),
            };
            let container = resource.container.ok_or(Error::ResourceTypeMismatch)?;
            if scope != Scope::Container && resource.blob.is_none() {
                return Err(Error::ResourceTypeMismatch);
            }
            // A snapshot or version SAS is signed over the timestamp it names.
            let snapshot = match sas.field("sr") {
                "bs" => Some("snapshot"),
                "bv" => Some("versionid"),
                _ => None,
            }
            .map(|name| query.get(name).ok_or(Error::AuthenticationFailed))
            .transpose()?
            .map_or("", String::as_str);
            let canonical = match (scope, resource.blob) {
                (Scope::Blob, Some(blob)) => {
                    format!("/blob/{}/{container}/{blob}", resource.account.as_str())
                }
                (Scope::Directory, Some(blob)) => {
                    let directory = signed_directory(blob, sas.field("sdd"))?;
                    format!(
                        "/blob/{}/{container}/{directory}",
                        resource.account.as_str()
                    )
                }
                _ => format!("/blob/{}/{container}", resource.account.as_str()),
            };
            if delegated {
                if sas.has("si") || sas.field("sks") != "b" || sas.field("skv") < "2018-11-09" {
                    return Err(Error::AuthenticationFailed);
                }
                if ["sduoid", "skdutid", "srh", "srq"]
                    .iter()
                    .any(|name| sas.has(name))
                {
                    return Err(Error::Unsupported);
                }
                (
                    Kind::Service { identifier: None },
                    delegation::string_to_sign(&sas, &canonical, snapshot),
                )
            } else {
                let identifier = sas.has("si").then(|| sas.field("si").to_owned());
                (
                    Kind::Service { identifier },
                    service_string(&sas, &canonical, snapshot),
                )
            }
        };
        let key_window = if delegated {
            let (key, window) = delegation.find(resource.account, &sas)?;
            sas.verify(&[key], &string_to_sign)?;
            Some(window)
        } else {
            sas.verify(keys, &string_to_sign)?;
            None
        };
        let overrides = if matches!(kind, Kind::Service { .. }) {
            let field = |name| sas.has(name).then(|| sas.field(name).to_owned());
            Overrides {
                cache_control: field("rscc"),
                disposition: field("rscd"),
                encoding: field("rsce"),
                language: field("rscl"),
                content_type: field("rsct"),
            }
        } else {
            Overrides::default()
        };
        Ok(Some(Self {
            kind,
            sas,
            overrides,
            key_window,
        }))
    }

    pub(crate) fn identifier(&self) -> Option<&str> {
        match &self.kind {
            Kind::Service { identifier, .. } => identifier.as_deref(),
            Kind::Account => None,
        }
    }

    /// The object id of the user whose delegation key signed the token, if it is a
    /// user-delegation SAS.
    pub(crate) fn delegated_oid(&self) -> Option<&str> {
        self.key_window.map(|_| self.sas.field("skoid"))
    }

    /// Checks window, permissions, resource type, source address, and protocol.
    pub(crate) fn authorize(
        &self,
        need: &Need,
        policy: Option<&SignedIdentifier>,
        connection: &Connection,
    ) -> Result<()> {
        let (start, expiry, permissions) = match (self.identifier(), policy) {
            (Some(_), None) => return Err(Error::AuthenticationFailed),
            (Some(_), Some(policy)) => {
                let time = |sent: Option<SystemTime>, stored: &Option<String>| match sent {
                    Some(time) => Ok(Some(time)),
                    None => stored.as_deref().map(sas::parse_time).transpose(),
                };
                let permissions = if self.sas.has("sp") {
                    self.sas.field("sp")
                } else {
                    policy.permission.as_deref().unwrap_or_default()
                };
                (
                    time(self.sas.start(), &policy.start)?,
                    time(self.sas.expiry(), &policy.expiry)?,
                    permissions,
                )
            }
            (None, _) => (self.sas.start(), self.sas.expiry(), self.sas.field("sp")),
        };
        sas::check_window(start, expiry, connection.now)?;
        if let Some((key_start, key_expiry)) = self.key_window {
            sas::check_window(Some(key_start), Some(key_expiry), connection.now)?;
        }
        let grants =
            |any: &str| any == "*" || any.chars().any(|letter| permissions.contains(letter));
        match &self.kind {
            Kind::Account => {
                if !self.sas.field("ss").contains('b') {
                    return Err(Error::ServiceMismatch);
                }
                let (resource, any) = need.account.ok_or(Error::PermissionMismatch)?;
                if resource != '*' && !self.sas.field("srt").contains(resource) {
                    return Err(Error::ResourceTypeMismatch);
                }
                if !grants(any) {
                    return Err(Error::PermissionMismatch);
                }
            }
            Kind::Service { .. } => {
                let any = need.service.ok_or(Error::ResourceTypeMismatch)?;
                if !grants(any) {
                    return Err(Error::PermissionMismatch);
                }
            }
        }
        self.check_connection(connection)
    }

    fn check_connection(&self, connection: &Connection) -> Result<()> {
        match self.sas.field("spr") {
            "https" if !connection.https => return Err(Error::ProtocolMismatch),
            "" | "https" | "https,http" | "http,https" => (),
            _ => return Err(Error::AuthenticationFailed),
        }
        let range = self.sas.field("sip");
        if !range.is_empty()
            && let Some(client) = connection.client_ip
            && !ip_in_range(range, client)
        {
            return Err(Error::SourceIpMismatch);
        }
        Ok(())
    }
}

/// The directory a directory SAS signs: the first `sdd` components of the requested path.
fn signed_directory(path: &str, depth: &str) -> Result<String> {
    let depth: usize = depth.parse().map_err(|_| Error::AuthenticationFailed)?;
    let parts: Vec<&str> = path.split('/').take(depth).collect();
    if parts.len() < depth {
        return Err(Error::AuthenticationFailed);
    }
    Ok(parts.join("/"))
}

fn ip_in_range(range: &str, client: IpAddr) -> bool {
    let parse = |text: &str| text.parse::<IpAddr>().ok();
    match range.split_once('-') {
        Some((low, high)) => match (parse(low), parse(high)) {
            (Some(low), Some(high)) => match (low, high, client) {
                (IpAddr::V4(low), IpAddr::V4(high), IpAddr::V4(client)) => {
                    (u32::from(low)..=u32::from(high)).contains(&u32::from(client))
                }
                (IpAddr::V6(low), IpAddr::V6(high), IpAddr::V6(client)) => {
                    (u128::from(low)..=u128::from(high)).contains(&u128::from(client))
                }
                _ => false,
            },
            _ => false,
        },
        None => parse(range) == Some(client),
    }
}

/// Account SAS string-to-sign. Version 2020-12-06 added the encryption scope.
fn account_string(sas: &Sas, account: &AccountName) -> String {
    let mut fields = vec![
        account.as_str(),
        sas.field("sp"),
        sas.field("ss"),
        sas.field("srt"),
        sas.field("st"),
        sas.field("se"),
        sas.field("sip"),
        sas.field("spr"),
        sas.field("sv"),
    ];
    if sas.field("sv") >= "2020-12-06" {
        fields.push(sas.field("ses"));
    }
    let mut text = fields.join("\n");
    text.push('\n');
    text
}

/// Service SAS string-to-sign. Version 2018-11-09 added the resource and
/// snapshot time; 2020-12-06 added the encryption scope.
fn service_string(sas: &Sas, canonical: &str, snapshot: &str) -> String {
    let version = sas.field("sv");
    let mut fields = vec![
        sas.field("sp"),
        sas.field("st"),
        sas.field("se"),
        canonical,
        sas.field("si"),
        sas.field("sip"),
        sas.field("spr"),
        version,
    ];
    if version >= "2018-11-09" {
        fields.push(sas.field("sr"));
        fields.push(snapshot);
    }
    if version >= "2020-12-06" {
        fields.push(sas.field("ses"));
    }
    fields.extend(["rscc", "rscd", "rsce", "rscl", "rsct"].map(|name| sas.field(name)));
    fields.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::Principal;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    const KEY: [u8; 32] = [7; 32];

    fn hmac(key: &[u8], text: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(text.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    fn sign(text: &str) -> String {
        hmac(&KEY, text)
    }

    fn query(pairs: &[(&str, &str)], signed: &str) -> Query {
        let mut query: Query = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        query.insert("sig".into(), sign(signed));
        query
    }

    fn account() -> AccountName {
        AccountName::parse("testaccount").unwrap()
    }

    #[test]
    fn service_sas_string_follows_the_documented_field_order() {
        let pairs = [
            ("sv", "2023-11-03"),
            ("sr", "b"),
            ("sp", "r"),
            ("se", "2030-01-01T00:00:00Z"),
            ("rsct", "text/plain"),
        ];
        let expected = "r\n\n2030-01-01T00:00:00Z\n/blob/testaccount/box/dir/a.txt\n\n\n\n2023-11-03\nb\n\n\n\n\n\n\ntext/plain";
        let query = query(&pairs, expected);
        let resource = Resource {
            account: &account(),
            container: Some("box"),
            blob: Some("dir/a.txt"),
        };
        let token = Token::verify(&query, &resource, &[KEY.to_vec()], &Keys::default())
            .unwrap()
            .unwrap();
        assert_eq!(token.overrides.content_type.as_deref(), Some("text/plain"));
        let tampered = Resource {
            blob: Some("dir/other.txt"),
            ..resource
        };
        assert!(Token::verify(&query, &tampered, &[KEY.to_vec()], &Keys::default()).is_err());
    }

    #[test]
    fn earlier_signed_versions_omit_newer_fields() {
        let sas = |version: &'static str| {
            Sas::from_query(&Query::from([
                ("sv".into(), version.into()),
                ("sig".into(), "x".into()),
                ("sp".into(), "r".into()),
                ("sr".into(), "c".into()),
            ]))
            .unwrap()
            .unwrap()
        };
        let lines = |version| {
            service_string(&sas(version), "/blob/a/c", "")
                .split('\n')
                .count()
        };
        assert_eq!(lines("2023-11-03"), 16);
        assert_eq!(lines("2019-12-12"), 15);
        assert_eq!(lines("2016-05-31"), 13);
        let account_lines = |version| {
            account_string(&sas(version), &account())
                .split('\n')
                .count()
        };
        assert_eq!(account_lines("2023-11-03"), 11);
        assert_eq!(account_lines("2019-12-12"), 10);
    }

    #[test]
    fn account_sas_requires_service_resource_type_and_permission() {
        let signed = "testaccount\nrw\nb\nco\n\n2030-01-01T00:00:00Z\n\n\n2023-11-03\n\n";
        let pairs = [
            ("sv", "2023-11-03"),
            ("ss", "b"),
            ("srt", "co"),
            ("sp", "rw"),
            ("se", "2030-01-01T00:00:00Z"),
        ];
        let query = query(&pairs, signed);
        let resource = Resource {
            account: &account(),
            container: None,
            blob: None,
        };
        let token = Token::verify(&query, &resource, &[KEY.to_vec()], &Keys::default())
            .unwrap()
            .unwrap();
        let now = sas::parse_time("2029-01-01").unwrap();
        let connection = Connection {
            now,
            client_ip: None,
            https: false,
        };
        let need = |resource, any| Need {
            service: None,
            account: Some((resource, any)),
            public: Public::Never,
        };
        assert_eq!(token.authorize(&need('o', "w"), None, &connection), Ok(()));
        assert_eq!(
            token.authorize(&need('o', "d"), None, &connection),
            Err(Error::PermissionMismatch)
        );
        assert_eq!(
            token.authorize(&need('s', "w"), None, &connection),
            Err(Error::ResourceTypeMismatch)
        );
        let late = Connection {
            now: sas::parse_time("2031-01-01").unwrap(),
            ..connection
        };
        assert_eq!(
            token.authorize(&need('o', "w"), None, &late),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn a_directory_sas_signs_the_first_sdd_components_of_the_requested_path() {
        assert_eq!(signed_directory("a/b/c.txt", "2").as_deref(), Ok("a/b"));
        assert_eq!(signed_directory("a/b", "2").as_deref(), Ok("a/b"));
        assert_eq!(signed_directory("a", "2"), Err(Error::AuthenticationFailed));
        assert_eq!(signed_directory("a", "x"), Err(Error::AuthenticationFailed));
        let pairs = [
            ("sv", "2023-11-03"),
            ("sr", "d"),
            ("sdd", "1"),
            ("sp", "rl"),
            ("se", "2030-01-01T00:00:00Z"),
        ];
        let signed = "rl\n\n2030-01-01T00:00:00Z\n/blob/testaccount/box/dir\n\n\n\n2023-11-03\nd\n\n\n\n\n\n\n";
        let query = query(&pairs, signed);
        let account = account();
        let resource = |blob| Resource {
            account: &account,
            container: Some("box"),
            blob: Some(blob),
        };
        for blob in ["dir", "dir/nested/file.txt"] {
            assert!(
                Token::verify(&query, &resource(blob), &[KEY.to_vec()], &Keys::default())
                    .unwrap()
                    .is_some(),
                "{blob}"
            );
        }
        assert!(
            Token::verify(
                &query,
                &resource("other/file"),
                &[KEY.to_vec()],
                &Keys::default()
            )
            .is_err()
        );
    }

    #[test]
    fn source_address_and_protocol_are_enforced() {
        let range = |text, ip: &str| ip_in_range(text, ip.parse().unwrap());
        assert!(range("10.0.0.1", "10.0.0.1"));
        assert!(!range("10.0.0.1", "10.0.0.2"));
        assert!(range("10.0.0.1-10.0.0.9", "10.0.0.5"));
        assert!(!range("10.0.0.1-10.0.0.9", "10.0.0.10"));
        assert!(!range("10.0.0.1-::1", "10.0.0.5"));
    }

    #[test]
    fn user_delegation_sas_needs_an_issued_key_inside_its_lifetime() {
        let keys = Keys::default();
        let (start, expiry) = (
            sas::parse_time("2029-01-01T00:00:00Z").unwrap(),
            sas::parse_time("2029-01-02T00:00:00Z").unwrap(),
        );
        let issued = keys
            .issue(&account(), &Principal::default(), (start, expiry), start)
            .unwrap();
        let (oid, tid) = (issued.oid.as_str(), issued.tid.as_str());
        let signed = format!(
            "r\n\n2029-01-01T12:00:00Z\n/blob/testaccount/box/a.txt\n{oid}\n{tid}\n2029-01-01T00:00:00Z\n2029-01-02T00:00:00Z\nb\n2023-11-03\n\n\n\n\n\n2023-11-03\nb\n\n\n\n\n\n\n"
        );
        let mut query: Query = [
            ("sv", "2023-11-03"),
            ("sr", "b"),
            ("sp", "r"),
            ("se", "2029-01-01T12:00:00Z"),
            ("skoid", oid),
            ("sktid", tid),
            ("skt", "2029-01-01T00:00:00Z"),
            ("ske", "2029-01-02T00:00:00Z"),
            ("sks", "b"),
            ("skv", "2023-11-03"),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
        query.insert("sig".into(), hmac(&issued.value, &signed));
        let resource = Resource {
            account: &account(),
            container: Some("box"),
            blob: Some("a.txt"),
        };
        let token = Token::verify(&query, &resource, &[KEY.to_vec()], &keys)
            .unwrap()
            .unwrap();
        let need = Need {
            service: Some("r"),
            account: None,
            public: Public::Never,
        };
        let connection = |now| Connection {
            now: sas::parse_time(now).unwrap(),
            client_ip: None,
            https: true,
        };
        assert_eq!(
            token.authorize(&need, None, &connection("2029-01-01T06:00:00Z")),
            Ok(())
        );
        // The SAS window ends at 12:00 even though the key lives on.
        assert!(
            token
                .authorize(&need, None, &connection("2029-01-01T13:00:00Z"))
                .is_err()
        );
        let write = Need {
            service: Some("w"),
            ..need
        };
        assert_eq!(
            token.authorize(&write, None, &connection("2029-01-01T06:00:00Z")),
            Err(Error::PermissionMismatch)
        );

        let verify = |query: &Query, keys: &Keys| {
            Token::verify(query, &resource, &[KEY.to_vec()], keys).err()
        };
        assert_eq!(
            verify(&query, &Keys::default()),
            Some(Error::AuthenticationFailed)
        );
        let mut other_oid = query.clone();
        other_oid.insert("skoid".into(), "someone-else".into());
        assert_eq!(verify(&other_oid, &keys), Some(Error::AuthenticationFailed));
        let mut forged = query.clone();
        forged.insert("sp".into(), "rw".into());
        assert_eq!(verify(&forged, &keys), Some(Error::AuthenticationFailed));
        let mut policy = query.clone();
        policy.insert("si".into(), "policy".into());
        assert_eq!(verify(&policy, &keys), Some(Error::AuthenticationFailed));
        let mut not_blob_service = query.clone();
        not_blob_service.insert("sks".into(), "q".into());
        assert_eq!(
            verify(&not_blob_service, &keys),
            Some(Error::AuthenticationFailed)
        );
        let mut account_key_signature = query.clone();
        account_key_signature.insert("sig".into(), hmac(&KEY, &signed));
        assert_eq!(
            verify(&account_key_signature, &keys),
            Some(Error::AuthenticationFailed)
        );

        // After the key's own expiry the SAS fails even though its window has not ended.
        let late = Token::verify(&query, &resource, &[], &keys)
            .unwrap()
            .unwrap();
        assert!(
            late.authorize(&need, None, &connection("2029-01-02T00:00:00Z"))
                .is_err()
        );
    }

    #[test]
    fn snapshot_and_version_sas_are_signed_over_the_named_timestamp() {
        let snapshot = "2029-01-01T00:00:00.0000000Z";
        let resource = Resource {
            account: &account(),
            container: Some("box"),
            blob: Some("a.txt"),
        };
        let signed = format!(
            "r\n\n2030-01-01T00:00:00Z\n/blob/testaccount/box/a.txt\n\n\n\n2023-11-03\nbs\n{snapshot}\n\n\n\n\n\n"
        );
        let mut pairs = vec![
            ("sv", "2023-11-03"),
            ("sr", "bs"),
            ("sp", "r"),
            ("se", "2030-01-01T00:00:00Z"),
            ("snapshot", snapshot),
        ];
        let query = query(&pairs, &signed);
        assert!(
            Token::verify(&query, &resource, &[KEY.to_vec()], &Keys::default())
                .unwrap()
                .is_some()
        );
        pairs.pop();
        let missing = self::query(&pairs, &signed);
        assert_eq!(
            Token::verify(&missing, &resource, &[KEY.to_vec()], &Keys::default()).err(),
            Some(Error::AuthenticationFailed)
        );
        let mut other = query.clone();
        other.insert("snapshot".into(), "2029-01-02T00:00:00.0000000Z".into());
        assert!(Token::verify(&other, &resource, &[KEY.to_vec()], &Keys::default()).is_err());
    }
}
