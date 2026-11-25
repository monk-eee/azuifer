//! Parsing of a container ACL request body: up to five stored access policies.

use crate::{
    domain::{Error, Result, SignedIdentifier},
    sas::parse_time,
    xml_tree,
};

const MAX_IDENTIFIERS: usize = 5;
const MAX_ID_LENGTH: usize = 64;
const PERMISSIONS: &str = "racwdxyltfmeop";

pub(crate) fn parse(body: &[u8]) -> Result<Vec<SignedIdentifier>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let root = xml_tree::parse(body)?;
    if root.name != "SignedIdentifiers" {
        return Err(Error::InvalidXml);
    }
    let identifiers =
        root.named("SignedIdentifier")
            .map(|node| {
                let id = node.text_of("Id").ok_or(Error::InvalidXml)?;
                if id.is_empty() || id.chars().count() > MAX_ID_LENGTH {
                    return Err(Error::InvalidXml);
                }
                let policy = node.child("AccessPolicy");
                let field = |name: &str| {
                    policy
                        .and_then(|policy| policy.text_of(name))
                        .map(str::to_owned)
                };
                let (start, expiry, permission) =
                    (field("Start"), field("Expiry"), field("Permission"));
                for time in [&start, &expiry].into_iter().flatten() {
                    parse_time(time).map_err(|_| Error::InvalidXml)?;
                }
                if permission.as_deref().is_some_and(|letters| {
                    letters.chars().any(|letter| !PERMISSIONS.contains(letter))
                }) {
                    return Err(Error::InvalidXml);
                }
                Ok(SignedIdentifier {
                    id: id.to_owned(),
                    start,
                    expiry,
                    permission,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    let mut ids: Vec<&str> = identifiers
        .iter()
        .map(|policy| policy.id.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if identifiers.len() > MAX_IDENTIFIERS || ids.len() != identifiers.len() {
        return Err(Error::InvalidXml);
    }
    Ok(identifiers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_round_trip_and_are_validated() {
        let xml = b"<?xml version=\"1.0\"?><SignedIdentifiers><SignedIdentifier><Id>read-only</Id><AccessPolicy><Start>2023-01-01T00:00:00Z</Start><Expiry>2030-01-01T00:00:00Z</Expiry><Permission>rl</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
        let parsed = parse(xml).unwrap();
        assert_eq!(parsed[0].id, "read-only");
        assert_eq!(parsed[0].permission.as_deref(), Some("rl"));
        assert!(parse(b"<SignedIdentifiers/>").unwrap().is_empty());
        assert!(parse(b"").unwrap().is_empty());
        let bad_time = "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Expiry>soon</Expiry></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
        let bad_permission = "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>z</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
        let duplicate = "<SignedIdentifiers><SignedIdentifier><Id>a</Id></SignedIdentifier><SignedIdentifier><Id>a</Id></SignedIdentifier></SignedIdentifiers>";
        let many = format!(
            "<SignedIdentifiers>{}</SignedIdentifiers>",
            (0..6)
                .map(|n| format!("<SignedIdentifier><Id>{n}</Id></SignedIdentifier>"))
                .collect::<String>()
        );
        for bad in [bad_time, bad_permission, duplicate, &many, "<Other/>"] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
