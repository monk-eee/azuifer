//! Request bodies: stored access policies (XML) and share permissions (JSON).

use super::{
    error::{Error, Result},
    model::AccessPolicy,
    time,
};
use quick_xml::{Reader, events::Event};

const MAX_POLICIES: usize = 5;

/// Parses a `SignedIdentifiers` document.
pub(super) fn parse_access_policies(body: &[u8]) -> Result<Vec<AccessPolicy>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidXmlDocument)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut policies: Vec<AccessPolicy> = Vec::new();
    let mut open: Vec<String> = Vec::new();
    let mut current: Option<AccessPolicy> = None;
    let mut seen_root = false;
    loop {
        let event = reader.read_event().map_err(|_| Error::InvalidXmlDocument)?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Eof => break,
            Event::Start(tag) | Event::Empty(tag) => {
                let name = tag.name().as_ref().to_owned();
                match (open.len(), name.as_str()) {
                    (0, "SignedIdentifiers") if !seen_root => {
                        seen_root = true;
                        if empty {
                            continue;
                        }
                        open.push(name);
                    }
                    (1, "SignedIdentifier") => {
                        if policies.len() == MAX_POLICIES {
                            return Err(Error::InvalidXmlDocument);
                        }
                        current = Some(AccessPolicy {
                            id: String::new(),
                            start: None,
                            expiry: None,
                            permission: None,
                        });
                        if !empty {
                            open.push(name);
                        }
                    }
                    (2, "AccessPolicy") if !empty => open.push(name),
                    (2, "Id") | (3, "Start" | "Expiry" | "Permission") => {
                        let value = if empty {
                            String::new()
                        } else {
                            reader
                                .read_text(tag.name())
                                .map_err(|_| Error::InvalidXmlDocument)?
                                .trim()
                                .to_owned()
                        };
                        let policy = current.as_mut().ok_or(Error::InvalidXmlDocument)?;
                        match name.as_str() {
                            "Id" => policy.id = value,
                            "Start" => policy.start = Some(value).filter(|v| !v.is_empty()),
                            "Expiry" => policy.expiry = Some(value).filter(|v| !v.is_empty()),
                            _ => policy.permission = Some(value).filter(|v| !v.is_empty()),
                        }
                    }
                    _ => return Err(Error::InvalidXmlDocument),
                }
            }
            Event::End(_) => match open.pop().as_deref() {
                Some("SignedIdentifier") => {
                    let policy = current.take().ok_or(Error::InvalidXmlDocument)?;
                    validate(&policy, &policies)?;
                    policies.push(policy);
                }
                Some(_) => {}
                None => return Err(Error::InvalidXmlDocument),
            },
            _ => return Err(Error::InvalidXmlDocument),
        }
    }
    if !seen_root || !open.is_empty() {
        return Err(Error::InvalidXmlDocument);
    }
    Ok(policies)
}

fn validate(policy: &AccessPolicy, earlier: &[AccessPolicy]) -> Result<()> {
    if policy.id.is_empty()
        || policy.id.chars().count() > 64
        || earlier.iter().any(|other| other.id == policy.id)
    {
        return Err(Error::InvalidXmlDocument);
    }
    for value in [&policy.start, &policy.expiry].into_iter().flatten() {
        if time::parse_iso(value).is_none() {
            return Err(Error::InvalidXmlDocument);
        }
    }
    if let Some(permission) = &policy.permission
        && !permission.chars().all(|letter| "rcwdl".contains(letter))
    {
        return Err(Error::InvalidXmlDocument);
    }
    Ok(())
}

/// Reads the SDDL from a Create Permission body: `{"permission": "..."}`.
pub(super) fn parse_permission(body: &[u8]) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Body {
        permission: String,
    }
    serde_json::from_slice::<Body>(body)
        .map(|body| body.permission)
        .map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        <SignedIdentifiers><SignedIdentifier><Id>policy1</Id><AccessPolicy>\
        <Start>2023-01-01T00:00:00.0000000Z</Start><Expiry>2030-01-01T00:00:00Z</Expiry>\
        <Permission>rwdl</Permission></AccessPolicy></SignedIdentifier>\
        <SignedIdentifier><Id>empty</Id></SignedIdentifier></SignedIdentifiers>";

    #[test]
    fn parses_signed_identifiers() {
        let policies = parse_access_policies(DOCUMENT.as_bytes()).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].id, "policy1");
        assert_eq!(policies[0].permission.as_deref(), Some("rwdl"));
        assert_eq!(policies[1].expiry, None);
        assert!(
            parse_access_policies(b"<SignedIdentifiers/>")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_malformed_or_invalid_policies() {
        let duplicate = DOCUMENT.replace("<Id>empty</Id>", "<Id>policy1</Id>");
        for bad in [
            "",
            "<Other/>",
            "<SignedIdentifiers><Bogus/></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><Id></Id></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>x</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Expiry>soon</Expiry></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
            "<SignedIdentifiers>",
            duplicate.as_str(),
        ] {
            assert_eq!(
                parse_access_policies(bad.as_bytes()),
                Err(Error::InvalidXmlDocument),
                "{bad}"
            );
        }
        let six = format!(
            "<SignedIdentifiers>{}</SignedIdentifiers>",
            (0..6)
                .map(|n| format!("<SignedIdentifier><Id>p{n}</Id></SignedIdentifier>"))
                .collect::<String>()
        );
        assert_eq!(
            parse_access_policies(six.as_bytes()),
            Err(Error::InvalidXmlDocument)
        );
    }

    #[test]
    fn permission_body_is_json() {
        assert_eq!(
            parse_permission(br#"{"permission":"O:SYG:SYD:"}"#).unwrap(),
            "O:SYG:SYD:"
        );
        assert_eq!(parse_permission(b"nope"), Err(Error::InvalidInput));
    }
}
