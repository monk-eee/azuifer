//! Removes credentials from text before it reaches a log, span, metric, or exporter (ADR-0007).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

pub(crate) const MASK: &str = "REDACTED";

/// Query parameters and assignments whose values are credentials.
const SENSITIVE_NAMES: [&str; 8] = [
    "sig",
    "signature",
    "sas",
    "sastoken",
    "token",
    "access_token",
    "accountkey",
    "key",
];
/// Authorization schemes whose credential follows the scheme name.
const SENSITIVE_SCHEMES: [&str; 3] = ["sharedkeylite ", "sharedkey ", "bearer "];

/// Masks configured account keys and credential-shaped text.
pub(crate) struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// `keys` are raw account keys; each is masked in its Base64 and URL-encoded forms.
    pub(crate) fn new<'a>(keys: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut secrets = Vec::new();
        for key in keys.into_iter().filter(|key| !key.is_empty()) {
            let encoded = STANDARD.encode(key);
            secrets.push(utf8_percent_encode(&encoded, NON_ALPHANUMERIC).to_string());
            secrets.push(encoded);
        }
        Self { secrets }
    }

    /// Masks secrets, credential assignments such as `sig=...`, and Authorization credentials.
    pub(crate) fn text(&self, input: &str) -> String {
        let mut output = input.to_owned();
        for secret in &self.secrets {
            output = output.replace(secret, MASK);
        }
        mask_schemes(&mask_assignments(&output))
    }
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

fn is_value_end(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'&' | b'"' | b'\'' | b'>' | b'<')
}

fn mask_assignments(input: &str) -> String {
    let lower = input.to_ascii_lowercase().into_bytes();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        let at_boundary = index == 0 || !is_name_byte(bytes[index - 1]);
        let name = SENSITIVE_NAMES.iter().find(|name| {
            at_boundary
                && lower[index..].starts_with(name.as_bytes())
                && bytes.get(index + name.len()) == Some(&b'=')
        });
        let Some(name) = name else {
            index += 1;
            continue;
        };
        let value_start = index + name.len() + 1;
        let value_end = bytes[value_start..]
            .iter()
            .position(|byte| is_value_end(*byte))
            .map_or(bytes.len(), |offset| value_start + offset);
        output.push_str(&input[copied..value_start]);
        output.push_str(MASK);
        copied = value_end;
        index = value_end;
    }
    output.push_str(&input[copied..]);
    output
}

fn mask_schemes(input: &str) -> String {
    let lower = input.to_ascii_lowercase().into_bytes();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        let at_boundary = index == 0 || !bytes[index - 1].is_ascii_alphanumeric();
        let scheme = SENSITIVE_SCHEMES
            .iter()
            .find(|scheme| at_boundary && lower[index..].starts_with(scheme.as_bytes()));
        let Some(scheme) = scheme else {
            index += 1;
            continue;
        };
        let credential_start = index + scheme.len();
        let credential_end = bytes[credential_start..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\''))
            .map_or(bytes.len(), |offset| credential_start + offset);
        output.push_str(&input[copied..credential_start]);
        output.push_str(MASK);
        copied = credential_end;
        index = credential_end;
    }
    output.push_str(&input[copied..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef+/";

    fn redactor() -> Redactor {
        Redactor::new([KEY])
    }

    #[test]
    fn masks_sas_signatures_and_keeps_other_parameters() {
        let query = "sv=2023-11-03&se=2030-01-01T00%3A00%3A00Z&sp=r&sig=ab%2Bc%2F%3D&comp=list";
        assert_eq!(
            redactor().text(query),
            "sv=2023-11-03&se=2030-01-01T00%3A00%3A00Z&sp=r&sig=REDACTED&comp=list"
        );
        assert_eq!(redactor().text("SIG=abc"), "SIG=REDACTED");
        assert_eq!(
            redactor().text("design=abc&sig="),
            "design=abc&sig=REDACTED"
        );
    }

    #[test]
    fn masks_account_keys_in_every_encoding() {
        let encoded = STANDARD.encode(KEY);
        let percent = utf8_percent_encode(&encoded, NON_ALPHANUMERIC).to_string();
        let text = redactor().text(&format!("key {encoded} and {percent}"));
        assert!(
            !text.contains(&encoded) && !text.contains(&percent),
            "{text}"
        );
        assert_eq!(text, "key REDACTED and REDACTED");
    }

    #[test]
    fn masks_authorization_credentials() {
        assert_eq!(
            redactor().text("Authorization: SharedKey devstoreaccount1:c2lnbmF0dXJl rest"),
            "Authorization: SharedKey REDACTED rest"
        );
        assert_eq!(
            redactor().text("bearer eyJhbGci.payload.sig"),
            "bearer REDACTED"
        );
        assert_eq!(
            redactor().text("copy https://x/y?sv=1&sig=abc&sr=b"),
            "copy https://x/y?sv=1&sig=REDACTED&sr=b"
        );
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        assert_eq!(
            redactor().text("GET comp=list /devstoreaccount1/c"),
            "GET comp=list /devstoreaccount1/c"
        );
        assert_eq!(Redactor::new([&b""[..]]).text("abc"), "abc");
    }
}
