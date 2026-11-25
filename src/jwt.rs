//! Compact JWS parsing and RS256 verification for bearer tokens (ADR-0011).
//!
//! Only what Azure Storage bearer validation needs: split a token, read its
//! header and claims, and verify an RS256 signature against a JWK set. No other
//! algorithm is accepted, so `none` and HMAC downgrades cannot be selected by a
//! token.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;

/// Azure Entra access tokens are a few kilobytes; anything larger is not one.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum JwtError {
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
}

impl JwtError {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Malformed => "the token is not a well-formed JWT",
            Self::UnsupportedAlgorithm => "the token is not signed with RS256",
            Self::UnknownKey => "no configured key matches the token's key id",
            Self::BadSignature => "the token signature does not verify",
        }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// `aud` is a string or an array of strings.
#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(crate) enum Audience {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Audience {
    pub(crate) fn values(&self) -> &[String] {
        match self {
            Self::None => &[],
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct Claims {
    #[serde(default)]
    pub(crate) iss: Option<String>,
    #[serde(default)]
    pub(crate) aud: Audience,
    #[serde(default)]
    pub(crate) exp: Option<f64>,
    #[serde(default)]
    pub(crate) nbf: Option<f64>,
    #[serde(default)]
    pub(crate) oid: Option<String>,
    #[serde(default)]
    pub(crate) tid: Option<String>,
    #[serde(default)]
    pub(crate) roles: Option<Vec<String>>,
}

pub(crate) struct Jwt<'a> {
    header: Header,
    pub(crate) claims: Claims,
    signing_input: &'a str,
    signature: &'a str,
}

impl<'a> Jwt<'a> {
    /// Splits and decodes a compact token. The signature segment is not decoded
    /// here, so a hand-built unsigned token still parses for reduced validation.
    pub(crate) fn parse(token: &'a str) -> Result<Self, JwtError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(JwtError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(header), Some(claims), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError::Malformed);
        };
        let decode = |segment: &str| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .map_err(|_| JwtError::Malformed)
        };
        Ok(Self {
            header: serde_json::from_slice(&decode(header)?).map_err(|_| JwtError::Malformed)?,
            claims: serde_json::from_slice(&decode(claims)?).map_err(|_| JwtError::Malformed)?,
            signing_input: &token[..header.len() + 1 + claims.len()],
            signature,
        })
    }

    /// Verifies the RS256 signature with the key named by `kid`, or with any key
    /// when the token names none.
    pub(crate) fn verify(&self, keys: &KeySet) -> Result<(), JwtError> {
        if self.header.alg != "RS256" {
            return Err(JwtError::UnsupportedAlgorithm);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(self.signature)
            .map_err(|_| JwtError::Malformed)?;
        let mut candidates = keys
            .keys
            .iter()
            .filter(|key| self.header.kid.is_none() || key.kid == self.header.kid)
            .peekable();
        if candidates.peek().is_none() {
            return Err(JwtError::UnknownKey);
        }
        let verified = candidates.any(|key| {
            RsaPublicKeyComponents {
                n: &key.modulus,
                e: &key.exponent,
            }
            .verify(
                &RSA_PKCS1_2048_8192_SHA256,
                self.signing_input.as_bytes(),
                &signature,
            )
            .is_ok()
        });
        if verified {
            Ok(())
        } else {
            Err(JwtError::BadSignature)
        }
    }
}

struct Jwk {
    kid: Option<String>,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

/// The RSA signing keys of a JWKS document.
#[derive(Default)]
pub(crate) struct KeySet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

impl KeySet {
    /// Reads the RSA signature keys of a JWKS document. Other key types and
    /// encryption keys are skipped; a document without a usable key is an error.
    pub(crate) fn parse(document: &[u8]) -> Result<Self, &'static str> {
        let set: JwkSet = serde_json::from_slice(document).map_err(|_| "invalid JWKS document")?;
        let strip = |bytes: Vec<u8>| {
            let start = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len());
            bytes[start..].to_vec()
        };
        let mut keys = Vec::new();
        for raw in set.keys {
            if raw.kty != "RSA" || raw.usage.as_deref().is_some_and(|usage| usage != "sig") {
                continue;
            }
            let (Some(n), Some(e)) = (raw.n, raw.e) else {
                return Err("an RSA key in the JWKS lacks `n` or `e`");
            };
            let decode = |value: &str| {
                URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| "an RSA key in the JWKS is not base64url")
            };
            keys.push(Jwk {
                kid: raw.kid,
                modulus: strip(decode(&n)?),
                exponent: strip(decode(&e)?),
            });
        }
        if keys.is_empty() {
            return Err("the JWKS contains no RSA signature key");
        }
        Ok(Self { keys })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{RSA_PKCS1_SHA256, RsaKeyPair},
    };

    // A throwaway 2048-bit key used only by tests; it protects nothing. It is stored
    // as Base64 PKCS#8 DER so that secret scanners do not mistake it for a real key.
    const TEST_KEY: &str = include_str!("../tests/data/rs256-test-key.pk8.b64");

    pub(crate) fn test_key() -> RsaKeyPair {
        let der = base64::engine::general_purpose::STANDARD
            .decode(TEST_KEY.trim())
            .unwrap();
        RsaKeyPair::from_pkcs8(&der).unwrap()
    }

    pub(crate) fn jwks(kid: &str) -> String {
        let public = RsaPublicKeyComponents::<Vec<u8>>::from(test_key().public());
        format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"{kid}","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(public.n),
            URL_SAFE_NO_PAD.encode(public.e),
        )
    }

    pub(crate) fn sign(header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let key = test_key();
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    const HEADER: &str = r#"{"alg":"RS256","typ":"JWT","kid":"k1"}"#;
    const CLAIMS: &str =
        r#"{"iss":"https://sts.windows.net/t/","aud":["a","b"],"exp":2000000000,"oid":"o"}"#;

    #[test]
    fn rs256_signature_verifies_against_the_matching_key() {
        let token = sign(HEADER, CLAIMS);
        let jwt = Jwt::parse(&token).unwrap();
        assert_eq!(jwt.claims.aud.values(), ["a", "b"]);
        assert_eq!(jwt.claims.oid.as_deref(), Some("o"));
        let keys = KeySet::parse(jwks("k1").as_bytes()).unwrap();
        assert_eq!(jwt.verify(&keys), Ok(()));
    }

    #[test]
    fn a_tampered_payload_or_foreign_key_is_rejected() {
        let token = sign(HEADER, CLAIMS);
        let (head, rest) = token.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let forged = format!(
            "{head}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(CLAIMS.replace("\"o\"", "\"admin\""))
        );
        let keys = KeySet::parse(jwks("k1").as_bytes()).unwrap();
        assert_eq!(
            Jwt::parse(&forged).unwrap().verify(&keys),
            Err(JwtError::BadSignature)
        );
        let other = KeySet::parse(jwks("other").as_bytes()).unwrap();
        assert_eq!(
            Jwt::parse(&token).unwrap().verify(&other),
            Err(JwtError::UnknownKey)
        );
    }

    #[test]
    fn only_rs256_is_accepted() {
        let keys = KeySet::parse(jwks("k1").as_bytes()).unwrap();
        for alg in ["none", "HS256", "RS384"] {
            let token = sign(&format!(r#"{{"alg":"{alg}","kid":"k1"}}"#), CLAIMS);
            assert_eq!(
                Jwt::parse(&token).unwrap().verify(&keys),
                Err(JwtError::UnsupportedAlgorithm),
                "{alg}"
            );
        }
    }

    #[test]
    fn a_token_without_kid_tries_every_key() {
        let token = sign(r#"{"alg":"RS256"}"#, CLAIMS);
        let keys = KeySet::parse(jwks("anything").as_bytes()).unwrap();
        assert_eq!(Jwt::parse(&token).unwrap().verify(&keys), Ok(()));
    }

    #[test]
    fn malformed_tokens_do_not_parse() {
        for token in [
            "",
            "a.b",
            "a.b.c.d",
            "!!.!!.!!",
            &"x".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert!(Jwt::parse(token).is_err(), "{token:.20}");
        }
        let not_json = URL_SAFE_NO_PAD.encode("nope");
        assert!(Jwt::parse(&format!("{not_json}.{not_json}.")).is_err());
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(CLAIMS)
        );
        assert!(Jwt::parse(&unsigned).is_ok());
    }

    #[test]
    fn jwks_keeps_only_rsa_signature_keys() {
        let document = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"},
            {"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"}]}"#;
        assert!(KeySet::parse(document.as_bytes()).is_err());
        assert!(KeySet::parse(b"{}").is_err());
        assert!(KeySet::parse(br#"{"keys":[{"kty":"RSA","n":"AQAB"}]}"#).is_err());
    }
}
