use super::error::{QueueError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) type Metadata = BTreeMap<String, String>;

pub(super) const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub(super) const MAX_VISIBILITY_SECONDS: i64 = 7 * 24 * 3600;
pub(super) const MAX_METADATA_BYTES: usize = 8 * 1024;
pub(super) const MAX_POLICIES: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QueueName(String);

impl QueueName {
    pub(super) fn parse(value: &str) -> Result<Self> {
        if !(3..=63).contains(&value.len()) {
            return Err(QueueError::OutOfRangeName);
        }
        let bytes = value.as_bytes();
        let valid = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
            && !value.contains("--");
        if !valid {
            return Err(QueueError::InvalidResourceName);
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MessageId(String);

impl MessageId {
    pub(super) fn parse(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 128 {
            return Err(QueueError::InvalidUri);
        }
        Ok(Self(value))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PopReceipt(String);

impl PopReceipt {
    pub(super) fn parse(value: &str) -> Result<Self> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        if value.is_empty() || STANDARD.decode(value).is_err() {
            return Err(QueueError::InvalidQuery(
                "popreceipt",
                value.to_owned(),
                "Invalid pop receipt format",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stored message as exposed to the protocol layer; times are Unix milliseconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Message {
    pub(super) id: String,
    pub(super) inserted: i64,
    pub(super) expires: Option<i64>,
    pub(super) next_visible: i64,
    pub(super) dequeue_count: i64,
    pub(super) pop_receipt: String,
    pub(super) text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct AccessPolicy {
    pub(super) id: String,
    pub(super) start: Option<i64>,
    pub(super) expiry: Option<i64>,
    pub(super) permission: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Retention {
    pub(super) enabled: bool,
    pub(super) days: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Logging {
    pub(super) version: String,
    pub(super) read: bool,
    pub(super) write: bool,
    pub(super) delete: bool,
    pub(super) retention: Retention,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Metrics {
    pub(super) version: String,
    pub(super) enabled: bool,
    pub(super) include_apis: Option<bool>,
    pub(super) retention: Retention,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CorsRule {
    pub(super) allowed_origins: String,
    pub(super) allowed_methods: String,
    pub(super) max_age: u32,
    pub(super) exposed_headers: String,
    pub(super) allowed_headers: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ServiceProperties {
    pub(super) logging: Logging,
    pub(super) hour_metrics: Metrics,
    pub(super) minute_metrics: Metrics,
    pub(super) cors: Vec<CorsRule>,
}

impl Default for ServiceProperties {
    fn default() -> Self {
        let off = Retention {
            enabled: false,
            days: None,
        };
        Self {
            logging: Logging {
                version: "1.0".into(),
                read: false,
                write: false,
                delete: false,
                retention: off.clone(),
            },
            hour_metrics: Metrics {
                version: "1.0".into(),
                enabled: true,
                include_apis: Some(true),
                retention: Retention {
                    enabled: true,
                    days: Some(7),
                },
            },
            minute_metrics: Metrics {
                version: "1.0".into(),
                enabled: false,
                include_apis: None,
                retention: off,
            },
            cors: Vec::new(),
        }
    }
}

/// A partial Set Queue Service Properties body: omitted sections stay unchanged.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct PropertiesPatch {
    pub(super) logging: Option<Logging>,
    pub(super) hour_metrics: Option<Metrics>,
    pub(super) minute_metrics: Option<Metrics>,
    pub(super) cors: Option<Vec<CorsRule>>,
}

impl PropertiesPatch {
    pub(super) fn apply(self, properties: &mut ServiceProperties) {
        if let Some(logging) = self.logging {
            properties.logging = logging;
        }
        if let Some(metrics) = self.hour_metrics {
            properties.hour_metrics = metrics;
        }
        if let Some(metrics) = self.minute_metrics {
            properties.minute_metrics = metrics;
        }
        if let Some(cors) = self.cors {
            properties.cors = cors;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_names_follow_azure_rules() {
        assert!(QueueName::parse("my-queue-1").is_ok());
        assert_eq!(QueueName::parse("ab"), Err(QueueError::OutOfRangeName));
        assert_eq!(
            QueueName::parse(&"a".repeat(64)),
            Err(QueueError::OutOfRangeName)
        );
        for bad in ["-abc", "abc-", "a--b", "Abc", "ab_c", "ab.c"] {
            assert_eq!(
                QueueName::parse(bad),
                Err(QueueError::InvalidResourceName),
                "{bad}"
            );
        }
    }

    #[test]
    fn patch_replaces_only_present_sections() {
        let mut properties = ServiceProperties::default();
        let cors = vec![CorsRule {
            allowed_origins: "*".into(),
            allowed_methods: "GET".into(),
            max_age: 5,
            exposed_headers: String::new(),
            allowed_headers: String::new(),
        }];
        PropertiesPatch {
            cors: Some(cors.clone()),
            ..PropertiesPatch::default()
        }
        .apply(&mut properties);
        assert_eq!(properties.cors, cors);
        assert_eq!(properties.logging, ServiceProperties::default().logging);
    }
}
