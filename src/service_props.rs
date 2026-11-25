//! Blob service properties (ADR-0019): stored per account, returned on request,
//! and used by the HTTP edge for CORS. Settings a local emulator cannot honor,
//! such as metrics collection and retention, are accepted and stored only.

use crate::{
    domain::{Error, Result, xml_safe},
    wire::Xml,
    xml_tree::{self, Node},
};
use serde::{Deserialize, Serialize};

const MAX_CORS_RULES: usize = 5;
const METHODS: [&str; 8] = [
    "DELETE", "GET", "HEAD", "MERGE", "POST", "OPTIONS", "PUT", "PATCH",
];

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Retention {
    pub(crate) enabled: bool,
    pub(crate) days: Option<u32>,
    pub(crate) allow_permanent_delete: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Logging {
    pub(crate) version: String,
    pub(crate) delete: bool,
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) retention: Retention,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Metrics {
    pub(crate) version: String,
    pub(crate) enabled: bool,
    pub(crate) include_apis: Option<bool>,
    pub(crate) retention: Retention,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CorsRule {
    pub(crate) allowed_origins: String,
    pub(crate) allowed_methods: String,
    pub(crate) allowed_headers: String,
    pub(crate) exposed_headers: String,
    pub(crate) max_age_seconds: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct StaticWebsite {
    pub(crate) enabled: bool,
    pub(crate) index_document: Option<String>,
    pub(crate) error_document404_path: Option<String>,
    pub(crate) default_index_document_path: Option<String>,
}

/// Each field is `None` when the account never set it (or, in an update, when
/// the request leaves it unchanged).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ServiceProperties {
    pub(crate) logging: Option<Logging>,
    pub(crate) hour_metrics: Option<Metrics>,
    pub(crate) minute_metrics: Option<Metrics>,
    pub(crate) cors: Option<Vec<CorsRule>>,
    pub(crate) default_service_version: Option<String>,
    pub(crate) delete_retention: Option<Retention>,
    pub(crate) static_website: Option<StaticWebsite>,
}

impl ServiceProperties {
    /// What a new account reports before anything is set.
    pub(crate) fn defaults() -> Self {
        let off = Retention::default();
        Self {
            logging: Some(Logging {
                version: "1.0".into(),
                retention: off.clone(),
                ..Logging::default()
            }),
            hour_metrics: Some(Metrics {
                version: "1.0".into(),
                enabled: true,
                include_apis: Some(true),
                retention: Retention {
                    enabled: true,
                    days: Some(7),
                    allow_permanent_delete: None,
                },
            }),
            minute_metrics: Some(Metrics {
                version: "1.0".into(),
                retention: off.clone(),
                ..Metrics::default()
            }),
            cors: Some(Vec::new()),
            default_service_version: None,
            delete_retention: Some(off),
            static_website: Some(StaticWebsite::default()),
        }
    }

    /// Applies an update: only the elements present in it replace stored ones.
    pub(crate) fn merged(self, update: Self) -> Self {
        Self {
            logging: update.logging.or(self.logging),
            hour_metrics: update.hour_metrics.or(self.hour_metrics),
            minute_metrics: update.minute_metrics.or(self.minute_metrics),
            cors: update.cors.or(self.cors),
            default_service_version: update
                .default_service_version
                .or(self.default_service_version),
            delete_retention: update.delete_retention.or(self.delete_retention),
            static_website: update.static_website.or(self.static_website),
        }
    }

    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let root = xml_tree::parse(body)?;
        if root.name != "StorageServiceProperties" {
            return Err(Error::InvalidXml);
        }
        let properties = Self {
            logging: root.child("Logging").map(parse_logging).transpose()?,
            hour_metrics: root.child("HourMetrics").map(parse_metrics).transpose()?,
            minute_metrics: root.child("MinuteMetrics").map(parse_metrics).transpose()?,
            cors: root.child("Cors").map(parse_cors).transpose()?,
            default_service_version: root.text_of("DefaultServiceVersion").map(str::to_owned),
            delete_retention: root
                .child("DeleteRetentionPolicy")
                .map(parse_retention)
                .transpose()?,
            static_website: root.child("StaticWebsite").map(parse_website).transpose()?,
        };
        if properties
            .default_service_version
            .as_deref()
            .is_some_and(|version| crate::domain::ApiVersion::parse(version).is_err())
        {
            return Err(Error::InvalidXml);
        }
        Ok(properties)
    }

    pub(crate) fn to_xml(&self) -> Xml {
        let mut xml = Xml::root("StorageServiceProperties", &[]);
        if let Some(logging) = &self.logging {
            xml.open("Logging");
            xml.element("Version", &logging.version);
            for (name, value) in [
                ("Delete", logging.delete),
                ("Read", logging.read),
                ("Write", logging.write),
            ] {
                xml.element(name, bool_text(value));
            }
            write_retention(&mut xml, "RetentionPolicy", &logging.retention);
            xml.close("Logging");
        }
        for (tag, metrics) in [
            ("HourMetrics", &self.hour_metrics),
            ("MinuteMetrics", &self.minute_metrics),
        ] {
            if let Some(metrics) = metrics {
                xml.open(tag);
                xml.element("Version", &metrics.version);
                xml.element("Enabled", bool_text(metrics.enabled));
                if let Some(include) = metrics.include_apis {
                    xml.element("IncludeAPIs", bool_text(include));
                }
                write_retention(&mut xml, "RetentionPolicy", &metrics.retention);
                xml.close(tag);
            }
        }
        if let Some(rules) = &self.cors {
            xml.open("Cors");
            for rule in rules {
                xml.open("CorsRule");
                xml.element("AllowedOrigins", &rule.allowed_origins);
                xml.element("AllowedMethods", &rule.allowed_methods);
                xml.element("MaxAgeInSeconds", &rule.max_age_seconds.to_string());
                xml.element("ExposedHeaders", &rule.exposed_headers);
                xml.element("AllowedHeaders", &rule.allowed_headers);
                xml.close("CorsRule");
            }
            xml.close("Cors");
        }
        if let Some(version) = &self.default_service_version {
            xml.element("DefaultServiceVersion", version);
        }
        if let Some(retention) = &self.delete_retention {
            write_retention(&mut xml, "DeleteRetentionPolicy", retention);
        }
        if let Some(site) = &self.static_website {
            xml.open("StaticWebsite");
            xml.element("Enabled", bool_text(site.enabled));
            for (tag, value) in [
                ("IndexDocument", &site.index_document),
                ("ErrorDocument404Path", &site.error_document404_path),
                (
                    "DefaultIndexDocumentPath",
                    &site.default_index_document_path,
                ),
            ] {
                if let Some(value) = value {
                    xml.element(tag, value);
                }
            }
            xml.close("StaticWebsite");
        }
        xml
    }
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn write_retention(xml: &mut Xml, tag: &str, retention: &Retention) {
    xml.open(tag);
    xml.element("Enabled", bool_text(retention.enabled));
    if let Some(days) = retention.days {
        xml.element("Days", &days.to_string());
    }
    if let Some(allow) = retention.allow_permanent_delete {
        xml.element("AllowPermanentDelete", bool_text(allow));
    }
    xml.close(tag);
}

fn parse_retention(node: &Node) -> Result<Retention> {
    let enabled = node.flag("Enabled")?.ok_or(Error::InvalidXml)?;
    let days = node.number("Days")?;
    if days.is_some_and(|days| !(1..=365).contains(&days)) || enabled && days.is_none() {
        return Err(Error::InvalidXml);
    }
    Ok(Retention {
        enabled,
        days,
        allow_permanent_delete: node.flag("AllowPermanentDelete")?,
    })
}

fn parse_logging(node: &Node) -> Result<Logging> {
    Ok(Logging {
        version: node.text_of("Version").ok_or(Error::InvalidXml)?.to_owned(),
        delete: node.flag("Delete")?.ok_or(Error::InvalidXml)?,
        read: node.flag("Read")?.ok_or(Error::InvalidXml)?,
        write: node.flag("Write")?.ok_or(Error::InvalidXml)?,
        retention: node
            .child("RetentionPolicy")
            .map(parse_retention)
            .transpose()?
            .ok_or(Error::InvalidXml)?,
    })
}

fn parse_metrics(node: &Node) -> Result<Metrics> {
    let enabled = node.flag("Enabled")?.ok_or(Error::InvalidXml)?;
    let include_apis = node.flag("IncludeAPIs")?;
    if enabled && include_apis.is_none() {
        return Err(Error::InvalidXml);
    }
    Ok(Metrics {
        version: node.text_of("Version").ok_or(Error::InvalidXml)?.to_owned(),
        enabled,
        include_apis,
        retention: node
            .child("RetentionPolicy")
            .map(parse_retention)
            .transpose()?
            .unwrap_or_default(),
    })
}

fn items(text: &str) -> Vec<&str> {
    text.split(',').map(str::trim).collect()
}

fn parse_cors(node: &Node) -> Result<Vec<CorsRule>> {
    let rules = node
        .named("CorsRule")
        .map(|rule| {
            let origins = rule.text_of("AllowedOrigins").ok_or(Error::InvalidXml)?;
            let methods = rule.text_of("AllowedMethods").ok_or(Error::InvalidXml)?;
            let max_age = rule.number("MaxAgeInSeconds")?.ok_or(Error::InvalidXml)?;
            let origin_list = items(origins);
            if origins.is_empty()
                || origin_list.len() > 64
                || origin_list.iter().any(|origin| origin.is_empty())
                || items(methods)
                    .iter()
                    .any(|method| !METHODS.contains(&method.to_ascii_uppercase().as_str()))
                || max_age > 2_147_483_647
            {
                return Err(Error::InvalidXml);
            }
            let allowed_headers = rule.text_of("AllowedHeaders").unwrap_or_default();
            let exposed_headers = rule.text_of("ExposedHeaders").unwrap_or_default();
            if ![origins, methods, allowed_headers, exposed_headers]
                .iter()
                .all(|text| xml_safe(text))
            {
                return Err(Error::InvalidXml);
            }
            Ok(CorsRule {
                allowed_origins: origins.to_owned(),
                allowed_methods: methods.to_ascii_uppercase(),
                allowed_headers: allowed_headers.to_owned(),
                exposed_headers: exposed_headers.to_owned(),
                max_age_seconds: max_age,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if rules.len() > MAX_CORS_RULES {
        return Err(Error::InvalidXml);
    }
    Ok(rules)
}

fn parse_website(node: &Node) -> Result<StaticWebsite> {
    let text = |name| node.text_of(name).map(str::to_owned);
    Ok(StaticWebsite {
        enabled: node.flag("Enabled")?.ok_or(Error::InvalidXml)?,
        index_document: text("IndexDocument"),
        error_document404_path: text("ErrorDocument404Path"),
        default_index_document_path: text("DefaultIndexDocumentPath"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &[u8] = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><StorageServiceProperties>\
        <Logging><Version>1.0</Version><Delete>true</Delete><Read>false</Read><Write>true</Write>\
        <RetentionPolicy><Enabled>true</Enabled><Days>5</Days></RetentionPolicy></Logging>\
        <Cors><CorsRule><AllowedOrigins>https://a.test,https://b.test</AllowedOrigins>\
        <AllowedMethods>get,PUT</AllowedMethods><MaxAgeInSeconds>60</MaxAgeInSeconds>\
        <ExposedHeaders>x-ms-*</ExposedHeaders><AllowedHeaders>x-ms-meta-*</AllowedHeaders></CorsRule></Cors>\
        <DefaultServiceVersion>2023-11-03</DefaultServiceVersion></StorageServiceProperties>";

    #[test]
    fn updates_replace_only_the_elements_they_contain() {
        let update = ServiceProperties::parse(DOCUMENT).unwrap();
        assert_eq!(update.hour_metrics, None);
        let merged = ServiceProperties::defaults().merged(update);
        assert!(merged.logging.as_ref().unwrap().delete);
        assert!(
            merged.hour_metrics.as_ref().unwrap().enabled,
            "default kept"
        );
        let rule = &merged.cors.as_ref().unwrap()[0];
        assert_eq!(rule.allowed_methods, "GET,PUT");
        let xml = merged
            .to_xml()
            .finish("StorageServiceProperties", axum::http::StatusCode::OK);
        assert_eq!(xml.status(), 200);
    }

    #[test]
    fn invalid_settings_are_rejected() {
        for bad in [
            "<Wrong/>",
            "<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>TRACE</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds></CorsRule></Cors></StorageServiceProperties>",
            "<StorageServiceProperties><DefaultServiceVersion>soon</DefaultServiceVersion></StorageServiceProperties>",
            "<StorageServiceProperties><HourMetrics><Version>1.0</Version><Enabled>true</Enabled></HourMetrics></StorageServiceProperties>",
        ] {
            assert!(ServiceProperties::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        let too_many = format!(
            "<StorageServiceProperties><Cors>{}</Cors></StorageServiceProperties>",
            "<CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>GET</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds></CorsRule>".repeat(6)
        );
        assert!(ServiceProperties::parse(too_many.as_bytes()).is_err());
    }
}
