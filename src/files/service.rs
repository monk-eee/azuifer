//! Get and Set File Service Properties: metrics, CORS and SMB multichannel are validated and
//! stored per account and returned on request; a local emulator collects no metrics and
//! serves no SMB, so the settings are not acted on.

use super::{
    error::{Error, Result},
    store::{Store, db_error},
};
use crate::{
    domain::AccountName,
    service_props::{self, CorsRule, Metrics, Retention},
    wire::Xml,
    xml_tree,
};
use axum::{http::StatusCode, response::Response};
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS service_properties (
    account TEXT PRIMARY KEY, body TEXT NOT NULL
) STRICT;";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct FileServiceProperties {
    hour_metrics: Metrics,
    minute_metrics: Metrics,
    cors: Vec<CorsRule>,
    smb_multichannel: bool,
}

impl Default for FileServiceProperties {
    fn default() -> Self {
        Self {
            hour_metrics: Metrics {
                version: "1.0".into(),
                enabled: true,
                include_apis: Some(true),
                retention: Retention {
                    enabled: true,
                    days: Some(7),
                    allow_permanent_delete: None,
                },
            },
            minute_metrics: Metrics {
                version: "1.0".into(),
                enabled: false,
                include_apis: None,
                retention: Retention::default(),
            },
            cors: Vec::new(),
            smb_multichannel: false,
        }
    }
}

/// A Set File Service Properties body: omitted sections stay as stored.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Patch {
    hour_metrics: Option<Metrics>,
    minute_metrics: Option<Metrics>,
    cors: Option<Vec<CorsRule>>,
    smb_multichannel: Option<bool>,
}

impl Patch {
    pub(super) fn parse(body: &[u8]) -> Result<Self> {
        let invalid = |_| Error::InvalidXmlDocument;
        let root = xml_tree::parse(body).map_err(invalid)?;
        if root.name != "StorageServiceProperties" {
            return Err(Error::InvalidXmlDocument);
        }
        let multichannel = root
            .child("ProtocolSettings")
            .and_then(|settings| settings.child("Smb"))
            .and_then(|smb| smb.child("Multichannel"))
            .map(|node| node.flag("Enabled"))
            .transpose()
            .map_err(invalid)?
            .flatten();
        Ok(Self {
            hour_metrics: root
                .child("HourMetrics")
                .map(service_props::parse_metrics)
                .transpose()
                .map_err(invalid)?,
            minute_metrics: root
                .child("MinuteMetrics")
                .map(service_props::parse_metrics)
                .transpose()
                .map_err(invalid)?,
            cors: root
                .child("Cors")
                .map(service_props::parse_cors)
                .transpose()
                .map_err(invalid)?,
            smb_multichannel: multichannel,
        })
    }

    fn apply(self, properties: &mut FileServiceProperties) {
        if let Some(metrics) = self.hour_metrics {
            properties.hour_metrics = metrics;
        }
        if let Some(metrics) = self.minute_metrics {
            properties.minute_metrics = metrics;
        }
        if let Some(cors) = self.cors {
            properties.cors = cors;
        }
        if let Some(enabled) = self.smb_multichannel {
            properties.smb_multichannel = enabled;
        }
    }
}

impl FileServiceProperties {
    pub(super) fn to_response(&self) -> Response {
        let mut xml = Xml::root("StorageServiceProperties", &[]);
        service_props::write_metrics(&mut xml, "HourMetrics", &self.hour_metrics);
        service_props::write_metrics(&mut xml, "MinuteMetrics", &self.minute_metrics);
        service_props::write_cors(&mut xml, &self.cors);
        xml.open("ProtocolSettings");
        xml.open("Smb");
        xml.open("Multichannel");
        xml.element(
            "Enabled",
            if self.smb_multichannel {
                "true"
            } else {
                "false"
            },
        );
        xml.close("Multichannel");
        xml.close("Smb");
        xml.close("ProtocolSettings");
        xml.finish("StorageServiceProperties", StatusCode::OK)
    }
}

impl Store {
    pub(crate) async fn service_properties(
        &self,
        account: AccountName,
    ) -> Result<FileServiceProperties> {
        self.run(move |db, _| load(db, &account)).await
    }

    pub(crate) async fn set_service_properties(
        &self,
        account: AccountName,
        patch: Patch,
    ) -> Result<()> {
        self.run(move |db, _| {
            let mut properties = load(db, &account)?;
            patch.apply(&mut properties);
            let body = serde_json::to_string(&properties).map_err(|_| Error::Internal)?;
            db.execute(
                "INSERT INTO service_properties (account, body) VALUES (?1, ?2)
                 ON CONFLICT (account) DO UPDATE SET body = excluded.body",
                params![account.as_str(), body],
            )
            .map_err(db_error)?;
            Ok(())
        })
        .await
    }
}

fn load(db: &rusqlite::Connection, account: &AccountName) -> Result<FileServiceProperties> {
    let stored: Option<String> = db
        .query_row(
            "SELECT body FROM service_properties WHERE account = ?1",
            params![account.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    match stored {
        Some(text) => serde_json::from_str(&text).map_err(|_| Error::Internal),
        None => Ok(FileServiceProperties::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_replaces_only_the_sections_it_carries() {
        let body = b"<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins>\
            <AllowedMethods>GET</AllowedMethods><MaxAgeInSeconds>60</MaxAgeInSeconds>\
            <ExposedHeaders></ExposedHeaders><AllowedHeaders></AllowedHeaders></CorsRule></Cors>\
            <ProtocolSettings><Smb><Multichannel><Enabled>true</Enabled></Multichannel></Smb>\
            </ProtocolSettings></StorageServiceProperties>";
        let mut properties = FileServiceProperties::default();
        Patch::parse(body).unwrap().apply(&mut properties);
        assert_eq!(properties.cors.len(), 1);
        assert!(properties.smb_multichannel);
        assert_eq!(
            properties.hour_metrics,
            FileServiceProperties::default().hour_metrics
        );
    }

    #[test]
    fn malformed_bodies_are_invalid_xml() {
        for bad in [
            "<Other/>",
            "<StorageServiceProperties><Cors>",
            "<StorageServiceProperties><HourMetrics><Version>1.0</Version><Enabled>true</Enabled></HourMetrics></StorageServiceProperties>",
        ] {
            assert_eq!(
                Patch::parse(bad.as_bytes()),
                Err(Error::InvalidXmlDocument),
                "{bad}"
            );
        }
    }
}
