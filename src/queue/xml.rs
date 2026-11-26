use super::{
    error::{QueueError, Result},
    model::{
        AccessPolicy, CorsRule, Logging, MAX_MESSAGE_BYTES, MAX_POLICIES, Message, Metadata,
        Metrics, PropertiesPatch, Retention, ServiceProperties,
    },
    time,
};
use crate::{clock, sas, wire::Xml};
use axum::{http::StatusCode, response::Response};
use quick_xml::{Reader, events::Event};

const MAX_DEPTH: usize = 16;

/// A parsed XML element: its own character data and its child elements.
#[derive(Debug, Default)]
pub(super) struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|node| node.name == name)
    }

    fn required(&self, name: &str) -> Result<&Node> {
        self.child(name).ok_or(QueueError::InvalidXml)
    }

    fn flag(&self) -> Result<bool> {
        match self.text.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(QueueError::InvalidXml),
        }
    }

    /// Rejects elements other than `allowed`, so typos never pass silently.
    fn only(&self, allowed: &[&str]) -> Result<()> {
        if self
            .children
            .iter()
            .all(|node| allowed.contains(&node.name.as_str()))
        {
            Ok(())
        } else {
            Err(QueueError::InvalidXml)
        }
    }
}

fn xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn push_text(stack: &mut [Node], text: &str) -> Result<()> {
    if !text.chars().all(xml_char) {
        return Err(QueueError::InvalidXml);
    }
    match stack.last_mut() {
        Some(node) => node.text.push_str(text),
        None if text.trim().is_empty() => {}
        None => return Err(QueueError::InvalidXml),
    }
    Ok(())
}

fn attach(stack: &mut [Node], root: &mut Option<Node>, node: Node) -> Result<()> {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None if root.is_none() => *root = Some(node),
        None => return Err(QueueError::InvalidXml),
    }
    Ok(())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Node> {
    let text = std::str::from_utf8(bytes).map_err(|_| QueueError::InvalidXml)?;
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    loop {
        match reader.read_event().map_err(|_| QueueError::InvalidXml)? {
            Event::Start(tag) => {
                if root.is_some() || stack.len() >= MAX_DEPTH {
                    return Err(QueueError::InvalidXml);
                }
                stack.push(Node {
                    name: tag.name().as_ref().to_owned(),
                    ..Node::default()
                });
            }
            Event::Empty(tag) => {
                let node = Node {
                    name: tag.name().as_ref().to_owned(),
                    ..Node::default()
                };
                attach(&mut stack, &mut root, node)?;
            }
            Event::End(_) => {
                let node = stack.pop().ok_or(QueueError::InvalidXml)?;
                attach(&mut stack, &mut root, node)?;
            }
            Event::Text(content) => push_text(&mut stack, &content.xml10_content())?,
            Event::CData(content) => push_text(&mut stack, &content.xml10_content())?,
            Event::GeneralRef(reference) => {
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(ch)) => ch,
                    Ok(None) => match &*reference {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return Err(QueueError::InvalidXml),
                    },
                    Err(_) => return Err(QueueError::InvalidXml),
                };
                push_text(&mut stack, resolved.encode_utf8(&mut [0; 4]))?;
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::DocType(_) => return Err(QueueError::InvalidXml),
            Event::Eof => break,
        }
    }
    match (stack.is_empty(), root) {
        (true, Some(root)) => Ok(root),
        _ => Err(QueueError::InvalidXml),
    }
}

fn blank(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_whitespace)
}

/// The `MessageText` of a `QueueMessage` body, or `None` when no text was sent.
pub(super) fn message_text(bytes: &[u8]) -> Result<Option<String>> {
    if blank(bytes) {
        return Ok(None);
    }
    let root = parse(bytes)?;
    if root.name != "QueueMessage" {
        return Err(QueueError::InvalidXml);
    }
    let Some(text) = root.child("MessageText") else {
        return Ok(None);
    };
    if text.text.len() > MAX_MESSAGE_BYTES {
        return Err(QueueError::BodyTooLarge(MAX_MESSAGE_BYTES as u64));
    }
    Ok(Some(text.text.clone()))
}

fn policy_time(node: Option<&Node>) -> Result<Option<i64>> {
    node.map(|node| {
        sas::parse_time(node.text.trim())
            .map(clock::to_millis)
            .map_err(|_| QueueError::InvalidXml)
    })
    .transpose()
}

fn valid_permissions(permission: &str) -> bool {
    let mut order = "raup".chars();
    permission
        .chars()
        .all(|letter| order.by_ref().any(|allowed| allowed == letter))
}

pub(super) fn parse_acl(bytes: &[u8]) -> Result<Vec<AccessPolicy>> {
    if blank(bytes) {
        return Ok(Vec::new());
    }
    let root = parse(bytes)?;
    if root.name != "SignedIdentifiers" {
        return Err(QueueError::InvalidXml);
    }
    root.only(&["SignedIdentifier"])?;
    if root.children.len() > MAX_POLICIES {
        return Err(QueueError::InvalidXml);
    }
    let mut policies: Vec<AccessPolicy> = Vec::new();
    for identifier in &root.children {
        identifier.only(&["Id", "AccessPolicy"])?;
        let id = identifier.required("Id")?.text.clone();
        if id.is_empty() || id.chars().count() > 64 || policies.iter().any(|p| p.id == id) {
            return Err(QueueError::InvalidXml);
        }
        let policy = identifier.child("AccessPolicy");
        if let Some(policy) = policy {
            policy.only(&["Start", "Expiry", "Permission"])?;
        }
        let permission = policy
            .and_then(|policy| policy.child("Permission"))
            .map_or_else(String::new, |node| node.text.trim().to_owned());
        if !valid_permissions(&permission) {
            return Err(QueueError::InvalidXml);
        }
        policies.push(AccessPolicy {
            id,
            start: policy_time(policy.and_then(|p| p.child("Start")))?,
            expiry: policy_time(policy.and_then(|p| p.child("Expiry")))?,
            permission,
        });
    }
    Ok(policies)
}

fn retention(node: &Node) -> Result<Retention> {
    let policy = node.required("RetentionPolicy")?;
    policy.only(&["Enabled", "Days"])?;
    let enabled = policy.required("Enabled")?.flag()?;
    let days = match (enabled, policy.child("Days")) {
        (true, Some(days)) => {
            let days: u32 = days
                .text
                .trim()
                .parse()
                .map_err(|_| QueueError::InvalidXml)?;
            if !(1..=365).contains(&days) {
                return Err(QueueError::InvalidXml);
            }
            Some(days)
        }
        (true, None) => return Err(QueueError::InvalidXml),
        (false, _) => None,
    };
    Ok(Retention { enabled, days })
}

fn version(node: &Node) -> Result<String> {
    let version = node.required("Version")?.text.trim();
    if version != "1.0" {
        return Err(QueueError::InvalidXml);
    }
    Ok(version.to_owned())
}

fn logging(node: &Node) -> Result<Logging> {
    node.only(&["Version", "Read", "Write", "Delete", "RetentionPolicy"])?;
    Ok(Logging {
        version: version(node)?,
        read: node.required("Read")?.flag()?,
        write: node.required("Write")?.flag()?,
        delete: node.required("Delete")?.flag()?,
        retention: retention(node)?,
    })
}

fn metrics(node: &Node) -> Result<Metrics> {
    node.only(&["Version", "Enabled", "IncludeAPIs", "RetentionPolicy"])?;
    let enabled = node.required("Enabled")?.flag()?;
    let include_apis = node.child("IncludeAPIs").map(Node::flag).transpose()?;
    if enabled && include_apis.is_none() {
        return Err(QueueError::InvalidXml);
    }
    Ok(Metrics {
        version: version(node)?,
        enabled,
        include_apis: include_apis.filter(|_| enabled),
        retention: retention(node)?,
    })
}

const CORS_METHODS: [&str; 8] = [
    "DELETE", "GET", "HEAD", "MERGE", "POST", "OPTIONS", "PUT", "PATCH",
];

fn cors_rule(node: &Node) -> Result<CorsRule> {
    node.only(&[
        "AllowedOrigins",
        "AllowedMethods",
        "MaxAgeInSeconds",
        "ExposedHeaders",
        "AllowedHeaders",
    ])?;
    let text = |name| -> Result<String> { Ok(node.required(name)?.text.trim().to_owned()) };
    let allowed_methods = text("AllowedMethods")?;
    let methods_valid = !allowed_methods.is_empty()
        && allowed_methods
            .split(',')
            .all(|method| CORS_METHODS.contains(&method.trim().to_ascii_uppercase().as_str()));
    let allowed_origins = text("AllowedOrigins")?;
    if !methods_valid || allowed_origins.is_empty() {
        return Err(QueueError::InvalidXml);
    }
    let max_age: u32 = text("MaxAgeInSeconds")?
        .parse()
        .map_err(|_| QueueError::InvalidXml)?;
    if i32::try_from(max_age).is_err() {
        return Err(QueueError::InvalidXml);
    }
    Ok(CorsRule {
        allowed_origins,
        allowed_methods,
        max_age,
        exposed_headers: text("ExposedHeaders")?,
        allowed_headers: text("AllowedHeaders")?,
    })
}

pub(super) fn parse_properties(bytes: &[u8]) -> Result<PropertiesPatch> {
    let root = parse(bytes)?;
    if root.name != "StorageServiceProperties" {
        return Err(QueueError::InvalidXml);
    }
    root.only(&["Logging", "HourMetrics", "MinuteMetrics", "Cors"])?;
    let cors = root
        .child("Cors")
        .map(|cors| {
            cors.only(&["CorsRule"])?;
            if cors.children.len() > 5 {
                return Err(QueueError::InvalidXml);
            }
            cors.children.iter().map(cors_rule).collect()
        })
        .transpose()?;
    Ok(PropertiesPatch {
        logging: root.child("Logging").map(logging).transpose()?,
        hour_metrics: root.child("HourMetrics").map(metrics).transpose()?,
        minute_metrics: root.child("MinuteMetrics").map(metrics).transpose()?,
        cors,
    })
}

pub(super) enum MessageView {
    Put,
    Get,
    Peek,
}

pub(super) fn messages(messages: &[Message], view: &MessageView) -> Result<Response> {
    let mut xml = Xml::root("QueueMessagesList", &[]);
    for message in messages {
        xml.open("QueueMessage");
        xml.element("MessageId", &message.id);
        xml.element("InsertionTime", &time::http_date(message.inserted)?);
        let expiry = match message.expires {
            Some(expires) => time::http_date(expires)?,
            None => time::never_expires()?,
        };
        xml.element("ExpirationTime", &expiry);
        if !matches!(view, MessageView::Peek) {
            xml.element("PopReceipt", &message.pop_receipt);
            xml.element("TimeNextVisible", &time::http_date(message.next_visible)?);
        }
        if !matches!(view, MessageView::Put) {
            xml.element("DequeueCount", &message.dequeue_count.to_string());
            xml.element("MessageText", &message.text);
        }
        xml.close("QueueMessage");
    }
    let status = if matches!(view, MessageView::Put) {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok(xml.finish("QueueMessagesList", status))
}

pub(super) struct Listing<'a> {
    pub(super) endpoint: &'a str,
    pub(super) prefix: &'a str,
    pub(super) marker: &'a str,
    pub(super) limit: u32,
    pub(super) queues: Vec<(String, Metadata)>,
    pub(super) next: &'a str,
    pub(super) metadata: bool,
}

pub(super) fn list_queues(listing: Listing<'_>) -> Response {
    let mut xml = Xml::root(
        "EnumerationResults",
        &[("ServiceEndpoint", listing.endpoint)],
    );
    if !listing.prefix.is_empty() {
        xml.element("Prefix", listing.prefix);
    }
    if !listing.marker.is_empty() {
        xml.element("Marker", listing.marker);
    }
    xml.element("MaxResults", &listing.limit.to_string());
    xml.open("Queues");
    for (name, metadata) in &listing.queues {
        xml.open("Queue");
        xml.element("Name", name);
        if listing.metadata && !metadata.is_empty() {
            xml.open("Metadata");
            for (key, value) in metadata {
                xml.element(key, value);
            }
            xml.close("Metadata");
        }
        xml.close("Queue");
    }
    xml.close("Queues");
    xml.element("NextMarker", listing.next);
    xml.finish("EnumerationResults", StatusCode::OK)
}

pub(super) fn acl(policies: &[AccessPolicy]) -> Response {
    let mut xml = Xml::root("SignedIdentifiers", &[]);
    for policy in policies {
        xml.open("SignedIdentifier");
        xml.element("Id", &policy.id);
        xml.open("AccessPolicy");
        if let Some(start) = policy.start {
            xml.element("Start", &time::iso8601(start));
        }
        if let Some(expiry) = policy.expiry {
            xml.element("Expiry", &time::iso8601(expiry));
        }
        xml.element("Permission", &policy.permission);
        xml.close("AccessPolicy");
        xml.close("SignedIdentifier");
    }
    xml.finish("SignedIdentifiers", StatusCode::OK)
}

fn flag(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn write_retention(xml: &mut Xml, retention: &Retention) {
    xml.open("RetentionPolicy");
    xml.element("Enabled", flag(retention.enabled));
    if let Some(days) = retention.days {
        xml.element("Days", &days.to_string());
    }
    xml.close("RetentionPolicy");
}

fn write_metrics(xml: &mut Xml, tag: &str, metrics: &Metrics) {
    xml.open(tag);
    xml.element("Version", &metrics.version);
    xml.element("Enabled", flag(metrics.enabled));
    if let Some(include) = metrics.include_apis {
        xml.element("IncludeAPIs", flag(include));
    }
    write_retention(xml, &metrics.retention);
    xml.close(tag);
}

pub(super) fn properties(properties: &ServiceProperties) -> Response {
    let mut xml = Xml::root("StorageServiceProperties", &[]);
    let logging = &properties.logging;
    xml.open("Logging");
    xml.element("Version", &logging.version);
    xml.element("Read", flag(logging.read));
    xml.element("Write", flag(logging.write));
    xml.element("Delete", flag(logging.delete));
    write_retention(&mut xml, &logging.retention);
    xml.close("Logging");
    write_metrics(&mut xml, "HourMetrics", &properties.hour_metrics);
    write_metrics(&mut xml, "MinuteMetrics", &properties.minute_metrics);
    xml.open("Cors");
    for rule in &properties.cors {
        xml.open("CorsRule");
        xml.element("AllowedOrigins", &rule.allowed_origins);
        xml.element("AllowedMethods", &rule.allowed_methods);
        xml.element("MaxAgeInSeconds", &rule.max_age.to_string());
        xml.element("ExposedHeaders", &rule.exposed_headers);
        xml.element("AllowedHeaders", &rule.allowed_headers);
        xml.close("CorsRule");
    }
    xml.close("Cors");
    xml.finish("StorageServiceProperties", StatusCode::OK)
}

pub(super) fn stats(last_sync_millis: i64) -> Result<Response> {
    let mut xml = Xml::root("StorageServiceStats", &[]);
    xml.open("GeoReplication");
    xml.element("Status", "live");
    xml.element("LastSyncTime", &time::http_date(last_sync_millis)?);
    xml.close("GeoReplication");
    Ok(xml.finish("StorageServiceStats", StatusCode::OK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn message_text_is_preserved_exactly_and_unescaped() {
        let xml = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><QueueMessage><MessageText>  a &amp; b &lt;c&gt; &#x41; <![CDATA[<raw>]]> </MessageText></QueueMessage>";
        assert_eq!(
            message_text(xml).unwrap().as_deref(),
            Some("  a & b <c> A <raw> ")
        );
        assert_eq!(
            message_text(b"<QueueMessage><MessageText /></QueueMessage>").unwrap(),
            Some(String::new())
        );
        assert_eq!(message_text(b"  ").unwrap(), None);
        assert_eq!(message_text(b"<QueueMessage/>").unwrap(), None);
    }

    #[test]
    fn malformed_or_hostile_documents_are_rejected() {
        for bad in [
            &b"<QueueMessage><MessageText>x</QueueMessage>"[..],
            b"<QueueMessage><MessageText>x</MessageText></QueueMessage><extra/>",
            b"<!DOCTYPE a [<!ENTITY x 'y'>]><QueueMessage/>",
            b"<Other><MessageText>x</MessageText></Other>",
            b"<QueueMessage><MessageText>&unknown;</MessageText></QueueMessage>",
            b"<QueueMessage><MessageText>a\x01b</MessageText></QueueMessage>",
            b"text",
        ] {
            assert_eq!(message_text(bad), Err(QueueError::InvalidXml));
        }
        let big = format!(
            "<QueueMessage><MessageText>{}</MessageText></QueueMessage>",
            "x".repeat(MAX_MESSAGE_BYTES + 1)
        );
        assert!(matches!(
            message_text(big.as_bytes()),
            Err(QueueError::BodyTooLarge(_))
        ));
        let limit = format!(
            "<QueueMessage><MessageText>{}</MessageText></QueueMessage>",
            "x".repeat(MAX_MESSAGE_BYTES)
        );
        assert!(message_text(limit.as_bytes()).is_ok());
    }

    #[test]
    fn signed_identifiers_round_trip_and_validate() {
        let xml = b"<SignedIdentifiers><SignedIdentifier><Id>one</Id><AccessPolicy><Start>2024-01-01T00:00:00Z</Start><Expiry>2030-01-01T00:00:00.0000000Z</Expiry><Permission>rau</Permission></AccessPolicy></SignedIdentifier><SignedIdentifier><Id>two</Id></SignedIdentifier></SignedIdentifiers>";
        let policies = parse_acl(xml).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].permission, "rau");
        assert_eq!(policies[0].start, Some(1_704_067_200_000));
        assert_eq!(policies[1].start, None);
        assert_eq!(parse_acl(b"").unwrap(), Vec::new());
        let duplicate = b"<SignedIdentifiers><SignedIdentifier><Id>a</Id></SignedIdentifier><SignedIdentifier><Id>a</Id></SignedIdentifier></SignedIdentifiers>";
        assert!(parse_acl(duplicate).is_err());
        let wrong_order = b"<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>ar</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
        assert!(parse_acl(wrong_order).is_err());
        let six = format!(
            "<SignedIdentifiers>{}</SignedIdentifiers>",
            (0..6)
                .map(|n| format!("<SignedIdentifier><Id>{n}</Id></SignedIdentifier>"))
                .collect::<String>()
        );
        assert!(parse_acl(six.as_bytes()).is_err());
    }

    #[test]
    fn service_properties_parse_sections_and_validate_cors() {
        let xml = b"<StorageServiceProperties><Logging><Version>1.0</Version><Read>true</Read><Write>false</Write><Delete>false</Delete><RetentionPolicy><Enabled>true</Enabled><Days>5</Days></RetentionPolicy></Logging><Cors><CorsRule><AllowedOrigins>http://a.example</AllowedOrigins><AllowedMethods>GET,PUT</AllowedMethods><MaxAgeInSeconds>60</MaxAgeInSeconds><ExposedHeaders>x-ms-*</ExposedHeaders><AllowedHeaders>x-ms-meta-*</AllowedHeaders></CorsRule></Cors></StorageServiceProperties>";
        let patch = parse_properties(xml).unwrap();
        assert!(patch.logging.as_ref().unwrap().read);
        assert_eq!(patch.logging.unwrap().retention.days, Some(5));
        assert!(patch.hour_metrics.is_none());
        assert_eq!(patch.cors.unwrap()[0].max_age, 60);
        let bad_method = b"<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>FETCH</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds><ExposedHeaders></ExposedHeaders><AllowedHeaders></AllowedHeaders></CorsRule></Cors></StorageServiceProperties>";
        assert!(parse_properties(bad_method).is_err());
        let enabled_without_days = b"<StorageServiceProperties><HourMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>true</IncludeAPIs><RetentionPolicy><Enabled>true</Enabled></RetentionPolicy></HourMetrics></StorageServiceProperties>";
        assert!(parse_properties(enabled_without_days).is_err());
        assert!(
            parse_properties(b"<StorageServiceProperties><Unknown/></StorageServiceProperties>")
                .is_err()
        );
    }

    #[tokio::test]
    async fn message_lists_use_the_azure_element_sets() {
        let message = Message {
            id: "id-1".into(),
            inserted: 1_699_014_615_000,
            expires: None,
            next_visible: 1_699_014_645_000,
            dequeue_count: 2,
            pop_receipt: "receipt".into(),
            text: "a<b".into(),
        };
        let get = body(messages(std::slice::from_ref(&message), &MessageView::Get).unwrap()).await;
        assert!(get.contains("<MessageId>id-1</MessageId>"));
        assert!(get.contains("<InsertionTime>Fri, 03 Nov 2023 12:30:15 GMT</InsertionTime>"));
        assert!(get.contains("<ExpirationTime>Fri, 31 Dec 9999 23:59:59 GMT</ExpirationTime>"));
        assert!(get.contains("<PopReceipt>receipt</PopReceipt>"));
        assert!(get.contains("<TimeNextVisible>Fri, 03 Nov 2023 12:30:45 GMT</TimeNextVisible>"));
        assert!(get.contains("<DequeueCount>2</DequeueCount><MessageText>a&lt;b</MessageText>"));
        let peek =
            body(messages(std::slice::from_ref(&message), &MessageView::Peek).unwrap()).await;
        assert!(!peek.contains("PopReceipt") && !peek.contains("TimeNextVisible"));
        let put = body(messages(&[message], &MessageView::Put).unwrap()).await;
        assert!(put.contains("PopReceipt") && !put.contains("MessageText"));
    }

    #[tokio::test]
    async fn listing_omits_empty_prefix_marker_and_metadata() {
        let xml = body(list_queues(Listing {
            endpoint: "http://h/acct/",
            prefix: "",
            marker: "",
            limit: 5000,
            queues: vec![
                ("a".into(), Metadata::from([("k".into(), "v".into())])),
                ("b".into(), Metadata::new()),
            ],
            next: "",
            metadata: true,
        }))
        .await;
        assert!(xml.contains("ServiceEndpoint=\"http://h/acct/\""));
        assert!(!xml.contains("<Prefix>") && !xml.contains("<Marker>"));
        assert!(xml.contains("<Queue><Name>a</Name><Metadata><k>v</k></Metadata></Queue>"));
        assert!(xml.contains("<Queue><Name>b</Name></Queue><"));
        assert!(xml.ends_with("<NextMarker></NextMarker></EnumerationResults>"));
    }
}
