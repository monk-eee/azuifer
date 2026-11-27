//! The Avro object container Query Blob Contents answers with: a union of four record types
//! (`resultData`, `progress`, `end`, `error`) in the schema, then one block of records.

const SCHEMA: &str = r#"[{"type":"record","name":"resultData","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"data","type":"bytes"}]},{"type":"record","name":"progress","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"bytesScanned","type":"long"},{"name":"totalBytes","type":"long"}]},{"type":"record","name":"end","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"totalBytes","type":"long"}]},{"type":"record","name":"error","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"fatal","type":"boolean"},{"name":"name","type":"string"},{"name":"description","type":"string"},{"name":"position","type":"long"}]}]"#;

const DATA: i64 = 0;
const PROGRESS: i64 = 1;
const END: i64 = 2;
const ERROR: i64 = 3;

/// Appends an Avro `long`: zigzag, then base-128 with the low group first.
fn long(out: &mut Vec<u8>, value: i64) {
    let mut n = ((value << 1) ^ (value >> 63)).cast_unsigned();
    while n >= 0x80 {
        out.push((n & 0x7f) as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    long(out, count(value.len() as u64));
    out.extend_from_slice(value);
}

fn count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(super) struct Writer {
    records: Vec<u8>,
    count: i64,
}

impl Writer {
    pub(super) fn new() -> Self {
        Self {
            records: Vec::new(),
            count: 0,
        }
    }

    fn start(&mut self, kind: i64) {
        long(&mut self.records, kind);
        self.count += 1;
    }

    pub(super) fn data(&mut self, payload: &[u8]) {
        self.start(DATA);
        bytes(&mut self.records, payload);
    }

    pub(super) fn progress(&mut self, scanned: u64, total: u64) {
        self.start(PROGRESS);
        long(&mut self.records, count(scanned));
        long(&mut self.records, count(total));
    }

    pub(super) fn end(&mut self, total: u64) {
        self.start(END);
        long(&mut self.records, count(total));
    }

    pub(super) fn error(&mut self, fatal: bool, name: &str, description: &str, position: u64) {
        self.start(ERROR);
        self.records.push(u8::from(fatal));
        bytes(&mut self.records, name.as_bytes());
        bytes(&mut self.records, description.as_bytes());
        long(&mut self.records, count(position));
    }

    /// The complete container: header, then every record in one block.
    pub(super) fn finish(self) -> Vec<u8> {
        let sync = *uuid::Uuid::new_v4().as_bytes();
        let mut out = b"Obj\x01".to_vec();
        long(&mut out, 2);
        bytes(&mut out, b"avro.schema");
        bytes(&mut out, SCHEMA.as_bytes());
        bytes(&mut out, b"avro.codec");
        bytes(&mut out, b"null");
        long(&mut out, 0);
        out.extend_from_slice(&sync);
        long(&mut out, self.count);
        long(&mut out, count(self.records.len() as u64));
        out.extend_from_slice(&self.records);
        out.extend_from_slice(&sync);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longs_use_zigzag_varints() {
        let encode = |value| {
            let mut out = Vec::new();
            long(&mut out, value);
            out
        };
        assert_eq!(encode(0), [0]);
        assert_eq!(encode(-1), [1]);
        assert_eq!(encode(1), [2]);
        assert_eq!(encode(64), [0x80, 0x01]);
        assert_eq!(encode(-65), [0x81, 0x01]);
    }

    #[test]
    fn the_container_frames_records_between_sync_markers() {
        let mut writer = Writer::new();
        writer.data(b"hi");
        writer.end(2);
        let file = writer.finish();
        assert!(file.starts_with(b"Obj\x01"));
        let sync = &file[file.len() - 16..];
        assert_eq!(file.windows(16).filter(|window| *window == sync).count(), 2);
        // Union index 0 and a two byte `bytes` value, then union index 2 and the total.
        let records = &file[file.len() - 16 - 6..file.len() - 16];
        assert_eq!(records, [0, 4, b'h', b'i', 4, 4]);
    }
}
