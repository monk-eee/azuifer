//! The Avro object container Query Blob Contents answers with: a union of four record types
//! (`resultData`, `error`, `progress`, `end`) in the schema, then a block per record.

const SCHEMA: &str = r#"[{"type":"record","name":"resultData","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"data","type":"bytes"}]},{"type":"record","name":"error","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"fatal","type":"boolean"},{"name":"name","type":"string"},{"name":"description","type":"string"},{"name":"position","type":"long"}]},{"type":"record","name":"progress","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"bytesScanned","type":"long"},{"name":"totalBytes","type":"long"}]},{"type":"record","name":"end","namespace":"com.microsoft.azure.storage.queryBlobContents","fields":[{"name":"totalBytes","type":"long"}]}]"#;

const DATA: i64 = 0;
const ERROR: i64 = 1;
const PROGRESS: i64 = 2;
const END: i64 = 3;

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
    stream: Vec<u8>,
    record: Vec<u8>,
    sync: [u8; 16],
}

impl Writer {
    pub(super) fn new() -> Self {
        let sync = *uuid::Uuid::new_v4().as_bytes();
        let mut stream = b"Obj\x01".to_vec();
        long(&mut stream, 1);
        bytes(&mut stream, b"avro.schema");
        bytes(&mut stream, SCHEMA.as_bytes());
        long(&mut stream, 0);
        stream.extend_from_slice(&sync);
        Self {
            stream,
            record: Vec::new(),
            sync,
        }
    }

    fn write(&mut self, kind: i64, fields: impl FnOnce(&mut Vec<u8>)) {
        self.record.clear();
        long(&mut self.record, kind);
        fields(&mut self.record);
        long(&mut self.stream, 1);
        bytes(&mut self.stream, &self.record);
        self.stream.extend_from_slice(&self.sync);
    }

    pub(super) fn data(&mut self, payload: &[u8]) {
        self.write(DATA, |record| bytes(record, payload));
    }

    pub(super) fn progress(&mut self, scanned: u64, total: u64) {
        self.write(PROGRESS, |record| {
            long(record, count(scanned));
            long(record, count(total));
        });
    }

    pub(super) fn end(&mut self, total: u64) {
        self.write(END, |record| long(record, count(total)));
    }

    pub(super) fn error(&mut self, fatal: bool, name: &str, description: &str, position: u64) {
        self.write(ERROR, |record| {
            record.push(u8::from(fatal));
            bytes(record, name.as_bytes());
            bytes(record, description.as_bytes());
            long(record, count(position));
        });
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.stream
    }

    pub(super) fn encoded_len(&self) -> usize {
        self.stream.len()
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
        assert_eq!(file.windows(16).filter(|window| *window == sync).count(), 3);
        let end_block = &file[file.len() - 16 - 4..file.len() - 16];
        assert_eq!(end_block, [2, 4, 6, 4]);
    }
}
