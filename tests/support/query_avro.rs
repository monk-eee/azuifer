use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = "com.microsoft.azure.storage.queryBlobContents";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Data,
    Error,
    Progress,
    End,
}

pub enum Record<'a> {
    Data(&'a [u8]),
    Error {
        fatal: bool,
        name: &'a str,
        description: &'a str,
        position: u64,
    },
    Progress {
        scanned: u64,
        total: u64,
    },
    End(u64),
}

pub struct Stream<'a> {
    pub schema: Vec<Kind>,
    pub qualified_names: bool,
    pub explicit_null_codec: bool,
    pub block_sizes: Vec<usize>,
    pub records: Vec<Record<'a>>,
}

#[derive(Deserialize)]
struct SchemaRecord<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    namespace: Option<&'a str>,
    #[serde(borrow)]
    fields: Vec<Field<'a>>,
}

#[derive(Deserialize)]
struct Field<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}

fn schema(bytes: &[u8]) -> Result<(Vec<Kind>, bool)> {
    let records: Vec<SchemaRecord<'_>> =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid Avro query schema"))?;
    let mut kinds = Vec::new();
    let mut qualified = true;
    for record in records {
        let (namespace, name) = record
            .name
            .rsplit_once('.')
            .map_or((record.namespace, record.name), |(namespace, name)| {
                (Some(namespace), name)
            });
        qualified &= namespace == Some(NAMESPACE);
        let (kind, fields): (Kind, &[(&str, &str)]) = match name {
            "resultData" => (Kind::Data, &[("data", "bytes")]),
            "error" => (
                Kind::Error,
                &[
                    ("fatal", "boolean"),
                    ("name", "string"),
                    ("description", "string"),
                    ("position", "long"),
                ],
            ),
            "progress" => (
                Kind::Progress,
                &[("bytesScanned", "long"), ("totalBytes", "long")],
            ),
            "end" => (Kind::End, &[("totalBytes", "long")]),
            _ => anyhow::bail!("unexpected Avro query record"),
        };
        ensure!(
            record.kind == "record"
                && !kinds.contains(&kind)
                && record
                    .fields
                    .iter()
                    .map(|field| (field.name, field.kind))
                    .eq(fields.iter().copied()),
            "unexpected Avro query fields"
        );
        kinds.push(kind);
    }
    ensure!(kinds.len() == 4, "incomplete Avro query schema");
    Ok((kinds, qualified))
}

struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(size)
            .context("truncated Avro data")?;
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().context("missing Avro byte")
    }

    fn long(&mut self) -> Result<i64> {
        let mut bits = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            ensure!(shift != 63 || byte <= 1, "invalid Avro long");
            bits |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok((bits >> 1).cast_signed() ^ -(bits & 1).cast_signed());
            }
        }
        anyhow::bail!("invalid Avro long")
    }

    fn count(&mut self) -> Result<usize> {
        usize::try_from(self.long()?).context("invalid Avro length")
    }

    fn nonnegative(&mut self) -> Result<u64> {
        u64::try_from(self.long()?).context("negative Avro query count")
    }

    fn field(&mut self) -> Result<&'a [u8]> {
        let size = self.count()?;
        self.take(size)
    }

    fn text(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.field()?).map_err(|_| anyhow::anyhow!("invalid Avro string"))
    }

    fn record(&mut self, kinds: &[Kind]) -> Result<Record<'a>> {
        let index = self.count()?;
        Ok(
            match kinds.get(index).context("unknown query union index")? {
                Kind::Data => Record::Data(self.field()?),
                Kind::Error => {
                    let flag = self.byte()?;
                    ensure!(flag <= 1, "invalid Avro error flag");
                    Record::Error {
                        fatal: flag == 1,
                        name: self.text()?,
                        description: self.text()?,
                        position: self.nonnegative()?,
                    }
                }
                Kind::Progress => Record::Progress {
                    scanned: self.nonnegative()?,
                    total: self.nonnegative()?,
                },
                Kind::End => Record::End(self.nonnegative()?),
            },
        )
    }
}

pub fn decode(bytes: &[u8]) -> Result<Stream<'_>> {
    let mut input = Bytes(bytes);
    ensure!(
        input.take(4)? == b"Obj\x01",
        "missing Avro object container header"
    );
    let mut schema_field = None;
    let mut explicit_null_codec = false;
    loop {
        let count = input.long()?;
        if count == 0 {
            break;
        }
        let mut block = if count < 0 {
            let bytes = input.count()?;
            Bytes(input.take(bytes)?)
        } else {
            Bytes(input.0)
        };
        ensure!(
            count.unsigned_abs() <= block.0.len() as u64,
            "invalid Avro metadata count"
        );
        for _ in 0..count.unsigned_abs() {
            let key = block.field()?;
            let value = block.field()?;
            match key {
                b"avro.schema" if schema_field.is_none() => schema_field = Some(value),
                b"avro.codec" if !explicit_null_codec && value == b"null" => {
                    explicit_null_codec = true
                }
                _ => anyhow::bail!("unexpected Avro query metadata"),
            }
        }
        if count > 0 {
            input = block;
        } else {
            ensure!(block.0.is_empty(), "invalid Avro metadata block length");
        }
    }
    let (schema, qualified_names) = schema(schema_field.context("missing Avro schema")?)?;
    let sync = input.take(16)?;
    let mut records = Vec::new();
    let mut block_sizes = Vec::new();
    while !input.0.is_empty() {
        let count = input.count()?;
        let size = input.count()?;
        ensure!(count > 0 && count <= size, "invalid Avro data count");
        let mut block = Bytes(input.take(size)?);
        ensure!(input.take(16)? == sync, "wrong Avro block sync marker");
        for _ in 0..count {
            records.push(block.record(&schema)?);
        }
        ensure!(block.0.is_empty(), "invalid Avro data block length");
        block_sizes.push(count);
    }
    Ok(Stream {
        schema,
        qualified_names,
        explicit_null_codec,
        block_sizes,
        records,
    })
}
