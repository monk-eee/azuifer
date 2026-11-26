//! Compact binary encoding of typed entity properties for SQLite storage.

use super::{
    datetime::Ticks,
    model::{Properties, PropertyName, Value},
};
use uuid::Uuid;

pub(super) fn encode(properties: &Properties) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(properties.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for (name, value) in properties {
        put_bytes(&mut out, name.as_str().as_bytes());
        match value {
            Value::String(value) => {
                out.push(0);
                put_bytes(&mut out, value.as_bytes());
            }
            Value::Boolean(value) => out.extend_from_slice(&[1, u8::from(*value)]),
            Value::Int32(value) => {
                out.push(2);
                out.extend_from_slice(&value.to_le_bytes());
            }
            Value::Int64(value) => {
                out.push(3);
                out.extend_from_slice(&value.to_le_bytes());
            }
            Value::Double(value) => {
                out.push(4);
                out.extend_from_slice(&value.to_bits().to_le_bytes());
            }
            Value::DateTime(value) => {
                out.push(5);
                out.extend_from_slice(&value.get().to_le_bytes());
            }
            Value::Guid(value) => {
                out.push(6);
                out.extend_from_slice(value.as_bytes());
            }
            Value::Binary(value) => {
                out.push(7);
                put_bytes(&mut out, value);
            }
        }
    }
    out
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Decodes stored properties; `None` means the stored bytes are corrupt.
pub(super) fn decode(bytes: &[u8]) -> Option<Properties> {
    let mut reader = Reader(bytes);
    let count = reader.u32()?;
    let mut properties = Properties::new();
    for _ in 0..count {
        let name = PropertyName::parse(&reader.string()?).ok()?;
        let value = match reader.take(1)?.first()? {
            0 => Value::String(reader.string()?),
            1 => Value::Boolean(*reader.take(1)?.first()? != 0),
            2 => Value::Int32(i32::from_le_bytes(reader.array()?)),
            3 => Value::Int64(i64::from_le_bytes(reader.array()?)),
            4 => Value::Double(f64::from_bits(u64::from_le_bytes(reader.array()?))),
            5 => Value::DateTime(Ticks::new(i64::from_le_bytes(reader.array()?))?),
            6 => Value::Guid(Uuid::from_bytes(reader.array()?)),
            7 => {
                let length = usize::try_from(reader.u32()?).ok()?;
                Value::Binary(reader.take(length)?.to_vec())
            }
            _ => return None,
        };
        properties.insert(name, value);
    }
    reader.0.is_empty().then_some(properties)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(length)?;
        self.0 = tail;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn string(&mut self) -> Option<String> {
        let length = usize::try_from(self.u32()?).ok()?;
        String::from_utf8(self.take(length)?.to_vec()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_edm_type_round_trips_through_storage() {
        let mut properties = Properties::new();
        for (name, value) in [
            ("S", Value::String("héllo".into())),
            ("B", Value::Boolean(true)),
            ("I32", Value::Int32(i32::MIN)),
            ("I64", Value::Int64(i64::MAX)),
            ("D", Value::Double(-1.5e300)),
            ("Inf", Value::Double(f64::INFINITY)),
            (
                "T",
                Value::DateTime(Ticks::parse("9999-12-31T23:59:59.9999999Z").unwrap()),
            ),
            ("G", Value::Guid(Uuid::from_u128(0x1234))),
            ("Bin", Value::Binary(vec![0, 255, 7])),
        ] {
            properties.insert(PropertyName::parse(name).unwrap(), value);
        }
        let decoded = decode(&encode(&properties)).unwrap();
        assert_eq!(decoded, properties);
        assert!(decode(&encode(&properties)[..5]).is_none());
        assert!(decode(&[0, 0, 0, 0, 9]).is_none());
    }

    #[test]
    fn nan_survives_as_nan() {
        let mut properties = Properties::new();
        properties.insert(PropertyName::parse("N").unwrap(), Value::Double(f64::NAN));
        let decoded = decode(&encode(&properties)).unwrap();
        assert!(matches!(decoded.values().next(), Some(Value::Double(v)) if v.is_nan()));
    }
}
