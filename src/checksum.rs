use crate::domain::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc::{CRC_64_NVME, Crc};
use md5::{Digest as _, Md5};

const CRC64: Crc<u64> = Crc::<u64>::new(&CRC_64_NVME);

#[derive(Clone, Copy)]
pub(crate) enum Checksum {
    Md5([u8; 16]),
    Crc64(u64),
}

pub(crate) struct Hasher {
    md5: Md5,
    crc64: crc::Digest<'static, u64>,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self {
            md5: Md5::new(),
            crc64: CRC64.digest(),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.crc64.update(data);
    }

    pub(crate) fn finish(self, expected: Option<Checksum>) -> Result<Checksums> {
        let checksums = Checksums {
            md5: self.md5.finalize().into(),
            crc64: self.crc64.finalize(),
        };
        checksums.verify(expected)?;
        Ok(checksums)
    }
}

pub(crate) struct Checksums {
    pub(crate) md5: [u8; 16],
    crc64: u64,
}

impl Checksums {
    /// Compares the digests of the bytes seen with the one the request declared.
    pub(crate) fn verify(&self, expected: Option<Checksum>) -> Result<()> {
        match expected {
            Some(Checksum::Md5(expected)) if expected != self.md5 => Err(Error::Md5Mismatch),
            Some(Checksum::Crc64(expected)) if expected != self.crc64 => Err(Error::Crc64Mismatch),
            _ => Ok(()),
        }
    }

    pub(crate) fn md5_text(&self) -> String {
        STANDARD.encode(self.md5)
    }

    pub(crate) fn crc64_text(&self) -> String {
        STANDARD.encode(self.crc64.to_le_bytes())
    }

    pub(crate) fn response(&self, requested: Option<Checksum>) -> (&'static str, String) {
        if matches!(requested, Some(Checksum::Md5(_))) {
            ("content-md5", self.md5_text())
        } else {
            ("x-ms-content-crc64", self.crc64_text())
        }
    }
}
