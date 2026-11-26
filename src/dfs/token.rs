//! Continuation tokens of the DFS operations that return `x-ms-continuation`.

use crate::domain::{Error, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const VERSION: &str = "v1:";
const MAX_TOKEN: usize = 5462;

/// The path an interrupted batch stopped at, as an opaque header and query value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Continuation(String);

impl Continuation {
    pub(super) fn after(path: &str) -> Self {
        Self(path.to_owned())
    }

    pub(super) fn path(&self) -> &str {
        &self.0
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        if value.len() > MAX_TOKEN {
            return Err(Error::InvalidQuery);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Error::InvalidQuery)?;
        let text = String::from_utf8(bytes).map_err(|_| Error::InvalidQuery)?;
        text.strip_prefix(VERSION)
            .map(|path| Self(path.to_owned()))
            .ok_or(Error::InvalidQuery)
    }

    pub(super) fn render(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!("{VERSION}{}", self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_any_path_including_the_filesystem_root() {
        for path in ["", "a", "dir/sub dir/é.txt"] {
            let token = Continuation::after(path).render();
            assert!(!token.is_empty());
            assert_eq!(Continuation::parse(&token).unwrap().path(), path);
        }
    }

    #[test]
    fn tokens_that_were_not_issued_here_are_rejected() {
        for bad in ["*", "bm90LW1pbmU", &"A".repeat(6000)] {
            assert!(Continuation::parse(bad).is_err(), "{bad}");
        }
        assert!(Continuation::parse(&URL_SAFE_NO_PAD.encode([0xff, 0xfe])).is_err());
    }
}
