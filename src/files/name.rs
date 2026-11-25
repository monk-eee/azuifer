use super::error::{Error, Result};

const MAX_COMPONENT_CHARS: usize = 255;
const MAX_PATH_CHARS: usize = 2048;
const MAX_DEPTH: usize = 250;
const RESERVED: [&str; 24] = [
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM1", "COM2", "COM3",
    "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "PRN", "AUX", "NUL", "CON", "CLOCK$", "..",
];

/// A validated share name: DNS-style, lowercase, 3 to 63 characters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShareName(String);

impl ShareName {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let edge =
            |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        if !(3..=63).contains(&value.len())
            || !edge(value.chars().next())
            || !edge(value.chars().next_back())
            || value.contains("--")
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::InvalidResourceName);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Case-insensitive identity of a directory or file name. Azure compares names with
/// an upper-case fold, so listings sort in the same order.
pub(crate) fn fold(name: &str) -> String {
    name.to_uppercase()
}

/// A path below a share's root directory: validated components in their original case.
/// The empty path is the root directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EntryPath(Vec<String>);

impl EntryPath {
    pub(crate) fn root() -> Self {
        Self(Vec::new())
    }

    /// Parses a decoded `dir/dir/name` path. Trailing dots on a component are dropped
    /// unless `keep_trailing_dots` is set (`x-ms-allow-trailing-dot`), and one trailing
    /// slash is ignored.
    pub(crate) fn parse(value: &str, keep_trailing_dots: bool) -> Result<Self> {
        let value = value.strip_suffix('/').unwrap_or(value);
        if value.is_empty() {
            return Ok(Self::root());
        }
        if value.chars().count() > MAX_PATH_CHARS {
            return Err(Error::InvalidFileOrDirectoryPathName);
        }
        let components = value
            .split('/')
            .map(|component| component_name(component, keep_trailing_dots))
            .collect::<Result<Vec<_>>>()?;
        if components.len() > MAX_DEPTH {
            return Err(Error::InvalidFileOrDirectoryPathName);
        }
        Ok(Self(components))
    }

    pub(crate) fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn components(&self) -> &[String] {
        &self.0
    }

    /// The final component, which is the entry's own name.
    pub(crate) fn name(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    /// True when `self` is `other` or lies below it, ignoring case.
    pub(crate) fn starts_with(&self, other: &Self) -> bool {
        self.0.len() >= other.0.len()
            && self.0.iter().zip(&other.0).all(|(a, b)| fold(a) == fold(b))
    }

    pub(crate) fn joined(&self) -> String {
        self.0.join("/")
    }
}

fn component_name(component: &str, keep_trailing_dots: bool) -> Result<String> {
    let name = if keep_trailing_dots {
        component
    } else {
        component.trim_end_matches('.')
    };
    if name.is_empty() || name == "." {
        return Err(Error::InvalidResourceName);
    }
    if name.chars().count() > MAX_COMPONENT_CHARS {
        return Err(Error::InvalidFileOrDirectoryPathName);
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '"' | '\\' | '/' | ':' | '|' | '<' | '>' | '*' | '?')
    }) {
        return Err(Error::InvalidResourceName);
    }
    if RESERVED.contains(&fold(name).as_str()) {
        return Err(Error::InvalidResourceName);
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_names_follow_dns_rules() {
        for good in ["abc", "my-share", "a1b", &"a".repeat(63)] {
            assert!(ShareName::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "ab",
            "My-share",
            "-abc",
            "abc-",
            "a--b",
            "a_b",
            "",
            &"a".repeat(64),
        ] {
            assert_eq!(
                ShareName::parse(bad),
                Err(Error::InvalidResourceName),
                "{bad}"
            );
        }
    }

    #[test]
    fn paths_split_into_validated_components() {
        let path = EntryPath::parse("Docs/Reports/Q1.txt", false).unwrap();
        assert_eq!(path.components(), ["Docs", "Reports", "Q1.txt"]);
        assert_eq!(path.name(), Some("Q1.txt"));
        assert_eq!(path.joined(), "Docs/Reports/Q1.txt");
        assert!(EntryPath::parse("", false).unwrap().is_root());
        assert_eq!(EntryPath::parse("dir/", false).unwrap().joined(), "dir");
    }

    #[test]
    fn invalid_components_are_rejected() {
        for bad in [
            "a//b", "a/./b", "a/../b", "a:b", "a|b", "a*b", "a?b", "a<b", "a\"b", "a\\b", "con",
            "Lpt3", "CLOCK$", "a\u{1}b", "...",
        ] {
            assert_eq!(
                EntryPath::parse(bad, false),
                Err(Error::InvalidResourceName),
                "{bad}"
            );
        }
        assert_eq!(
            EntryPath::parse(&"a".repeat(256), false),
            Err(Error::InvalidFileOrDirectoryPathName)
        );
        assert_eq!(
            EntryPath::parse(&vec!["d"; 251].join("/"), false),
            Err(Error::InvalidFileOrDirectoryPathName)
        );
        assert_eq!(
            EntryPath::parse(&vec!["dddddddddd"; 300].join("/"), false),
            Err(Error::InvalidFileOrDirectoryPathName)
        );
    }

    #[test]
    fn trailing_dots_are_dropped_unless_allowed() {
        assert_eq!(
            EntryPath::parse("a/file1..", false).unwrap().joined(),
            "a/file1"
        );
        assert_eq!(EntryPath::parse("a./b", false).unwrap().joined(), "a/b");
        assert_eq!(
            EntryPath::parse("file1..", true).unwrap().joined(),
            "file1.."
        );
    }

    #[test]
    fn prefix_comparison_ignores_case() {
        let dir = EntryPath::parse("Dir", false).unwrap();
        assert!(
            EntryPath::parse("dir/File", false)
                .unwrap()
                .starts_with(&dir)
        );
        assert!(!EntryPath::parse("other", false).unwrap().starts_with(&dir));
        assert!(dir.starts_with(&EntryPath::root()));
    }

    #[test]
    fn folding_is_case_insensitive() {
        assert_eq!(fold("ReadMe.TXT"), fold("readme.txt"));
    }
}
