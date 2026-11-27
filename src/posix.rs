//! POSIX permissions and access control lists of hierarchical-namespace paths (ADR-0020).
//!
//! These are plain values: parsing and rendering of the `x-ms-permissions`, `x-ms-umask`
//! and `x-ms-acl` forms, ACL edits (set, modify, remove), default-ACL inheritance with the
//! umask, and the POSIX.1e access check. Storage and HTTP live elsewhere.

use crate::domain::{Error, Result, xml_safe};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

/// The owner and owning group of a path nobody has chown-ed.
pub(crate) const SUPERUSER: &str = "$superuser";

/// Azure accepts at most 32 entries in each of the access and default ACLs.
const MAX_ENTRIES: usize = 32;
const MAX_ID: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Perms(u8);

impl Perms {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const READ: Self = Self(4);
    pub(crate) const WRITE: Self = Self(2);
    pub(crate) const EXECUTE: Self = Self(1);
    pub(crate) const ALL: Self = Self(7);

    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The three-character `rwx` form, with `-` for each missing right.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let [r, w, x] = text.as_bytes() else {
            return Err(Error::InvalidHeader);
        };
        let bit = |byte: u8, letter: u8, value: u8| match byte {
            b'-' => Ok(0),
            b if b == letter => Ok(value),
            _ => Err(Error::InvalidHeader),
        };
        Ok(Self(
            bit(*r, b'r', 4)? | bit(*w, b'w', 2)? | bit(*x, b'x', 1)?,
        ))
    }

    fn symbols(self) -> String {
        [(4, 'r'), (2, 'w'), (1, 'x')]
            .iter()
            .map(|(bit, letter)| if self.0 & bit != 0 { *letter } else { '-' })
            .collect()
    }
}

/// Owner, group and other rights plus the sticky bit, as `x-ms-permissions` shows them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mode {
    pub(crate) owner: Perms,
    pub(crate) group: Perms,
    pub(crate) other: Perms,
    pub(crate) sticky: bool,
}

impl Mode {
    /// The default creation mode of a file (0666) or directory (0777).
    pub(crate) fn creation(kind: PathKind) -> Self {
        let rights = match kind {
            PathKind::File => Perms::READ.union(Perms::WRITE),
            PathKind::Directory => Perms::ALL,
        };
        Self {
            owner: rights,
            group: rights,
            other: rights,
            sticky: false,
        }
    }

    /// Symbolic (`rwxr-x--T`) or octal (`0750`, `750`) notation.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        if text.is_ascii() && (text.len() == 9 || text.len() == 10 && text.ends_with('+')) {
            return Self::parse_symbolic(&text[..9]);
        }
        let digits: Vec<u8> = text
            .bytes()
            .map(|byte| match byte {
                b'0'..=b'7' => Ok(byte - b'0'),
                _ => Err(Error::InvalidHeader),
            })
            .collect::<Result<_>>()?;
        let (sticky, rights): (bool, &[u8]) = match digits.as_slice() {
            rights if rights.len() == 3 => (false, rights),
            [0, rights @ ..] if rights.len() == 3 => (false, rights),
            [1, rights @ ..] if rights.len() == 3 => (true, rights),
            _ => return Err(Error::InvalidHeader),
        };
        Ok(Self {
            owner: Perms(rights[0]),
            group: Perms(rights[1]),
            other: Perms(rights[2]),
            sticky,
        })
    }

    fn parse_symbolic(text: &str) -> Result<Self> {
        let sticky_slot = text.as_bytes().get(8).copied().unwrap_or(b'-');
        let sticky = matches!(sticky_slot, b't' | b'T');
        let other_text = match sticky_slot {
            b't' => format!("{}x", &text[6..8]),
            b'T' => format!("{}-", &text[6..8]),
            _ => text[6..9].to_owned(),
        };
        Ok(Self {
            owner: Perms::parse(&text[0..3])?,
            group: Perms::parse(&text[3..6])?,
            other: Perms::parse(&other_text)?,
            sticky,
        })
    }

    /// `rwxr-x---`, with `t` or `T` in the last place when the sticky bit is set.
    pub(crate) fn render(self) -> String {
        let mut text = format!(
            "{}{}{}",
            self.owner.symbols(),
            self.group.symbols(),
            self.other.symbols()
        );
        if self.sticky {
            let last = if self.other.contains(Perms::EXECUTE) {
                't'
            } else {
                'T'
            };
            text.pop();
            text.push(last);
        }
        text
    }

    /// The octal form, such as `0750`, with the sticky bit as the first digit.
    #[cfg(test)]
    pub(crate) fn octal(self) -> String {
        let digit = |perms: Perms| perms.0;
        format!(
            "{}{}{}{}",
            u8::from(self.sticky),
            digit(self.owner),
            digit(self.group),
            digit(self.other)
        )
    }

    /// `permission & !umask`, the rights a new path keeps.
    fn without(self, umask: Self) -> Self {
        Self {
            owner: Perms(self.owner.0 & !umask.owner.0),
            group: Perms(self.group.0 & !umask.group.0),
            other: Perms(self.other.0 & !umask.other.0),
            sticky: self.sticky && !umask.sticky,
        }
    }
}

/// Whether the path is a file or a directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    Access,
    Default,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tag {
    User,
    Group,
    Mask,
    Other,
}

/// One entry of an `x-ms-acl` value. `perms` is absent in the removal form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) scope: Scope,
    pub(crate) tag: Tag,
    pub(crate) id: Option<String>,
    pub(crate) perms: Option<Perms>,
}

/// Whether the entries of an ACL list carry permissions.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Form {
    /// `[default:]type:id:rwx`, to set or modify.
    Full,
    /// `[default:]type:id`, to remove.
    Removal,
}

impl Entry {
    fn parse(text: &str, form: Form) -> Result<Self> {
        let mut parts: Vec<&str> = text.trim().split(':').collect();
        let scope = if parts.first() == Some(&"default") {
            parts.remove(0);
            Scope::Default
        } else {
            Scope::Access
        };
        let (tag, id, perms) = match (parts.as_slice(), form) {
            ([tag, id, perms], Form::Full) => (*tag, *id, Some(Perms::parse(perms)?)),
            ([tag, id], Form::Removal) | ([tag, id, ""], Form::Removal) => (*tag, *id, None),
            _ => return Err(Error::InvalidHeader),
        };
        let tag = match tag {
            "user" => Tag::User,
            "group" => Tag::Group,
            "mask" => Tag::Mask,
            "other" => Tag::Other,
            _ => return Err(Error::InvalidHeader),
        };
        let id = if id.is_empty() {
            None
        } else if id.len() > MAX_ID || !xml_safe(id) || id.contains(',') {
            return Err(Error::InvalidHeader);
        } else {
            Some(id.to_owned())
        };
        if matches!(tag, Tag::Mask | Tag::Other) && id.is_some() {
            return Err(Error::InvalidHeader);
        }
        Ok(Self {
            scope,
            tag,
            id,
            perms,
        })
    }

    fn render(&self) -> String {
        let tag = match self.tag {
            Tag::User => "user",
            Tag::Group => "group",
            Tag::Mask => "mask",
            Tag::Other => "other",
        };
        let scope = match self.scope {
            Scope::Access => "",
            Scope::Default => "default:",
        };
        format!(
            "{scope}{tag}:{}:{}",
            self.id.as_deref().unwrap_or_default(),
            self.perms.map(Perms::symbols).unwrap_or_default()
        )
    }
}

/// Parses a comma-separated `x-ms-acl` list.
pub(crate) fn parse_entries(text: &str, form: Form) -> Result<Vec<Entry>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<Entry> = text
        .split(',')
        .map(|part| Entry::parse(part, form))
        .collect::<Result<_>>()?;
    for scope in [Scope::Access, Scope::Default] {
        if entries.iter().filter(|entry| entry.scope == scope).count() > MAX_ENTRIES {
            return Err(Error::InvalidHeader);
        }
    }
    Ok(entries)
}

/// The access (or default) ACL of one path: the three base entries, an optional
/// mask, and named users and groups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Acl {
    owner: Perms,
    group: Perms,
    other: Perms,
    mask: Option<Perms>,
    users: BTreeMap<String, Perms>,
    groups: BTreeMap<String, Perms>,
}

/// Who is asking, for an access check.
pub(crate) struct Subject<'a> {
    pub(crate) oid: Option<&'a str>,
    /// Groups the caller belongs to; the token does not carry them, so this is
    /// empty unless a test or a future directory lookup supplies them.
    pub(crate) groups: &'a [&'a str],
}

impl Acl {
    fn base(mode: Mode) -> Self {
        Self {
            owner: mode.owner,
            group: mode.group,
            other: mode.other,
            mask: None,
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }

    fn has_named(&self) -> bool {
        !self.users.is_empty() || !self.groups.is_empty()
    }

    /// The group class `x-ms-permissions` shows: the mask when there is one.
    fn group_class(&self) -> Perms {
        self.mask.unwrap_or(self.group)
    }

    fn mode(&self, sticky: bool) -> Mode {
        Mode {
            owner: self.owner,
            group: self.group_class(),
            other: self.other,
            sticky,
        }
    }

    fn compute_mask(&mut self) {
        let named = self
            .users
            .values()
            .chain(self.groups.values())
            .fold(self.group, |all, perms| all.union(*perms));
        self.mask = Some(named);
    }

    fn put(&mut self, entry: &Entry) {
        let Some(perms) = entry.perms else { return };
        match (entry.tag, &entry.id) {
            (Tag::User, None) => self.owner = perms,
            (Tag::Group, None) => self.group = perms,
            (Tag::Other, _) => self.other = perms,
            (Tag::Mask, _) => self.mask = Some(perms),
            (Tag::User, Some(id)) => {
                self.users.insert(id.clone(), perms);
            }
            (Tag::Group, Some(id)) => {
                self.groups.insert(id.clone(), perms);
            }
        }
    }

    /// Replaces the ACL with the given entries; base entries the list omits keep
    /// their rights. A missing mask is computed when named entries exist.
    fn replaced(&self, entries: &[&Entry]) -> Self {
        let mut acl = Self {
            mask: None,
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
            ..self.clone()
        };
        for entry in entries {
            acl.put(entry);
        }
        if acl.has_named() && acl.mask.is_none() {
            acl.compute_mask();
        }
        acl
    }

    /// Adds or replaces the given entries and keeps the others. The mask is
    /// recomputed unless the list supplies one.
    fn modified(&self, entries: &[&Entry]) -> Self {
        let mut acl = self.clone();
        for entry in entries {
            acl.put(entry);
        }
        let given = entries.iter().any(|entry| entry.tag == Tag::Mask);
        if acl.has_named() && !given {
            acl.compute_mask();
        }
        acl
    }

    /// Drops the named entries the list names; base entries cannot be removed.
    fn removed(&self, entries: &[&Entry]) -> Self {
        let mut acl = self.clone();
        for entry in entries {
            match (entry.tag, &entry.id) {
                (Tag::User, Some(id)) => {
                    acl.users.remove(id);
                }
                (Tag::Group, Some(id)) => {
                    acl.groups.remove(id);
                }
                _ => (),
            }
        }
        if acl.has_named() {
            acl.compute_mask();
        } else {
            acl.mask = None;
        }
        acl
    }

    fn render(&self, scope: Scope) -> Vec<String> {
        let entry = |tag, id: Option<&String>, perms| Entry {
            scope,
            tag,
            id: id.cloned(),
            perms: Some(perms),
        };
        let mut entries = vec![entry(Tag::User, None, self.owner)];
        entries.extend(
            self.users
                .iter()
                .map(|(id, perms)| entry(Tag::User, Some(id), *perms)),
        );
        entries.push(entry(Tag::Group, None, self.group));
        entries.extend(
            self.groups
                .iter()
                .map(|(id, perms)| entry(Tag::Group, Some(id), *perms)),
        );
        if let Some(mask) = self.mask {
            entries.push(entry(Tag::Mask, None, mask));
        }
        entries.push(entry(Tag::Other, None, self.other));
        entries.iter().map(Entry::render).collect()
    }

    /// The POSIX.1e algorithm: the owner entry, else a named user entry limited by
    /// the mask, else the matching group entries limited by the mask, else other.
    fn permits(&self, owns: bool, in_group: bool, subject: &Subject<'_>, wanted: Perms) -> bool {
        if owns {
            return self.owner.contains(wanted);
        }
        let mask = self.mask.unwrap_or(Perms::ALL);
        if let Some(perms) = subject.oid.and_then(|oid| self.users.get(oid)) {
            return perms.intersect(mask).contains(wanted);
        }
        let mut matched = false;
        let mut granted = false;
        if in_group {
            matched = true;
            granted |= self.group.intersect(mask).contains(wanted);
        }
        for (name, perms) in &self.groups {
            if subject.groups.contains(&name.as_str()) {
                matched = true;
                granted |= perms.intersect(mask).contains(wanted);
            }
        }
        if matched {
            return granted;
        }
        self.other.contains(wanted)
    }
}

/// Owner, group, sticky bit, access ACL and (for directories) default ACL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Attributes {
    pub(crate) owner: String,
    pub(crate) group: String,
    sticky: bool,
    access: Acl,
    default: Option<Acl>,
}

/// What a create request says about the new path's rights.
#[derive(Clone, Default)]
pub(crate) struct Creation {
    pub(crate) permissions: Option<Mode>,
    pub(crate) umask: Option<Mode>,
    pub(crate) acl: Option<Vec<Entry>>,
    pub(crate) owner: Option<String>,
    pub(crate) group: Option<String>,
}

/// The umask Azure applies when a request does not name one.
fn default_umask() -> Mode {
    Mode {
        owner: Perms::NONE,
        group: Perms::WRITE,
        other: Perms::ALL,
        sticky: false,
    }
}

impl Attributes {
    /// The rights of a path nobody changed: `$superuser`, 0640 for a file and 0750
    /// for a directory.
    pub(crate) fn initial(kind: PathKind) -> Self {
        let mode = Mode::creation(kind).without(default_umask());
        Self {
            owner: SUPERUSER.to_owned(),
            group: SUPERUSER.to_owned(),
            sticky: false,
            access: Acl::base(mode),
            default: None,
        }
    }

    pub(crate) fn mode(&self) -> Mode {
        self.access.mode(self.sticky)
    }

    #[cfg(test)]
    pub(crate) fn has_default(&self) -> bool {
        self.default.is_some()
    }

    /// The rights of a path created under `parent` (ADR-0020): a default ACL on
    /// the parent is inherited and limited by the requested mode, otherwise the
    /// umask limits it. An explicit ACL replaces both.
    pub(crate) fn inherit(parent: &Self, kind: PathKind, creation: &Creation) -> Result<Self> {
        let requested = creation.permissions.unwrap_or_else(|| Mode::creation(kind));
        let mut attributes = Self {
            owner: creation
                .owner
                .clone()
                .unwrap_or_else(|| SUPERUSER.to_owned()),
            group: creation
                .group
                .clone()
                .unwrap_or_else(|| parent.group.clone()),
            sticky: requested.sticky,
            access: Acl::base(requested.without(creation.umask.unwrap_or_else(default_umask))),
            default: None,
        };
        if let Some(inherited) = &parent.default {
            let mut access = inherited.clone();
            access.owner = access.owner.intersect(requested.owner);
            access.other = access.other.intersect(requested.other);
            match &mut access.mask {
                Some(mask) => *mask = mask.intersect(requested.group),
                None => access.group = access.group.intersect(requested.group),
            }
            attributes.access = access;
            if kind == PathKind::Directory {
                attributes.default = Some(inherited.clone());
            }
        }
        if let Some(entries) = &creation.acl {
            attributes.replace_acl(entries, kind);
        }
        Ok(attributes)
    }

    /// `x-ms-permissions` on an existing path (chmod): owner and other change, and
    /// the group class changes the mask when named entries exist.
    pub(crate) fn set_mode(&mut self, mode: Mode) {
        self.access.owner = mode.owner;
        self.access.other = mode.other;
        match &mut self.access.mask {
            Some(mask) => *mask = mode.group,
            None => self.access.group = mode.group,
        }
        self.sticky = mode.sticky;
    }

    fn partition(entries: &[Entry]) -> (Vec<&Entry>, Vec<&Entry>) {
        let access = entries
            .iter()
            .filter(|entry| entry.scope == Scope::Access)
            .collect();
        let default = entries
            .iter()
            .filter(|entry| entry.scope == Scope::Default)
            .collect();
        (access, default)
    }

    /// Set Access Control: the given entries replace the ACL. Default entries
    /// only apply to directories.
    pub(crate) fn replace_acl(&mut self, entries: &[Entry], kind: PathKind) {
        let (access, default) = Self::partition(entries);
        let previous = self.access.clone();
        self.access = previous.replaced(&access);
        self.default = (kind == PathKind::Directory && !default.is_empty()).then(|| {
            let base = self
                .default
                .clone()
                .unwrap_or_else(|| previous.replaced(&[]));
            base.replaced(&default)
        });
    }

    /// Recursive `modify`: adds or replaces entries and keeps the rest.
    pub(crate) fn modify_acl(&mut self, entries: &[Entry], kind: PathKind) {
        let (access, default) = Self::partition(entries);
        let previous = self.access.clone();
        self.access = previous.modified(&access);
        if kind == PathKind::Directory && !default.is_empty() {
            let base = self
                .default
                .clone()
                .unwrap_or_else(|| previous.replaced(&[]));
            self.default = Some(base.modified(&default));
        }
    }

    /// Recursive `remove`: drops the named entries.
    pub(crate) fn remove_acl(&mut self, entries: &[Entry]) {
        let (access, default) = Self::partition(entries);
        self.access = self.access.removed(&access);
        if let Some(current) = &self.default {
            self.default = Some(current.removed(&default));
        }
    }

    /// The `x-ms-acl` value: access entries, then `default:` entries.
    pub(crate) fn acl_text(&self) -> String {
        let mut parts = self.access.render(Scope::Access);
        if let Some(default) = &self.default {
            parts.extend(default.render(Scope::Default));
        }
        parts.join(",")
    }

    /// Rebuilds attributes from their stored columns. An empty ACL means the
    /// path was never given one.
    pub(crate) fn stored(
        kind: PathKind,
        owner: &str,
        group: &str,
        acl: &str,
        sticky: bool,
    ) -> Result<Self> {
        let mut attributes = Self::initial(kind);
        if !owner.is_empty() {
            owner.clone_into(&mut attributes.owner);
        }
        if !group.is_empty() {
            group.clone_into(&mut attributes.group);
        }
        attributes.sticky = sticky;
        if !acl.is_empty() {
            let entries = parse_entries(acl, Form::Full).map_err(|_| Error::Internal)?;
            let (access, default) = Self::partition(&entries);
            attributes.access = attributes.access.replaced(&access);
            attributes.default =
                (!default.is_empty()).then(|| attributes.access.replaced(&default));
        }
        Ok(attributes)
    }

    /// Whether `oid` may do `wanted` to this path under its access ACL.
    pub(crate) fn permits(&self, subject: &Subject<'_>, wanted: Perms) -> bool {
        let owns = subject.oid.is_some_and(|oid| oid == self.owner);
        let in_group = subject.oid.is_some_and(|oid| oid == self.group)
            || subject.groups.contains(&self.group.as_str());
        self.access.permits(owns, in_group, subject, wanted)
    }

    pub(crate) fn owned_by(&self, oid: Option<&str>) -> bool {
        oid.is_some_and(|oid| oid == self.owner)
    }
}
