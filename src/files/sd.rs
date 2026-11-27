//! Security descriptors in two forms: the base64 binary self-relative form of MS-DTYP 2.4.6
//! that FileREST 2024-11-04 and later accepts, and the SDDL text Azuifer stores (ADR-0032).
//!
//! Only descriptors with an owner, a group and a DACL of allow or deny entries convert. A
//! SACL, an object, callback or audit entry, or a control flag outside the DACL ones is
//! refused, as is a conversion that cannot be reversed exactly.

use super::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};

const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const DACL_AUTO_INHERITED: u16 = 0x0400;
const DACL_PROTECTED: u16 = 0x1000;
const KNOWN_CONTROL: u16 =
    SELF_RELATIVE | DACL_PRESENT | DACL_AUTO_INHERIT_REQ | DACL_AUTO_INHERITED | DACL_PROTECTED;
const HEADER: usize = 20;
const MAX_ACES: usize = 1000;

const SID_ALIASES: [(&str, &str); 22] = [
    ("SY", "S-1-5-18"),
    ("BA", "S-1-5-32-544"),
    ("BU", "S-1-5-32-545"),
    ("BG", "S-1-5-32-546"),
    ("PU", "S-1-5-32-547"),
    ("SO", "S-1-5-32-549"),
    ("PO", "S-1-5-32-550"),
    ("BO", "S-1-5-32-551"),
    ("RU", "S-1-5-32-554"),
    ("WD", "S-1-1-0"),
    ("CO", "S-1-3-0"),
    ("CG", "S-1-3-1"),
    ("OW", "S-1-3-4"),
    ("NU", "S-1-5-2"),
    ("IU", "S-1-5-4"),
    ("SU", "S-1-5-6"),
    ("AN", "S-1-5-7"),
    ("AU", "S-1-5-11"),
    ("LS", "S-1-5-19"),
    ("NS", "S-1-5-20"),
    ("ED", "S-1-5-9"),
    ("PS", "S-1-5-10"),
];

/// Whole-mask aliases first, then the single-bit ones SDDL also writes.
const RIGHTS: [(&str, u32); 17] = [
    ("FA", 0x001f_01ff),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00a0),
    ("GA", 0x1000_0000),
    ("GR", 0x8000_0000),
    ("GW", 0x4000_0000),
    ("GX", 0x2000_0000),
    ("SD", 0x0001_0000),
    ("RC", 0x0002_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0002),
    ("LC", 0x0000_0004),
    ("SW", 0x0000_0008),
    ("RP", 0x0000_0010),
];

const ACE_FLAGS: [(&str, u8); 5] = [
    ("OI", 0x01),
    ("CI", 0x02),
    ("NP", 0x04),
    ("IO", 0x08),
    ("ID", 0x10),
];

fn invalid<T>() -> Result<T> {
    Err(Error::FileInvalidPermission)
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Reads the SID at `at`, returning its SDDL form and its length in bytes.
fn read_sid(bytes: &[u8], at: usize) -> Result<(String, usize)> {
    let head = bytes.get(at..at + 8).ok_or(Error::FileInvalidPermission)?;
    let count = usize::from(head[1]);
    if head[0] != 1 || count == 0 || count > 15 {
        return invalid();
    }
    let length = 8 + 4 * count;
    let raw = bytes
        .get(at..at + length)
        .ok_or(Error::FileInvalidPermission)?;
    let authority = raw[2..8]
        .iter()
        .fold(0u64, |all, byte| (all << 8) | u64::from(*byte));
    let mut text = if authority < 1 << 32 {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012x}")
    };
    for chunk in raw[8..].as_chunks::<4>().0 {
        let value = u32::from_le_bytes(*chunk);
        text.push_str(&format!("-{value}"));
    }
    let alias = SID_ALIASES.iter().find(|(_, sid)| *sid == text);
    Ok((alias.map_or(text, |(name, _)| (*name).to_owned()), length))
}

fn write_sid(text: &str, out: &mut Vec<u8>) -> Result<()> {
    let text = SID_ALIASES
        .iter()
        .find(|(name, _)| *name == text)
        .map_or(text, |(_, sid)| *sid);
    let mut parts = text.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return invalid();
    }
    let authority = parts.next().ok_or(Error::FileInvalidPermission)?;
    let authority = match authority.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => authority.parse(),
    }
    .map_err(|_| Error::FileInvalidPermission)?;
    if authority >= 1 << 48 {
        return invalid();
    }
    let subs = parts
        .map(|part| {
            part.parse::<u32>()
                .map_err(|_| Error::FileInvalidPermission)
        })
        .collect::<Result<Vec<_>>>()?;
    if subs.is_empty() || subs.len() > 15 {
        return invalid();
    }
    out.extend([
        1,
        u8::try_from(subs.len()).map_err(|_| Error::FileInvalidPermission)?,
    ]);
    out.extend(&authority.to_be_bytes()[2..]);
    for sub in subs {
        out.extend(sub.to_le_bytes());
    }
    Ok(())
}

fn rights_text(mask: u32) -> String {
    match RIGHTS.iter().take(4).find(|(_, value)| *value == mask) {
        Some((name, _)) => (*name).to_owned(),
        None => format!("0x{mask:x}"),
    }
}

fn parse_rights(text: &str) -> Result<u32> {
    if let Some(hex) = text.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).map_err(|_| Error::FileInvalidPermission);
    }
    if text.is_empty() || !text.len().is_multiple_of(2) || !text.is_ascii() {
        return invalid();
    }
    let mut mask = 0;
    for pair in text.as_bytes().chunks(2) {
        let name = std::str::from_utf8(pair).map_err(|_| Error::FileInvalidPermission)?;
        let (_, value) = RIGHTS
            .iter()
            .find(|(alias, _)| *alias == name)
            .ok_or(Error::FileInvalidPermission)?;
        mask |= value;
    }
    Ok(mask)
}

/// The SDDL of a base64 binary self-relative security descriptor.
pub(super) fn sddl_from_binary(text: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| Error::FileInvalidPermission)?;
    let control = le16(&bytes, 2).ok_or(Error::FileInvalidPermission)?;
    let offset = |at| le32(&bytes, at).and_then(|value| usize::try_from(value).ok());
    let (owner, group, sacl, dacl) = (
        offset(4).ok_or(Error::FileInvalidPermission)?,
        offset(8).ok_or(Error::FileInvalidPermission)?,
        offset(12).ok_or(Error::FileInvalidPermission)?,
        offset(16).ok_or(Error::FileInvalidPermission)?,
    );
    if bytes[0] != 1
        || control & SELF_RELATIVE == 0
        || control & DACL_PRESENT == 0
        || control & !KNOWN_CONTROL != 0
        || sacl != 0
        || owner < HEADER
        || group < HEADER
        || dacl < HEADER
    {
        return invalid();
    }
    let (owner, _) = read_sid(&bytes, owner)?;
    let (group, _) = read_sid(&bytes, group)?;
    let acl = bytes
        .get(dacl..dacl + 8)
        .ok_or(Error::FileInvalidPermission)?;
    let size = usize::from(le16(acl, 2).ok_or(Error::FileInvalidPermission)?);
    let count = usize::from(le16(acl, 4).ok_or(Error::FileInvalidPermission)?);
    if !matches!(acl[0], 2 | 4) || size < 8 || count > MAX_ACES {
        return invalid();
    }
    let body = bytes
        .get(dacl..dacl + size)
        .ok_or(Error::FileInvalidPermission)?;
    let mut text = format!("O:{owner}G:{group}D:");
    for (flag, name) in [
        (DACL_PROTECTED, "P"),
        (DACL_AUTO_INHERIT_REQ, "AR"),
        (DACL_AUTO_INHERITED, "AI"),
    ] {
        if control & flag != 0 {
            text.push_str(name);
        }
    }
    let mut at = 8;
    for _ in 0..count {
        let head = body.get(at..at + 8).ok_or(Error::FileInvalidPermission)?;
        let (kind, flags) = (head[0], head[1]);
        let ace_size = usize::from(le16(head, 2).ok_or(Error::FileInvalidPermission)?);
        let mask = le32(head, 4).ok_or(Error::FileInvalidPermission)?;
        let known: u8 = ACE_FLAGS.iter().fold(0, |all, (_, bit)| all | bit);
        if kind > 1 || flags & !known != 0 {
            return Err(Error::CannotConvertToSddlDueToCustomAce);
        }
        let (sid, length) = read_sid(body, at + 8)?;
        if ace_size != 8 + length {
            return invalid();
        }
        let flags: String = ACE_FLAGS
            .iter()
            .filter(|(_, bit)| flags & bit != 0)
            .map(|(name, _)| *name)
            .collect();
        text.push_str(&format!(
            "({};{flags};{};;;{sid})",
            if kind == 0 { "A" } else { "D" },
            rights_text(mask)
        ));
        at += ace_size;
    }
    if at != size {
        return invalid();
    }
    Ok(text)
}

/// The base64 binary self-relative form of an SDDL string with the same restrictions.
pub(super) fn binary_from_sddl(sddl: &str) -> Result<String> {
    let rest = sddl
        .strip_prefix("O:")
        .ok_or(Error::FileInvalidPermission)?;
    let (owner, rest) = rest.split_once("G:").ok_or(Error::FileInvalidPermission)?;
    let (group, dacl) = rest.split_once("D:").ok_or(Error::FileInvalidPermission)?;
    let letters = dacl.find('(').unwrap_or(dacl.len());
    let (flags, aces) = dacl.split_at(letters);
    let mut control = SELF_RELATIVE | DACL_PRESENT;
    let mut remaining = flags;
    for (name, flag) in [
        ("P", DACL_PROTECTED),
        ("AR", DACL_AUTO_INHERIT_REQ),
        ("AI", DACL_AUTO_INHERITED),
    ] {
        if let Some(after) = remaining.strip_prefix(name) {
            control |= flag;
            remaining = after;
        }
    }
    if !remaining.is_empty() {
        return invalid();
    }
    let mut entries: Vec<u8> = Vec::new();
    let mut count = 0u16;
    let mut rest = aces;
    while !rest.is_empty() {
        let inner = rest.strip_prefix('(').ok_or(Error::FileInvalidPermission)?;
        let (ace, after) = inner.split_once(')').ok_or(Error::FileInvalidPermission)?;
        rest = after;
        let fields: Vec<&str> = ace.split(';').collect();
        let [kind, flags, rights, object, inherited, sid] = fields[..] else {
            return invalid();
        };
        if !object.is_empty() || !inherited.is_empty() || usize::from(count) == MAX_ACES {
            return invalid();
        }
        let kind: u8 = match kind {
            "A" => 0,
            "D" => 1,
            _ => return invalid(),
        };
        let mut bits = 0u8;
        let mut left = flags;
        while !left.is_empty() {
            let (_, bit) = ACE_FLAGS
                .iter()
                .find(|(name, _)| left.starts_with(name))
                .ok_or(Error::FileInvalidPermission)?;
            bits |= bit;
            left = &left[2..];
        }
        let mut sid_bytes = Vec::new();
        write_sid(sid, &mut sid_bytes)?;
        let size = u16::try_from(8 + sid_bytes.len()).map_err(|_| Error::FileInvalidPermission)?;
        entries.extend([kind, bits]);
        entries.extend(size.to_le_bytes());
        entries.extend(parse_rights(rights)?.to_le_bytes());
        entries.extend(sid_bytes);
        count += 1;
    }
    let acl_size = u16::try_from(8 + entries.len()).map_err(|_| Error::FileInvalidPermission)?;
    let (mut owner_bytes, mut group_bytes) = (Vec::new(), Vec::new());
    write_sid(owner, &mut owner_bytes)?;
    write_sid(group, &mut group_bytes)?;
    let owner_at = HEADER + usize::from(acl_size);
    let group_at = owner_at + owner_bytes.len();
    let to_u32 = |value: usize| u32::try_from(value).map_err(|_| Error::FileInvalidPermission);
    let mut out = vec![1, 0];
    out.extend(control.to_le_bytes());
    out.extend(to_u32(owner_at)?.to_le_bytes());
    out.extend(to_u32(group_at)?.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(to_u32(HEADER)?.to_le_bytes());
    out.extend([2, 0]);
    out.extend(acl_size.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend([0, 0]);
    out.extend(entries);
    out.extend(owner_bytes);
    out.extend(group_bytes);
    Ok(STANDARD.encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = "O:SYG:SYD:(A;;FA;;;SY)";

    fn simple_binary() -> Vec<u8> {
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut bytes = vec![1, 0, 0x04, 0x80];
        bytes.extend(48u32.to_le_bytes());
        bytes.extend(60u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(20u32.to_le_bytes());
        bytes.extend([2, 0, 28, 0, 1, 0, 0, 0]);
        bytes.extend([0, 0, 20, 0]);
        bytes.extend(0x001f_01ffu32.to_le_bytes());
        bytes.extend(sid);
        bytes.extend(sid);
        bytes.extend(sid);
        bytes
    }

    #[test]
    fn a_known_descriptor_converts_both_ways() {
        let binary = STANDARD.encode(simple_binary());
        assert_eq!(sddl_from_binary(&binary).as_deref(), Ok(SIMPLE));
        assert_eq!(binary_from_sddl(SIMPLE), Ok(binary));
    }

    #[test]
    fn descriptors_with_many_entries_and_flags_round_trip() {
        let sddl = "O:S-1-5-21-1-2-3-4G:BAD:PAI(A;OICI;FA;;;SY)(D;CIIO;0x1200a9;;;S-1-5-21-1-2-3-500)(A;;FRFX;;;WD)";
        let binary = binary_from_sddl(sddl).unwrap();
        let back = sddl_from_binary(&binary).unwrap();
        assert_eq!(
            back,
            "O:S-1-5-21-1-2-3-4G:BAD:PAI(A;OICI;FA;;;SY)(D;CIIO;0x1200a9;;;S-1-5-21-1-2-3-500)(A;;0x1200a9;;;WD)"
        );
        assert_eq!(binary_from_sddl(&back).unwrap(), binary);
    }

    #[test]
    fn descriptors_that_do_not_convert_are_refused() {
        let mut sacl = simple_binary();
        sacl[12] = 20;
        let mut object_ace = simple_binary();
        object_ace[20 + 8] = 5;
        let mut no_dacl = simple_binary();
        no_dacl[2] = 0;
        for (text, error) in [
            (STANDARD.encode(&sacl), Error::FileInvalidPermission),
            (STANDARD.encode(&no_dacl), Error::FileInvalidPermission),
            (
                STANDARD.encode(&object_ace),
                Error::CannotConvertToSddlDueToCustomAce,
            ),
            (
                STANDARD.encode(&simple_binary()[..30]),
                Error::FileInvalidPermission,
            ),
            ("not base64!".to_owned(), Error::FileInvalidPermission),
            (String::new(), Error::FileInvalidPermission),
        ] {
            assert_eq!(sddl_from_binary(&text), Err(error), "{text}");
        }
        for sddl in [
            "junk",
            "O:SYG:SY",
            "O:SYG:SYD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e9;;SY)",
            "O:SYG:SYD:(A;;FA;;;SY",
            "O:SYG:SYD:(A;;ZZ;;;SY)",
            "O:SYG:SYD:(A;;FA;;;XX)",
            "O:SYG:SYD:(AU;;FA;;;SY)",
            "O:SYG:SYS:(AU;;FA;;;SY)D:",
        ] {
            assert_eq!(
                binary_from_sddl(sddl),
                Err(Error::FileInvalidPermission),
                "{sddl}"
            );
        }
    }

    #[test]
    fn hostile_descriptors_are_refused_or_convert_back_exactly() {
        let good = simple_binary();
        let mut forged: Vec<Vec<u8>> = (0..good.len())
            .flat_map(|at| {
                [0x00u8, 0x01, 0x7f, 0x80, 0xff].map(|byte| {
                    let mut bytes = good.clone();
                    bytes[at] = byte;
                    bytes
                })
            })
            .collect();
        forged.extend((0..good.len()).map(|length| good[..length].to_vec()));
        let mut many = good.clone();
        many[24..26].copy_from_slice(&u16::MAX.to_le_bytes());
        forged.push(many);
        let mut huge = vec![1, 0, 0x04, 0x80];
        huge.extend([0xff; 16]);
        forged.push(huge);
        for bytes in forged {
            if let Ok(sddl) = sddl_from_binary(&STANDARD.encode(&bytes)) {
                let back = binary_from_sddl(&sddl).expect("an SDDL it produced converts back");
                assert_eq!(sddl_from_binary(&back).as_deref(), Ok(sddl.as_str()));
            }
        }
        crate::hostile::sweep(
            &[
                "O:S-1-5-21-1-2-3-4G:BAD:PAI(A;OICI;FA;;;SY)(D;CIIO;0x1200a9;;;S-1-5-21-1-2-3-500)(A;;FRFX;;;WD)",
            ],
            ("(A;;FA;;;SY)", ""),
            |text| {
                if let Ok(binary) = binary_from_sddl(text) {
                    assert!(sddl_from_binary(&binary).is_ok(), "{text:?}");
                }
            },
        );
        crate::hostile::sweep(&["AQAEgDA8AAA="], ("A", "="), |text| {
            let _ = sddl_from_binary(text);
        });
    }
}
