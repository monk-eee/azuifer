//! Tests of permission and ACL parsing, rendering, inheritance and access checks.

use super::*;

fn mode(text: &str) -> Mode {
    Mode::parse(text).unwrap()
}

fn entries(text: &str) -> Vec<Entry> {
    parse_entries(text, Form::Full).unwrap()
}

fn subject(oid: &str) -> Subject<'_> {
    Subject {
        oid: Some(oid),
        groups: &[],
    }
}

#[test]
fn permissions_parse_in_symbolic_and_octal_form_and_render_back() {
    assert_eq!(mode("rwxr-x---").octal(), "0750");
    assert_eq!(mode("0750"), mode("rwxr-x---"));
    assert_eq!(mode("750"), mode("0750"));
    assert_eq!(mode("rwxr-x---+"), mode("0750"));
    assert_eq!(mode("0640").render(), "rw-r-----");
    assert_eq!(mode("1766").render(), "rwxrw-rwT");
    assert_eq!(mode("rwxrw-rwt").octal(), "1767");
    assert_eq!(mode("rwxrw-rwT").octal(), "1766");
    assert_eq!(mode("rwxrw-rwT").render(), "rwxrw-rwT");
    for bad in [
        "",
        "rwx",
        "0888",
        "2750",
        "rwxr-x--q",
        "07500",
        "rwxrwxrwxx",
    ] {
        assert!(Mode::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_umask_removes_rights_from_the_requested_mode() {
    let umask = mode("0057");
    assert_eq!(mode("0777").without(umask).octal(), "0720");
    assert_eq!(
        Mode::creation(PathKind::File).without(default_umask()),
        mode("0640")
    );
    assert_eq!(
        Mode::creation(PathKind::Directory).without(default_umask()),
        mode("0750")
    );
}

#[test]
fn acl_entries_parse_render_and_reject_malformed_text() {
    let parsed = entries(
        "user::rwx,user:abc@contoso.com:r-x,group::r--,mask::rwx,other::---,default:user::rwx",
    );
    assert_eq!(parsed.len(), 6);
    assert_eq!(parsed[5].scope, Scope::Default);
    for bad in [
        "user:rwx",
        "bogus::rwx",
        "user::rwz",
        "mask:x:rwx",
        "user::rwx,",
        "user::rwx::",
    ] {
        assert!(parse_entries(bad, Form::Full).is_err(), "{bad}");
    }
    let removal = parse_entries("user:abc,default:group:def", Form::Removal).unwrap();
    assert_eq!(removal[1].scope, Scope::Default);
    assert!(removal.iter().all(|entry| entry.perms.is_none()));
    let many = (0..33)
        .map(|n| format!("user:u{n}:r--"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_entries(&many, Form::Full).is_err());
}

#[test]
fn a_new_path_starts_with_the_documented_defaults() {
    let file = Attributes::initial(PathKind::File);
    assert_eq!(file.mode().render(), "rw-r-----");
    assert_eq!(file.acl_text(), "user::rw-,group::r--,other::---");
    let directory = Attributes::initial(PathKind::Directory);
    assert_eq!(directory.mode().render(), "rwxr-x---");
    assert_eq!(directory.owner, SUPERUSER);
}

#[test]
fn named_entries_add_a_mask_that_the_group_class_shows() {
    let mut attributes = Attributes::initial(PathKind::File);
    attributes.replace_acl(
        &entries("user::rw-,user:alice:rwx,group::r--,other::---"),
        PathKind::File,
    );
    assert_eq!(
        attributes.acl_text(),
        "user::rw-,user:alice:rwx,group::r--,mask::rwx,other::---"
    );
    assert_eq!(attributes.mode().render(), "rw-rwx---");
    assert!(attributes.permits(&subject("alice"), Perms::READ));
    attributes.replace_acl(
        &entries("user::rw-,user:alice:rwx,group::r--,mask::r--,other::---"),
        PathKind::File,
    );
    assert!(attributes.permits(&subject("alice"), Perms::READ));
    assert!(!attributes.permits(&subject("alice"), Perms::WRITE));
}

#[test]
fn access_checks_follow_owner_named_user_group_then_other() {
    let mut attributes = Attributes::initial(PathKind::File);
    attributes.owner = "owner".into();
    attributes.group = "team".into();
    attributes.replace_acl(
        &entries("user::rw-,user:alice:r--,group::r-x,other::---"),
        PathKind::File,
    );
    assert!(attributes.permits(&subject("owner"), Perms::READ.union(Perms::WRITE)));
    assert!(!attributes.permits(&subject("owner"), Perms::EXECUTE));
    assert!(attributes.permits(&subject("alice"), Perms::READ));
    assert!(!attributes.permits(&subject("alice"), Perms::WRITE));
    // The mask is r-x (group r-x with alice r--), so alice cannot execute.
    assert!(!attributes.permits(&subject("alice"), Perms::EXECUTE));
    assert!(attributes.permits(&subject("team"), Perms::READ));
    assert!(!attributes.permits(&subject("stranger"), Perms::READ));
    let anonymous = Subject {
        oid: None,
        groups: &["team"],
    };
    assert!(attributes.permits(&anonymous, Perms::READ.union(Perms::EXECUTE)));
    assert!(!attributes.permits(&anonymous, Perms::WRITE));
}

#[test]
fn chmod_changes_the_mask_when_named_entries_exist() {
    let mut attributes = Attributes::initial(PathKind::Directory);
    attributes.replace_acl(
        &entries("user::rwx,user:alice:rwx,group::r-x,other::---"),
        PathKind::Directory,
    );
    attributes.set_mode(mode("0710"));
    assert_eq!(attributes.mode().render(), "rwx--x---");
    assert!(attributes.acl_text().contains("group::r-x"));
    assert!(attributes.acl_text().contains("mask::--x"));
    assert!(!attributes.permits(&subject("alice"), Perms::READ));
    let mut plain = Attributes::initial(PathKind::File);
    plain.set_mode(mode("1777"));
    assert_eq!(plain.mode().render(), "rwxrwxrwt");
}

#[test]
fn default_acls_are_inherited_and_limited_by_the_requested_mode_not_the_umask() {
    let mut parent = Attributes::initial(PathKind::Directory);
    parent.replace_acl(
        &entries(
            "user::rwx,group::r-x,other::---,default:user::rwx,default:user:alice:rwx,default:group::r-x,default:other::r-x",
        ),
        PathKind::Directory,
    );
    let file = Attributes::inherit(&parent, PathKind::File, &Creation::default()).unwrap();
    assert_eq!(
        file.acl_text(),
        "user::rw-,user:alice:rwx,group::r-x,mask::rw-,other::r--"
    );
    assert!(!file.has_default());
    let directory =
        Attributes::inherit(&parent, PathKind::Directory, &Creation::default()).unwrap();
    assert!(directory.has_default());
    assert_eq!(directory.mode().render(), "rwxrwxr-x");
    assert!(directory.acl_text().ends_with("default:other::r-x"));
}

#[test]
fn without_a_default_acl_the_umask_applies_and_an_explicit_acl_replaces_everything() {
    let parent = Attributes::initial(PathKind::Directory);
    let create = |creation: Creation, kind| Attributes::inherit(&parent, kind, &creation).unwrap();
    assert_eq!(
        create(Creation::default(), PathKind::File).mode().render(),
        "rw-r-----"
    );
    let open = create(
        Creation {
            permissions: Some(mode("0777")),
            umask: Some(mode("0022")),
            ..Creation::default()
        },
        PathKind::Directory,
    );
    assert_eq!(open.mode().render(), "rwxr-xr-x");
    let explicit = create(
        Creation {
            acl: Some(entries("user::rwx,group::---,other::r--,default:user::rwx")),
            ..Creation::default()
        },
        PathKind::Directory,
    );
    assert_eq!(explicit.mode().render(), "rwx---r--");
    assert!(explicit.has_default());
    let owned = create(
        Creation {
            owner: Some("me".into()),
            group: Some("us".into()),
            ..Creation::default()
        },
        PathKind::File,
    );
    assert_eq!((owned.owner.as_str(), owned.group.as_str()), ("me", "us"));
}

#[test]
fn modify_and_remove_edit_named_entries_and_keep_the_rest() {
    let mut attributes = Attributes::initial(PathKind::Directory);
    attributes.modify_acl(
        &entries("user:alice:r-x,default:user:bob:rw-"),
        PathKind::Directory,
    );
    assert_eq!(
        attributes.acl_text(),
        "user::rwx,user:alice:r-x,group::r-x,mask::r-x,other::---,\
         default:user::rwx,default:user:bob:rw-,default:group::r-x,default:mask::rwx,default:other::---"
    );
    attributes.modify_acl(&entries("user:alice:rwx"), PathKind::Directory);
    assert!(attributes.acl_text().contains("user:alice:rwx,"));
    attributes.remove_acl(&parse_entries("user:alice,default:user:bob", Form::Removal).unwrap());
    assert_eq!(
        attributes.acl_text(),
        "user::rwx,group::r-x,other::---,default:user::rwx,default:group::r-x,default:other::---"
    );
    let mut file = Attributes::initial(PathKind::File);
    file.modify_acl(&entries("default:user:bob:rwx"), PathKind::File);
    assert!(!file.has_default(), "files hold no default ACL");
}

#[test]
fn stored_attributes_round_trip_through_their_columns() {
    let mut attributes = Attributes::initial(PathKind::Directory);
    attributes.owner = "owner".into();
    attributes.replace_acl(
        &entries("user::rwx,user:alice:r-x,group::r-x,other::---,default:group::rwx"),
        PathKind::Directory,
    );
    attributes.set_mode(mode("1750"));
    let sticky = attributes.mode().sticky;
    let back = Attributes::stored(
        PathKind::Directory,
        &attributes.owner,
        "",
        &attributes.acl_text(),
        sticky,
    )
    .unwrap();
    assert_eq!(back.acl_text(), attributes.acl_text());
    assert_eq!(back.mode(), attributes.mode());
    let untouched = Attributes::stored(PathKind::File, "", "", "", false).unwrap();
    assert_eq!(untouched, Attributes::initial(PathKind::File));
}
