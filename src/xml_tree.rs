//! A small XML tree for request bodies that are not worth a streaming parser:
//! service properties and container ACLs. The tree is bounded in depth and size.

use crate::domain::{Error, Result};
use quick_xml::{Reader, events::Event};

const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) text: String,
    /// The text as written, before trimming, for values such as a tab or newline separator.
    pub(crate) raw: String,
    pub(crate) children: Vec<Node>,
}

impl Node {
    pub(crate) fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|child| child.name == name)
    }

    pub(crate) fn named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |child| child.name == name)
    }

    pub(crate) fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.as_str())
    }

    pub(crate) fn flag(&self, name: &str) -> Result<Option<bool>> {
        self.text_of(name)
            .map(|text| match text {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(Error::InvalidXml),
            })
            .transpose()
    }

    pub(crate) fn number(&self, name: &str) -> Result<Option<u32>> {
        self.text_of(name)
            .map(|text| text.parse().map_err(|_| Error::InvalidXml))
            .transpose()
    }
}

pub(crate) fn parse(body: &[u8]) -> Result<Node> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidXml)?;
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut count = 0usize;
    let attach = |node: Node, stack: &mut Vec<Node>, root: &mut Option<Node>| match stack.last_mut()
    {
        Some(parent) => {
            parent.children.push(node);
            Ok(())
        }
        None if root.is_none() => {
            *root = Some(node);
            Ok(())
        }
        None => Err(Error::InvalidXml),
    };
    loop {
        match reader.read_event().map_err(|_| Error::InvalidXml)? {
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => (),
            Event::DocType(_) => return Err(Error::InvalidXml),
            Event::Start(_) | Event::Empty(_) if stack.len() >= MAX_DEPTH || count >= MAX_NODES => {
                return Err(Error::InvalidXml);
            }
            Event::Start(tag) => {
                count += 1;
                stack.push(node_named(tag.name().as_ref()));
            }
            Event::Empty(tag) => {
                count += 1;
                attach(node_named(tag.name().as_ref()), &mut stack, &mut root)?;
            }
            Event::Text(content) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&content.xml10_content());
                } else if !content.xml10_content().trim().is_empty() {
                    return Err(Error::InvalidXml);
                }
            }
            Event::CData(content) => {
                let top = stack.last_mut().ok_or(Error::InvalidXml)?;
                top.text.push_str(&content);
            }
            Event::GeneralRef(reference) => {
                let top = stack.last_mut().ok_or(Error::InvalidXml)?;
                if let Some(ch) = reference
                    .resolve_char_ref()
                    .map_err(|_| Error::InvalidXml)?
                {
                    top.text.push(ch);
                } else {
                    top.text.push(match &*reference {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return Err(Error::InvalidXml),
                    });
                }
            }
            Event::End(_) => {
                let mut node = stack.pop().ok_or(Error::InvalidXml)?;
                node.raw.clone_from(&node.text);
                node.text = node.text.trim().to_owned();
                attach(node, &mut stack, &mut root)?;
            }
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(Error::InvalidXml);
    }
    root.ok_or(Error::InvalidXml)
}

fn node_named(name: &str) -> Node {
    Node {
        name: name.to_owned(),
        ..Node::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_elements_entities_and_empty_tags() {
        let tree = parse(
            b"<?xml version=\"1.0\"?><Root><A>x &amp; y &#65;</A><B/><C><D>1</D><D>2</D></C></Root>",
        )
        .unwrap();
        assert_eq!(tree.name, "Root");
        assert_eq!(tree.text_of("A"), Some("x & y A"));
        assert_eq!(tree.text_of("B"), Some(""));
        assert_eq!(tree.child("C").unwrap().named("D").count(), 2);
        assert_eq!(tree.child("C").unwrap().number("D").unwrap(), Some(1));
    }

    #[test]
    fn rejects_malformed_and_dangerous_documents() {
        for bad in [
            &b"<Root><A></Root>"[..],
            b"<Root/><Root/>",
            b"",
            b"<!DOCTYPE x><Root/>",
            b"<Root>&unknown;</Root>",
            b"text<Root/>",
        ] {
            assert_eq!(parse(bad).err(), Some(Error::InvalidXml), "{bad:?}");
        }
        assert!(parse(&b"<A>".repeat(40)).is_err());
    }
}
