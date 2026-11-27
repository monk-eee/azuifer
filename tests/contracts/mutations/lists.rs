use super::{
    ASSEMBLED, Body, FIRST_BLOCK, Probe, Response, SECOND_BLOCK, Step, header_text, media,
    usable_etag,
};
use crate::contracts::cassette::{Media, project_xml};
use anyhow::{Context as _, Result, bail};
use reqwest::{Method, header::HeaderMap};
use serde::{Deserialize, Serialize};

const A: &str = "YQ==";
const B: &str = "Yg==";
const SHADOW: &[u8] = b"staged replacement";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Marker {
    Missing,
    Empty,
    Present,
}

impl Marker {
    pub(super) fn observe(value: Option<&str>) -> Self {
        match value {
            None => Self::Missing,
            Some("") => Self::Empty,
            Some(_) => Self::Present,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Id {
    A,
    B,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Block {
    id: Id,
    size: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Blocks {
    media: Media,
    blob_length: Option<u64>,
    committed: Option<Vec<Block>>,
    uncommitted: Option<Vec<Block>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireBlocks {
    committed_blocks: Option<WireSection>,
    uncommitted_blocks: Option<WireSection>,
}

#[derive(Deserialize)]
struct WireSection {
    #[serde(rename = "Block", default)]
    blocks: Vec<WireBlock>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireBlock {
    name: String,
    size: u64,
}

impl WireSection {
    fn project(self) -> Vec<Block> {
        self.blocks
            .into_iter()
            .map(|wire| Block {
                id: match wire.name.as_str() {
                    A => Id::A,
                    B => Id::B,
                    _ => Id::Other,
                },
                size: wire.size,
            })
            .collect()
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageRanges {
    media: Media,
    blob_length: Option<u64>,
    ranges: Vec<[u64; 2]>,
    cleared: Vec<[u64; 2]>,
    next_marker: Marker,
}

#[derive(Deserialize)]
struct WirePages {
    #[serde(rename = "PageRange", default)]
    ranges: Vec<WireRange>,
    #[serde(rename = "ClearRange", default)]
    cleared: Vec<WireRange>,
    #[serde(rename = "NextMarker")]
    next_marker: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireRange {
    start: u64,
    end: u64,
}

pub(super) fn project(step: Step, headers: &HeaderMap, bytes: &[u8]) -> Result<Body> {
    let blob_length =
        header_text(headers, "x-ms-blob-content-length").and_then(|value| value.parse().ok());
    let media = media(headers);
    match step {
        Step::ListUncommittedBlocks | Step::ListCommittedBlocks | Step::ListAllBlocks => {
            let wire: WireBlocks = project_xml(bytes, "BlockList")?;
            Ok(Body::BlockList(Blocks {
                media,
                blob_length,
                committed: wire.committed_blocks.map(WireSection::project),
                uncommitted: wire.uncommitted_blocks.map(WireSection::project),
            }))
        }
        Step::ListPageRanges | Step::ListBoundedPageRanges => {
            let wire: WirePages = project_xml(bytes, "PageList")?;
            let ranges = |entries: Vec<WireRange>| {
                entries
                    .into_iter()
                    .map(|range| [range.start, range.end])
                    .collect()
            };
            Ok(Body::PageList(PageRanges {
                media,
                blob_length,
                ranges: ranges(wire.ranges),
                cleared: ranges(wire.cleared),
                next_marker: Marker::observe(wire.next_marker.as_deref()),
            }))
        }
        _ => bail!("unexpected listing step"),
    }
}

pub(super) fn matches_fixture(response: &Response) -> bool {
    use Step::*;
    let a = Block {
        id: Id::A,
        size: FIRST_BLOCK.len() as u64,
    };
    let b = Block {
        id: Id::B,
        size: SECOND_BLOCK.len() as u64,
    };
    match (&response.body, response.step) {
        (Body::BlockList(list), ListUncommittedBlocks) => {
            list.media == Media::Xml
                && list.uncommitted.as_deref()
                    == Some(&[
                        Block {
                            id: Id::A,
                            size: SHADOW.len() as u64,
                        },
                        b,
                    ])
                && list.committed.as_ref().is_none_or(Vec::is_empty)
        }
        (Body::BlockList(list), ListCommittedBlocks) => {
            list.media == Media::Xml
                && list.committed.as_deref() == Some(&[a])
                && list.uncommitted.as_ref().is_none_or(Vec::is_empty)
        }
        (Body::BlockList(list), ListAllBlocks) => {
            list.media == Media::Xml
                && list.blob_length == Some(ASSEMBLED.len() as u64)
                && list.committed.as_deref() == Some(&[b, a])
                && list.uncommitted.as_ref().is_none_or(Vec::is_empty)
        }
        (Body::PageList(list), ListPageRanges | ListBoundedPageRanges) => {
            let start = if response.step == ListPageRanges {
                512
            } else {
                1024
            };
            list.media == Media::Xml
                && list.blob_length == Some(2048)
                && list.ranges == [[start, 1535]]
                && list.cleared.is_empty()
                && list.next_marker != Marker::Present
        }
        _ => false,
    }
}

impl Probe<'_> {
    pub(super) fn block_list_selectors(&mut self) -> Result<()> {
        self.setup(self.put_block(A, FIRST_BLOCK), 201, "stage initial block")?;
        let seeded = self.setup(
            self.commit("<BlockList><Latest>YQ==</Latest></BlockList>", "assembled"),
            201,
            "commit initial block",
        )?;
        let initial = usable_etag(seeded.headers()).context("initial block commit lacks ETag")?;
        self.setup(
            self.put_block(A, SHADOW),
            201,
            "stage replacement for first block",
        )?;
        self.setup(self.put_block(B, SECOND_BLOCK), 201, "stage second block")?;

        let list = |probe: &Self, kind: &str| {
            probe
                .request(Method::GET)
                .query(&[("comp", "blocklist"), ("blocklisttype", kind)])
        };
        self.record(
            Step::ListUncommittedBlocks,
            list(self, "uncommitted"),
            Some(initial),
        )?;
        self.record(
            Step::ListCommittedBlocks,
            list(self, "committed"),
            Some(initial),
        )?;
        let updated = self.record(
            Step::CommitSelectedBlocks,
            self.commit(
                "<BlockList><Uncommitted>Yg==</Uncommitted><Committed>YQ==</Committed></BlockList>",
                "assembled",
            ),
            Some(initial),
        )?.etag.context("selected block commit lacks ETag")?;
        self.record(Step::ListAllBlocks, list(self, "all"), Some(&updated))?;
        self.setup(
            self.put_block("Yw==", b"uncommitted"),
            201,
            "stage block before width rejection",
        )?;
        self.record(
            Step::RejectBlockWidth,
            self.put_block("Y2Q=", b"wrong width"),
            Some(&updated),
        )?;
        self.record(
            Step::ReadCommitted,
            self.request(Method::GET),
            Some(&updated),
        )?;
        Ok(())
    }
}
