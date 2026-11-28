//! Blob retention decides when an extent can be passed to the shared reader tracker.

use super::{extent, snapshots};
use uuid::Uuid;

/// Removes an extent nothing references any more, unless a snapshot, version or deleted
/// blob retains it or a download is still reading it.
pub(super) fn reclaim(mode: &super::Mode, id: Uuid) {
    if let super::Mode::Disk {
        extents,
        pinned,
        readers,
        ..
    } = mode
        && !snapshots::is_pinned(pinned, id)
    {
        readers.reclaim(&extent(extents, id));
    }
}
