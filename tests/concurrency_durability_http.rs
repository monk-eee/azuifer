//! Concurrency and durability tests of the Blob and DFS services against the built binary:
//! exclusive creates, conditional writes, leases and renames raced from many threads, and
//! state across graceful restarts, crashes and damaged content.
//!
//! Every race asserts an outcome no interleaving may break: how many callers win, that no
//! caller gets a 5xx, and that what a later reader sees is something one caller wrote.

#[path = "concurrency_durability_http/durability.rs"]
mod durability;
#[path = "concurrency_durability_http/harness.rs"]
mod harness;
#[path = "concurrency_durability_http/races.rs"]
mod races;
