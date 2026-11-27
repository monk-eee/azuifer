use super::{
    error::{QueueError, Result},
    model::{AccessPolicy, Message, Metadata, PopReceipt, PropertiesPatch, ServiceProperties},
};
use crate::{clock::Clock, domain::AccountName};
use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS queues (
    account TEXT NOT NULL, name TEXT NOT NULL, metadata TEXT NOT NULL, acl TEXT NOT NULL,
    created INTEGER NOT NULL,
    PRIMARY KEY (account, name)
) STRICT;
CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL, queue TEXT NOT NULL, id TEXT NOT NULL,
    inserted INTEGER NOT NULL, expires INTEGER, visible INTEGER NOT NULL,
    dequeues INTEGER NOT NULL, receipt TEXT NOT NULL, body TEXT NOT NULL,
    UNIQUE (account, queue, id),
    FOREIGN KEY (account, queue) REFERENCES queues (account, name) ON DELETE CASCADE
) STRICT;
CREATE INDEX IF NOT EXISTS messages_visibility ON messages (account, queue, visible, seq);
CREATE TABLE IF NOT EXISTS service_properties (
    account TEXT PRIMARY KEY, properties TEXT NOT NULL
) STRICT;";

/// Queue state for every account, in its own SQLite database (ADR-0010, ADR-0013).
#[derive(Clone)]
pub(super) struct Store(Arc<Inner>);

struct Inner {
    db: Mutex<Connection>,
    clock: Clock,
    _lock: Option<File>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Created {
    New,
    Existing,
}

pub(super) struct NewMessage {
    pub(super) text: String,
    pub(super) visibility_millis: i64,
    pub(super) ttl_millis: Option<i64>,
}

pub(super) struct QueueListing {
    pub(super) prefix: String,
    pub(super) after: String,
    pub(super) limit: u32,
}

impl Store {
    pub(super) fn open(location: Option<&Path>, clock: Clock) -> anyhow::Result<Self> {
        let (db, lock) = if let Some(root) = location {
            let dir = root.join("queue");
            fs::create_dir_all(&dir).context("could not create the queue storage directory")?;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(dir.join("queue.lock"))
                .context("could not open the queue lock file")?;
            lock.try_lock()
                .context("the queue storage directory is already in use")?;
            let db = Connection::open(dir.join("queue.sqlite3"))
                .context("could not open queue metadata")?;
            let journal: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
            anyhow::ensure!(
                journal.eq_ignore_ascii_case("wal"),
                "queue storage does not support SQLite WAL"
            );
            db.pragma_update(None, "synchronous", "FULL")?;
            (db, Some(lock))
        } else {
            (Connection::open_in_memory()?, None)
        };
        db.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        anyhow::ensure!(
            version <= SCHEMA_VERSION,
            "queue storage was written by a newer Azuifer (schema {version})"
        );
        db.execute_batch(SCHEMA)?;
        db.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self(Arc::new(Inner {
            db: Mutex::new(db),
            clock,
            _lock: lock,
        })))
    }

    /// Runs one operation as a single immediate transaction off the async executor,
    /// with the time read once so every check in the operation agrees.
    async fn run<T, F>(&self, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>, i64) -> Result<T> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = inner.db.lock().map_err(|_| {
                tracing::error!("queue metadata lock is poisoned");
                QueueError::Internal
            })?;
            let now = inner.clock.now_millis();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let value = action(&tx, now)?;
            tx.commit()?;
            Ok(value)
        })
        .await
        .map_err(|_| {
            tracing::error!("queue metadata operation did not complete");
            QueueError::Internal
        })?
    }

    pub(super) async fn create_queue(
        &self,
        account: AccountName,
        name: String,
        metadata: Metadata,
    ) -> Result<Created> {
        self.run(move |tx, now| {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT metadata FROM queues WHERE account = ?1 AND name = ?2",
                    params![account.as_str(), name],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                return if decode::<Metadata>(&existing)? == metadata {
                    Ok(Created::Existing)
                } else {
                    Err(QueueError::QueueAlreadyExists)
                };
            }
            tx.execute(
                "INSERT INTO queues (account, name, metadata, acl, created) VALUES (?1, ?2, ?3, '[]', ?4)",
                params![account.as_str(), name, encode(&metadata)?, now],
            )?;
            Ok(Created::New)
        })
        .await
    }

    pub(super) async fn delete_queue(&self, account: AccountName, name: String) -> Result<()> {
        self.run(move |tx, _| {
            let deleted = tx.execute(
                "DELETE FROM queues WHERE account = ?1 AND name = ?2",
                params![account.as_str(), name],
            )?;
            if deleted == 0 {
                return Err(QueueError::QueueNotFound);
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn queue_metadata(
        &self,
        account: AccountName,
        name: String,
    ) -> Result<(Metadata, i64)> {
        self.run(move |tx, now| {
            let metadata = queue_column(tx, &account, &name, "metadata")?;
            let count = tx.query_row(
                "SELECT COUNT(*) FROM messages WHERE account = ?1 AND queue = ?2 AND (expires IS NULL OR expires > ?3)",
                params![account.as_str(), name, now],
                |row| row.get(0),
            )?;
            Ok((decode(&metadata)?, count))
        })
        .await
    }

    pub(super) async fn set_metadata(
        &self,
        account: AccountName,
        name: String,
        metadata: Metadata,
    ) -> Result<()> {
        self.run(move |tx, _| update_queue(tx, &account, &name, "metadata", &encode(&metadata)?))
            .await
    }

    pub(super) async fn acl(
        &self,
        account: AccountName,
        name: String,
    ) -> Result<Vec<AccessPolicy>> {
        self.run(move |tx, _| decode(&queue_column(tx, &account, &name, "acl")?))
            .await
    }

    pub(super) async fn set_acl(
        &self,
        account: AccountName,
        name: String,
        policies: Vec<AccessPolicy>,
    ) -> Result<()> {
        self.run(move |tx, _| update_queue(tx, &account, &name, "acl", &encode(&policies)?))
            .await
    }

    pub(super) async fn list_queues(
        &self,
        account: AccountName,
        listing: QueueListing,
    ) -> Result<Vec<(String, Metadata)>> {
        self.run(move |tx, _| {
            let mut statement = tx.prepare(
                "SELECT name, metadata FROM queues WHERE account = ?1 AND name > ?2 ORDER BY name",
            )?;
            let rows = statement.query_map(params![account.as_str(), listing.after], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut queues = Vec::new();
            for row in rows {
                let (name, metadata) = row?;
                if !name.starts_with(&listing.prefix) {
                    if name > listing.prefix {
                        break;
                    }
                    continue;
                }
                // One extra row tells the caller whether another page follows.
                if queues.len() > listing.limit as usize {
                    break;
                }
                queues.push((name, decode(&metadata)?));
            }
            Ok(queues)
        })
        .await
    }

    pub(super) async fn put_message(
        &self,
        account: AccountName,
        queue: String,
        message: NewMessage,
    ) -> Result<Message> {
        self.run(move |tx, now| {
            require_queue(tx, &account, &queue)?;
            purge(tx, &account, &queue, now)?;
            let id = Uuid::new_v4().to_string();
            let receipt = new_receipt();
            let expires = message.ttl_millis.and_then(|ttl| now.checked_add(ttl));
            let visible = now + message.visibility_millis;
            tx.execute(
                "INSERT INTO messages (account, queue, id, inserted, expires, visible, dequeues, receipt, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
                params![account.as_str(), queue, id, now, expires, visible, receipt, message.text],
            )?;
            Ok(Message {
                id,
                inserted: now,
                expires,
                next_visible: visible,
                dequeue_count: 0,
                pop_receipt: receipt,
                text: message.text,
            })
        })
        .await
    }

    pub(super) async fn get_messages(
        &self,
        account: AccountName,
        queue: String,
        count: u32,
        visibility_millis: i64,
    ) -> Result<Vec<Message>> {
        self.run(move |tx, now| {
            require_queue(tx, &account, &queue)?;
            purge(tx, &account, &queue, now)?;
            let mut messages = read_visible(tx, &account, &queue, now, count)?;
            for (seq, message) in &mut messages {
                message.dequeue_count += 1;
                message.pop_receipt = new_receipt();
                message.next_visible = now + visibility_millis;
                tx.execute(
                    "UPDATE messages SET dequeues = ?1, receipt = ?2, visible = ?3 WHERE seq = ?4",
                    params![
                        message.dequeue_count,
                        message.pop_receipt,
                        message.next_visible,
                        *seq
                    ],
                )?;
            }
            Ok(messages.into_iter().map(|(_, message)| message).collect())
        })
        .await
    }

    pub(super) async fn peek_messages(
        &self,
        account: AccountName,
        queue: String,
        count: u32,
    ) -> Result<Vec<Message>> {
        self.run(move |tx, now| {
            require_queue(tx, &account, &queue)?;
            let messages = read_visible(tx, &account, &queue, now, count)?;
            Ok(messages.into_iter().map(|(_, message)| message).collect())
        })
        .await
    }

    /// Replaces the pop receipt and visibility, and the text when one is given.
    pub(super) async fn update_message(
        &self,
        account: AccountName,
        queue: String,
        id: String,
        receipt: PopReceipt,
        visibility_millis: i64,
        text: Option<String>,
    ) -> Result<(String, i64)> {
        self.run(move |tx, now| {
            let seq = matching_message(tx, &account, &queue, &id, &receipt, now)?;
            let new = new_receipt();
            let visible = now + visibility_millis;
            tx.execute(
                "UPDATE messages SET receipt = ?1, visible = ?2, body = COALESCE(?3, body) WHERE seq = ?4",
                params![new, visible, text, seq],
            )?;
            Ok((new, visible))
        })
        .await
    }

    pub(super) async fn delete_message(
        &self,
        account: AccountName,
        queue: String,
        id: String,
        receipt: PopReceipt,
    ) -> Result<()> {
        self.run(move |tx, now| {
            let seq = matching_message(tx, &account, &queue, &id, &receipt, now)?;
            tx.execute("DELETE FROM messages WHERE seq = ?1", params![seq])?;
            Ok(())
        })
        .await
    }

    pub(super) async fn clear_messages(&self, account: AccountName, queue: String) -> Result<()> {
        self.run(move |tx, _| {
            require_queue(tx, &account, &queue)?;
            tx.execute(
                "DELETE FROM messages WHERE account = ?1 AND queue = ?2",
                params![account.as_str(), queue],
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn service_properties(
        &self,
        account: AccountName,
    ) -> Result<ServiceProperties> {
        self.run(move |tx, _| load_properties(tx, &account)).await
    }

    pub(super) async fn update_properties(
        &self,
        account: AccountName,
        patch: PropertiesPatch,
    ) -> Result<()> {
        self.run(move |tx, _| {
            let mut properties = load_properties(tx, &account)?;
            patch.apply(&mut properties);
            tx.execute(
                "INSERT INTO service_properties (account, properties) VALUES (?1, ?2)
                 ON CONFLICT (account) DO UPDATE SET properties = excluded.properties",
                params![account.as_str(), encode(&properties)?],
            )?;
            Ok(())
        })
        .await
    }
}

fn new_receipt() -> String {
    STANDARD.encode(Uuid::new_v4().as_bytes())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| {
        tracing::error!("could not encode queue state");
        QueueError::Internal
    })
}

fn decode<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|_| {
        tracing::error!("stored queue state is unreadable");
        QueueError::Internal
    })
}

fn load_properties(tx: &Transaction<'_>, account: &AccountName) -> Result<ServiceProperties> {
    let stored: Option<String> = tx
        .query_row(
            "SELECT properties FROM service_properties WHERE account = ?1",
            params![account.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    stored.map_or_else(|| Ok(ServiceProperties::default()), |text| decode(&text))
}

fn require_queue(tx: &Transaction<'_>, account: &AccountName, queue: &str) -> Result<()> {
    queue_column(tx, account, queue, "name").map(drop)
}

// `column` is always a literal from this module, never request input.
fn queue_column(
    tx: &Transaction<'_>,
    account: &AccountName,
    queue: &str,
    column: &str,
) -> Result<String> {
    tx.query_row(
        &format!("SELECT {column} FROM queues WHERE account = ?1 AND name = ?2"),
        params![account.as_str(), queue],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(QueueError::QueueNotFound)
}

fn update_queue(
    tx: &Transaction<'_>,
    account: &AccountName,
    queue: &str,
    column: &str,
    value: &str,
) -> Result<()> {
    let updated = tx.execute(
        &format!("UPDATE queues SET {column} = ?1 WHERE account = ?2 AND name = ?3"),
        params![value, account.as_str(), queue],
    )?;
    if updated == 0 {
        return Err(QueueError::QueueNotFound);
    }
    Ok(())
}

fn purge(tx: &Transaction<'_>, account: &AccountName, queue: &str, now: i64) -> Result<()> {
    tx.execute(
        "DELETE FROM messages WHERE account = ?1 AND queue = ?2 AND expires IS NOT NULL AND expires <= ?3",
        params![account.as_str(), queue, now],
    )?;
    Ok(())
}

fn read_visible(
    tx: &Transaction<'_>,
    account: &AccountName,
    queue: &str,
    now: i64,
    count: u32,
) -> Result<Vec<(i64, Message)>> {
    let mut statement = tx.prepare(
        "SELECT seq, id, inserted, expires, visible, dequeues, receipt, body FROM messages
         WHERE account = ?1 AND queue = ?2 AND visible <= ?3 AND (expires IS NULL OR expires > ?3)
         ORDER BY seq LIMIT ?4",
    )?;
    let rows = statement.query_map(params![account.as_str(), queue, now, count], |row| {
        Ok((
            row.get(0)?,
            Message {
                id: row.get(1)?,
                inserted: row.get(2)?,
                expires: row.get(3)?,
                next_visible: row.get(4)?,
                dequeue_count: row.get(5)?,
                pop_receipt: row.get(6)?,
                text: row.get(7)?,
            },
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Finds the message and checks its current pop receipt.
fn matching_message(
    tx: &Transaction<'_>,
    account: &AccountName,
    queue: &str,
    id: &str,
    receipt: &PopReceipt,
    now: i64,
) -> Result<i64> {
    require_queue(tx, account, queue)?;
    let found: Option<(i64, String, Option<i64>)> = tx
        .query_row(
            "SELECT seq, receipt, expires FROM messages WHERE account = ?1 AND queue = ?2 AND id = ?3",
            params![account.as_str(), queue, id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match found {
        Some((_, _, Some(expires))) if expires <= now => Err(QueueError::MessageNotFound),
        Some((seq, current, _)) if current == receipt.as_str() => Ok(seq),
        _ => Err(QueueError::MessageNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn account() -> AccountName {
        AccountName::parse("devstoreaccount1").unwrap()
    }

    fn message(text: &str, visibility_millis: i64, ttl_millis: Option<i64>) -> NewMessage {
        NewMessage {
            text: text.into(),
            visibility_millis,
            ttl_millis,
        }
    }

    async fn store_with_queue() -> (Store, Clock) {
        let clock = Clock::new();
        let store = Store::open(None, clock.clone()).unwrap();
        store
            .create_queue(account(), "q".into(), Metadata::new())
            .await
            .unwrap();
        (store, clock)
    }

    #[tokio::test]
    async fn received_messages_hide_until_the_clock_passes_the_visibility_timeout() {
        let (store, clock) = store_with_queue().await;
        store
            .put_message(account(), "q".into(), message("one", 0, Some(600_000)))
            .await
            .unwrap();
        let first = store
            .get_messages(account(), "q".into(), 5, 30_000)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].dequeue_count, 1);
        assert!(
            store
                .get_messages(account(), "q".into(), 5, 30_000)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .peek_messages(account(), "q".into(), 5)
                .await
                .unwrap()
                .is_empty()
        );
        clock.advance(Duration::from_secs(31));
        let second = store
            .get_messages(account(), "q".into(), 5, 30_000)
            .await
            .unwrap();
        assert_eq!(second[0].id, first[0].id);
        assert_eq!(second[0].dequeue_count, 2);
        assert_ne!(second[0].pop_receipt, first[0].pop_receipt);
    }

    #[tokio::test]
    async fn stale_receipts_fail_and_leave_the_message_intact() {
        let (store, clock) = store_with_queue().await;
        let put = store
            .put_message(account(), "q".into(), message("body", 0, None))
            .await
            .unwrap();
        let first = store
            .get_messages(account(), "q".into(), 1, 10_000)
            .await
            .unwrap()
            .remove(0);
        clock.advance(Duration::from_secs(11));
        let second = store
            .get_messages(account(), "q".into(), 1, 10_000)
            .await
            .unwrap()
            .remove(0);
        let stale = PopReceipt::parse(&first.pop_receipt).unwrap();
        assert_eq!(
            store
                .delete_message(account(), "q".into(), put.id.clone(), stale.clone())
                .await,
            Err(QueueError::MessageNotFound)
        );
        assert_eq!(
            store
                .update_message(account(), "q".into(), put.id.clone(), stale, 0, None)
                .await,
            Err(QueueError::MessageNotFound)
        );
        let (updated, _) = store
            .update_message(
                account(),
                "q".into(),
                put.id.clone(),
                PopReceipt::parse(&second.pop_receipt).unwrap(),
                0,
                Some("new".into()),
            )
            .await
            .unwrap();
        assert_ne!(updated, second.pop_receipt);
        let visible = store.peek_messages(account(), "q".into(), 1).await.unwrap();
        assert_eq!(visible[0].text, "new");
        assert_eq!(visible[0].dequeue_count, 2);
        store
            .delete_message(
                account(),
                "q".into(),
                put.id.clone(),
                PopReceipt::parse(&updated).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .delete_message(
                    account(),
                    "q".into(),
                    put.id,
                    PopReceipt::parse(&updated).unwrap()
                )
                .await,
            Err(QueueError::MessageNotFound)
        );
    }

    #[tokio::test]
    async fn expired_messages_disappear_and_never_expiring_ones_stay() {
        let (store, clock) = store_with_queue().await;
        store
            .put_message(account(), "q".into(), message("short", 0, Some(5_000)))
            .await
            .unwrap();
        store
            .put_message(account(), "q".into(), message("forever", 0, None))
            .await
            .unwrap();
        assert_eq!(
            store.queue_metadata(account(), "q".into()).await.unwrap().1,
            2
        );
        clock.advance(Duration::from_secs(6));
        let (_, count) = store.queue_metadata(account(), "q".into()).await.unwrap();
        assert_eq!(count, 1);
        let remaining = store.peek_messages(account(), "q".into(), 5).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].text, "forever");
        assert_eq!(remaining[0].expires, None);
    }

    #[tokio::test]
    async fn create_is_idempotent_only_for_identical_metadata() {
        let (store, _) = store_with_queue().await;
        let metadata = Metadata::from([("a".into(), "b".into())]);
        assert_eq!(
            store
                .create_queue(account(), "q".into(), Metadata::new())
                .await,
            Ok(Created::Existing)
        );
        assert_eq!(
            store
                .create_queue(account(), "q".into(), metadata.clone())
                .await,
            Err(QueueError::QueueAlreadyExists)
        );
        assert_eq!(
            store
                .create_queue(account(), "other".into(), metadata)
                .await,
            Ok(Created::New)
        );
    }

    #[tokio::test]
    async fn messages_are_served_in_insertion_order_and_deleting_a_queue_removes_them() {
        let (store, _) = store_with_queue().await;
        for text in ["a", "b", "c"] {
            store
                .put_message(account(), "q".into(), message(text, 0, None))
                .await
                .unwrap();
        }
        let first_two = store
            .get_messages(account(), "q".into(), 2, 30_000)
            .await
            .unwrap();
        let texts: Vec<_> = first_two.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, ["a", "b"]);
        store.delete_queue(account(), "q".into()).await.unwrap();
        assert_eq!(
            store.peek_messages(account(), "q".into(), 1).await,
            Err(QueueError::QueueNotFound)
        );
        store
            .create_queue(account(), "q".into(), Metadata::new())
            .await
            .unwrap();
        assert!(
            store
                .peek_messages(account(), "q".into(), 5)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn state_survives_reopening_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Clock::new();
        let store = Store::open(Some(dir.path()), clock.clone()).unwrap();
        store
            .create_queue(
                account(),
                "q".into(),
                Metadata::from([("k".into(), "v".into())]),
            )
            .await
            .unwrap();
        let put = store
            .put_message(account(), "q".into(), message("kept", 0, None))
            .await
            .unwrap();
        let got = store
            .get_messages(account(), "q".into(), 1, 60_000)
            .await
            .unwrap();
        assert!(
            Store::open(Some(dir.path()), clock.clone()).is_err(),
            "directory lock"
        );
        drop(store);
        let reopened = Store::open(Some(dir.path()), clock.clone()).unwrap();
        let (metadata, count) = reopened
            .queue_metadata(account(), "q".into())
            .await
            .unwrap();
        assert_eq!((metadata["k"].as_str(), count), ("v", 1));
        clock.advance(Duration::from_secs(61));
        let again = reopened
            .get_messages(account(), "q".into(), 1, 1_000)
            .await
            .unwrap();
        assert_eq!(again[0].id, put.id);
        assert_eq!(again[0].dequeue_count, got[0].dequeue_count + 1);
    }

    #[tokio::test]
    async fn listing_pages_by_prefix_and_marker() {
        let clock = Clock::new();
        let store = Store::open(None, clock).unwrap();
        for name in ["aa1", "ab1", "ab2", "ab3", "b1"] {
            store
                .create_queue(account(), name.into(), Metadata::new())
                .await
                .unwrap();
        }
        let page = store
            .list_queues(
                account(),
                QueueListing {
                    prefix: "ab".into(),
                    after: "ab1".into(),
                    limit: 1,
                },
            )
            .await
            .unwrap();
        let names: Vec<_> = page.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["ab2", "ab3"]);
    }
}
