//! Queue message transactions, including visibility, expiry, and pop receipts.

use super::{NewMessage, Store, require_queue};
use crate::{
    domain::AccountName,
    queue::{
        error::{QueueError, Result},
        model::{Message, PopReceipt},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{OptionalExtension as _, Transaction, params};
use uuid::Uuid;

impl Store {
    pub(in crate::queue) async fn put_message(
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

    pub(in crate::queue) async fn get_messages(
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

    pub(in crate::queue) async fn peek_messages(
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
    pub(in crate::queue) async fn update_message(
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

    pub(in crate::queue) async fn delete_message(
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

    pub(in crate::queue) async fn clear_messages(
        &self,
        account: AccountName,
        queue: String,
    ) -> Result<()> {
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
}

fn new_receipt() -> String {
    STANDARD.encode(Uuid::new_v4().as_bytes())
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
