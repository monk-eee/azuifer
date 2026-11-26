use super::{Store, db_error, internal};
use crate::{
    domain::{AccountName, Result},
    service_props::ServiceProperties,
};
use rusqlite::{OptionalExtension as _, params};

impl Store {
    /// The stored properties, or the defaults of an account that never set any.
    pub(crate) async fn service_properties(
        &self,
        account: AccountName,
    ) -> Result<ServiceProperties> {
        self.run(move |db, _, _| stored(db, &account)).await
    }

    pub(crate) async fn set_service_properties(
        &self,
        account: AccountName,
        update: ServiceProperties,
    ) -> Result<()> {
        self.run(move |db, _, _| {
            let tx = db.transaction().map_err(db_error)?;
            let merged = stored(&tx, &account)?.merged(update);
            let json = serde_json::to_string(&merged)
                .map_err(|_| internal("could not encode service properties"))?;
            tx.execute(
                "INSERT INTO account_settings (account, service_properties) VALUES (?1, ?2)
                 ON CONFLICT(account) DO UPDATE SET service_properties=excluded.service_properties",
                params![account.as_str(), json],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok(())
        })
        .await
    }
}

pub(super) fn stored(
    db: &rusqlite::Connection,
    account: &AccountName,
) -> Result<ServiceProperties> {
    let json: Option<String> = db
        .query_row(
            "SELECT service_properties FROM account_settings WHERE account=?1",
            [account.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    match json {
        Some(json) => serde_json::from_str(&json)
            .map_err(|_| internal("stored service properties are unreadable")),
        None => Ok(ServiceProperties::defaults()),
    }
}
