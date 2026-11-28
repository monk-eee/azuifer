//! The namespace store's view for the lease gauge.

use super::Inner;
use crate::runtime_metrics::{Gauges, Probe};

/// Leases that still hold writers off: held, or being broken but not yet broken.
const ACTIVE: &str = "(lease_state=1 AND (lease_duration<0 OR lease_expiry>?1)) OR (lease_state=2 AND lease_expiry>?1)";

impl Probe for Inner {
    fn sample(&self, gauges: &mut Gauges) {
        let Ok(db) = self.db.lock() else { return };
        let now = self.clock.now_millis();
        for (kind, table) in [("blob", "blobs"), ("container", "containers")] {
            let count = db.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE {ACTIVE}"),
                [now],
                |row| row.get::<_, i64>(0),
            );
            if let Ok(count) = count {
                gauges.leases(kind, u64::try_from(count).unwrap_or(0));
            }
        }
    }
}
