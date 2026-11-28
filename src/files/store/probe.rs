//! The Files store's view for the lease gauge.

use super::Inner;
use crate::{
    files::lease::{self, Lease, State},
    runtime_metrics::{Gauges, Probe},
};

impl Probe for Inner {
    fn sample(&self, gauges: &mut Gauges) {
        let Ok(db) = self.db.lock() else { return };
        let now = self.env.clock.now_millis();
        // Snapshots copy a share's files, leases included; only the live share counts.
        for (kind, sql) in [
            (
                "share",
                "SELECT lease FROM shares WHERE snapshot=0 AND lease IS NOT NULL",
            ),
            (
                "file",
                "SELECT n.lease FROM nodes n JOIN shares s ON s.id=n.share_id
                 WHERE s.snapshot=0 AND n.lease IS NOT NULL",
            ),
        ] {
            let Ok(mut query) = db.prepare(sql) else {
                continue;
            };
            let Ok(rows) = query.query_map([], |row| row.get::<_, String>(0)) else {
                continue;
            };
            let held = rows
                .flatten()
                .filter_map(|text| serde_json::from_str::<Lease>(&text).ok())
                .filter(|stored| {
                    matches!(
                        lease::state(Some(stored), now),
                        State::Leased | State::Breaking
                    )
                })
                .count();
            gauges.leases(kind, held as u64);
        }
    }
}
