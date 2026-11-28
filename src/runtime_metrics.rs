//! Metrics from inside the stores: queue depth, active leases, contention on the metadata
//! lock, content reclamation, and backend failures.
//!
//! The counters are process-wide atomics the stores bump where the event happens, so no
//! store needs a handle to the exporter. The gauges are sampled when they are read: a store
//! registers a [`Probe`] and is asked for its state at each Prometheus scrape or OTLP
//! collection. Prometheus and OTLP read the same [`SPECS`], so they cannot disagree.
//! Labels hold only store, kind, account, and queue names; no request value is ever one.

use crate::metrics::{family, sample};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};

/// The backend a counter belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Store {
    /// The shared Blob and DFS namespace.
    Namespace,
    Queue,
    Table,
    Files,
    /// Content streamed to clients after its metadata lock was released; shared by
    /// Blob, DFS, and Files.
    Content,
}

impl Store {
    const ALL: [Self; 5] = [
        Self::Namespace,
        Self::Queue,
        Self::Table,
        Self::Files,
        Self::Content,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Queue => "queue",
            Self::Table => "table",
            Self::Files => "files",
            Self::Content => "content",
        }
    }
}

/// What kind of backend failure was answered with an internal error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    /// A SQLite error other than a busy or locked database.
    Database,
    /// SQLite reported the database busy or locked.
    Busy,
    /// A filesystem error on stored content.
    Io,
    /// A stored state that could not be used: a poisoned lock, a mismatch between metadata
    /// and content, or a task that did not complete.
    Internal,
}

impl Failure {
    const ALL: [Self; 4] = [Self::Database, Self::Busy, Self::Io, Self::Internal];

    fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Busy => "busy",
            Self::Io => "io",
            Self::Internal => "internal",
        }
    }
}

/// Why a content file was removed.
#[derive(Clone, Copy)]
pub(crate) enum Removal {
    /// Nothing references it any more, and no download is still reading it.
    Reclaimed,
    /// Found unreferenced when the data directory was opened, after a crash.
    Recovered,
}

impl Removal {
    const ALL: [Self; 2] = [Self::Reclaimed, Self::Recovered];

    fn name(self) -> &'static str {
        match self {
            Self::Reclaimed => "reclaimed",
            Self::Recovered => "recovered",
        }
    }
}

/// A store that can report the state behind the gauges.
pub(crate) trait Probe: Send + Sync {
    fn sample(&self, gauges: &mut Gauges);
}

#[derive(Default)]
pub(crate) struct Gauges {
    leases: BTreeMap<&'static str, u64>,
    queues: BTreeMap<(String, String), (u64, u64)>,
}

impl Gauges {
    /// Adds `count` held leases of `kind`; a kind reported as zero still appears.
    pub(crate) fn leases(&mut self, kind: &'static str, count: u64) {
        *self.leases.entry(kind).or_default() += count;
    }

    pub(crate) fn queue(&mut self, account: &str, queue: &str, visible: u64, invisible: u64) {
        let depth = self
            .queues
            .entry((account.to_owned(), queue.to_owned()))
            .or_default();
        depth.0 += visible;
        depth.1 += invisible;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    Counter,
    Gauge,
}

pub(crate) struct Spec {
    pub(crate) prometheus: &'static str,
    pub(crate) otel: &'static str,
    pub(crate) help: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) kind: Kind,
}

const QUEUE_MESSAGES: usize = 0;
const ACTIVE_LEASES: usize = 1;
const LOCK_ACQUISITIONS: usize = 2;
const LOCK_CONTENDED: usize = 3;
const LOCK_WAIT: usize = 4;
const GC_EXTENTS: usize = 5;
const GC_BYTES: usize = 6;
const FAILURES: usize = 7;

pub(crate) const SPECS: [Spec; 8] = [
    Spec {
        prometheus: "azuifer_queue_messages",
        otel: "azuifer.queue.messages",
        help: "Messages in each queue, by whether they can be received now.",
        unit: "{message}",
        kind: Kind::Gauge,
    },
    Spec {
        prometheus: "azuifer_active_leases",
        otel: "azuifer.leases.active",
        help: "Leases held or breaking on blobs, containers, shares, and files. DFS paths are blobs.",
        unit: "{lease}",
        kind: Kind::Gauge,
    },
    Spec {
        prometheus: "azuifer_store_lock_acquisitions_total",
        otel: "azuifer.store.lock.acquisitions",
        help: "Acquisitions of a store's metadata lock, which serializes its SQLite connection.",
        unit: "{acquisition}",
        kind: Kind::Counter,
    },
    Spec {
        prometheus: "azuifer_store_lock_contended_total",
        otel: "azuifer.store.lock.contended",
        help: "Acquisitions of a store's metadata lock that had to wait for another operation.",
        unit: "{acquisition}",
        kind: Kind::Counter,
    },
    Spec {
        prometheus: "azuifer_store_lock_wait_seconds_total",
        otel: "azuifer.store.lock.wait",
        help: "Time operations spent waiting for a store's metadata lock.",
        unit: "s",
        kind: Kind::Counter,
    },
    Spec {
        prometheus: "azuifer_gc_extents_total",
        otel: "azuifer.gc.extents",
        help: "Content files removed once nothing referenced or read them.",
        unit: "{extent}",
        kind: Kind::Counter,
    },
    Spec {
        prometheus: "azuifer_gc_bytes_total",
        otel: "azuifer.gc.bytes",
        help: "Bytes of the content files removed.",
        unit: "By",
        kind: Kind::Counter,
    },
    Spec {
        prometheus: "azuifer_backend_failures_total",
        otel: "azuifer.backend.failures",
        help: "Storage failures answered with an internal error, by store and kind.",
        unit: "{failure}",
        kind: Kind::Counter,
    },
];

type Labels = Vec<(&'static str, String)>;
pub(crate) type Sampled = (Labels, f64);

#[derive(Default)]
struct Lock {
    acquired: AtomicU64,
    contended: AtomicU64,
    wait_nanos: AtomicU64,
}

#[derive(Default)]
struct Removed {
    extents: AtomicU64,
    bytes: AtomicU64,
}

struct Runtime {
    locks: [Lock; Store::ALL.len()],
    failures: [[AtomicU64; Failure::ALL.len()]; Store::ALL.len()],
    removed: [Removed; Removal::ALL.len()],
}

static RUNTIME: Runtime = Runtime {
    locks: [const {
        Lock {
            acquired: AtomicU64::new(0),
            contended: AtomicU64::new(0),
            wait_nanos: AtomicU64::new(0),
        }
    }; Store::ALL.len()],
    failures: [const { [const { AtomicU64::new(0) }; Failure::ALL.len()] }; Store::ALL.len()],
    removed: [const {
        Removed {
            extents: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }; Removal::ALL.len()],
};

/// The stores that report gauges, held weakly so a dropped store is forgotten.
pub(crate) struct Probes(Mutex<Vec<Weak<dyn Probe>>>);

static PROBES: Probes = Probes::new();

impl Probes {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    pub(crate) fn register(&self, probe: Weak<dyn Probe>) {
        let mut probes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        probes.retain(|probe| probe.strong_count() > 0);
        probes.push(probe);
    }

    fn gauges(&self) -> Gauges {
        let live: Vec<Arc<dyn Probe>> = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        let mut gauges = Gauges::default();
        for probe in live {
            probe.sample(&mut gauges);
        }
        gauges
    }
}

/// Locks `mutex`, counting the acquisition and the time spent waiting when another
/// operation held it. Poisoning is reported exactly as `Mutex::lock` reports it.
pub(crate) fn lock<T>(
    store: Store,
    mutex: &Mutex<T>,
) -> Result<MutexGuard<'_, T>, PoisonError<MutexGuard<'_, T>>> {
    let counters = &RUNTIME.locks[store as usize];
    counters.acquired.fetch_add(1, Relaxed);
    match mutex.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Poisoned(poisoned)) => Err(poisoned),
        Err(TryLockError::WouldBlock) => {
            let started = Instant::now();
            let guard = mutex.lock();
            let waited = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            counters.contended.fetch_add(1, Relaxed);
            counters.wait_nanos.fetch_add(waited, Relaxed);
            guard
        }
    }
}

pub(crate) fn failure(store: Store, kind: Failure) {
    RUNTIME.failures[store as usize][kind as usize].fetch_add(1, Relaxed);
}

/// Classifies a SQLite error: busy and locked are contention, everything else is a fault.
pub(crate) fn database_failure(store: Store, error: &rusqlite::Error) {
    let busy = matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    );
    failure(
        store,
        if busy {
            Failure::Busy
        } else {
            Failure::Database
        },
    );
}

pub(crate) fn removed(why: Removal, bytes: u64) {
    let removed = &RUNTIME.removed[why as usize];
    removed.extents.fetch_add(1, Relaxed);
    removed.bytes.fetch_add(bytes, Relaxed);
}

/// Registers a store for the gauges. It is forgotten once the store is dropped.
pub(crate) fn register(probe: Weak<dyn Probe>) {
    PROBES.register(probe);
}

fn label(name: &'static str, value: &str) -> (&'static str, String) {
    (name, value.to_owned())
}

/// Every series of one spec, as it stands now. Probe-backed specs query their stores.
pub(crate) fn collect(spec: usize) -> Vec<Sampled> {
    collect_in(&PROBES, spec)
}

fn collect_in(probes: &Probes, spec: usize) -> Vec<Sampled> {
    let mut out = Vec::new();
    match spec {
        QUEUE_MESSAGES => {
            for ((account, queue), (visible, invisible)) in probes.gauges().queues {
                for (state, count) in [("visible", visible), ("invisible", invisible)] {
                    out.push((
                        vec![
                            label("account", &account),
                            label("queue", &queue),
                            label("state", state),
                        ],
                        count as f64,
                    ));
                }
            }
        }
        ACTIVE_LEASES => {
            for (kind, count) in probes.gauges().leases {
                out.push((vec![label("kind", kind)], count as f64));
            }
        }
        LOCK_ACQUISITIONS | LOCK_CONTENDED | LOCK_WAIT => {
            for store in Store::ALL {
                let counters = &RUNTIME.locks[store as usize];
                let acquired = counters.acquired.load(Relaxed);
                if acquired == 0 {
                    continue;
                }
                let value = match spec {
                    LOCK_ACQUISITIONS => acquired as f64,
                    LOCK_CONTENDED => counters.contended.load(Relaxed) as f64,
                    _ => counters.wait_nanos.load(Relaxed) as f64 / 1e9,
                };
                out.push((vec![label("store", store.name())], value));
            }
        }
        GC_EXTENTS | GC_BYTES => {
            for why in Removal::ALL {
                let slot = &RUNTIME.removed[why as usize];
                let value = if spec == GC_EXTENTS {
                    slot.extents.load(Relaxed)
                } else {
                    slot.bytes.load(Relaxed)
                };
                out.push((vec![label("reason", why.name())], value as f64));
            }
        }
        FAILURES => {
            for store in Store::ALL {
                let in_use = RUNTIME.locks[store as usize].acquired.load(Relaxed) > 0;
                for kind in Failure::ALL {
                    let count = RUNTIME.failures[store as usize][kind as usize].load(Relaxed);
                    if in_use || count > 0 {
                        out.push((
                            vec![label("store", store.name()), label("kind", kind.name())],
                            count as f64,
                        ));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Appends every runtime series in the Prometheus text exposition format.
pub(crate) fn render(out: &mut String) {
    render_in(&PROBES, out);
}

fn render_in(probes: &Probes, out: &mut String) {
    for (index, spec) in SPECS.iter().enumerate() {
        let kind = match spec.kind {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        };
        family(out, spec.prometheus, kind, spec.help);
        for (labels, value) in collect_in(probes, index) {
            let labels = labels
                .iter()
                .map(|(name, value)| format!("{name}=\"{}\"", escape(value)))
                .collect::<Vec<_>>()
                .join(",");
            sample(out, spec.prometheus, &labels, &value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl Probe for Fixed {
        fn sample(&self, gauges: &mut Gauges) {
            gauges.leases("probe-test", 2);
            gauges.queue("probe-acct", "probe-q", 3, 1);
        }
    }

    fn series(spec: usize, label: (&str, &str)) -> Option<f64> {
        collect(spec)
            .into_iter()
            .find(|(labels, _)| labels.iter().any(|(k, v)| *k == label.0 && v == label.1))
            .map(|(_, value)| value)
    }

    #[test]
    fn an_uncontended_lock_is_counted_and_a_contended_one_records_its_wait() {
        let mutex = Mutex::new(0);
        drop(lock(Store::Table, &mutex));
        let acquired = series(LOCK_ACQUISITIONS, ("store", "table")).unwrap();
        assert!(acquired >= 1.0);
        let contended = |spec| series(spec, ("store", "table")).unwrap_or(0.0);
        let was = contended(LOCK_CONTENDED);
        let waited = contended(LOCK_WAIT);

        let held = mutex.lock().unwrap();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| drop(lock(Store::Table, &mutex)));
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
            waiter.join().unwrap();
        });
        assert!(contended(LOCK_CONTENDED) >= was + 1.0);
        assert!(contended(LOCK_WAIT) >= waited + 0.04);
    }

    #[test]
    fn a_poisoned_lock_is_reported_as_poisoned() {
        let mutex = Mutex::new(0);
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = mutex.lock().unwrap();
                    panic!("poison it");
                })
                .join()
        });
        assert!(lock(Store::Table, &mutex).is_err());
    }

    #[test]
    fn failures_removals_and_probes_are_reported_and_a_dropped_store_is_forgotten() {
        failure(Store::Content, Failure::Io);
        let io = series(FAILURES, ("store", "content")).unwrap();
        assert!(io >= 1.0);
        database_failure(
            Store::Content,
            &rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                None,
            ),
        );
        let busy = collect(FAILURES)
            .into_iter()
            .find(|(labels, _)| {
                labels.contains(&("store", "content".into()))
                    && labels.contains(&("kind", "busy".into()))
            })
            .map(|(_, value)| value);
        assert!(busy.unwrap() >= 1.0);

        removed(Removal::Recovered, 7);
        assert!(series(GC_BYTES, ("reason", "recovered")).unwrap() >= 7.0);
        assert!(series(GC_EXTENTS, ("reason", "reclaimed")).is_some());

        // A registry of its own, so no store another test has open is sampled.
        let probes = Probes::new();
        let held = |spec, label| {
            collect_in(&probes, spec)
                .into_iter()
                .find(|(labels, _)| {
                    labels
                        .iter()
                        .any(|(k, v)| *k == label && v.starts_with("probe-"))
                })
                .map(|(_, value)| value)
        };
        let probe = Arc::new(Fixed);
        probes.register(Arc::downgrade(&probe) as Weak<dyn Probe>);
        assert_eq!(held(ACTIVE_LEASES, "kind"), Some(2.0));
        assert_eq!(held(QUEUE_MESSAGES, "queue"), Some(3.0));
        drop(probe);
        assert_eq!(held(ACTIVE_LEASES, "kind"), None);
    }

    #[test]
    fn prometheus_output_escapes_label_values() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        let mut text = String::new();
        render_in(&Probes::new(), &mut text);
        for spec in &SPECS {
            assert!(text.contains(&format!("# TYPE {} ", spec.prometheus)));
        }
    }
}
