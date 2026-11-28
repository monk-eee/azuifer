//! A small deterministic generator for the model-based tests (specification section 14).
//!
//! Every model test seeds it with a fixed number, so a failure names the seed and step
//! that reproduce it and CI never flakes.

/// SplitMix64: a full-period generator whose consecutive seeds give unrelated streams.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..bound`; zero when `bound` is zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }

    /// One element of a non-empty slice.
    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_always_gives_the_same_stream_and_bounds_hold() {
        let mut a = Rng::seeded(7);
        let mut b = Rng::seeded(7);
        let first: Vec<u64> = (0..8).map(|_| a.below(1000)).collect();
        assert_eq!(first, (0..8).map(|_| b.below(1000)).collect::<Vec<_>>());
        assert!(first.iter().all(|value| *value < 1000));
        let mut other = Rng::seeded(8);
        assert_ne!(first, (0..8).map(|_| other.below(1000)).collect::<Vec<_>>());
        assert_eq!(Rng::seeded(1).below(0), 0);
        assert_eq!(*Rng::seeded(1).pick(&[5]), 5);
    }
}
