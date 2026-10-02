//! How many of something each key holds, forgetting a key at zero: so a map of them only ever
//! holds what's in use (allocations per player, per IP, per game; streams per IP).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

pub struct Counts<K>(HashMap<K, u32>);

impl<K: Hash + Eq> Default for Counts<K> {
    fn default() -> Self {
        Counts(HashMap::new())
    }
}

impl<K: Hash + Eq> Counts<K> {
    pub fn get<Q: Hash + Eq + ?Sized>(&self, k: &Q) -> u32
    where
        K: Borrow<Q>,
    {
        self.0.get(k).copied().unwrap_or(0)
    }

    pub fn add(&mut self, k: K) {
        *self.0.entry(k).or_default() += 1;
    }

    /// One fewer; the key is gone at zero. Releasing a key that holds nothing does nothing.
    pub fn release<Q: Hash + Eq + ?Sized>(&mut self, k: &Q)
    where
        K: Borrow<Q>,
    {
        if let Some(n) = self.0.get_mut(k) {
            *n -= 1;
            if *n == 0 {
                self.0.remove(k);
            }
        }
    }

    /// Keys holding something.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_forgotten_at_zero() {
        let mut c = Counts::default();
        c.add("a");
        c.add("a");
        c.add("b");
        assert_eq!((c.get(&"a"), c.get(&"b"), c.len()), (2, 1, 2));
        c.release(&"a");
        c.release(&"b");
        assert_eq!((c.get(&"a"), c.get(&"b"), c.len()), (1, 0, 1));
        c.release(&"b");
        c.release(&"a");
        assert!(c.is_empty());
    }
}
