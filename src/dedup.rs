//! Suppression of copies of the same SRT packet.
//!
//! Lune sends some packets over several links on purpose: SRT control
//! packets on every live link, retransmissions on two, everything in
//! `redundant` mode, and the server's ACKs and NAKs to every link. That buys
//! reliability, but the SRT endpoint behind each side should see a packet
//! once: a NAK that arrives three times makes the encoder retransmit three
//! times, and every one of those retransmissions goes out on two links.
//! Each receiving end therefore forwards the first copy of a datagram and
//! drops byte-identical ones for a short while.
//!
//! Byte-identical within the window means a copy: distinct SRT data packets
//! differ in sequence number, a retransmission differs from its original in
//! the R bit, and control packets carry a microsecond timestamp.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

/// Copies arrive apart by the difference in the links' latencies, which on
/// cellular links can be a second or more.
pub const WINDOW: Duration = Duration::from_secs(2);

pub struct Dedup {
    window: Duration,
    order: VecDeque<(Instant, u64)>,
    seen: HashMap<u64, u32>,
    hasher_key: (u64, u64),
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new(WINDOW)
    }
}

impl Dedup {
    pub fn new(window: Duration) -> Self {
        // A per-instance key, so nobody can craft two different packets that
        // collide in somebody else's table.
        Self { window, order: VecDeque::new(), seen: HashMap::new(), hasher_key: (rand_u64(), rand_u64()) }
    }

    fn hash(&self, bytes: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hasher_key.hash(&mut hasher);
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Whether `bytes` is the first copy seen within the window. Records it
    /// either way.
    pub fn first(&mut self, bytes: &[u8], now: Instant) -> bool {
        while let Some(&(at, hash)) = self.order.front() {
            if now.duration_since(at) < self.window {
                break;
            }
            self.order.pop_front();
            if let Some(count) = self.seen.get_mut(&hash) {
                *count -= 1;
                if *count == 0 {
                    self.seen.remove(&hash);
                }
            }
        }
        let hash = self.hash(bytes);
        let count = self.seen.entry(hash).or_insert(0);
        *count += 1;
        self.order.push_back((now, hash));
        *count == 1
    }
}

fn rand_u64() -> u64 {
    // RandomState is seeded from the OS per process and per instance; its
    // hash of nothing is a fine source for a table key.
    use std::hash::BuildHasher;
    std::collections::hash_map::RandomState::new().hash_one(0u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_first_copy_only_within_the_window() {
        let mut dedup = Dedup::new(Duration::from_millis(100));
        let start = Instant::now();
        assert!(dedup.first(b"nak 1", start));
        assert!(!dedup.first(b"nak 1", start + Duration::from_millis(40)));
        assert!(dedup.first(b"nak 2", start + Duration::from_millis(50)));
        // The window is measured from the first sighting and each copy
        // renews it, so a copy 99 ms after the last is still one.
        assert!(!dedup.first(b"nak 1", start + Duration::from_millis(120)));
        assert!(dedup.first(b"nak 1", start + Duration::from_millis(300)));
    }

    #[test]
    fn forgets_old_entries() {
        let mut dedup = Dedup::new(Duration::from_millis(10));
        let start = Instant::now();
        for i in 0..1000u32 {
            dedup.first(&i.to_be_bytes(), start + Duration::from_millis(u64::from(i)));
        }
        assert!(dedup.order.len() <= 11);
        assert!(dedup.seen.len() <= 11);
    }
}
