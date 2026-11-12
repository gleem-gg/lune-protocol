//! Restoring SRT packet order behind bonded links.
//!
//! Split across links with different latencies, SRT data packets reach the
//! server out of order. An SRT receiver takes every gap in the sequence for a
//! loss and NAKs it at once, so packets that were only late get sent again:
//! measured with two links 0.2 ms and 8 ms apart, the encoder retransmitted
//! about a tenth of the stream and its bitrate control backed off to the
//! minimum. The receiving end therefore holds packets that arrive after a
//! gap until the gap fills, and hands them on in sequence.
//!
//! A gap that does not fill within the hold time was a real loss: the held
//! packets go on and the SRT receiver NAKs the gap as usual. The hold time
//! follows how long gaps have recently taken to fill, so a session whose
//! links are close in latency adds almost nothing.
//!
//! Only SRT data packets are ordered. Control packets pass straight through,
//! and so does anything older than what was already handed on (a late
//! packet or a retransmission after its gap was given up), because the SRT
//! receiver wants those as soon as possible.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::srt;

/// Shortest hold time; covers jitter between links of equal latency.
pub const HOLD_MIN: Duration = Duration::from_millis(10);
/// Longest hold time. A gap older than this is a loss for SRT to repair, and
/// the delay it adds stays small next to SRT's own latency buffer.
pub const HOLD_MAX: Duration = Duration::from_millis(100);
/// Headroom over the slowest recent fill.
const HOLD_MARGIN: Duration = Duration::from_millis(5);
/// How long a measured fill time counts towards the hold time.
const FILL_MEMORY: Duration = Duration::from_secs(10);
/// Most packets held at once; beyond this the oldest gap is given up.
pub const MAX_HELD: usize = 4096;

/// SRT data sequence numbers are 31 bits.
const SEQ_MASK: u32 = 0x7fff_ffff;

fn seq_after(a: u32, b: u32) -> bool {
    let distance = a.wrapping_sub(b) & SEQ_MASK;
    distance != 0 && distance < 1 << 30
}

fn data_sequence(packet: &[u8]) -> Option<u32> {
    if packet.len() < 4 || srt::is_control(packet) {
        return None;
    }
    Some(u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) & SEQ_MASK)
}

pub struct Reorder {
    /// The sequence number the SRT receiver should get next.
    next: Option<u32>,
    /// Packets that arrived after a gap, by sequence number, with when they arrived.
    held: BTreeMap<u32, (Instant, Vec<u8>)>,
    /// When the oldest current gap was first seen.
    gap_since: Option<Instant>,
    /// Recent times a gap took to fill, newest last.
    fills: VecDeque<(Instant, Duration)>,
    hold: Duration,
    /// Gaps given up after the hold time, for the statistics.
    pub gaps_given_up: u64,
    /// Gaps that filled while held: reordering that would have cost a NAK.
    pub gaps_filled: u64,
}

impl Default for Reorder {
    fn default() -> Self {
        Self {
            next: None,
            held: BTreeMap::new(),
            gap_since: None,
            fills: VecDeque::new(),
            hold: HOLD_MIN,
            gaps_given_up: 0,
            gaps_filled: 0,
        }
    }
}

impl Reorder {
    /// Takes one SRT packet; everything that may go to the receiver now,
    /// in order, is appended to `out`.
    pub fn push(&mut self, packet: &[u8], now: Instant, out: &mut Vec<Vec<u8>>) {
        let Some(sequence) = data_sequence(packet) else {
            out.push(packet.to_vec());
            return;
        };
        let Some(next) = self.next else {
            self.next = Some(sequence.wrapping_add(1) & SEQ_MASK);
            out.push(packet.to_vec());
            return;
        };

        if sequence == next {
            out.push(packet.to_vec());
            self.next = Some(sequence.wrapping_add(1) & SEQ_MASK);
            if self.gap_since.is_some() && self.held.is_empty() {
                self.gap_since = None;
            }
            self.drain(now, out);
        } else if seq_after(sequence, next) {
            if self.held.is_empty() {
                self.gap_since = Some(now);
            }
            self.held.entry(sequence).or_insert_with(|| (now, packet.to_vec()));
            if self.held.len() > MAX_HELD {
                self.give_up(now, out);
            }
        } else {
            // Older than what the receiver already has: a late copy or a
            // retransmission. SRT sorts those out itself.
            out.push(packet.to_vec());
        }
    }

    /// Gives up gaps that have been open longer than the hold time.
    pub fn expire(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        while let Some(since) = self.gap_since {
            if now.duration_since(since) < self.hold {
                break;
            }
            self.give_up(now, out);
        }
    }

    /// When `expire` next has something to do, if anything is held.
    pub fn deadline(&self) -> Option<Instant> {
        self.gap_since.map(|since| since + self.hold)
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    pub fn hold(&self) -> Duration {
        self.hold
    }

    /// Hands on consecutive held packets after `next` moved.
    fn drain(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        let Some(mut next) = self.next else { return };
        let mut released = false;
        while let Some((_, packet)) = self.held.remove(&next) {
            out.push(packet);
            next = next.wrapping_add(1) & SEQ_MASK;
            released = true;
        }
        self.next = Some(next);
        if !released {
            // The gap the held packets wait behind is still open.
            return;
        }
        if let Some(since) = self.gap_since {
            self.record_fill(now, now.duration_since(since));
        }
        // A later gap, if any, has been open since its first held packet came.
        self.gap_since = self.oldest_held().and_then(|s| self.held.get(&s)).map(|&(at, _)| at);
    }

    /// Skips the oldest gap: the receiver gets the held packets after it and
    /// NAKs what is missing.
    fn give_up(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        let Some((&first, _)) = self.held.iter().next() else {
            self.gap_since = None;
            return;
        };
        // BTreeMap order is numeric; after a wrap the oldest held packet is
        // the one furthest behind, not the smallest number.
        let oldest = self.oldest_held().unwrap_or(first);
        self.gaps_given_up += 1;
        self.next = Some(oldest);
        // Not a fill: the gap was lost, so it must not stretch the hold time.
        self.gap_since = None;
        self.drain(now, out);
    }

    fn oldest_held(&self) -> Option<u32> {
        let next = self.next?;
        self.held.keys().copied().min_by_key(|&s| s.wrapping_sub(next) & SEQ_MASK)
    }

    fn record_fill(&mut self, now: Instant, took: Duration) {
        self.gaps_filled += 1;
        self.fills.push_back((now, took));
        while self.fills.front().is_some_and(|&(at, _)| now.duration_since(at) > FILL_MEMORY) {
            self.fills.pop_front();
        }
        let slowest = self.fills.iter().map(|&(_, d)| d).max().unwrap_or_default();
        self.hold = (slowest + slowest / 4 + HOLD_MARGIN).clamp(HOLD_MIN, HOLD_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(sequence: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[..4].copy_from_slice(&(sequence & SEQ_MASK).to_be_bytes());
        packet
    }

    fn control() -> Vec<u8> {
        let mut packet = vec![0u8; 16];
        packet[0] = 0x80; // control flag, ACK type
        packet[1] = 0x02;
        packet
    }

    fn sequences(out: &[Vec<u8>]) -> Vec<u32> {
        out.iter().filter_map(|p| data_sequence(p)).collect()
    }

    #[test]
    fn in_order_packets_pass_straight_through() {
        let mut r = Reorder::default();
        let now = Instant::now();
        let mut out = Vec::new();
        for s in 100..105 {
            r.push(&data(s), now, &mut out);
        }
        assert_eq!(sequences(&out), vec![100, 101, 102, 103, 104]);
        assert_eq!(r.held(), 0);
    }

    #[test]
    fn a_late_packet_is_put_back_in_place() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&data(4), t, &mut out);
        assert_eq!(sequences(&out), vec![1]);
        r.push(&data(2), t + Duration::from_millis(8), &mut out);
        assert_eq!(sequences(&out), vec![1, 2, 3, 4]);
        assert_eq!(r.gaps_filled, 1);
        assert_eq!(r.gaps_given_up, 0);
    }

    #[test]
    fn a_real_loss_is_given_up_after_the_hold_time() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.expire(t + HOLD_MIN / 2, &mut out);
        assert_eq!(sequences(&out), vec![1]);
        r.expire(t + HOLD_MIN, &mut out);
        assert_eq!(sequences(&out), vec![1, 3]);
        assert_eq!(r.gaps_given_up, 1);
        // The retransmission of 2 arrives later and goes straight on.
        r.push(&data(2), t + Duration::from_millis(30), &mut out);
        assert_eq!(sequences(&out), vec![1, 3, 2]);
    }

    #[test]
    fn control_packets_are_never_held() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&control(), t, &mut out);
        assert_eq!(out.len(), 2);
        assert!(srt::is_control(&out[1]));
    }

    #[test]
    fn the_hold_time_follows_measured_fills() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&data(2), t + Duration::from_millis(40), &mut out);
        // 40 ms + a quarter + 5 ms margin.
        assert_eq!(r.hold(), Duration::from_millis(55));
        // A gap that would take longer than 100 ms is capped.
        r.push(&data(5), t + Duration::from_millis(50), &mut out);
        r.push(&data(4), t + Duration::from_millis(250), &mut out);
        assert_eq!(r.hold(), HOLD_MAX);
    }

    #[test]
    fn a_gap_found_while_another_is_open_keeps_both() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        for s in [1, 3, 5] {
            r.push(&data(s), t, &mut out);
        }
        r.push(&data(2), t + Duration::from_millis(5), &mut out);
        assert_eq!(sequences(&out), vec![1, 2, 3]);
        assert_eq!(r.held(), 1);
        r.push(&data(4), t + Duration::from_millis(6), &mut out);
        assert_eq!(sequences(&out), vec![1, 2, 3, 4, 5]);
        assert_eq!(r.held(), 0);
        assert_eq!(r.deadline(), None);
    }

    #[test]
    fn filling_part_of_a_gap_neither_counts_nor_restarts_its_timer() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(4), t, &mut out);
        r.push(&data(2), t + Duration::from_millis(5), &mut out);
        assert_eq!(sequences(&out), vec![1, 2]);
        assert_eq!(r.gaps_filled, 0);
        assert_eq!(r.deadline(), Some(t + HOLD_MIN));
        r.expire(t + HOLD_MIN, &mut out);
        assert_eq!(sequences(&out), vec![1, 2, 4]);
        assert_eq!(r.hold(), HOLD_MIN);
    }

    #[test]
    fn a_later_gap_is_timed_from_its_own_first_packet() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&data(6), t + Duration::from_millis(2), &mut out);
        r.push(&data(2), t + Duration::from_millis(4), &mut out);
        // 3 went on; 4 and 5 are missing behind 6, which arrived at t+2.
        assert_eq!(sequences(&out), vec![1, 2, 3]);
        assert_eq!(r.deadline(), Some(t + Duration::from_millis(2) + r.hold()));
    }

    #[test]
    fn sequence_numbers_wrap_at_31_bits() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(SEQ_MASK - 1), t, &mut out);
        r.push(&data(0), t, &mut out);
        r.push(&data(SEQ_MASK), t, &mut out);
        assert_eq!(sequences(&out), vec![SEQ_MASK - 1, SEQ_MASK, 0]);
    }

    #[test]
    fn duplicates_of_held_packets_are_kept_once() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(1), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&data(3), t, &mut out);
        r.push(&data(2), t, &mut out);
        assert_eq!(sequences(&out), vec![1, 2, 3]);
    }

    #[test]
    fn too_many_held_packets_give_up_the_oldest_gap() {
        let mut r = Reorder::default();
        let t = Instant::now();
        let mut out = Vec::new();
        r.push(&data(0), t, &mut out);
        for s in 2..(MAX_HELD as u32 + 3) {
            r.push(&data(s), t, &mut out);
        }
        assert_eq!(r.gaps_given_up, 1);
        assert_eq!(r.held(), 0);
        assert_eq!(out.len(), MAX_HELD + 2);
    }
}
