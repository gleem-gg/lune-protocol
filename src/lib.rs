//! Lune, a bonding protocol that carries one SRT connection from a sender to
//! an ingest over several network links at once. The specification is at
//! <https://lune.gleem.gg/>; section names below refer to it.
//!
//! Everything both ends have to agree on byte for byte lives here, so a wire
//! change breaks the build on both sides instead of in the field:
//!
//! - [`packet`]: framing and the packet types ("Framing", "Packet
//!   reference"), for streaming and for the per-link speed test;
//! - [`cookie`]: the stateless HELLO → COOKIE check ("Cookie");
//! - [`ticket`]: verifying the tickets an operator mints ("Tickets");
//! - [`srt`]: the two bits of an SRT header the scheduler looks at;
//! - [`dedup`]: dropping the extra copies of packets sent over several links;
//! - the limits and timers ("Limits and timers"), and serial-number arithmetic for the
//!   wrapping `link_seq` counters.

pub mod cookie;
pub mod dedup;
pub mod packet;
pub mod reorder;
pub mod srt;
pub mod ticket;

use std::time::Duration;

/// First byte of every Lune datagram.
pub const MAGIC: u8 = 0xA2;

/// Default UDP port of the relay.
pub const DEFAULT_PORT: u16 = 29530;

/// Links per session, so `link_id` is 0–7.
pub const MAX_LINKS: usize = 8;

/// Longest datagram either side sends or accepts.
pub const MAX_DATAGRAM: usize = 1500;

/// Receive buffers are at least this large, so an oversized datagram shows up
/// as one (and is dropped) instead of being silently truncated.
pub const RECV_BUFFER: usize = 2048;

pub const MAX_TICKET_LEN: usize = 1024;

pub const PING_INTERVAL: Duration = Duration::from_millis(200);
pub const LINK_DEAD_AFTER: Duration = Duration::from_millis(1500);
pub const PONGS_TO_REVIVE: u32 = 2;

/// The server removes a binding it has not heard from for this long.
pub const BINDING_IDLE: Duration = Duration::from_secs(10);
/// And ends a session none of whose links it has heard from for this long.
pub const SESSION_IDLE: Duration = Duration::from_secs(30);
/// Server → sender packets go to the links heard from within this window.
pub const DOWNSTREAM_RECENT: Duration = Duration::from_millis(1500);

/// Allowance for clock drift between the ticket issuer and an ingest.
pub const CLOCK_SKEW_SECONDS: i64 = 30;

/// Per-link scheduler window, in packets.
pub const WINDOW_INITIAL: u32 = 16;
pub const WINDOW_MIN: u32 = 4;
pub const WINDOW_MAX: u32 = 4096;

/// Speed test probes ("Speed test", 0x09–0x0C): the longest a probe may
/// run, and the most the server grants.
pub const PROBE_MAX_SECONDS: u8 = 15;
pub const PROBE_MAX_MBPS: u16 = 100;
/// The server keeps a probe this long past its granted seconds, for the
/// sender's last packets and a queue that is still draining.
pub const PROBE_GRACE: Duration = Duration::from_secs(3);
/// The server answers a probe's PROBE_DATA with at most one PROBE_REPORT
/// per this interval.
pub const PROBE_REPORT_INTERVAL: Duration = Duration::from_millis(50);

/// `a` is later than `b` in RFC 1982 serial-number order over u32, which is
/// how every wrapping counter on the wire is compared.
pub fn seq_after(a: u32, b: u32) -> bool {
    a != b && (a.wrapping_sub(b) as i32) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_numbers_compare_across_the_wrap() {
        assert!(seq_after(2, 1));
        assert!(!seq_after(1, 2));
        assert!(!seq_after(7, 7));
        assert!(seq_after(3, u32::MAX));
        assert!(!seq_after(u32::MAX, 3));
    }
}
