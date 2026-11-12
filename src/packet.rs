//! Lune framing (specification: "Framing" and "Packet reference").
//!
//! Every datagram is `0xA2`, a type byte and a body whose length is fixed by
//! the type. DATA means something different in each direction (sender → ingest
//! carries a `link_seq`, ingest → sender does not), so decoding is split by
//! direction: a receiver only ever asks for what may arrive at it, and
//! anything else is `None` and dropped silently, as the specification requires.

use crate::{MAGIC, MAX_DATAGRAM, MAX_TICKET_LEN};

pub const TYPE_DATA: u8 = 0x00;
pub const TYPE_HELLO: u8 = 0x01;
pub const TYPE_COOKIE: u8 = 0x02;
pub const TYPE_REGISTER: u8 = 0x03;
pub const TYPE_REGISTERED: u8 = 0x04;
pub const TYPE_REJECT: u8 = 0x05;
pub const TYPE_PING: u8 = 0x06;
pub const TYPE_PONG: u8 = 0x07;
pub const TYPE_CLOSE: u8 = 0x08;
pub const TYPE_PROBE_START: u8 = 0x09;
pub const TYPE_PROBE_ACCEPTED: u8 = 0x0A;
pub const TYPE_PROBE_DATA: u8 = 0x0B;
pub const TYPE_PROBE_REPORT: u8 = 0x0C;
pub const TYPE_KEYFRAME_REQUEST: u8 = 0x0D;

/// Header plus `link_seq`, the per-packet overhead sender → ingest.
pub const DATA_UP_OVERHEAD: usize = 6;
/// Header only, ingest → sender.
pub const DATA_DOWN_OVERHEAD: usize = 2;
/// The smallest SRT packet: its header.
pub const SRT_HEADER_LEN: usize = 16;

pub const HELLO_LEN: usize = 34;
pub const COOKIE_LEN: usize = 34;
pub const REGISTER_FIXED_LEN: usize = 53;
pub const REGISTERED_LEN: usize = 27;
pub const REJECT_LEN: usize = 3;
pub const PING_LEN: usize = 15;
pub const PONG_LEN: usize = 23;
pub const CLOSE_LEN: usize = 3;
pub const PROBE_START_FIXED_LEN: usize = 37;
pub const PROBE_ACCEPTED_LEN: usize = 9;
/// The fields of a PROBE_DATA; padding follows up to its length.
pub const PROBE_DATA_HEADER_LEN: usize = 18;
/// As long as a PROBE_REPORT, so a report never answers with more bytes than
/// the datagram it answers (the reason HELLO is padded).
pub const PROBE_DATA_MIN_LEN: usize = 34;
pub const PROBE_REPORT_LEN: usize = 34;
pub const KEYFRAME_REQUEST_LEN: usize = 6;

pub type Nonce = [u8; 16];
pub type Cookie = [u8; 16];
/// A stream session uuid as its 16 raw bytes.
pub type SessionId = [u8; 16];

/// REJECT reasons ("Packet reference").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    UnknownLink = 1,
    BadTicket = 2,
    Expired = 3,
    SessionFull = 4,
    Draining = 5,
    BadCookie = 6,
    /// A PROBE_START the server will not take now: the device already has
    /// a probe running or started one too recently, or the server runs as
    /// many probes as it allows. Worth retrying a little later.
    ProbeBusy = 7,
}

impl RejectReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::UnknownLink,
            2 => Self::BadTicket,
            3 => Self::Expired,
            4 => Self::SessionFull,
            5 => Self::Draining,
            6 => Self::BadCookie,
            7 => Self::ProbeBusy,
            _ => return None,
        })
    }
}

/// CLOSE reasons ("Packet reference").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    Normal = 0,
    Shutdown = 1,
    Replaced = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub link_id: u8,
    pub ping_seq: u32,
    pub sent_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub link_id: u8,
    pub ping_seq: u32,
    pub sent_us: u64,
    pub rx_highest_link_seq: u32,
    pub rx_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register<'a> {
    pub link_id: u8,
    pub nonce: Nonce,
    pub cookie: Cookie,
    pub session: SessionId,
    pub ticket: &'a [u8],
}

/// PROBE_START: a speed test of the link it arrives on, authorised like a
/// REGISTER but without a session ("Speed test").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStart<'a> {
    pub nonce: Nonce,
    pub cookie: Cookie,
    pub seconds: u8,
    pub ticket: &'a [u8],
}

/// The fields of a PROBE_DATA; its padding carries nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeData {
    pub probe_id: u32,
    pub seq: u32,
    pub sent_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReport {
    pub probe_id: u32,
    /// `seq` and `sent_us` of the PROBE_DATA this report answers.
    pub seq: u32,
    pub sent_us: u64,
    /// When the server received that PROBE_DATA, µs since the probe started,
    /// on the server's clock.
    pub server_us: u32,
    /// PROBE_DATA datagrams and their bytes (whole datagrams) received so far.
    pub rx_count: u32,
    pub rx_bytes: u64,
}

/// What a sender may send an ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream<'a> {
    Data { link_seq: u32, srt: &'a [u8] },
    Hello { link_id: u8, nonce: Nonce },
    Register(Register<'a>),
    Ping(Ping),
    /// The raw reason byte: the server ends the session whatever it says.
    Close { reason: u8 },
    ProbeStart(ProbeStart<'a>),
    ProbeData(ProbeData),
}

/// What an ingest may send a sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Downstream<'a> {
    Data { srt: &'a [u8] },
    Cookie { nonce: Nonce, cookie: Cookie },
    Registered { link_id: u8, session: SessionId, server_time_ms: u64 },
    /// The raw reason byte, so a sender can log a reason newer than itself.
    Reject { reason: u8 },
    Pong(Pong),
    Close { reason: u8 },
    ProbeAccepted { probe_id: u32, seconds: u8, max_mbps: u16 },
    ProbeReport(ProbeReport),
    /// Ask the encoder for a keyframe now (0x0D KEYFRAME_REQUEST). Sent on
    /// every link; `request_id` lets the sender act on it once.
    KeyframeRequest { request_id: u32 },
}

fn header(datagram: &[u8]) -> Option<u8> {
    if datagram.len() < 2 || datagram.len() > MAX_DATAGRAM || datagram[0] != MAGIC {
        return None;
    }
    Some(datagram[1])
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes[..N].try_into().expect("caller checked the length")
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(array(&bytes[at..]))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(array(&bytes[at..]))
}

/// Decode a datagram that arrived at the server.
pub fn decode_upstream(datagram: &[u8]) -> Option<Upstream<'_>> {
    let d = datagram;
    match header(d)? {
        TYPE_DATA if d.len() >= DATA_UP_OVERHEAD + SRT_HEADER_LEN => {
            Some(Upstream::Data { link_seq: u32_at(d, 2), srt: &d[DATA_UP_OVERHEAD..] })
        }
        TYPE_HELLO if d.len() == HELLO_LEN => Some(Upstream::Hello { link_id: d[2], nonce: array(&d[3..]) }),
        TYPE_REGISTER if d.len() >= REGISTER_FIXED_LEN => {
            let ticket_len = u16::from_be_bytes([d[51], d[52]]) as usize;
            if ticket_len == 0 || ticket_len > MAX_TICKET_LEN || d.len() != REGISTER_FIXED_LEN + ticket_len {
                return None;
            }
            Some(Upstream::Register(Register {
                link_id: d[2],
                nonce: array(&d[3..]),
                cookie: array(&d[19..]),
                session: array(&d[35..]),
                ticket: &d[REGISTER_FIXED_LEN..],
            }))
        }
        TYPE_PING if d.len() == PING_LEN => {
            Some(Upstream::Ping(Ping { link_id: d[2], ping_seq: u32_at(d, 3), sent_us: u64_at(d, 7) }))
        }
        TYPE_CLOSE if d.len() == CLOSE_LEN => Some(Upstream::Close { reason: d[2] }),
        TYPE_PROBE_START if d.len() >= PROBE_START_FIXED_LEN => {
            let ticket_len = u16::from_be_bytes([d[35], d[36]]) as usize;
            if ticket_len == 0 || ticket_len > MAX_TICKET_LEN || d.len() != PROBE_START_FIXED_LEN + ticket_len {
                return None;
            }
            Some(Upstream::ProbeStart(ProbeStart {
                nonce: array(&d[2..]),
                cookie: array(&d[18..]),
                seconds: d[34],
                ticket: &d[PROBE_START_FIXED_LEN..],
            }))
        }
        TYPE_PROBE_DATA if d.len() >= PROBE_DATA_MIN_LEN => Some(Upstream::ProbeData(ProbeData {
            probe_id: u32_at(d, 2),
            seq: u32_at(d, 6),
            sent_us: u64_at(d, 10),
        })),
        _ => None,
    }
}

/// Decode a datagram that arrived at the sender.
pub fn decode_downstream(datagram: &[u8]) -> Option<Downstream<'_>> {
    let d = datagram;
    match header(d)? {
        TYPE_DATA if d.len() >= DATA_DOWN_OVERHEAD + SRT_HEADER_LEN => {
            Some(Downstream::Data { srt: &d[DATA_DOWN_OVERHEAD..] })
        }
        TYPE_COOKIE if d.len() == COOKIE_LEN => {
            Some(Downstream::Cookie { nonce: array(&d[2..]), cookie: array(&d[18..]) })
        }
        TYPE_REGISTERED if d.len() == REGISTERED_LEN => Some(Downstream::Registered {
            link_id: d[2],
            session: array(&d[3..]),
            server_time_ms: u64_at(d, 19),
        }),
        TYPE_REJECT if d.len() == REJECT_LEN => Some(Downstream::Reject { reason: d[2] }),
        TYPE_PONG if d.len() == PONG_LEN => Some(Downstream::Pong(Pong {
            link_id: d[2],
            ping_seq: u32_at(d, 3),
            sent_us: u64_at(d, 7),
            rx_highest_link_seq: u32_at(d, 15),
            rx_count: u32_at(d, 19),
        })),
        TYPE_CLOSE if d.len() == CLOSE_LEN => Some(Downstream::Close { reason: d[2] }),
        TYPE_PROBE_ACCEPTED if d.len() == PROBE_ACCEPTED_LEN => Some(Downstream::ProbeAccepted {
            probe_id: u32_at(d, 2),
            seconds: d[6],
            max_mbps: u16::from_be_bytes([d[7], d[8]]),
        }),
        TYPE_PROBE_REPORT if d.len() == PROBE_REPORT_LEN => Some(Downstream::ProbeReport(ProbeReport {
            probe_id: u32_at(d, 2),
            seq: u32_at(d, 6),
            sent_us: u64_at(d, 10),
            server_us: u32_at(d, 18),
            rx_count: u32_at(d, 22),
            rx_bytes: u64_at(d, 26),
        })),
        TYPE_KEYFRAME_REQUEST if d.len() == KEYFRAME_REQUEST_LEN => Some(Downstream::KeyframeRequest { request_id: u32_at(d, 2) }),
        _ => None,
    }
}

/// DATA sender → ingest, written into `out` (cleared first) so the hot path
/// reuses one buffer instead of allocating per packet.
pub fn write_data_up(out: &mut Vec<u8>, link_seq: u32, srt: &[u8]) {
    out.clear();
    out.extend_from_slice(&[MAGIC, TYPE_DATA]);
    out.extend_from_slice(&link_seq.to_be_bytes());
    out.extend_from_slice(srt);
}

/// DATA ingest → sender, written into `out` (cleared first).
pub fn write_data_down(out: &mut Vec<u8>, srt: &[u8]) {
    out.clear();
    out.extend_from_slice(&[MAGIC, TYPE_DATA]);
    out.extend_from_slice(srt);
}

pub fn hello(link_id: u8, nonce: &Nonce) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_HELLO;
    out[2] = link_id;
    out[3..19].copy_from_slice(nonce);
    out
}

pub fn cookie(nonce: &Nonce, cookie: &Cookie) -> [u8; COOKIE_LEN] {
    let mut out = [0u8; COOKIE_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_COOKIE;
    out[2..18].copy_from_slice(nonce);
    out[18..34].copy_from_slice(cookie);
    out
}

/// REGISTER. `ticket` must be 1–1024 bytes; the caller checked it when the
/// ticket was accepted, so a violation here is a bug.
pub fn register(link_id: u8, nonce: &Nonce, cookie: &Cookie, session: &SessionId, ticket: &[u8]) -> Vec<u8> {
    assert!(!ticket.is_empty() && ticket.len() <= MAX_TICKET_LEN, "ticket length out of range");
    let mut out = Vec::with_capacity(REGISTER_FIXED_LEN + ticket.len());
    out.extend_from_slice(&[MAGIC, TYPE_REGISTER, link_id]);
    out.extend_from_slice(nonce);
    out.extend_from_slice(cookie);
    out.extend_from_slice(session);
    out.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    out.extend_from_slice(ticket);
    out
}

pub fn registered(link_id: u8, session: &SessionId, server_time_ms: u64) -> [u8; REGISTERED_LEN] {
    let mut out = [0u8; REGISTERED_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_REGISTERED;
    out[2] = link_id;
    out[3..19].copy_from_slice(session);
    out[19..27].copy_from_slice(&server_time_ms.to_be_bytes());
    out
}

pub fn reject(reason: RejectReason) -> [u8; REJECT_LEN] {
    [MAGIC, TYPE_REJECT, reason as u8]
}

pub fn ping(ping: &Ping) -> [u8; PING_LEN] {
    let mut out = [0u8; PING_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_PING;
    out[2] = ping.link_id;
    out[3..7].copy_from_slice(&ping.ping_seq.to_be_bytes());
    out[7..15].copy_from_slice(&ping.sent_us.to_be_bytes());
    out
}

pub fn pong(pong: &Pong) -> [u8; PONG_LEN] {
    let mut out = [0u8; PONG_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_PONG;
    out[2] = pong.link_id;
    out[3..7].copy_from_slice(&pong.ping_seq.to_be_bytes());
    out[7..15].copy_from_slice(&pong.sent_us.to_be_bytes());
    out[15..19].copy_from_slice(&pong.rx_highest_link_seq.to_be_bytes());
    out[19..23].copy_from_slice(&pong.rx_count.to_be_bytes());
    out
}

pub fn close(reason: CloseReason) -> [u8; CLOSE_LEN] {
    [MAGIC, TYPE_CLOSE, reason as u8]
}

/// PROBE_START. `ticket` must be 1–1024 bytes, as for [`register`].
pub fn probe_start(nonce: &Nonce, cookie: &Cookie, seconds: u8, ticket: &[u8]) -> Vec<u8> {
    assert!(!ticket.is_empty() && ticket.len() <= MAX_TICKET_LEN, "ticket length out of range");
    let mut out = Vec::with_capacity(PROBE_START_FIXED_LEN + ticket.len());
    out.extend_from_slice(&[MAGIC, TYPE_PROBE_START]);
    out.extend_from_slice(nonce);
    out.extend_from_slice(cookie);
    out.push(seconds);
    out.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    out.extend_from_slice(ticket);
    out
}

pub fn probe_accepted(probe_id: u32, seconds: u8, max_mbps: u16) -> [u8; PROBE_ACCEPTED_LEN] {
    let mut out = [0u8; PROBE_ACCEPTED_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_PROBE_ACCEPTED;
    out[2..6].copy_from_slice(&probe_id.to_be_bytes());
    out[6] = seconds;
    out[7..9].copy_from_slice(&max_mbps.to_be_bytes());
    out
}

/// PROBE_DATA of `len` bytes (34–1500), zero-padded, written into `out`
/// (resized, so the sender reuses one buffer).
pub fn write_probe_data(out: &mut Vec<u8>, data: &ProbeData, len: usize) {
    assert!((PROBE_DATA_MIN_LEN..=MAX_DATAGRAM).contains(&len), "probe datagram length out of range");
    out.resize(len, 0);
    out[0] = MAGIC;
    out[1] = TYPE_PROBE_DATA;
    out[2..6].copy_from_slice(&data.probe_id.to_be_bytes());
    out[6..10].copy_from_slice(&data.seq.to_be_bytes());
    out[10..18].copy_from_slice(&data.sent_us.to_be_bytes());
}

pub fn probe_report(report: &ProbeReport) -> [u8; PROBE_REPORT_LEN] {
    let mut out = [0u8; PROBE_REPORT_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_PROBE_REPORT;
    out[2..6].copy_from_slice(&report.probe_id.to_be_bytes());
    out[6..10].copy_from_slice(&report.seq.to_be_bytes());
    out[10..18].copy_from_slice(&report.sent_us.to_be_bytes());
    out[18..22].copy_from_slice(&report.server_us.to_be_bytes());
    out[22..26].copy_from_slice(&report.rx_count.to_be_bytes());
    out[26..34].copy_from_slice(&report.rx_bytes.to_be_bytes());
    out
}

pub fn keyframe_request(request_id: u32) -> [u8; KEYFRAME_REQUEST_LEN] {
    let mut out = [0u8; KEYFRAME_REQUEST_LEN];
    out[0] = MAGIC;
    out[1] = TYPE_KEYFRAME_REQUEST;
    out[2..6].copy_from_slice(&request_id.to_be_bytes());
    out
}

/// The specification's packet vectors ("Test vectors"), byte for byte.
#[cfg(test)]
mod vectors {
    use super::*;

    const NONCE: Nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const COOKIE: Cookie = [
        0xe5, 0x5a, 0x04, 0x1a, 0x98, 0x64, 0x3b, 0x60, 0xb2, 0x74, 0x4a, 0x49, 0x74, 0x22, 0x80, 0xb2,
    ];
    const SESSION: SessionId = [
        0x0f, 0x8e, 0x7d, 0x6c, 0x5b, 0x4a, 0x49, 0x38, 0x82, 0x71, 0x60, 0x5f, 0x4e, 0x3d, 0x2c, 0x1b,
    ];
    const TICKET_V1: &str = "eyJ2IjoxLCJ0eXAiOiJpbmdlc3QiLCJraWQiOiJmc24xLTIwMjYtMDkiLCJkaWQiOiI5ZDNjMmY0ZS02YjFhLTRjOGUtOWYyZC0xYTJiM2M0ZDVlNmYiLCJzaWQiOiIwZjhlN2Q2Yy01YjRhLTQ5MzgtODI3MS02MDVmNGUzZDJjMWIiLCJwYXRoIjoibGl2ZVwvOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwibW9kZSI6InNwbGl0IiwianRpIjoiUTdtWnAzTHg5S2ZUMndCbiIsImlhdCI6MTc5MDAwMDAwMCwiZXhwIjoxNzkwMDAwOTAwfQ.nDRiBsl1DEt1DfMN2_1pbuggEMN4Qv222TXDGANWIk8";

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn hello() {
        let bytes = hex("a20101101112131415161718191a1b1c1d1e1f000000000000000000000000000000");
        assert_eq!(super::hello(1, &NONCE).to_vec(), bytes);
        assert_eq!(decode_upstream(&bytes), Some(Upstream::Hello { link_id: 1, nonce: NONCE }));
    }

    #[test]
    fn hello_padding_is_not_checked() {
        let mut bytes = super::hello(1, &NONCE);
        bytes[33] = 0xff;
        assert!(matches!(decode_upstream(&bytes), Some(Upstream::Hello { .. })));
    }

    #[test]
    fn cookie() {
        let bytes = hex("a202101112131415161718191a1b1c1d1e1fe55a041a98643b60b2744a49742280b2");
        assert_eq!(super::cookie(&NONCE, &COOKIE).to_vec(), bytes);
        assert_eq!(decode_downstream(&bytes), Some(Downstream::Cookie { nonce: NONCE, cookie: COOKIE }));
    }

    #[test]
    fn register_carrying_ticket_v1() {
        let bytes = hex(concat!(
            "a20301101112131415161718191a1b1c1d1e1fe55a041a98643b60b2744a49742280b20f8e7d6c5b4a49388271605f4e3d2c1b0186",
            "65794a32496a6f784c434a30655841694f694a70626d646c633351694c434a72615751694f694a6d633234784c5449774d6a59744d446b694c434a6b615751694f6949355a444e6a4d6d59305a533032596a46684c54526a4f4755744f5759795a43307859544a694d324d305a44566c4e6d59694c434a7a615751694f6949775a6a686c4e32513259793031596a52684c5451354d7a67744f4449334d5330324d44566d4e47557a5a444a6a4d5749694c434a775958526f496a6f6962476c325a5677764f57517a597a4a6d4e4755744e6d497859533030597a686c4c546c6d4d6d51744d574579596a4e6a4e4751315a545a6d496977696257396b5a534936496e4e7762476c3049697769616e5270496a6f6955546474576e417a5448673553325a554d6e644362694973496d6c68644349364d5463354d4441774d4441774d4377695a586877496a6f784e7a6b774d4441774f54417766512e6e44526942736c314445743144664d4e325f317062756767454d4e34517632323254584447414e57496b38"
        ));
        assert_eq!(bytes.len(), 443);
        assert_eq!(super::register(1, &NONCE, &COOKIE, &SESSION, TICKET_V1.as_bytes()), bytes);
        assert_eq!(
            decode_upstream(&bytes),
            Some(Upstream::Register(Register {
                link_id: 1,
                nonce: NONCE,
                cookie: COOKIE,
                session: SESSION,
                ticket: TICKET_V1.as_bytes(),
            }))
        );
    }

    #[test]
    fn register_with_a_ticket_length_that_disagrees_is_dropped() {
        let mut bytes = super::register(1, &NONCE, &COOKIE, &SESSION, b"abc");
        bytes.push(b'd');
        assert_eq!(decode_upstream(&bytes), None);

        let mut empty = super::register(1, &NONCE, &COOKIE, &SESSION, b"a");
        empty.truncate(REGISTER_FIXED_LEN);
        empty[51] = 0;
        empty[52] = 0;
        assert_eq!(decode_upstream(&empty), None);
    }

    #[test]
    fn registered() {
        let bytes = hex("a204010f8e7d6c5b4a49388271605f4e3d2c1b000001a0c4506cfa");
        assert_eq!(super::registered(1, &SESSION, 1_790_000_000_250).to_vec(), bytes);
        assert_eq!(
            decode_downstream(&bytes),
            Some(Downstream::Registered { link_id: 1, session: SESSION, server_time_ms: 1_790_000_000_250 })
        );
    }

    #[test]
    fn reject_and_close() {
        assert_eq!(super::reject(RejectReason::Expired).to_vec(), hex("a20503"));
        assert_eq!(decode_downstream(&hex("a20503")), Some(Downstream::Reject { reason: 3 }));
        assert_eq!(super::close(CloseReason::Normal).to_vec(), hex("a20800"));
        assert_eq!(decode_upstream(&hex("a20800")), Some(Upstream::Close { reason: 0 }));
        assert_eq!(decode_downstream(&hex("a20802")), Some(Downstream::Close { reason: 2 }));
    }

    #[test]
    fn data_up() {
        let bytes = hex("a2000000000100000001c0000001000000641234abcd47400010");
        let mut out = Vec::new();
        write_data_up(&mut out, 1, &bytes[6..]);
        assert_eq!(out, bytes);
        assert_eq!(decode_upstream(&bytes), Some(Upstream::Data { link_seq: 1, srt: &bytes[6..] }));

        let retx = hex("a2000000000200000001c4000001000000c81234abcd47400010");
        assert_eq!(retx[10], 0xc4);
        let Some(Upstream::Data { link_seq, srt }) = decode_upstream(&retx) else { panic!() };
        assert_eq!(link_seq, 2);
        assert!(crate::srt::is_retransmission(srt));
        assert!(!crate::srt::is_retransmission(&bytes[6..]));
    }

    #[test]
    fn data_down() {
        let bytes = hex("a2008002000000000007000001f45678ef01");
        let mut out = Vec::new();
        write_data_down(&mut out, &bytes[2..]);
        assert_eq!(out, bytes);
        let Some(Downstream::Data { srt }) = decode_downstream(&bytes) else { panic!() };
        assert!(crate::srt::is_control(srt));
    }

    #[test]
    fn ping_and_pong() {
        let ping = Ping { link_id: 1, ping_seq: 42, sent_us: 1_790_000_000_123_456 };
        let bytes = hex("a206010000002a00065bfeda27c240");
        assert_eq!(super::ping(&ping).to_vec(), bytes);
        assert_eq!(decode_upstream(&bytes), Some(Upstream::Ping(ping)));

        let pong = Pong {
            link_id: 1,
            ping_seq: 42,
            sent_us: 1_790_000_000_123_456,
            rx_highest_link_seq: 1000,
            rx_count: 998,
        };
        let bytes = hex("a207010000002a00065bfeda27c240000003e8000003e6");
        assert_eq!(super::pong(&pong).to_vec(), bytes);
        assert_eq!(decode_downstream(&bytes), Some(Downstream::Pong(pong)));
    }

    #[test]
    fn probe_start_carrying_ticket_v1() {
        // The fixed part; ticket V1 follows, the same bytes as in REGISTER.
        let mut bytes = hex("a209101112131415161718191a1b1c1d1e1fe55a041a98643b60b2744a49742280b20a0186");
        bytes.extend_from_slice(TICKET_V1.as_bytes());
        assert_eq!(bytes.len(), 427);
        assert_eq!(super::probe_start(&NONCE, &COOKIE, 10, TICKET_V1.as_bytes()), bytes);
        assert_eq!(
            decode_upstream(&bytes),
            Some(Upstream::ProbeStart(ProbeStart { nonce: NONCE, cookie: COOKIE, seconds: 10, ticket: TICKET_V1.as_bytes() }))
        );

        let mut longer = super::probe_start(&NONCE, &COOKIE, 10, b"abc");
        longer.push(b'd');
        assert_eq!(decode_upstream(&longer), None);
        let mut empty = super::probe_start(&NONCE, &COOKIE, 10, b"a");
        empty.truncate(PROBE_START_FIXED_LEN);
        empty[35] = 0;
        empty[36] = 0;
        assert_eq!(decode_upstream(&empty), None);
    }

    #[test]
    fn probe_accepted() {
        let bytes = hex("a20a1a2b3c4d0a0064");
        assert_eq!(super::probe_accepted(0x1a2b3c4d, 10, 100).to_vec(), bytes);
        assert_eq!(
            decode_downstream(&bytes),
            Some(Downstream::ProbeAccepted { probe_id: 0x1a2b3c4d, seconds: 10, max_mbps: 100 })
        );
    }

    #[test]
    fn probe_data_and_report() {
        let data = ProbeData { probe_id: 0x1a2b3c4d, seq: 1, sent_us: 1_790_000_000_123_456 };
        let bytes = hex("a20b1a2b3c4d0000000100065bfeda27c24000000000000000000000000000000000");
        let mut out = vec![0xff; 3];
        write_probe_data(&mut out, &data, PROBE_DATA_MIN_LEN);
        assert_eq!(out, bytes);
        assert_eq!(decode_upstream(&bytes), Some(Upstream::ProbeData(data)));

        // Padded to the sender's usual size; the padding is not checked.
        write_probe_data(&mut out, &data, 1400);
        assert_eq!(out.len(), 1400);
        out[1399] = 0xff;
        assert_eq!(decode_upstream(&out), Some(Upstream::ProbeData(data)));
        // Shorter than a report: dropped.
        assert_eq!(decode_upstream(&bytes[..PROBE_DATA_MIN_LEN - 1]), None);

        let report = ProbeReport {
            probe_id: 0x1a2b3c4d,
            seq: 1,
            sent_us: 1_790_000_000_123_456,
            server_us: 250_000,
            rx_count: 1,
            rx_bytes: 34,
        };
        let bytes = hex("a20c1a2b3c4d0000000100065bfeda27c2400003d090000000010000000000000022");
        assert_eq!(super::probe_report(&report).to_vec(), bytes);
        assert_eq!(decode_downstream(&bytes), Some(Downstream::ProbeReport(report)));
    }

    #[test]
    fn reject_7_probe_busy() {
        assert_eq!(super::reject(RejectReason::ProbeBusy).to_vec(), hex("a20507"));
        assert_eq!(RejectReason::from_u8(7), Some(RejectReason::ProbeBusy));
        assert_eq!(RejectReason::from_u8(8), None);
    }

    #[test]
    fn probe_packets_only_go_one_way() {
        assert_eq!(decode_downstream(&super::probe_start(&NONCE, &COOKIE, 10, b"t")), None);
        assert_eq!(decode_upstream(&super::probe_accepted(1, 10, 100)), None);
        let report = ProbeReport { probe_id: 1, seq: 1, sent_us: 1, server_us: 1, rx_count: 1, rx_bytes: 34 };
        assert_eq!(decode_upstream(&super::probe_report(&report)), None);
        let mut data = Vec::new();
        write_probe_data(&mut data, &ProbeData { probe_id: 1, seq: 1, sent_us: 1 }, PROBE_DATA_MIN_LEN);
        assert_eq!(decode_downstream(&data), None);
    }

    #[test]
    fn drops_what_does_not_belong() {
        // Wrong magic, unknown type, wrong lengths, wrong direction.
        assert_eq!(decode_upstream(&hex("a10800")), None);
        assert_eq!(decode_upstream(&hex("a20900")), None);
        assert_eq!(decode_upstream(&hex("a2080000")), None);
        assert_eq!(decode_upstream(&hex("a2")), None);
        assert_eq!(decode_upstream(&super::cookie(&NONCE, &COOKIE)), None);
        assert_eq!(decode_downstream(&super::hello(0, &NONCE)), None);
        // DATA shorter than an SRT header.
        assert_eq!(decode_upstream(&hex("a200000000010000000100000000000000000000")), None);
        // Longer than 1500 bytes.
        let mut big = vec![0u8; 1501];
        big[0] = 0xa2;
        assert_eq!(decode_upstream(&big), None);
        big.truncate(1500);
        assert!(decode_upstream(&big).is_some());
    }

    #[test]
    fn keyframe_request() {
        let bytes = super::keyframe_request(0x0102_0304);
        assert_eq!(bytes, [0xA2, 0x0D, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_downstream(&bytes), Some(Downstream::KeyframeRequest { request_id: 0x0102_0304 }));
        // Not something a sender may send.
        assert_eq!(decode_upstream(&bytes), None);
        assert_eq!(decode_downstream(&bytes[..5]), None);
    }
}
