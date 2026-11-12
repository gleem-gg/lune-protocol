//! The stateless registration cookie (specification: "Cookie").
//!
//! A HELLO costs the server one HMAC and no memory: the cookie it answers
//! with binds the source address, the nonce and the current minute under a
//! per-process secret, so only somebody who actually receives packets at that
//! address can present it back in a REGISTER.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;

use crate::packet::{Cookie, Nonce};

type HmacSha256 = Hmac<Sha256>;

/// 32 random bytes per ingest process, never stored or configured.
pub type CookieSecret = [u8; 32];

/// `ip16 || port || nonce || minute`, 42 bytes.
fn input(source: SocketAddr, nonce: &Nonce, minute: u64) -> [u8; 42] {
    let ip16 = match source.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut out = [0u8; 42];
    out[..16].copy_from_slice(&ip16);
    out[16..18].copy_from_slice(&source.port().to_be_bytes());
    out[18..34].copy_from_slice(nonce);
    out[34..42].copy_from_slice(&minute.to_be_bytes());
    out
}

fn compute(secret: &CookieSecret, source: SocketAddr, nonce: &Nonce, minute: u64) -> Cookie {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&input(source, nonce, minute));
    mac.finalize().into_bytes()[..16].try_into().expect("sha256 is 32 bytes")
}

/// The cookie for a HELLO from `source` at `unix_seconds`.
pub fn issue(secret: &CookieSecret, source: SocketAddr, nonce: &Nonce, unix_seconds: u64) -> Cookie {
    compute(secret, source, nonce, unix_seconds / 60)
}

/// Whether `cookie` was issued to `source` for `nonce` in the current or the
/// previous minute. Both candidates are always computed and compared in
/// constant time.
pub fn verify(secret: &CookieSecret, source: SocketAddr, nonce: &Nonce, cookie: &Cookie, unix_seconds: u64) -> bool {
    let minute = unix_seconds / 60;
    let current = compute(secret, source, nonce, minute).ct_eq(cookie);
    let previous = compute(secret, source, nonce, minute.wrapping_sub(1)).ct_eq(cookie);
    bool::from(current | previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> CookieSecret {
        std::array::from_fn(|i| i as u8)
    }

    fn nonce() -> Nonce {
        std::array::from_fn(|i| 0x10 + i as u8)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const NOW: u64 = 1_790_000_000;

    #[test]
    fn spec_vector_ipv4() {
        let source: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        assert_eq!(NOW / 60, 29_833_333);
        assert_eq!(
            hex(&input(source, &nonce(), NOW / 60)),
            "00000000000000000000ffffcb0071079c40101112131415161718191a1b1c1d1e1f0000000001c73875"
        );
        assert_eq!(hex(&issue(&secret(), source, &nonce(), NOW)), "e55a041a98643b60b2744a49742280b2");
    }

    #[test]
    fn spec_vector_ipv6() {
        let source: SocketAddr = "[2001:db8::7]:40000".parse().unwrap();
        assert_eq!(hex(&issue(&secret(), source, &nonce(), NOW)), "2c21408cf77edd1dba44918447c680c3");
    }

    #[test]
    fn ipv4_and_its_mapped_form_are_the_same_source() {
        // A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d.
        let v4: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:40000".parse().unwrap();
        assert_eq!(issue(&secret(), v4, &nonce(), NOW), issue(&secret(), mapped, &nonce(), NOW));
    }

    #[test]
    fn accepts_the_current_and_previous_minute_only() {
        let source: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let cookie = issue(&secret(), source, &nonce(), NOW);

        assert!(verify(&secret(), source, &nonce(), &cookie, NOW));
        assert!(verify(&secret(), source, &nonce(), &cookie, NOW + 60));
        assert!(!verify(&secret(), source, &nonce(), &cookie, NOW + 120));
        assert!(!verify(&secret(), source, &nonce(), &cookie, NOW - 60));
    }

    #[test]
    fn is_bound_to_address_port_nonce_and_secret() {
        let source: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let cookie = issue(&secret(), source, &nonce(), NOW);

        assert!(!verify(&secret(), "203.0.113.8:40000".parse().unwrap(), &nonce(), &cookie, NOW));
        assert!(!verify(&secret(), "203.0.113.7:40001".parse().unwrap(), &nonce(), &cookie, NOW));
        assert!(!verify(&secret(), source, &[0; 16], &cookie, NOW));
        assert!(!verify(&[9; 32], source, &nonce(), &cookie, NOW));
    }
}
