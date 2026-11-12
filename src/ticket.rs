//! Tickets (specification: "Tickets").
//!
//! Minted by whoever operates the service, verified by the ingest offline:
//!
//! ```text
//! ticket = base64url(json(payload)) "." base64url(hmac_sha256(base64url(json(payload)), secret[kid]))
//! ```
//!
//! The signature covers the *encoded* payload, so verification never depends
//! on how the issuer happened to order keys or escape slashes: the JSON is only
//! parsed once the bytes it came in are known to be authentic. The one
//! exception is `kid`, read from the still-unverified payload to pick the
//! secret; an unknown kid is simply a bad signature.

use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::CLOCK_SKEW_SECONDS;

type HmacSha256 = Hmac<Sha256>;

/// base64url that accepts input with or without `=` padding.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("the ticket is not in the expected form")]
    Malformed,
    #[error("the ticket signature does not verify")]
    BadSignature,
    #[error("the ticket is not valid here (wrong typ or v)")]
    WrongType,
    #[error("the ticket has expired")]
    Expired,
}

/// The kid → secret map, from `kid=secret[,kid=secret…]`. Secrets are used
/// as their ASCII bytes, never hex-decoded.
#[derive(Clone, Default)]
pub struct Secrets(BTreeMap<String, Vec<u8>>);

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secrets themselves: this ends up in logs.
        f.debug_tuple("Secrets").field(&self.kids()).finish()
    }
}

impl Secrets {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (kid, secret) = entry.split_once('=').ok_or_else(|| format!("{entry:?} is not kid=secret"))?;
            let (kid, secret) = (kid.trim(), secret.trim());
            if kid.is_empty() || secret.is_empty() {
                return Err(format!("{entry:?} has an empty kid or secret"));
            }
            if map.insert(kid.to_string(), secret.as_bytes().to_vec()).is_some() {
                return Err(format!("kid {kid} is listed twice"));
            }
        }
        if map.is_empty() {
            return Err("no kid=secret pair".into());
        }
        Ok(Self(map))
    }

    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(pairs.into_iter().map(|(k, s)| (k.to_string(), s.as_bytes().to_vec())).collect())
    }

    pub fn kids(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub fn get(&self, kid: &str) -> Option<&[u8]> {
        self.0.get(kid).map(Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What an ingest needs from a verified `ingest` ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestTicket {
    pub kid: String,
    pub did: Uuid,
    pub sid: Uuid,
    pub path: String,
    pub mode: String,
    pub exp: i64,
    /// `enc: 1`: the session publishes encrypted, with [`srt_passphrase`].
    pub enc: bool,
    /// Where the session's packets go (`fwd`); an extension, see [`Forward`].
    pub fwd: Forward,
}

/// Where an ingest hands a session's packets. An extension Gleem's ingest
/// uses; the Lune specification only knows the default, [`Forward::Media`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Forward {
    /// No `fwd`: an SRT stream for the SRT receiver.
    #[default]
    Media,
    /// `fwd: "turn"`: a bonded call's WebRTC traffic for the TURN relay,
    /// passed on as it comes.
    Turn,
}

/// What a verified `play` ticket carries. `play` tickets authorise reading a
/// stream from Gleem's SRT receiver; they are not part of the Lune
/// specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayTicket {
    pub kid: String,
    pub did: Uuid,
    pub path: String,
    pub kv: i64,
}

/// Steps 1–5 of 2.4: split, decode, pick the secret, check the signature,
/// then `v` and `typ`. Returns the parsed payload.
fn verify_signed(ticket: &str, secrets: &Secrets, typ: &str) -> Result<Map<String, Value>, TicketError> {
    let (payload_b64, signature_b64) = ticket.split_once('.').ok_or(TicketError::Malformed)?;
    if payload_b64.is_empty() || signature_b64.is_empty() {
        return Err(TicketError::Malformed);
    }

    let payload = decode_payload(payload_b64)?;
    let kid = payload.get("kid").and_then(Value::as_str).ok_or(TicketError::Malformed)?;
    let secret = secrets.get(kid).ok_or(TicketError::BadSignature)?;

    let signature = LENIENT.decode(signature_b64).map_err(|_| TicketError::BadSignature)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload_b64.as_bytes());
    // Constant time, via the MAC's own comparison.
    mac.verify_slice(&signature).map_err(|_| TicketError::BadSignature)?;

    if payload.get("v").and_then(Value::as_i64) != Some(1) || payload.get("typ").and_then(Value::as_str) != Some(typ) {
        return Err(TicketError::WrongType);
    }
    Ok(payload)
}

fn decode_payload(payload_b64: &str) -> Result<Map<String, Value>, TicketError> {
    let json = LENIENT.decode(payload_b64).map_err(|_| TicketError::Malformed)?;
    match serde_json::from_slice(&json) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(TicketError::Malformed),
    }
}

fn string(payload: &Map<String, Value>, key: &str) -> Result<String, TicketError> {
    payload.get(key).and_then(Value::as_str).map(str::to_string).ok_or(TicketError::Malformed)
}

fn uuid(payload: &Map<String, Value>, key: &str) -> Result<Uuid, TicketError> {
    let text = payload.get(key).and_then(Value::as_str).ok_or(TicketError::Malformed)?;
    Uuid::try_parse(text).map_err(|_| TicketError::Malformed)
}

/// Verify a ticket presented in a REGISTER. `now` is Unix seconds.
pub fn verify_ingest(ticket: &str, secrets: &Secrets, now: i64) -> Result<IngestTicket, TicketError> {
    let payload = verify_signed(ticket, secrets, "ingest")?;

    let exp = payload.get("exp").and_then(Value::as_i64).ok_or(TicketError::Expired)?;
    if exp < now - CLOCK_SKEW_SECONDS {
        return Err(TicketError::Expired);
    }

    Ok(IngestTicket {
        kid: string(&payload, "kid")?,
        did: uuid(&payload, "did")?,
        sid: uuid(&payload, "sid")?,
        path: string(&payload, "path")?,
        mode: payload.get("mode").and_then(Value::as_str).unwrap_or("split").to_string(),
        exp,
        enc: payload.get("enc").and_then(Value::as_i64) == Some(1),
        fwd: match payload.get("fwd") {
            None => Forward::Media,
            Some(Value::String(fwd)) if fwd == "turn" => Forward::Turn,
            // A destination this build does not know: relaying the session
            // anywhere else would be wrong.
            Some(_) => return Err(TicketError::Malformed),
        },
    })
}

/// The SRT passphrase Gleem derives for an encrypted session:
/// `base64url_nopad(HMAC-SHA256(secret[kid], "srt-passphrase:" + sid))`,
/// 43 characters. Issuer and ingest derive the same one; other operators may
/// choose passphrases any way they like.
pub fn srt_passphrase(secret: &[u8], sid: Uuid) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(b"srt-passphrase:");
    mac.update(sid.hyphenated().to_string().as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Verify a ticket presented to the SRT receiver as a stream id password. Play
/// tickets have no expiry; revocation is by `kv`, which the caller checks.
pub fn verify_play(ticket: &str, secrets: &Secrets) -> Result<PlayTicket, TicketError> {
    let payload = verify_signed(ticket, secrets, "play")?;
    Ok(PlayTicket {
        kid: string(&payload, "kid")?,
        did: uuid(&payload, "did")?,
        path: string(&payload, "path")?,
        kv: payload.get("kv").and_then(Value::as_i64).ok_or(TicketError::Malformed)?,
    })
}

/// What the sender reads from its own ticket without verifying it (it has no
/// secret): the session to register under and when to expect a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified {
    pub sid: Uuid,
    pub exp: i64,
}

pub fn peek_ingest(ticket: &str) -> Result<Unverified, TicketError> {
    if ticket.is_empty() || ticket.len() > crate::MAX_TICKET_LEN || !ticket.is_ascii() {
        return Err(TicketError::Malformed);
    }
    let (payload_b64, signature_b64) = ticket.split_once('.').ok_or(TicketError::Malformed)?;
    if payload_b64.is_empty() || signature_b64.is_empty() {
        return Err(TicketError::Malformed);
    }
    let payload = decode_payload(payload_b64)?;
    Ok(Unverified {
        sid: uuid(&payload, "sid")?,
        exp: payload.get("exp").and_then(Value::as_i64).ok_or(TicketError::Malformed)?,
    })
}

/// Sign `payload_json` as a ticket issuer would. For tests on both ends of
/// the wire, and for operators that mint tickets in Rust.
pub fn mint(payload_json: &str, secret: &[u8]) -> String {
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload_b64.as_bytes());
    format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// The specification's ticket vectors ("Test vectors").
#[cfg(test)]
mod vectors {
    use super::*;

    const DID: &str = "9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f";
    const SID: &str = "0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b";

    const V1_JSON: &str = r#"{"v":1,"typ":"ingest","kid":"fsn1-2026-09","did":"9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","sid":"0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b","path":"live\/9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","mode":"split","jti":"Q7mZp3Lx9KfT2wBn","iat":1790000000,"exp":1790000900}"#;
    const V1: &str = "eyJ2IjoxLCJ0eXAiOiJpbmdlc3QiLCJraWQiOiJmc24xLTIwMjYtMDkiLCJkaWQiOiI5ZDNjMmY0ZS02YjFhLTRjOGUtOWYyZC0xYTJiM2M0ZDVlNmYiLCJzaWQiOiIwZjhlN2Q2Yy01YjRhLTQ5MzgtODI3MS02MDVmNGUzZDJjMWIiLCJwYXRoIjoibGl2ZVwvOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwibW9kZSI6InNwbGl0IiwianRpIjoiUTdtWnAzTHg5S2ZUMndCbiIsImlhdCI6MTc5MDAwMDAwMCwiZXhwIjoxNzkwMDAwOTAwfQ.nDRiBsl1DEt1DfMN2_1pbuggEMN4Qv222TXDGANWIk8";

    const V2_JSON: &str = r#"{"v":1,"typ":"play","kid":"fsn1-2026-10","did":"9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","path":"live\/9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","kv":3,"iat":1789990000}"#;
    const V2: &str = "eyJ2IjoxLCJ0eXAiOiJwbGF5Iiwia2lkIjoiZnNuMS0yMDI2LTEwIiwiZGlkIjoiOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwicGF0aCI6ImxpdmVcLzlkM2MyZjRlLTZiMWEtNGM4ZS05ZjJkLTFhMmIzYzRkNWU2ZiIsImt2IjozLCJpYXQiOjE3ODk5OTAwMDB9.jnlLr-JaCI8nE3VJ9HfNfh0pR3DRDGSzMzRLhRhBqig";

    const V3_JSON: &str = r#"{"v":1,"typ":"ingest","kid":"fsn1-2026-09","did":"9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","sid":"0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b","path":"live\/9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","mode":"split","jti":"Hc4Vt8Rw1YsN6pDe","iat":1789996400,"exp":1789997300}"#;
    const V3: &str = "eyJ2IjoxLCJ0eXAiOiJpbmdlc3QiLCJraWQiOiJmc24xLTIwMjYtMDkiLCJkaWQiOiI5ZDNjMmY0ZS02YjFhLTRjOGUtOWYyZC0xYTJiM2M0ZDVlNmYiLCJzaWQiOiIwZjhlN2Q2Yy01YjRhLTQ5MzgtODI3MS02MDVmNGUzZDJjMWIiLCJwYXRoIjoibGl2ZVwvOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwibW9kZSI6InNwbGl0IiwianRpIjoiSGM0VnQ4UncxWXNONnBEZSIsImlhdCI6MTc4OTk5NjQwMCwiZXhwIjoxNzg5OTk3MzAwfQ.I1niWamoznhdWn4sJUpjDMtCb1yxN44yCvdtswE3YOU";

    const V4: &str = "eyJ2IjoxLCJ0eXAiOiJpbmdlc3QiLCJraWQiOiJmc24xLTIwMjYtMDkiLCJkaWQiOiI5ZDNjMmY0ZS02YjFhLTRjOGUtOWYyZC0xYTJiM2M0ZDVlNmYiLCJzaWQiOiIwZjhlN2Q2Yy01YjRhLTQ5MzgtODI3MS02MDVmNGUzZDJjMWIiLCJwYXRoIjoibGl2ZVwvOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwibW9kZSI6InNwbGl0IiwianRpIjoiUTdtWnAzTHg5S2ZUMndCbiIsImlhdCI6MTc5MDAwMDAwMCwiZXhwIjoxNzkwMDAwOTAwfQ.ADRiBsl1DEt1DfMN2_1pbuggEMN4Qv222TXDGANWIk8";

    const V5: &str = "eyJ2IjoxLCJ0eXAiOiJpbmdlc3QiLCJraWQiOiJmc24xLTIwMjYtMDkiLCJkaWQiOiI5ZDNjMmY0ZS02YjFhLTRjOGUtOWYyZC0xYTJiM2M0ZDVlNmYiLCJzaWQiOiIwZjhlN2Q2Yy01YjRhLTQ5MzgtODI3MS02MDVmNGUzZDJjMWIiLCJwYXRoIjoibGl2ZVwvOWQzYzJmNGUtNmIxYS00YzhlLTlmMmQtMWEyYjNjNGQ1ZTZmIiwibW9kZSI6InNwbGl0IiwianRpIjoiUTdtWnAzTHg5S2ZUMndCbiIsImlhdCI6MTc5MDAwMDAwMCwiZXhwIjoxNzkwMDAwOTAwfQ.jMF7EfVcR3fXRo8iFllAE0bE3nvZ-jbz2tis31ZS63c";

    fn secrets() -> Secrets {
        Secrets::from_pairs([("fsn1-2026-09", "test-secret-fsn1-2026-09"), ("fsn1-2026-10", "test-secret-fsn1-2026-10")])
    }

    #[test]
    fn minting_reproduces_the_issuer_bytes() {
        assert_eq!(V1.len(), 390);
        assert_eq!(mint(V1_JSON, b"test-secret-fsn1-2026-09"), V1);
        assert_eq!(mint(V2_JSON, b"test-secret-fsn1-2026-10"), V2);
        assert_eq!(mint(V3_JSON, b"test-secret-fsn1-2026-09"), V3);
        assert_eq!(mint(V1_JSON, b"not-the-secret"), V5);
    }

    #[test]
    fn v1_is_valid_through_its_window() {
        for now in [1_790_000_000, 1_790_000_900, 1_790_000_930] {
            let ticket = verify_ingest(V1, &secrets(), now).unwrap();
            assert_eq!(ticket.did.to_string(), DID);
            assert_eq!(ticket.sid.to_string(), SID);
            assert_eq!(ticket.path, format!("live/{DID}"));
            assert_eq!(ticket.mode, "split");
            assert_eq!(ticket.kid, "fsn1-2026-09");
            assert_eq!(ticket.exp, 1_790_000_900);
            assert!(!ticket.enc);
        }
        assert_eq!(verify_ingest(V1, &secrets(), 1_790_000_931), Err(TicketError::Expired));
    }

    #[test]
    fn v2_is_a_play_ticket() {
        let ticket = verify_play(V2, &secrets()).unwrap();
        assert_eq!(ticket.did.to_string(), DID);
        assert_eq!(ticket.path, format!("live/{DID}"));
        assert_eq!(ticket.kv, 3);
        assert_eq!(ticket.kid, "fsn1-2026-10");
    }

    #[test]
    fn v3_is_expired_after_the_skew_allowance() {
        assert_eq!(verify_ingest(V3, &secrets(), 1_790_000_000), Err(TicketError::Expired));
        assert!(verify_ingest(V3, &secrets(), 1_789_997_330).is_ok());
        assert_eq!(verify_ingest(V3, &secrets(), 1_789_997_331), Err(TicketError::Expired));
    }

    #[test]
    fn v4_and_v5_have_bad_signatures() {
        for now in [0, 1_790_000_000, i64::MAX / 2] {
            assert_eq!(verify_ingest(V4, &secrets(), now), Err(TicketError::BadSignature));
            assert_eq!(verify_ingest(V5, &secrets(), now), Err(TicketError::BadSignature));
        }
    }

    #[test]
    fn tickets_only_work_at_their_own_endpoint() {
        // V2 presented at REGISTER, V1 presented to the SRT receiver.
        assert_eq!(verify_ingest(V2, &secrets(), 1_790_000_000), Err(TicketError::WrongType));
        assert_eq!(verify_play(V1, &secrets()), Err(TicketError::WrongType));
    }

    #[test]
    fn an_unknown_kid_is_a_bad_signature() {
        let only_october = Secrets::from_pairs([("fsn1-2026-10", "test-secret-fsn1-2026-10")]);
        assert_eq!(verify_ingest(V1, &only_october, 1_790_000_000), Err(TicketError::BadSignature));
    }

    #[test]
    fn padding_is_optional() {
        // 390 chars: payload 346, which is 2 mod 4, so it pads with "==".
        let (payload, signature) = V1.split_once('.').unwrap();
        let padded = format!("{payload}==.{signature}=");
        // The signature covers the payload as sent, so padding the payload
        // changes what is signed; only the signature half may be padded.
        assert_eq!(verify_ingest(&padded, &secrets(), 1_790_000_000), Err(TicketError::BadSignature));
        let padded_signature = format!("{payload}.{signature}=");
        assert!(verify_ingest(&padded_signature, &secrets(), 1_790_000_000).is_ok());
    }

    #[test]
    fn fwd_turn_routes_to_the_relay_and_unknown_destinations_are_refused() {
        let secret = b"test-secret-fsn1-2026-09";
        let ticket = |fwd: &str| {
            mint(
                &format!(
                    r#"{{"v":1,"typ":"ingest","kid":"fsn1-2026-09","did":"{DID}","sid":"{SID}","path":"live\/{DID}","mode":"split","iat":1790000000,"exp":1790000900{fwd}}}"#
                ),
                secret,
            )
        };
        let now = 1_790_000_000;
        assert_eq!(verify_ingest(&ticket(""), &secrets(), now).unwrap().fwd, Forward::Media);
        assert_eq!(verify_ingest(&ticket(r#","fwd":"turn""#), &secrets(), now).unwrap().fwd, Forward::Turn);
        assert_eq!(verify_ingest(&ticket(r#","fwd":"elsewhere""#), &secrets(), now), Err(TicketError::Malformed));
        assert_eq!(verify_ingest(&ticket(r#","fwd":1"#), &secrets(), now), Err(TicketError::Malformed));
    }

    #[test]
    fn rejects_junk_as_malformed() {
        for junk in ["", "no-dot", ".", "a.", ".b", "!!!.abc", "bm90IGpzb24.abc", "WzFd.abc"] {
            assert_eq!(verify_ingest(junk, &secrets(), 0), Err(TicketError::Malformed), "{junk:?}");
        }
    }

    #[test]
    fn a_signed_ticket_without_exp_is_expired() {
        let ticket = mint(r#"{"v":1,"typ":"ingest","kid":"fsn1-2026-09","did":"9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","sid":"0f8e7d6c-5b4a-4938-8271-605f4e3d2c1b","path":"live/x"}"#, b"test-secret-fsn1-2026-09");
        assert_eq!(verify_ingest(&ticket, &secrets(), 0), Err(TicketError::Expired));
    }

    #[test]
    fn a_wrong_version_is_refused_and_extra_keys_are_ignored() {
        let v2 = mint(r#"{"v":2,"typ":"ingest","kid":"fsn1-2026-09","exp":99}"#, b"test-secret-fsn1-2026-09");
        assert_eq!(verify_ingest(&v2, &secrets(), 0), Err(TicketError::WrongType));

        let extra = mint(
            r#"{"v":1,"typ":"play","kid":"fsn1-2026-10","did":"9d3c2f4e-6b1a-4c8e-9f2d-1a2b3c4d5e6f","path":"live/x","kv":1,"iat":1,"new":"field"}"#,
            b"test-secret-fsn1-2026-10",
        );
        assert!(verify_play(&extra, &secrets()).is_ok());
    }

    #[test]
    fn the_box_reads_sid_and_exp_without_a_secret() {
        let peeked = peek_ingest(V1).unwrap();
        assert_eq!(peeked.sid.to_string(), SID);
        assert_eq!(peeked.exp, 1_790_000_900);
        assert_eq!(peek_ingest("garbage"), Err(TicketError::Malformed));
        assert_eq!(peek_ingest(V2), Err(TicketError::Malformed));
    }

    #[test]
    fn enc_is_read_only_as_1() {
        let with = |enc: &str| {
            mint(
                &V1_JSON.replace(r#""exp":1790000900}"#, &format!(r#""exp":1790000900,"enc":{enc}}}"#)),
                b"test-secret-fsn1-2026-09",
            )
        };
        assert!(verify_ingest(&with("1"), &secrets(), 1_790_000_000).unwrap().enc);
        assert!(!verify_ingest(&with("0"), &secrets(), 1_790_000_000).unwrap().enc);
        assert!(!verify_ingest(&with("true"), &secrets(), 1_790_000_000).unwrap().enc);
    }

    #[test]
    fn the_srt_passphrase_vector() {
        let passphrase = srt_passphrase(b"test-secret-fsn1-2026-09", Uuid::parse_str(SID).unwrap());
        assert_eq!(passphrase, "wZjS00HG-WdJtR89btWGEjft9iqPMw12FOe5XwMb4Ao");
        assert_eq!(passphrase.len(), 43);
    }

    #[test]
    fn secrets_parse_from_the_env_format() {
        let parsed = Secrets::parse("fsn1-2026-09=abc, fsn1-2026-10=def").unwrap();
        assert_eq!(parsed.kids(), ["fsn1-2026-09", "fsn1-2026-10"]);
        assert_eq!(parsed.get("fsn1-2026-10"), Some(&b"def"[..]));
        assert!(Secrets::parse("").is_err());
        assert!(Secrets::parse("nokey").is_err());
        assert!(Secrets::parse("a=1,a=2").is_err());
        assert!(!format!("{parsed:?}").contains("abc"));
    }
}
