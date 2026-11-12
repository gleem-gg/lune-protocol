//! The two facts about an SRT packet the scheduler needs, read straight from
//! its header. Lune never changes an SRT packet; it only decides which links
//! carry it.

/// A control packet (handshake, ACK, ACKACK, NAK, keepalive, shutdown): the
/// top bit of the first header byte.
pub fn is_control(packet: &[u8]) -> bool {
    packet.first().is_some_and(|b| b & 0x80 != 0)
}

/// A data packet the sender is retransmitting: the R bit of the message
/// number word, bit 2 of byte 4.
pub fn is_retransmission(packet: &[u8]) -> bool {
    !is_control(packet) && packet.get(4).is_some_and(|b| b & 0x04 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_headers() {
        let data = [0x00, 0, 0, 1, 0xc0, 0, 0, 1, 0, 0, 0, 0x64, 0x12, 0x34, 0xab, 0xcd];
        let mut retx = data;
        retx[4] = 0xc4;
        let control = [0x80, 0x02, 0, 0, 0, 0, 0, 0x07, 0, 0, 0x01, 0xf4, 0x56, 0x78, 0xef, 0x01];

        assert!(!is_control(&data) && !is_retransmission(&data));
        assert!(!is_control(&retx) && is_retransmission(&retx));
        assert!(is_control(&control) && !is_retransmission(&control));
        assert!(!is_control(&[]) && !is_retransmission(&[0, 0]));
    }
}
