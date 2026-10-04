//! Tunnel framing constants for ShadowVPN.
//!
//! ShadowVPN's tunnel framing is intentionally trivial: **the plaintext of each
//! UDP datagram is exactly one raw IP packet** as read from / written to the
//! TUN interface. There is no per-packet length prefix, no SOCKS address
//! header, and no multiplexing — UDP datagram boundaries are the frame
//! boundaries. The only on-wire structure is the cryptographic envelope
//! described in [`crate::crypto`]: `salt ++ AEAD(ciphertext ++ tag)`.
//!
//! This module exposes the size constants needed to size receive buffers
//! correctly on both the encrypted (UDP socket) and plaintext (TUN) sides.
//!
//! The same framing is used on both carriers; they differ only in how a frame is
//! delimited on the wire:
//!
//! * **UDP** — one datagram is one frame, so datagram boundaries *are* frame
//!   boundaries and nothing else is needed.
//! * **TCP** — a byte stream has no boundaries, so each frame is prefixed with
//!   a 2-byte big-endian length ([`TCP_LEN_PREFIX`]); see
//!   [`crate::transport`]. The length covers exactly what a UDP datagram would
//!   have carried, so the payload is identical on both carriers.

use crate::crypto::{Cipher, TAG_LEN};

/// Default tunnel MTU for the TUN interface, in bytes.
///
/// 1400 leaves comfortable headroom under a typical 1500-byte path MTU for the
/// outer IP + UDP headers and the ShadowVPN crypto overhead (salt + tag), so
/// that an encrypted datagram is unlikely to fragment on a normal Ethernet
/// path.
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// Default tunnel MTU when the carrier is **TCP**, in bytes.
///
/// On the UDP carrier the tunnel MTU must leave room for the outer IP + UDP +
/// crypto headers inside the path MTU, or the outer datagram fragments. On TCP
/// there is no such constraint: the outer TCP stream is segmented to its own
/// MSS regardless of how large one frame is, and it retransmits, so a large
/// frame costs nothing in reliability. That frees the tunnel MTU to be a full
/// 1500.
///
/// This matters most for **UDP traffic inside the tunnel**. UDP has no MSS
/// clamping, so an application sending its usual 1460-byte datagram (iperf3's
/// default, and typical of games, VoIP, WireGuard at 1420, QUIC at 1350) into a
/// 1400-byte tunnel gets **IP-fragmented into two packets** — or dropped with
/// `EMSGSIZE` if DF is set. Fragmentation doubles the packet count and makes
/// the datagram survive only if *every* fragment survives, which is why
/// UDP-in-TCP throughput collapses while TCP-in-TCP is unaffected.
///
/// 1500 fits those datagrams whole. It is the largest safe value because after
/// decapsulation the server forwards the packet out a real 1500-byte interface.
pub const DEFAULT_TUN_MTU_TCP: u16 = 1500;

/// A generous upper bound on the plaintext IP packet size we will read from the
/// TUN device in a single read, in bytes.
///
/// This is the largest IPv4/IPv6 datagram (65535) and bounds the plaintext
/// buffer size regardless of the configured MTU.
pub const MAX_IP_PACKET: usize = 65535;

/// Per-datagram crypto overhead for a given cipher, in bytes: the leading salt
/// plus the trailing AEAD tag.
///
/// `overhead = salt_len + TAG_LEN`. The plaintext (an IP packet) contributes
/// the rest of the datagram. There is no nonce on the wire
/// ([`crate::crypto::NONCE_LEN`] bytes of all-zero nonce are implicit), so it
/// does not appear here.
///
/// ```
/// use shadowvpn::crypto::Cipher;
/// use shadowvpn::protocol::crypto_overhead;
///
/// assert_eq!(crypto_overhead(Cipher::Aes128Gcm), 32); // 16-byte salt + 16-byte tag
/// assert_eq!(crypto_overhead(Cipher::ChaCha20Poly1305), 48);
/// ```
pub fn crypto_overhead(cipher: Cipher) -> usize {
    // `none` carries neither salt nor tag: the frame is the IP packet.
    if cipher.is_none() {
        return 0;
    }
    cipher.salt_len() + TAG_LEN
}

/// Size, in bytes, of the length prefix that delimits one frame on the TCP
/// carrier (a big-endian `u16`).
///
/// UDP needs no such prefix — a datagram is already self-delimiting — which is
/// why this constant only ever applies to the TCP carrier.
pub const TCP_LEN_PREFIX: usize = 2;

/// Re-exported from [`crate::transport::TCP_PAD_LEN`]: bytes in the optional
/// padding-length field.
pub const TCP_PAD_LEN: usize = crate::transport::TCP_PAD_LEN;

/// Re-exported from [`crate::transport::MAX_PADDING`]: largest padding a frame
/// may carry.
pub const MAX_PADDING: usize = crate::transport::MAX_PADDING;

/// Largest frame payload the TCP carrier can delimit, in bytes: the `u16`
/// length prefix caps a frame at 65535 payload bytes.
///
/// Re-exported from [`crate::transport::MAX_TCP_FRAME`] so callers that size
/// buffers (or decide whether a packet can be carried at all) have one place to
/// look.
pub const MAX_TCP_FRAME: usize = crate::transport::MAX_TCP_FRAME;

/// The size, in bytes, that a receive buffer must have to hold the largest
/// possible frame for `cipher` on the TCP carrier.
///
/// Equals [`max_datagram_size`] plus [`TCP_LEN_PREFIX`]. The prefix itself is
/// consumed by the framing reader and never handed to the crypto layer, but the
/// socket buffer does have to hold it.
pub fn max_tcp_frame_size(cipher: Cipher) -> usize {
    max_datagram_size(cipher) + TCP_LEN_PREFIX
}

/// The size, in bytes, of the largest on-wire TCP frame for `cipher` once
/// random padding is included.
///
/// Buffers must be sized for the padded frame, not just the payload, or a
/// maximally padded frame would be reported as oversized and dropped.
pub fn max_tcp_wire_size(cipher: Cipher, pad_max: usize) -> usize {
    max_tcp_frame_size(cipher)
        + if pad_max > 0 {
            TCP_PAD_LEN + pad_max
        } else {
            0
        }
}

/// The size, in bytes, that a UDP receive buffer must have to hold the
/// encrypted form of the largest plaintext IP packet for `cipher`.
///
/// Equals [`MAX_IP_PACKET`] plus [`crypto_overhead`].
pub fn max_datagram_size(cipher: Cipher) -> usize {
    MAX_IP_PACKET + crypto_overhead(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_matches_salt_plus_tag() {
        // AES-128-GCM: 16-byte salt + 16-byte tag.
        assert_eq!(crypto_overhead(Cipher::Aes128Gcm), 16 + 16);
        // ChaCha20-Poly1305: 32-byte salt + 16-byte tag.
        assert_eq!(crypto_overhead(Cipher::ChaCha20Poly1305), 32 + 16);
        // `none`: no envelope at all.
        assert_eq!(crypto_overhead(Cipher::None), 0);
    }

    #[test]
    fn tcp_frame_is_a_datagram_plus_prefix() {
        // The TCP carrier wraps exactly what UDP would have sent, plus a prefix.
        assert_eq!(max_tcp_frame_size(Cipher::Aes128Gcm), max_datagram_size(Cipher::Aes128Gcm) + TCP_LEN_PREFIX);
        assert_eq!(TCP_LEN_PREFIX, 2);
    }

    #[test]
    fn nonce_len_is_not_on_wire() {
        // Documented invariant: the 12-byte nonce is implicit, not transmitted.
        assert_eq!(crate::crypto::NONCE_LEN, 12);
    }
}
