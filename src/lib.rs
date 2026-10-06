//! # ShadowVPN
//!
//! A pre-shared-key (PSK), user-mode VPN written in Rust, on a configurable
//! UDP or TCP carrier.
//!
//! ShadowVPN is a fixed point-to-point / multi-client tunnel. A TUN-based
//! client reads IP packets from a virtual interface, encrypts each as a single
//! frame, and sends it to the server; the server decrypts, routes, and tunnels
//! return traffic back. The async runtime is [`tokio`].
//!
//! ## Carrier: UDP or TCP
//!
//! The wire payload is identical on both carriers; only the framing differs.
//!
//! * **UDP** (default) — one datagram is one frame. The kernel preserves the
//!   boundary, so nothing is added.
//! * **TCP** — a byte stream has no boundaries, so each frame is prefixed with
//!   a 2-byte big-endian length. The server `listen`s and keeps one connection
//!   per client; the client keeps one connection (reconnecting if it drops).
//!
//! Choose with `transport: "udp" | "tcp"` (or `--transport`). Both ends must
//! agree. See [`transport`].
//!
//! ## Encryption: AEAD or none
//!
//! By default every frame is sealed with a shadowsocks AEAD cipher
//! (`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`). Setting
//! `cipher: "none"` disables encryption and authentication entirely — frames
//! are raw IP packets, readable and forgeable by anyone on the path. It exists
//! for benchmarking and for links already protected by other means; no
//! password is required in that mode.
//!
//! On top of the tunnel it offers Tailscale-like conveniences, all negotiated
//! in-band with no external control plane: automatic tunnel-IP assignment
//! ([`assign`]), Magic DNS peer hostnames ([`magic`]), and subnet-route
//! advertise / approve / accept ([`mesh`]).
//!
//! Guides, configuration, and the wire-protocol spec also live on the
//! [project site](https://madeye.github.io/shadowvpn/).
//!
//! ## Wire protocol
//!
//! The on-wire crypto matches the **shadowsocks.org AEAD UDP scheme** exactly,
//! so the construction is spec-correct and interoperable. Each UDP datagram is:
//!
//! ```text
//! [ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag ]
//! ```
//!
//! with `salt_len == key_len`, a random per-datagram salt, a subkey of
//! `HKDF-SHA1(master_key, salt, "ss-subkey")`, and an all-zero 12-byte nonce.
//! The master key is derived from the password with OpenSSL's legacy
//! `EVP_BytesToKey` (MD5) KDF. See [`crypto`] for the full description.
//!
//! **Deviation from ss-proxy:** the plaintext is the raw IP packet from TUN,
//! with no SOCKS address header — this is a tunnel, not a SOCKS proxy. See
//! [`protocol`].
//!
//! ## Example
//!
//! The library is the same data plane the binaries use. Encrypt a raw IP
//! packet into a shadowsocks-AEAD UDP datagram and decrypt it back:
//!
//! ```
//! use shadowvpn::crypto::{decrypt_packet, encrypt_packet, evp_bytes_to_key, Cipher};
//!
//! let cipher = Cipher::ChaCha20Poly1305;
//! let key = evp_bytes_to_key(b"correct horse battery staple", cipher.key_len());
//! let packet = b"\x45\x00\x00\x1chello, tun"; // stand-in for a TUN IP packet
//! let wire = encrypt_packet(cipher, &key, packet).unwrap();
//! assert_eq!(decrypt_packet(cipher, &key, &wire).unwrap(), packet);
//! ```
//!
//! ## Multiple clients
//!
//! One server serves many clients. By default it routes by *learning* each
//! client's inner tunnel source IP, so clients need distinct addresses — a
//! client that omits its address is handed a stable, distinct tunnel IP by the
//! server automatically, keyed by a persisted node id (see [`assign`] and
//! [`state`]). With the
//! server's NAT mode every client may share one identical config (same
//! placeholder IP): the server tells them apart by UDP endpoint and maps each
//! onto a distinct internal IP, rewriting inner addresses in flight. See [`nat`]
//! and [`pool`].
//!
//! ## Binaries
//!
//! This crate ships three binaries: `shadowvpn-server` and `shadowvpn-client`
//! (always built), and `shadowvpn-uri` — a config import/export tool gated behind
//! the optional `uri` feature so the server/client builds stay lean (see the
//! `uri` module, compiled only with that feature).
//!
//! ## Crate features
//!
//! * `uri` — enables the `uri` module (`shadowvpn://` import/export + QR codes)
//!   and the `shadowvpn-uri` binary. Off by default so server/client builds stay
//!   lean.
//!
//! ## Modules
//!
//! * [`crypto`] — cipher abstraction, key derivation, packet encrypt/decrypt
//!   (including the `none` pass-through).
//! * [`transport`] — the UDP / TCP carrier abstraction and TCP framing.
//! * [`config`] — JSON + CLI configuration for the server and client.
//! * [`net`] — UDP socket construction with enlarged kernel buffers.
//! * [`protocol`] — tunnel framing constants and buffer sizing.
//! * [`obfs`] — optional carrier obfuscation (QUIC/HTTP3-shaped or base64).
//! * [`tun_device`] — async TUN interface wrapper (macOS utun + Linux + Windows).
//! * [`policy`] — client-side policy routing (gfwlist / chinadns split tunnel).
//! * [`mesh`] — Tailscale-like subnet routing (advertise / approve / accept).
//! * [`magic`] — Magic DNS: resolve joined peers by hostname.
//! * [`assign`] — node-id keyed tunnel-IP assignment (learning mode).
//! * [`state`] — private state-file helpers (client identity, server leases).
//! * [`nat`] — server-side per-client NAT (multiple clients, one shared config).
//! * [`pool`] — internal-IP allocation pool used by [`nat`].
//! * `uri` — `shadowvpn://` config import/export + QR codes (feature `uri`).

#![warn(missing_docs)]

pub mod assign;
pub mod batch;
pub mod bufpool;
pub mod config;
pub mod crypto;
pub mod magic;
pub mod mesh;
pub mod nat;
pub mod net;
pub mod obfs;
pub mod policy;
pub mod pool;
pub mod protocol;
pub mod transport;
pub mod state;
pub mod tun_device;
#[cfg(feature = "uri")]
pub mod uri;

/// How many packet-processing workers to run per direction.
///
/// ## Why this exists
///
/// Once the TCP windows are large enough that the link is no longer the limit,
/// throughput is set by **one task doing AEAD per packet**. A single core's
/// AEAD throughput (plus the per-packet TUN syscall) is well under a gigabit,
/// so a 500 Mbit/s target needs the crypto spread over several cores.
///
/// Packets are dispatched by a stable shard key (see
/// [`transport::Transport::recv_sharded`]), so everything that must stay
/// ordered — one subflow, or one peer's packets — lands on one worker and keeps
/// its order, while unrelated sources run in parallel.
///
/// Sized from the machine: enough workers to matter on a big box, but capped
/// because beyond a handful the shared routing/NAT state becomes the
/// contention rather than the crypto.
pub fn worker_count(requested: Option<usize>) -> usize {
    if let Some(n) = requested {
        // An explicit value is honoured as-is (floored at 1): it is the knob
        // for measuring where the bottleneck actually is, so do not second
        // guess it.
        return n.max(1);
    }
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4)
}
