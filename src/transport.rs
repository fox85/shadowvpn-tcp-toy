//! Carrier transport: UDP (original) or TCP, selected by configuration.
//!
//! ShadowVPN's data plane was built around **UDP datagram boundaries**: one IP
//! packet from the TUN device becomes one datagram, and the datagram *is* the
//! frame. TCP has no such boundaries — it is a byte stream — so a TCP carrier
//! needs explicit framing. This module supplies it, and hides the difference
//! behind a single [`Transport`] enum so the relay loops in `bin/server.rs` and
//! `bin/client.rs` stay carrier-agnostic.
//!
//! # TCP framing
//!
//! ```text
//! [ len: u16 big-endian ] ++ [ payload: len bytes ]
//! ```
//!
//! where `payload` is byte-for-byte what UDP would have carried in one datagram:
//! the obfuscated (optional) shadowsocks-AEAD envelope `salt ++ AEAD(ct ++ tag)`
//! — or, with `cipher = "none"`, the raw IP packet. The 2-byte prefix bounds a
//! frame at [`MAX_TCP_FRAME`] payload bytes; larger packets cannot be carried
//! and are dropped with a warning (`FrameReader` skips them rather than
//! desynchronising the stream).
//!
//! # Why one TCP connection is slow, and what to do about it
//!
//! A single TCP connection's throughput is capped by its window, not by the
//! link: `throughput ≈ window / RTT`. With a 64 KiB window and a 30 ms RTT that
//! is ~17 Mbit/s no matter how fast the path is — which is exactly the symptom
//! of a "correct but slow" TCP tunnel. Three things fix it, and this module
//! implements all three:
//!
//! 1. **Big socket buffers** — [`crate::net::connect_tcp_stream`] raises
//!    `SO_RCVBUF`/`SO_SNDBUF` on the *client* side too (an earlier version set
//!    them only on the listener, leaving dialled sockets at the OS default and
//!    pinning throughput at the default window).
//! 2. **Multiple parallel subflows** — `N` TCP connections aggregate `N`
//!    congestion windows and spread the load over `N` cores. Packets are
//!    assigned to a subflow by [`flow_hash`], so all packets of one inner
//!    connection take the same path and stay **in order**, while different
//!    inner connections spread out. This is the same trick ECMP/LAG and
//!    multipath VPNs use: parallel in aggregate, serial per flow.
//! 3. **Batched I/O** — [`FrameReader`] parses every frame available in one
//!    `read(2)` instead of issuing a syscall per frame, and the writer coalesces
//!    whatever is queued into one `write(2)`. At 500 Mbit/s and a 1400-byte MTU
//!    (~45 k packets/s) a syscall per packet is the difference between a busy
//!    core and an idle one.
//!
//! # Peer identity
//!
//! TCP is connection-oriented, but the relay loops identify peers by
//! [`SocketAddr`] (that is what NAT / lease / route tables are keyed on). A TCP
//! connection's remote `SocketAddr` is unique while the connection lives — the
//! OS never hands the same local ephemeral port to two live sockets to the same
//! destination — so `accept()`'s peer address is a safe per-connection key.
//!
//! One client's subflows are therefore *distinct* `SocketAddr`s. The server
//! groups them back into one client in its routing table (see
//! `Learned::learn`), so a client with 4 subflows is one tunnel IP reachable
//! via 4 endpoints, not four clients.
//!
//! # Layout
//!
//! * [`Transport::Udp`] — wraps the original `Arc<UdpSocket>`; unchanged
//!   behaviour (including the connected-socket fast path used by the client).
//! * [`Transport::TcpServer`] — a [`TcpHub`]: one accept loop, one reader task
//!   and one writer task per connection. All connections' frames are funnelled
//!   into a single inbound channel, so the existing "reader → processor"
//!   pipeline keeps working unchanged.
//! * [`Transport::TcpClient`] — a [`TcpClient`] holding `subflows` connections
//!   to the server, each supervised and reconnected independently.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use log::{debug, info, warn};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};

use crate::net::{bind_tcp_listener, connect_tcp_stream};

/// Number of bytes in the TCP length prefix (a big-endian `u16`).
pub const TCP_LEN_PREFIX: usize = 2;

/// Largest payload a single TCP frame can carry, in bytes (the `u16` limit).
///
/// A frame must hold a full tunnel datagram: obfuscation header (if any) +
/// crypto envelope + IP packet. With the default 1400-byte TUN MTU this is never
/// approached; a TUN MTU near 64 KiB plus crypto overhead can exceed it, in
/// which case the packet is dropped (see [`FrameReader`]).
pub const MAX_TCP_FRAME: usize = u16::MAX as usize;

/// Bytes in the padding-length field that follows the length prefix, in bytes.
///
/// Present only when padding is enabled. The field is a plain `u8`, so a frame
/// carries at most 255 padding bytes — far more than is useful, since padding
/// only needs to break up the length pattern, not to add bandwidth.
///
/// ## Frame format
///
/// ```text
/// padding off:  [ u16 payload_len ][ payload ]
/// padding on :  [ u16 payload_len ][ u8 pad_len ][ payload ][ pad bytes ]
/// ```
///
/// The length prefix always counts the **payload only**. Note that the two
/// modes are *not* wire-compatible with each other: both ends must agree,
/// exactly as they must on `transport` and `cipher`.
pub const TCP_PAD_LEN: usize = 1;

/// Largest number of padding bytes one frame may carry (the `u8` field's range).
pub const MAX_PADDING: usize = u8::MAX as usize;

/// How long a fresh TCP connection has to deliver its **first** frame before we
/// reset it.
///
/// A real client sends a keepalive the moment it connects (its keepalive ticker
/// fires immediately), so a connection that stays silent this long is not one
/// of ours — typically a port scanner completing a handshake and then waiting.
/// Resetting keeps the probe from holding a connection open indefinitely.
pub const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest frame a peer may declare before we conclude it is not speaking our
/// protocol, derived from the tunnel MTU.
///
/// The `u16` length prefix permits up to 65535, but a real frame is bounded by
/// the tunnel MTU plus the crypto envelope and any obfs header. Anything well
/// beyond that cannot have come from a ShadowVPN peer, and recognising it
/// **immediately** — rather than waiting for bytes that will never arrive — is
/// what turns a probe into an instant reset:
///
/// * `curl http://host:port/` starts with `"GE"`, which reads as **18245**;
/// * a TLS `ClientHello` starts `0x16 0x03`, which reads as **5635**;
/// * an SSH banner `SSH-2.0-...` starts `0x53 0x53`, which reads as **21331**.
///
/// All are an order of magnitude past any plausible frame at a normal MTU.
///
/// The bound is derived from the MTU rather than hard-coded because a tunnel
/// with a large MTU legitimately produces large frames, and a fixed ceiling
/// would reject them. [`MAX_TCP_FRAME`] disables the check (nothing can exceed
/// it), which is what the client — which trusts the server it dialled — uses.
pub fn plausible_frame_limit(mtu: u16) -> usize {
    // MTU + crypto envelope + obfs header + headroom. 512 bytes of slack is
    // generous: the envelope is well under 100 bytes for every cipher.
    mtu as usize + 512
}

/// Default upper bound on the random padding appended to each TCP frame, in
/// bytes.
///
/// This exists because a TCP tunnel leaks the **length** of what it carries,
/// and the handshake is the worst offender: a keepalive, an assignment request
/// and a DNS lookup each have a distinctive, fixed size, so a passive observer
/// sees the same few frame sizes at the same points in every session. That is a
/// fingerprint even though the contents are encrypted.
///
/// Appending a random 0..=N bytes per frame smears each size across a range, so
/// the observable sequence stops being constant. Cost is a few percent of
/// bandwidth at N=64 given ~1400-byte frames; 0 disables it.
///
/// The length prefix still counts the payload only, so this is pure obfuscation
/// — it adds nothing to security, it just removes the length side channel.
pub const DEFAULT_PADDING_MAX: usize = 64;

/// How long a **partially received** frame may stay incomplete before we reset.
///
/// This is what catches the common probes. `curl` to the port sends
/// `GET / HTTP/1.1...`; read as a length prefix, `"GE"` means 18245 bytes, so
/// the reader waits for 18245 bytes that never come. A TLS `ClientHello`
/// (`0x16 0x03`...) asks for 5635. Neither ever completes, and without this
/// deadline the connection just sits there until the peer gives up — the
/// "silently waits until timeout" behaviour.
///
/// A legitimate sender never leaves a partial frame: our writer emits whole
/// frames, and ordinary TCP segmentation is resolved in milliseconds. Several
/// seconds of a stalled partial frame is unambiguous.
///
/// This applies at any point in a connection's life, not just at the start —
/// an established peer that starts sending garbage is dropped the same way.
pub const STALLED_FRAME_TIMEOUT: Duration = Duration::from_secs(3);

/// Accept-queue backlog for the server's TCP listener.
pub const TCP_BACKLOG: u32 = 1024;

/// Per-connection outbound queue depth, and the depth of the hub's aggregated
/// inbound channel. Bounded so a stalled peer applies backpressure instead of
/// growing the heap without limit.
pub const TCP_CHANNEL_DEPTH: usize = 1024;

/// Size of a connection's read buffer.
///
/// Larger than one maximum-size frame (64 KiB + prefix) so a single `read(2)`
/// typically yields *several* frames at tunnel MTU — that is the whole point of
/// batching, and it is what turns a syscall-per-packet loop into a
/// syscall-per-burst loop.
const READ_BUF_BYTES: usize = 128 * 1024;

/// Maximum frames coalesced into one `write(2)`.
///
/// Bounded so a burst cannot grow the write buffer without limit; the writer
/// drains whatever is queued *now* and never waits to fill the batch, so this
/// adds no latency when traffic is sparse.
const WRITE_BATCH_FRAMES: usize = 64;

/// How long the accept loop backs off after a transient `accept()` failure.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// How long to wait between client reconnect attempts.
const RECONNECT_DELAY: Duration = Duration::from_millis(500);

/// How many consecutive reconnect attempts a subflow makes before giving up
/// (and letting the process exit so a supervisor can restart it).
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Choose which subflow carries one frame, given each subflow's current queue.
///
/// **This is the whole reason UDP-inside-TCP stops being slow once you have
/// several subflows.**
///
/// A single TCP connection stalls as a unit: lose one segment and everything
/// behind it waits for the retransmit — a head-of-line block lasting an RTT or,
/// after a timeout, much longer.
///
/// * Inner **TCP** copes with that. It is already ordered and
///   loss-recovering; the outer stall just looks like a slow link. So inner TCP
///   is **pinned**: reordering it would produce duplicate ACKs and spurious
///   fast retransmits, which costs more than parallelism gains.
/// * Inner **UDP** does not cope. A UDP flow has no retransmit timer of its
///   own, so a pinned UDP flow sees a *total blackout* for the duration of the
///   stall. Protocols that estimate RTT (QUIC, WireGuard, VoIP, games) read
///   that as a catastrophic path change: QUIC's probe timeout fires and its
///   congestion window collapses to a minimum, and rebuilding it takes many
///   round trips — which is exactly the "12 Mbit/s forever" symptom.
///
/// So unordered traffic is spread over **every subflow that is not backed up**,
/// picked by `hash` so the load stays balanced. Then only `1/N` of the packets
/// are caught by any one stall while the rest keep arriving: the inner protocol
/// sees a modest delay increase instead of a blackout, and keeps sending.
///
/// Note this does *not* require both ends to agree on the choice — UDP has no
/// ordering requirement, so unlike the pinned case the client's index and the
/// server's need not correspond.
fn pick_subflow(backlogs: &[usize], hash: u32, spin: u32, ordered: bool) -> usize {
    let n = backlogs.len();
    if n == 0 {
        return 0;
    }
    /// A subflow with no live connection (reconnecting) reports this backlog.
    const DEAD: usize = usize::MAX;

    if ordered {
        let pinned = (hash % n as u32) as usize;
        if backlogs[pinned] != DEAD {
            return pinned;
        }
        // The pinned subflow is down. Sending anywhere else reorders this
        // flow — but the alternative is dropping every packet until the
        // reconnect completes, and a reconnect already reorders everything
        // (the whole connection's packets were lost). So prefer *a* working
        // subflow over none: pick the least loaded one that is alive.
        return (0..n)
            .filter(|i| backlogs[*i] != DEAD)
            .min_by_key(|i| backlogs[*i])
            .unwrap_or(pinned);
    }
    // Among the least-loaded subflows, spread by `hash ^ spin`. `spin` changes
    // every packet, which is what scatters a *single* flow: without it a flow's
    // constant hash would pin it to one index even when every subflow is idle,
    // and pinning is the thing we are trying to avoid. Mixing rather than
    // replacing the hash keeps different flows from colliding on the same
    // subflow, so the spread stays even across many flows too.
    let min = backlogs.iter().copied().min().unwrap_or(0);
    let tied = backlogs.iter().filter(|b| **b == min).count().max(1);
    let k = ((hash ^ spin) % tied as u32) as usize;
    backlogs
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == min)
        .nth(k)
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// How many consecutive packets an unordered flow keeps on one subflow before
/// rotating to the next.
///
/// This is the knob that trades **reordering** against **spreading**, and it
/// matters more than it looks:
///
/// * `1` — rotate every packet. Maximum spreading, but a single flow's packets
///   arrive interleaved from `N` connections whose queue depths differ, so they
///   are *constantly* reordered. QUIC's reordering threshold is 3 packets, so
///   continuous reordering is read as continuous loss: spurious loss detection
///   collapses its congestion window and the flow never ramps up. That is the
///   mechanism behind "UDP-in-TCP is slower than TCP-in-TCP despite more
///   subflows".
/// * `large` — the flow barely rotates, so it degenerates into being pinned and
///   gets one congestion window.
///
/// A moderate value keeps **in-order runs** (so reordering counters and QUIC's
/// loss detector stay quiet) while still cycling through every subflow many
/// times per RTT — at 1400-byte packets and 100 Mbit/s that is ~9000 packets/s,
/// so 16 packets is under 2 ms, i.e. dozens of rotations per RTT on a typical
/// path. All subflows therefore stay in flight simultaneously and their windows
/// still add up.
///
/// Set to `1` to restore per-packet round-robin (only useful if the receiver is
/// genuinely reorder-proof), or raise it if a specific application is sensitive.
pub const UDP_ROTATE_EVERY: u32 = 16;

/// Checks whether a received frame is well-formed ShadowVPN traffic.
///
/// Used only for the **first** frame of a connection: that is enough to catch
/// every probe (a scanner cannot produce a frame that authenticates), and it
/// keeps the cost off the steady-state path — validating every frame would
/// double the per-packet AEAD work at exactly the rates we care about.
///
/// Once a connection has produced one valid frame it is treated as established
/// and is no longer re-validated; a peer that holds the shared key is not a
/// probe, and corruption beyond that point is handled by the processor.
pub type Validator = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Per-connection settings shared by both ends of the TCP carrier.
///
/// Bundled because every connection needs all of them, and passing them one by
/// one had grown to the point of being error-prone.
#[derive(Clone)]
pub struct TcpOptions {
    /// Buffer size for one frame, in bytes.
    pub buf_len: usize,
    /// Applied to a connection's first frame; see [`Validator`].
    pub validator: Option<Validator>,
    /// Declared payload lengths beyond this are rejected outright; see
    /// [`plausible_frame_limit`].
    pub plausible: usize,
    /// Upper bound on random padding per frame; 0 disables it. See
    /// [`DEFAULT_PADDING_MAX`].
    pub padding: usize,
}

/// How a packet should be placed on the subflows.
///
/// Returned by [`classify`] and passed down to the send path, because **the
/// scheduling decision depends on the inner protocol**:
///
/// * an inner **TCP** stream needs its packets delivered in order, so it is
///   pinned to one subflow no matter what;
/// * an inner **UDP** flow (QUIC, WireGuard, games, VoIP, DNS) tolerates
///   reordering — UDP has never promised ordering, and QUIC numbers its
///   packets precisely so it can handle out-of-order arrival. Pinning it to
///   one subflow exposes it to that connection's head-of-line stalls *in
///   full*: one lost outer segment blackholes the whole inner flow for the
///   duration. Spreading it over every healthy subflow means a stall catches
///   only `1/N` of the packets, which is the difference between a modest
///   delay blip and a congestion-window collapse (see [`pick_subflow`]).
#[derive(Clone, Copy, Debug)]
pub struct FlowHint {
    /// Stable hash of the inner 5-tuple; selects the *preferred* subflow.
    pub hash: u32,
    /// `true` for inner protocols that must not be reordered (TCP).
    pub ordered: bool,
}

/// Classify an IP packet for subflow scheduling: hash its 5-tuple and say
/// whether it needs ordered delivery.
///
/// The hash covers addresses + protocol + ports, so it is stable for every
/// packet of one inner connection. Ordered traffic is pinned to the subflow
/// the hash selects; unordered traffic spreads across the healthy ones, using
/// the same hash to keep the spread even.
///
/// Non-TCP/UDP traffic (ICMP, SCTP, …) hashes on addresses + protocol only —
/// still stable per flow. Anything unparseable hashes on the whole packet,
/// which is stable for a given sender; it is treated as unordered because a
/// protocol we cannot parse is one we cannot claim ordering requirements for.
pub fn classify(packet: &[u8]) -> FlowHint {
    // FNV-1a: cheap, no table, no dependencies, good enough spread for
    // spreading flows over a handful of subflows.
    let mut h: u32 = 0x811c9dc5;
    let mut absorb = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
    };

    // Default to unordered: only a protocol we positively identify as
    // stream-oriented gets pinned.
    let mut ordered = false;

    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let proto = packet[9];
            absorb(&packet[12..20]); // src ++ dst
            absorb(&[proto]);
            // Transport ports sit just past the IP header (IHL is in words).
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            if matches!(proto, 6 | 17) && packet.len() >= ihl + 4 {
                absorb(&packet[ihl..ihl + 4]); // src port ++ dst port
            }
            ordered = proto == 6; // TCP (6) only; UDP (17) may be spread
        }
        Some(6) if packet.len() >= 40 => {
            let proto = packet[6];
            absorb(&packet[8..40]); // src ++ dst
            absorb(&[proto]);
            // Ignore extension headers: a given flow's header chain is stable,
            // so the hash stays stable even if the ports are misread.
            if matches!(proto, 6 | 17) && packet.len() >= 44 {
                absorb(&packet[40..44]);
            }
            ordered = proto == 6;
        }
        _ => absorb(packet),
    }
    FlowHint { hash: h, ordered }
}

/// Hash an IP packet to a subflow index (the [`FlowHint::hash`] alone).
///
/// Kept for callers that only need the preferred subflow and do not care about
/// ordering — e.g. the server side when the client has a single endpoint.
pub fn flow_hash(packet: &[u8]) -> u32 {
    classify(packet).hash
}

/// Look up subflow `idx`'s writer handle, flattening the nested `Option`.
///
/// The returned borrow comes from the *guard's contents*, not from the guard's
/// own lifetime parameter — `Deref` hands out `&'a T` for `&'a Guard`, so `'a`
/// on the outer reference is what the result inherits.
fn slot_of<'a>(
    outbound: &'a tokio::sync::RwLockReadGuard<'_, Vec<Option<mpsc::Sender<Vec<u8>>>>>,
    idx: usize,
) -> Option<&'a mpsc::Sender<Vec<u8>>> {
    outbound.get(idx).and_then(|s| s.as_ref())
}

/// Frames currently queued behind a subflow's writer task.
///
/// `capacity()` is the free space in the bounded channel, so depth minus free
/// space is what is waiting. A subflow that is keeping up sits near zero; one
/// that is congested — or reconnecting, in which case there is no sender at
/// all — reads as maximally backed up.
fn backlog(slot: Option<&mpsc::Sender<Vec<u8>>>) -> usize {
    match slot {
        Some(tx) => TCP_CHANNEL_DEPTH.saturating_sub(tx.capacity()),
        // No live connection (reconnecting): `pick_subflow` treats this as
        // "dead" and avoids it.
        None => usize::MAX,
    }
}

/// How long [`FrameReader::next_frame`] may block on a read.
///
/// The distinction matters because a connection that is merely **idle** is
/// healthy — a client sits quiet between keepalives — while one that is
/// **mid-frame and stalled** is not. Timing out the former would break real
/// clients; timing out the latter is what rejects probes.
#[derive(Clone, Copy, Debug)]
pub enum ReadDeadline {
    /// The peer has not yet produced a frame that authenticates, so bound
    /// *every* read: neither silence nor a trickle is acceptable.
    Unverified,
    /// The peer has proved itself. Idling is normal, but a frame that is half
    /// delivered is not, so only those reads are bounded.
    Verified,
}

/// Outcome of one [`FrameReader::next_frame`] attempt.
#[derive(Debug)]
enum NextFrame {
    /// A complete frame of this length was copied into the caller's buffer.
    Frame(usize),
    /// The peer closed the stream cleanly.
    Eof,
    /// Bytes are buffered but the rest of the frame did not arrive in time.
    /// This is what a probe looks like, and the caller should reset.
    Stalled,
    /// The length prefix declared more bytes than any real frame could be
    /// (`declared` bytes). Not our protocol — reset without waiting.
    Implausible(usize),
}

/// Read half of a shared [`TcpStream`].
///
/// ## Why not `TcpStream::into_split()`
///
/// `into_split()` hands out halves whose teardown is not ours to control: the
/// write half's path can issue an orderly `shutdown()`, which sends a **FIN** —
/// and a force-reset must never send one. Observing a FIN+ACK alongside the RST
/// is exactly that: graceful teardown ran first, then the abortive close.
///
/// Holding `Arc<TcpStream>` instead means teardown is a plain `close()` of the
/// last file descriptor, and nothing ever calls `shutdown()`. With `SO_LINGER`
/// armed (see [`crate::net::arm_tcp_reset`]) that emits a RST and nothing else;
/// without it, a normal FIN close — so legitimate connections are unaffected.
struct SharedRead(Arc<TcpStream>);

/// Write half of a shared [`TcpStream`]; see [`SharedRead`].
struct SharedWrite(Arc<TcpStream>);

impl AsyncRead for SharedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let stream = &*self.0;
        loop {
            // `try_read` is the polling-safe primitive: it never registers
            // interest itself, so we stay in charge of readiness.
            let dst = buf.initialize_unfilled();
            if dst.is_empty() {
                return Poll::Ready(Ok(()));
            }
            match stream.try_read(dst) {
                Ok(0) => return Poll::Ready(Ok(())), // EOF
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            match stream.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SharedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let stream = &*self.0;
        loop {
            match stream.try_write(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            match stream.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // `try_write` goes straight to the socket; there is no buffer to flush.
        Poll::Ready(Ok(()))
    }

    /// Deliberately a no-op.
    ///
    /// A `shutdown()` is what sends a FIN, and this connection's teardown is
    /// either an armed RST (force-reset) or a plain `close()` (normal end).
    /// Nothing in the tunnel asks for a half-close, and offering one here would
    /// only reintroduce the FIN+ACK we removed.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A framed reader over any byte stream: one `read(2)` yields many frames.
///
/// TCP hands us bytes, not messages. The naive approach — `read_exact` the
/// 2-byte prefix, then `read_exact` the payload — costs at least two syscalls
/// per frame, and at 45 k frames/s that is most of a core. Instead this keeps a
/// buffer, tops it up with one `read(2)`, and hands out every complete frame in
/// it before reading again.
struct FrameReader<R: AsyncRead + Unpin> {
    inner: R,
    /// Read buffer; `buf[start..end]` is unparsed data.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// Declared lengths beyond this are not our protocol; see
    /// [`plausible_frame_limit`].
    plausible: usize,
    /// Whether frames carry a padding-length field, i.e. whether the peer has
    /// padding enabled. Must match the sender or every frame misparses.
    padded: bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R, plausible: usize, padded: bool) -> Self {
        Self {
            inner,
            buf: vec![0u8; READ_BUF_BYTES],
            start: 0,
            end: 0,
            plausible,
            padded,
        }
    }

    /// Bytes of framing ahead of the payload: the length prefix, plus the
    /// padding-length field when padding is in use.
    fn header_len(&self) -> usize {
        TCP_LEN_PREFIX + if self.padded { TCP_PAD_LEN } else { 0 }
    }

    /// Whether we are holding bytes that do not yet form a whole frame.
    ///
    /// A probe's bytes almost always land here: they parse as a length prefix
    /// asking for far more than the probe will ever send. Seeing this persist
    /// is what tells us to reset instead of waiting.
    fn has_partial(&self) -> bool {
        self.end > self.start
    }

    /// Copy the next complete frame into `out`.
    ///
    /// `deadline`, when set, bounds **each blocking read**. That is the only
    /// place a timeout can be applied: this method loops internally until a
    /// whole frame is assembled, so a caller sitting outside it never gets a
    /// chance to notice that we are stuck holding a partial frame — which is
    /// exactly what a probe produces. Timing out the read is what surfaces the
    /// stall; see [`ReadDeadline`] for how the bound differs before and after
    /// the peer has authenticated.
    ///
    /// Frames larger than `out` are drained and skipped so the stream stays
    /// synchronised.
    async fn next_frame(
        &mut self,
        out: &mut [u8],
        deadline: Option<ReadDeadline>,
    ) -> std::io::Result<NextFrame> {
        loop {
            // 1. Do we already hold a whole frame?
            let head = self.header_len();
            if self.end - self.start >= head {
                let len =
                    u16::from_be_bytes([self.buf[self.start], self.buf[self.start + 1]]) as usize;
                // Padding length, when padding is enabled. The prefix counts the
                // payload only, so padding is not included in `len`.
                let pad_len = if self.padded {
                    self.buf[self.start + TCP_LEN_PREFIX] as usize
                } else {
                    0
                };
                if len == 0 {
                    self.start += head + pad_len;
                    continue;
                }
                if len > self.plausible {
                    return Ok(NextFrame::Implausible(len));
                }
                let total = head + len + pad_len;
                if self.end - self.start >= total {
                    let body = self.start + head;
                    if len > out.len() {
                        warn!(
                            "dropping oversized {len}-byte TCP frame (buffer is {} bytes)",
                            out.len()
                        );
                        self.start += total;
                        continue;
                    }
                    out[..len].copy_from_slice(&self.buf[body..body + len]);
                    // Skip the payload *and* its padding.
                    self.start += total;
                    return Ok(NextFrame::Frame(len));
                }
            }

            // 2. Not enough bytes — slide the remainder down and read more.
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            if self.end == self.buf.len() {
                // A single frame larger than the whole buffer cannot be
                // framed at all (the u16 prefix caps it at 65535 < 128 KiB).
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TCP frame exceeds the read buffer; stream is corrupt",
                ));
            }
            // Once bytes are buffered a frame is in progress and must finish
            // quickly. Tightening the deadline mid-frame is what makes a probe
            // fail in seconds: `curl` to the port sends "GET / HTTP/1.1...",
            // and "GE" read as a length prefix asks for 18245 bytes that never
            // arrive (a TLS ClientHello asks for 5635). Before any bytes have
            // arrived, an unverified peer gets the longer first-frame window.
            let per_read = match deadline {
                Some(ReadDeadline::Unverified) => Some(if self.has_partial() {
                    STALLED_FRAME_TIMEOUT
                } else {
                    FIRST_FRAME_TIMEOUT
                }),
                Some(ReadDeadline::Verified) if self.has_partial() => Some(STALLED_FRAME_TIMEOUT),
                // Verified and idle: wait as long as it takes.
                _ => None,
            };
            let read = self.inner.read(&mut self.buf[self.end..]);
            let n = match per_read {
                Some(d) => match tokio::time::timeout(d, read).await {
                    Ok(r) => r?,
                    Err(_) => return Ok(NextFrame::Stalled),
                },
                None => read.await?,
            };
            if n == 0 {
                return Ok(NextFrame::Eof); // clean EOF
            }
            self.end += n;
        }
    }
}

/// Append `payload` as a framed, optionally padded frame to `out`.
///
/// Returns `false` (and appends nothing) when the payload cannot be framed, so
/// the caller can drop that packet and keep the stream usable.
///
/// With `pad_max > 0` a random-length run of **random bytes** follows the
/// payload, and its length is recorded in the `u8` field after the length
/// prefix. Both the length and the contents are random: a fixed length would
/// defeat the purpose, and fixed contents would make the tail trivially
/// strippable by anyone who noticed.
fn append_frame(out: &mut Vec<u8>, payload: &[u8], pad_max: usize) -> bool {
    if payload.is_empty() || payload.len() > MAX_TCP_FRAME {
        return false;
    }
    // The prefix counts the payload only — padding rides outside it, so the
    // payload length stays meaningful for the plausibility check.
    //
    // A peer with padding *disabled* still cannot parse this frame: it would
    // read the pad-length byte as the payload's first byte. Enabling padding
    // changes the frame layout, so both ends must agree on whether it is on
    // (they may differ on the bound, which is read per frame).
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if pad_max > 0 {
        let pad_len = rand::rng().random_range(0..=pad_max.min(MAX_PADDING));
        out.push(pad_len as u8);
        out.extend_from_slice(payload);
        if pad_len > 0 {
            let start = out.len();
            out.resize(start + pad_len, 0);
            rand::rng().fill(&mut out[start..]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    true
}

/// Drive one connection's read half: parse frames and push them to `inbound`.
///
/// Generic over what the consumer wants each frame tagged with: the server
/// needs the peer address alongside the bytes (its hub merges many
/// connections into one channel and must know where to reply), while the
/// client has exactly one server and so wants the bytes alone. `tag` is
/// called once per frame, so it is the only place the two differ.
async fn tcp_read_loop<R, T, F>(
    reader: R,
    inbound: mpsc::Sender<T>,
    tag: F,
    opts: TcpOptions,
    abort: Arc<ConnAbort>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    F: Fn(Vec<u8>) -> T,
{
    let padded = opts.padding > 0;
    let mut reader = FrameReader::new(reader, opts.plausible, padded);
    let mut frame = vec![0u8; opts.buf_len];
    let signal = abort.signal();
    let validator = opts.validator.clone();
    // Only the first frame is checked; see `Validator`.
    let mut authenticated = validator.is_none();

    loop {
        // A real client speaks up at once (keepalive/assign on connect), so an
        // unverified connection that neither completes a frame nor shuts down
        // is a probe. Once verified, only a half-delivered frame is suspect.
        let deadline = if authenticated {
            Some(ReadDeadline::Verified)
        } else {
            Some(ReadDeadline::Unverified)
        };

        // Note the state *before* awaiting: `fut` borrows `reader`, and it is
        // still alive while the select's handler runs.
        let had_partial = reader.has_partial();
        let fut = reader.next_frame(&mut frame, deadline);
        let res = tokio::select! {
            _ = signal.notified() => return Ok(()),
            r = fut => r?,
        };

        let n = match res {
            NextFrame::Frame(n) => n,
            NextFrame::Eof => return Ok(()), // peer closed
            NextFrame::Implausible(declared) => {
                warn!(
                    "tcp: peer declared a {declared}-byte frame (max plausible {}), resetting",
                    opts.plausible
                );
                abort.fire();
                return Ok(());
            }
            NextFrame::Stalled => {
                warn!(
                    "tcp: peer did not produce a complete frame in time{}, resetting",
                    if had_partial {
                        " (partial frame stalled)"
                    } else {
                        ""
                    }
                );
                abort.fire();
                return Ok(());
            }
        };
        if n == 0 {
            continue;
        }

        // Reject a first frame that is not ShadowVPN traffic. This covers the
        // probe that *does* complete a frame: enough bytes to satisfy its own
        // bogus length prefix, but nothing that authenticates.
        if !authenticated {
            if let Some(ref check) = validator {
                if !check(&frame[..n]) {
                    warn!("tcp: first frame failed validation, resetting");
                    abort.fire();
                    return Ok(());
                }
            }
            authenticated = true;
        }

        if inbound.send(tag(frame[..n].to_vec())).await.is_err() {
            return Ok(()); // consumer gone
        }
    }
}

/// Drive one connection's write half: coalesce queued frames into one write.
///
/// The first frame is awaited (so an idle connection costs nothing); whatever
/// else is already queued is then drained **without waiting** and written in
/// the same syscall. Sparse traffic therefore sees no added latency, while a
/// burst collapses from N syscalls to one.
async fn tcp_write_loop(
    mut writer: SharedWrite,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    abort: Arc<Notify>,
    padding: usize,
) {
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH_FRAMES);
    let mut out: Vec<u8> = Vec::with_capacity(READ_BUF_BYTES);

    loop {
        batch.clear();
        out.clear();

        // Ends on force-reset too, so this task drops its `Arc<TcpStream>`
        // promptly and the socket actually closes (which is what sends the
        // RST — see `SharedWrite`).
        match tokio::select! {
            _ = abort.notified() => None,
            v = outbound.recv() => v,
        } {
            Some(p) => batch.push(p),
            None => return, // all senders dropped, or aborted
        }
        while batch.len() < WRITE_BATCH_FRAMES {
            match outbound.try_recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }

        let mut dropped = 0usize;
        for payload in &batch {
            if !append_frame(&mut out, payload, padding) {
                dropped += 1;
            }
        }
        if dropped > 0 {
            warn!("dropped {dropped} packet(s) that could not be framed for TCP");
        }
        if out.is_empty() {
            continue;
        }
        if let Err(e) = writer.write_all(&out).await {
            debug!("tcp write failed: {e}");
            return;
        }
    }
}

/// Per-connection handle used to tear a connection down abruptly, emitting a
/// TCP **RST** rather than a FIN.
///
/// ## Why a socket has more than one file descriptor
///
/// The reader and writer tasks each hold an `Arc<TcpStream>` (see
/// [`SharedRead`]), and we additionally hold a `dup()` of the socket's fd. The
/// socket — and therefore the RST — is only torn down when the **last** of
/// those descriptors closes. So a reset is a two-part job:
///
/// 1. arm `SO_LINGER` on the socket (see [`crate::net::arm_tcp_reset`]), which
///    makes the eventual `close()` abortive;
/// 2. drop our descriptor and wake the tasks holding the rest.
///
/// Doing only (2) yields an orderly FIN close, which is the bug this replaces.
/// And (1) must not be paired with `shutdown()`, which sends a FIN of its own —
/// see `arm_tcp_reset`.
struct ConnAbort {
    /// Wakes the reader and writer tasks so they drop their `Arc<TcpStream>`.
    notify: Arc<Notify>,
    /// Our own duplicate of the connection's fd. `Mutex` because `fire` takes
    /// it out to close it; held here so the socket survives until we decide
    /// otherwise.
    #[cfg(unix)]
    fd: StdMutex<Option<std::os::fd::OwnedFd>>,
    /// Set once `SO_LINGER` has been armed, so repeated `fire()` calls are
    /// harmless and the log line is emitted only once.
    fired: AtomicBool,
}

impl ConnAbort {
    /// Build a teardown handle with no socket attached.
    ///
    /// Use [`ConnAbort::with_fd`] when the connection should emit a real RST;
    /// the client uses this one, since it reconnects on its own and never
    /// force-resets.
    fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            #[cfg(unix)]
            fd: StdMutex::new(None),
            fired: AtomicBool::new(false),
        }
    }

    /// Attach a duplicate of the connection's socket so [`ConnAbort::fire`]
    /// emits a RST.
    #[cfg(unix)]
    fn with_fd(mut self, fd: Option<std::os::fd::OwnedFd>) -> Self {
        self.fd = StdMutex::new(fd);
        self
    }

    /// The signal the reader and writer loops wait on.
    fn signal(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Reset the connection now: arm an abortive close, then release every
    /// descriptor so the socket actually closes and emits the RST.
    fn fire(&self) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return; // already reset
        }

        #[cfg(unix)]
        {
            // Arm first, then close: SO_LINGER applies to the socket, so the
            // order relative to *our* descriptor does not matter, but it must
            // be set before the last close — and the last close is whichever
            // task drops its half last, which we are about to wake.
            let taken = self.fd.lock().ok().and_then(|mut g| g.take());
            if let Some(fd) = taken {
                use std::os::fd::AsRawFd;
                crate::net::arm_tcp_reset(fd.as_raw_fd());
                // Closing our duplicate drops this reference; the socket stays
                // alive until the reader/writer halves are dropped below.
                drop(fd);
            } else {
                // No duplicate to arm through (dup failed, or already fired).
                // Still wake the tasks: Linux sends a RST on close when
                // unread data is pending, which is the usual probe case.
                log::debug!("force-reset: no socket fd to arm; closing without RST guarantee");
            }
        }

        // Wake both tasks so they drop their halves. `notify_waiters` reaches
        // the ones parked right now; `notify_one` stores a permit for a task
        // that is mid-iteration, so the abort is never lost.
        self.notify.notify_waiters();
        self.notify.notify_one();
    }
}

/// Server-side TCP carrier: many connections, presented as one packet source.
///
/// `accept()` spawns a reader and a writer task per connection. Every reader
/// tags its frames with the connection's peer address and pushes them into one
/// shared channel, which [`Transport::recv`] drains; [`Transport::send_to`]
/// looks the peer up in `outbound` and queues the bytes for its writer task.
///
/// One client's parallel subflows arrive as independent connections and stay
/// independent here; grouping them into one client is the routing table's job
/// (see `Learned::learn`), which keeps this layer simple.
pub struct TcpHub {
    /// Aggregated inbound frames from every connection.
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    /// Per-peer outbound queue handles, replaced as connections come and go.
    outbound: RwLock<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    /// Per-peer teardown handles for [`TcpHub::force_reset`].
    aborts: RwLock<HashMap<SocketAddr, Arc<ConnAbort>>>,
    /// Per-connection settings; see [`TcpOptions`].
    opts: TcpOptions,
    /// Monotonic counter mixed into unordered subflow selection (see
    /// [`pick_subflow`]).
    spins: AtomicU32,
}

impl TcpHub {
    /// Bind a listener on `addr` and start the accept loop.
    ///
    /// `validator` is applied to every connection's first frame; a frame that
    /// fails it resets the connection (see [`Validator`]).
    pub async fn bind(addr: SocketAddr, opts: TcpOptions) -> std::io::Result<Arc<Self>> {
        let listener: TcpListener = bind_tcp_listener(addr)?;
        let (tx, rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        let hub = Arc::new(Self {
            inbound: Mutex::new(rx),
            outbound: RwLock::new(HashMap::new()),
            aborts: RwLock::new(HashMap::new()),
            opts,
            spins: AtomicU32::new(0),
        });

        let hub2 = Arc::clone(&hub);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        if let Err(e) = crate::net::configure_tcp_stream(&stream) {
                            debug!("could not tune accepted TCP stream from {peer}: {e}");
                        }
                        // Duplicate the fd *before* splitting: `setsockopt`
                        // acts on the socket rather than on the descriptor, so a
                        // duplicate is enough to arm `SO_LINGER` later, and
                        // closing it is what drops this reference to the socket.
                        #[cfg(unix)]
                        let dup_fd = {
                            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
                            // SAFETY: `raw` is a live fd; `dup` returns either
                            // -1 or a fresh fd we take ownership of.
                            let dupped = unsafe { libc::dup(stream.as_raw_fd()) };
                            if dupped < 0 {
                                None
                            } else {
                                Some(unsafe { OwnedFd::from_raw_fd(dupped) })
                            }
                        };
                        #[cfg(unix)]
                        let abort = Arc::new(ConnAbort::new().with_fd(dup_fd));
                        #[cfg(not(unix))]
                        let abort = Arc::new(ConnAbort::new());
                        hub2.aborts.write().await.insert(peer, Arc::clone(&abort));

                        // Share one socket between the two tasks instead of
                        // splitting it: see `SharedRead` for why.
                        let shared = Arc::new(stream);
                        let reader = SharedRead(Arc::clone(&shared));
                        let writer = SharedWrite(Arc::clone(&shared));

                        let (out_tx, out_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
                        hub2.outbound.write().await.insert(peer, out_tx);

                        let hub3 = Arc::clone(&hub2);
                        let inbound_tx = tx.clone();
                        let read_abort = Arc::clone(&abort);
                        // Cloned *before* the spawn: the closure is `move`, so
                        // reaching for `hub2` inside it would move the whole Arc
                        // out of the accept loop, which needs it again on the
                        // next iteration.
                        let conn_opts = hub2.opts.clone();
                        tokio::spawn(async move {
                            if let Err(e) = tcp_read_loop(
                                reader,
                                inbound_tx,
                                move |p| (peer, p),
                                conn_opts,
                                read_abort,
                            )
                            .await
                            {
                                debug!("tcp connection from {peer} ended: {e}");
                            }
                            hub3.outbound.write().await.remove(&peer);
                            hub3.aborts.write().await.remove(&peer);
                        });
                        tokio::spawn(tcp_write_loop(
                            writer,
                            out_rx,
                            abort.signal(),
                            hub2.opts.padding,
                        ));
                        info!("tcp: accepted connection from {peer}");
                    }
                    Err(e) => {
                        warn!("tcp accept failed: {e}; retrying");
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    }
                }
            }
        });

        Ok(hub)
    }

    /// Receive the next frame from any connection.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut inbound = self.inbound.lock().await;
        let (peer, payload) = inbound.recv().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tcp hub has no live connections",
            )
        })?;
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((n, peer))
    }

    /// Tear down `peer`'s connection immediately, emitting a TCP RST.
    ///
    /// This is the response to a frame that is not valid ShadowVPN traffic: a
    /// port scan, a plain HTTP/`TLS` handshake, or a client with the wrong PSK.
    /// Dropping the packet and staying connected is the wrong answer — the
    /// connection stays open, the scanner learns a service is listening, and it
    /// can keep pushing bytes at us. Resetting closes the door at once.
    ///
    /// Safe against false positives because a frame that fails to de-obfuscate
    /// or to authenticate is, by construction, not from a peer holding the
    /// shared key: AEAD rejects it. A correctly configured client therefore
    /// never trips this.
    async fn force_reset(&self, peer: &SocketAddr) {
        // Stop queueing to it, so nothing more is written.
        self.outbound.write().await.remove(peer);
        if let Some(abort) = self.aborts.write().await.remove(peer) {
            abort.fire();
            warn!("tcp: force-reset connection from {peer}: non-conforming frame");
        }
    }

    /// Queue `wire` on the best connection among `peers`, preferring
    /// `preferred`.
    ///
    /// `peers` is every endpoint the destination client is known on — its
    /// parallel subflows — and `hint` says whether reordering is allowed
    /// (see [`FlowHint`]). Ordered traffic always goes to `preferred`.
    /// Unordered traffic also goes to `preferred` while it is healthy, and
    /// only spills to the least-backed-up alternative once `preferred` starts
    /// queueing: that keeps a QUIC connection in order in the common case and
    /// lets it use the other subflows precisely when its own one stalls, which
    /// is the case that otherwise costs it the whole round trip.
    async fn queue(
        &self,
        wire: &[u8],
        peers: &[SocketAddr],
        preferred: SocketAddr,
        hint: Option<FlowHint>,
    ) -> std::io::Result<()> {
        let tx = {
            let outbound = self.outbound.read().await;
            // No hint (control traffic) means "don't get clever": use the
            // preferred endpoint and keep it simple.
            let chosen = match hint {
                Some(h) if peers.len() > 1 => {
                    // Same epoch division as the client's `send_hint`.
                    let spin = self.spins.fetch_add(1, Ordering::Relaxed) / UDP_ROTATE_EVERY;
                    let backlogs: Vec<usize> =
                        peers.iter().map(|p| backlog(outbound.get(p))).collect();
                    peers[pick_subflow(&backlogs, h.hash, spin, h.ordered)]
                }
                _ => preferred,
            };

            match outbound.get(&chosen) {
                Some(tx) => tx.clone(),
                None => {
                    debug!("tcp: no live connection for {chosen}, dropping packet");
                    return Ok(());
                }
            }
        };
        if tx.send(wire.to_vec()).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tcp outbound task is gone",
            ));
        }
        Ok(())
    }
}

/// One live subflow's writer handle, or `None` while it is reconnecting.
///
/// Shared with each subflow's supervisor task so it can publish a fresh sender
/// after a reconnect without the relay loops noticing anything but a brief gap.
type Slots = Arc<RwLock<Vec<Option<mpsc::Sender<Vec<u8>>>>>>;

/// Client-side TCP carrier: `subflows` parallel connections to the server.
///
/// Each subflow is dialled, supervised, and reconnected independently: a single
/// stalled connection degrades throughput but does not stall the tunnel, and
/// the others keep carrying traffic while it recovers.
///
/// Inbound frames from all subflows share one channel; outbound packets pick a
/// subflow by [`flow_hash`] so each inner connection stays ordered.
pub struct TcpClient {
    /// The server address, used both to dial and as the peer identity reported
    /// by [`Transport::recv`] (the client has exactly one server).
    server: SocketAddr,
    /// The local address of the first successful connection. The client pins
    /// direct/domestic DNS to this address, so it must stay stable across
    /// reconnects — a rebinding would silently change the physical source IP.
    local: Option<SocketAddr>,
    /// Frames received from the server, across every subflow and reconnect.
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Writer handle per subflow; `None` while that subflow is reconnecting.
    outbound: Slots,
    /// Number of parallel connections this client maintains.
    subflows: usize,
    /// Monotonic counter mixed into unordered subflow selection so one flow's
    /// packets rotate across subflows instead of pinning to one.
    spins: AtomicU32,
}

impl TcpClient {
    /// Dial `server` with `subflows` parallel connections and start supervisors.
    ///
    /// The connections must exist *before* the TUN device is brought up, for the
    /// same source-address-selection reason the UDP path `connect()`s early (see
    /// `bin/client.rs`).
    pub async fn connect(
        server: SocketAddr,
        subflows: usize,
        opts: TcpOptions,
    ) -> std::io::Result<Arc<Self>> {
        let subflows = subflows.max(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);

        let mut slots: Vec<Option<mpsc::Sender<Vec<u8>>>> = Vec::with_capacity(subflows);
        let mut readers: Vec<tokio::task::JoinHandle<std::io::Result<()>>> =
            Vec::with_capacity(subflows);
        let mut local = None;

        for idx in 0..subflows {
            let (tx, addr, reader) = Self::dial(server, &inbound_tx, opts.clone()).await?;
            if idx == 0 {
                local = addr;
            }
            slots.push(Some(tx));
            readers.push(reader);
        }

        // Supervisors share the slot vector so a reconnect can swap a slot in
        // place without the relay loops noticing anything but a brief gap.
        let outbound: Slots = Arc::new(RwLock::new(slots));
        let client = Arc::new(Self {
            server,
            local,
            inbound: Mutex::new(inbound_rx),
            outbound: Arc::clone(&outbound),
            subflows,
            spins: AtomicU32::new(0),
        });

        for (idx, reader) in readers.into_iter().enumerate() {
            tokio::spawn(supervise_subflow(
                server,
                idx,
                Arc::clone(&outbound),
                inbound_tx.clone(),
                reader,
                opts.clone(),
            ));
        }

        Ok(client)
    }

    /// Open one connection: spawn its writer and reader tasks, and return the
    /// writer handle, local address, and the reader's join handle (which
    /// resolves when the connection ends).
    async fn dial(
        server: SocketAddr,
        inbound_tx: &mpsc::Sender<Vec<u8>>,
        opts: TcpOptions,
    ) -> std::io::Result<(
        mpsc::Sender<Vec<u8>>,
        Option<SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let stream = connect_tcp_stream(server).await?;
        let local = stream.local_addr().ok();
        // Same shared-socket arrangement as the server; see `SharedRead`. The
        // client never arms a RST, so this is purely about keeping one
        // teardown path for both ends.
        let shared = Arc::new(stream);
        let reader = SharedRead(Arc::clone(&shared));
        let writer = SharedWrite(Arc::clone(&shared));

        // The client never force-resets (it has exactly one server, and its
        // supervisor reconnects on its own), but both loops take a teardown
        // handle so the same functions serve either end. No validator: the
        // client trusts the server it dialled.
        let abort = Arc::new(ConnAbort::new());

        let (out_tx, out_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        tokio::spawn(tcp_write_loop(
            writer,
            out_rx,
            abort.signal(),
            opts.padding,
        ));

        let tx = inbound_tx.clone();
        let reader_task = tokio::spawn(tcp_read_loop(reader, tx, |p| p, opts, abort));

        Ok((out_tx, local, reader_task))
    }

    /// Receive the next frame from the server.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut inbound = self.inbound.lock().await;
        let payload = inbound.recv().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("tcp connection to {} is closed", self.server),
            )
        })?;
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((n, self.server))
    }

    /// Queue `wire` on the subflow chosen for `hint`.
    ///
    /// The caller passes the classification of the *plaintext* IP packet rather
    /// than letting us hash the ciphertext — the AEAD salt makes every
    /// ciphertext look unrelated, so hashing it would scatter one inner
    /// connection across all subflows and reorder it.
    ///
    /// Ordered traffic (inner TCP) is pinned. Unordered traffic (inner UDP —
    /// one QUIC connection is one 5-tuple) starts on its pinned subflow and
    /// spills to the least-backed-up one only when that subflow is queueing.
    /// Without the spill a QUIC connection would be capped at a single
    /// subflow's window and would gain nothing from `--subflows`; with it, a
    /// stall on one subflow is no longer head-of-line blocking for the whole
    /// connection.
    async fn send_hint(&self, wire: &[u8], hint: FlowHint) -> std::io::Result<()> {
        if wire.len() > MAX_TCP_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "packet of {} bytes exceeds the TCP frame limit ({})",
                    wire.len(),
                    MAX_TCP_FRAME
                ),
            ));
        }
        let n = self.subflows.max(1);
        // Divide so `spin` only changes every UDP_ROTATE_EVERY packets: see that
        // constant for why a per-packet counter is counter-productive.
        let spin = self.spins.fetch_add(1, Ordering::Relaxed) / UDP_ROTATE_EVERY;
        let idx = {
            let outbound = self.outbound.read().await;
            let backlogs: Vec<usize> = (0..n).map(|i| backlog(slot_of(&outbound, i))).collect();
            pick_subflow(&backlogs, hint.hash, spin, hint.ordered)
        };

        let tx = {
            let outbound = self.outbound.read().await;
            match outbound.get(idx).and_then(|s| s.as_ref()) {
                Some(tx) => tx.clone(),
                None => {
                    debug!("tcp: subflow {idx} is reconnecting, dropping packet");
                    return Ok(());
                }
            }
        };
        if tx.send(wire.to_vec()).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tcp outbound task is gone",
            ));
        }
        Ok(())
    }

    /// Fan `wire` out to every live subflow.
    ///
    /// Used for keepalives and control traffic: each subflow must prove itself
    /// alive independently, or the server would expire the ones carrying no
    /// data and the tunnel would silently shrink to a single path.
    async fn send_all(&self, wire: &[u8]) -> std::io::Result<()> {
        if wire.len() > MAX_TCP_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "packet of {} bytes exceeds the TCP frame limit ({})",
                    wire.len(),
                    MAX_TCP_FRAME
                ),
            ));
        }
        let senders: Vec<mpsc::Sender<Vec<u8>>> = {
            let outbound = self.outbound.read().await;
            outbound.iter().filter_map(|s| s.as_ref().cloned()).collect()
        };
        for tx in senders {
            if tx.send(wire.to_vec()).await.is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "tcp outbound task is gone",
                ));
            }
        }
        Ok(())
    }
}

/// Keep one subflow up: wait for its connection to end, then redial.
async fn supervise_subflow(
    server: SocketAddr,
    idx: usize,
    outbound: Slots,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    reader: tokio::task::JoinHandle<std::io::Result<()>>,
    opts: TcpOptions,
) {
    let mut reader = reader;
    let mut attempts = 0u32;

    loop {
        match (&mut reader).await {
            Ok(Ok(())) => debug!("tcp: subflow {idx} to {server} closed by peer"),
            Ok(Err(e)) => debug!("tcp: subflow {idx} to {server} ended: {e}"),
            Err(e) => warn!("tcp: subflow {idx} reader panicked: {e}"),
        }
        outbound.write().await[idx] = None;

        let (tx, _local, next_reader) = loop {
            attempts += 1;
            match TcpClient::dial(server, &inbound_tx, opts.clone()).await {
                Ok(v) => break v,
                Err(e) => {
                    if attempts >= MAX_RECONNECT_ATTEMPTS {
                        warn!("tcp: subflow {idx} giving up on {server} after {attempts} attempts: {e}");
                        return;
                    }
                    warn!(
                        "tcp: subflow {idx} reconnect to {server} failed ({attempts}/{MAX_RECONNECT_ATTEMPTS}): {e}"
                    );
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            }
        };

        attempts = 0;
        outbound.write().await[idx] = Some(tx);
        reader = next_reader;
        info!("tcp: subflow {idx} connected to {server}");
    }
}

/// The carrier: either the original UDP socket or one of the two TCP modes.
///
/// Cloning is cheap (all variants are reference-counted) and shares the same
/// underlying socket / hub, so the relay loops can each hold a clone.
#[derive(Clone)]
pub enum Transport {
    /// Original carrier: one datagram per IP packet.
    Udp {
        /// The bound (and, on the client, connected) UDP socket.
        socket: Arc<UdpSocket>,
    },
    /// Server-side TCP: accepts many connections.
    TcpServer(Arc<TcpHub>),
    /// Client-side TCP: parallel connections to the server.
    TcpClient(Arc<TcpClient>),
}

impl Transport {
    /// Wrap a UDP socket (the original behaviour).
    pub fn udp(socket: UdpSocket) -> Self {
        Transport::Udp {
            socket: Arc::new(socket),
        }
    }

    /// Start a TCP listener bound to `addr`; see [`TcpOptions`].
    pub async fn tcp_server(addr: SocketAddr, opts: TcpOptions) -> std::io::Result<Self> {
        Ok(Transport::TcpServer(TcpHub::bind(addr, opts).await?))
    }

    /// Dial a TCP server at `addr` with `subflows` parallel connections; see
    /// [`TcpOptions`].
    pub async fn tcp_client(
        addr: SocketAddr,
        subflows: usize,
        opts: TcpOptions,
    ) -> std::io::Result<Self> {
        Ok(Transport::TcpClient(
            TcpClient::connect(addr, subflows, opts).await?,
        ))
    }

    /// Receive the next tunnelled datagram (UDP) or frame (TCP) into `buf`,
    /// returning its length and the peer it came from.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            Transport::Udp { socket } => socket.recv_from(buf).await,
            Transport::TcpServer(hub) => hub.recv(buf).await,
            Transport::TcpClient(client) => client.recv(buf).await,
        }
    }

    /// Send `wire` to `peer`. Server-side API; the client uses
    /// [`Transport::send_hint`] / [`Transport::send_all`].
    pub async fn send_to(&self, wire: &[u8], peer: &SocketAddr) -> std::io::Result<()> {
        self.send_to_hint(wire, std::slice::from_ref(peer), *peer, None)
            .await
    }

    /// Send `wire` to one of `peers` — every endpoint the destination is known
    /// on — preferring `preferred`.
    ///
    /// `hint` carries the classification of the *plaintext* IP packet (see
    /// [`classify`]). Unordered traffic (inner UDP/QUIC) spills off
    /// `preferred` when it backs up; ordered traffic never does. Computing it
    /// before encryption matters: the AEAD salt makes every ciphertext look
    /// unrelated, so classifying the ciphertext would hash away the very
    /// 5-tuple this depends on.
    pub async fn send_to_hint(
        &self,
        wire: &[u8],
        peers: &[SocketAddr],
        preferred: SocketAddr,
        hint: Option<FlowHint>,
    ) -> std::io::Result<()> {
        match self {
            Transport::Udp { socket } => socket.send_to(wire, &preferred).await.map(|_| ()),
            Transport::TcpServer(hub) => hub.queue(wire, peers, preferred, hint).await,
            Transport::TcpClient(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a TCP client addresses one server; use send_hint",
            )),
        }
    }

    /// Send `wire` on the subflow chosen for the *plaintext* classified by
    /// `hint` (TCP client), or on the connected socket (UDP).
    pub async fn send_hint(&self, wire: &[u8], hint: FlowHint) -> std::io::Result<()> {
        match self {
            Transport::Udp { socket } => socket.send(wire).await.map(|_| ()),
            Transport::TcpClient(client) => client.send_hint(wire, hint).await,
            Transport::TcpServer(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a TCP server must address a specific peer; use send_to_hint",
            )),
        }
    }

    /// Send `wire` on the subflow pinned for `flow`, assuming ordered traffic.
    ///
    /// Convenience wrapper for control traffic, which is rare, tiny, and
    /// always wants a stable path rather than the fastest one.
    pub async fn send_on(&self, wire: &[u8], flow: u32) -> std::io::Result<()> {
        self.send_hint(
            wire,
            FlowHint {
                hash: flow,
                ordered: true,
            },
        )
        .await
    }

    /// Send `wire` to this transport's peer (client-side convenience).
    pub async fn send(&self, wire: &[u8]) -> std::io::Result<()> {
        self.send_on(wire, 0).await
    }

    /// Fan `wire` out to every subflow (keepalives must keep all of them warm).
    ///
    /// On UDP and on the server this is just a normal send.
    pub async fn send_all(&self, wire: &[u8]) -> std::io::Result<()> {
        match self {
            Transport::Udp { socket } => socket.send(wire).await.map(|_| ()),
            Transport::TcpClient(client) => client.send_all(wire).await,
            Transport::TcpServer(hub) => {
                // Best effort: the server has no "all peers" notion here.
                let _ = hub;
                Ok(())
            }
        }
    }

    /// Tear down `peer`'s connection immediately, emitting a TCP RST.
    ///
    /// The server calls this on a frame that is not valid ShadowVPN traffic;
    /// see [`TcpHub::force_reset`]. A no-op on the carriers where there is no
    /// connection to reset (UDP) or nothing to reset (the client has one
    /// server, and its supervisor will reconnect on its own).
    pub async fn force_reset(&self, peer: &SocketAddr) {
        match self {
            Transport::TcpServer(hub) => hub.force_reset(peer).await,
            _ => debug!("force-reset requested for {peer} but this carrier has no per-peer connection"),
        }
    }

    /// Number of parallel subflows (1 for UDP and for the server side).
    pub fn subflows(&self) -> usize {
        match self {
            Transport::TcpClient(client) => client.subflows,
            _ => 1,
        }
    }

    /// The local address of this end of the carrier, when it has one.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Transport::Udp { socket } => socket.local_addr(),
            Transport::TcpClient(client) => client.local.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "tcp client has no local address yet",
                )
            }),
            Transport::TcpServer(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a tcp hub has no single local address",
            )),
        }
    }

    /// Whether this carrier is TCP (used for logs and for sizing buffers).
    pub fn is_tcp(&self) -> bool {
        !matches!(self, Transport::Udp { .. })
    }

    /// A short carrier name for log lines (`"udp"` / `"tcp"`).
    pub fn name(&self) -> &'static str {
        if self.is_tcp() {
            "tcp"
        } else {
            "udp"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generous bound: these tests are about framing, not plausibility.
    const TEST_PLAUSIBLE: usize = 4096;

    /// Run the async reader on a one-shot runtime so the sync tests can await.
    fn read_all(wire: &[u8], padded: bool) -> Vec<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut r = FrameReader::new(wire, TEST_PLAUSIBLE, padded);
            let mut out = vec![0u8; 4096];
            let mut frames = Vec::new();
            loop {
                match r.next_frame(&mut out, None).await.unwrap() {
                    NextFrame::Frame(n) => frames.push(out[..n].to_vec()),
                    NextFrame::Eof | NextFrame::Stalled => break,
                    NextFrame::Implausible(len) => {
                        panic!("unexpected implausible frame of {len} bytes")
                    }
                }
            }
            frames
        })
    }

    #[test]
    fn unpadded_round_trip() {
        let mut wire = Vec::new();
        assert!(append_frame(&mut wire, b"hello", 0));
        // Layout with padding off: [u16 len][payload].
        assert_eq!(&wire[..TCP_LEN_PREFIX], &5u16.to_be_bytes());
        assert_eq!(wire.len(), TCP_LEN_PREFIX + 5);
        assert_eq!(read_all(&wire, false), vec![b"hello".to_vec()]);
    }

    #[test]
    fn padded_round_trip() {
        let mut wire = Vec::new();
        assert!(append_frame(&mut wire, b"hello", 64));
        // Layout with padding on: [u16 len][u8 pad_len][payload][pad].
        assert_eq!(&wire[..TCP_LEN_PREFIX], &5u16.to_be_bytes());
        let declared = wire[TCP_LEN_PREFIX] as usize;
        assert_eq!(wire.len(), TCP_LEN_PREFIX + TCP_PAD_LEN + 5 + declared);
        assert!(declared <= 64);
        assert_eq!(read_all(&wire, true), vec![b"hello".to_vec()]);
    }

    #[test]
    fn padding_is_skipped_and_payloads_survive() {
        // Several frames back to back: padding must be skipped each time, and
        // must never leak into the next payload even if its bytes look like a
        // length prefix.
        let mut wire = Vec::new();
        for payload in [b"a".as_slice(), b"bb".as_slice(), b"ccc".as_slice()] {
            assert!(append_frame(&mut wire, payload, 200));
        }
        assert_eq!(
            read_all(&wire, true),
            vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()]
        );
    }

    #[test]
    fn padding_length_varies() {
        // A fixed length would defeat the purpose of obscuring frame sizes.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let mut wire = Vec::new();
            assert!(append_frame(&mut wire, b"x", 64));
            seen.insert(wire[TCP_LEN_PREFIX]);
        }
        assert!(seen.len() > 1, "padding length never varied: {seen:?}");
    }

    #[test]
    fn padding_respects_the_u8_bound() {
        // The pad length field is a single u8, so a larger request is clamped
        // rather than silently truncating the written length.
        for _ in 0..200 {
            let mut wire = Vec::new();
            assert!(append_frame(&mut wire, b"x", 1000));
            let declared = wire[TCP_LEN_PREFIX] as usize;
            assert!(declared <= MAX_PADDING, "pad_len {declared} exceeds the u8 field");
        }
    }

    #[test]
    fn empty_and_oversized_payloads_are_rejected() {
        let mut wire = Vec::new();
        assert!(!append_frame(&mut wire, b"", 0));
        assert!(wire.is_empty(), "nothing should be written");

        let big = vec![0u8; MAX_TCP_FRAME + 1];
        assert!(!append_frame(&mut wire, &big, 0));
        assert!(wire.is_empty(), "nothing should be written");
    }

    #[test]
    fn truncated_stream_yields_no_frame() {
        // A peer that declares padding but stops mid-frame must not produce a
        // bogus frame from the bytes it did send.
        let mut wire = Vec::new();
        assert!(append_frame(&mut wire, b"payload", 32));
        let truncated = &wire[..wire.len() - 1];
        assert_eq!(read_all(truncated, true), Vec::<Vec<u8>>::new());
    }
}
