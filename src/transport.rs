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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex, RwLock};
use log::{debug, info, warn};

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
    if ordered {
        return (hash % n as u32) as usize;
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
        None => usize::MAX,
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
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0u8; READ_BUF_BYTES],
            start: 0,
            end: 0,
        }
    }

    /// Copy the next complete frame into `out`, returning its length.
    ///
    /// `Ok(None)` means the peer closed the stream. Frames larger than `out`
    /// are drained and skipped so the stream stays synchronised.
    async fn next_frame(&mut self, out: &mut [u8]) -> std::io::Result<Option<usize>> {
        loop {
            // 1. Do we already hold a whole frame?
            if self.end - self.start >= TCP_LEN_PREFIX {
                let len =
                    u16::from_be_bytes([self.buf[self.start], self.buf[self.start + 1]]) as usize;
                if len == 0 {
                    self.start += TCP_LEN_PREFIX;
                    continue;
                }
                if self.end - self.start - TCP_LEN_PREFIX >= len {
                    let body = self.start + TCP_LEN_PREFIX;
                    if len > out.len() {
                        warn!(
                            "dropping oversized {len}-byte TCP frame (buffer is {} bytes)",
                            out.len()
                        );
                        self.start = body + len;
                        continue;
                    }
                    out[..len].copy_from_slice(&self.buf[body..body + len]);
                    self.start = body + len;
                    return Ok(Some(len));
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
            let n = self.inner.read(&mut self.buf[self.end..]).await?;
            if n == 0 {
                return Ok(None); // clean EOF
            }
            self.end += n;
        }
    }
}

/// Append `payload` as a length-prefixed frame to `out`.
///
/// Returns `false` (and appends nothing) when the payload cannot be framed, so
/// the caller can drop that packet and keep the stream usable.
fn append_frame(out: &mut Vec<u8>, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > MAX_TCP_FRAME {
        return false;
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
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
    buf_len: usize,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    F: Fn(Vec<u8>) -> T,
{
    let mut reader = FrameReader::new(reader);
    let mut frame = vec![0u8; buf_len];
    loop {
        let n = match reader.next_frame(&mut frame).await? {
            Some(n) => n,
            None => return Ok(()), // peer closed
        };
        if n == 0 {
            continue;
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
async fn tcp_write_loop(mut writer: OwnedWriteHalf, mut outbound: mpsc::Receiver<Vec<u8>>) {
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH_FRAMES);
    let mut out: Vec<u8> = Vec::with_capacity(READ_BUF_BYTES);

    loop {
        batch.clear();
        out.clear();

        match outbound.recv().await {
            Some(p) => batch.push(p),
            None => return, // all senders dropped
        }
        while batch.len() < WRITE_BATCH_FRAMES {
            match outbound.try_recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }

        let mut dropped = 0usize;
        for payload in &batch {
            if !append_frame(&mut out, payload) {
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
    /// Monotonic counter mixed into unordered subflow selection (see
    /// [`pick_subflow`]).
    spins: AtomicU32,
}

impl TcpHub {
    /// Bind a listener on `addr` and start the accept loop.
    pub async fn bind(addr: SocketAddr, buf_len: usize) -> std::io::Result<Arc<Self>> {
        let listener: TcpListener = bind_tcp_listener(addr)?;
        let (tx, rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        let hub = Arc::new(Self {
            inbound: Mutex::new(rx),
            outbound: RwLock::new(HashMap::new()),
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
                        let (reader, writer) = stream.into_split();
                        let (out_tx, out_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
                        hub2.outbound.write().await.insert(peer, out_tx);

                        let hub3 = Arc::clone(&hub2);
                        let inbound_tx = tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                tcp_read_loop(reader, inbound_tx, move |p| (peer, p), buf_len).await
                            {
                                debug!("tcp connection from {peer} ended: {e}");
                            }
                            hub3.outbound.write().await.remove(&peer);
                        });
                        tokio::spawn(tcp_write_loop(writer, out_rx));
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

    /// Queue `wire` for delivery to `peer`'s connection.
    ///
    /// A peer with no live connection (already gone, or never accepted) is not an
    /// error — the packet is dropped, exactly as a UDP `send_to` to a stale
    /// address would be.
    async fn send_to(&self, wire: &[u8], peer: &SocketAddr) -> std::io::Result<()> {
        self.queue(wire, std::slice::from_ref(peer), *peer, None)
            .await
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
                    let spin = self.spins.fetch_add(1, Ordering::Relaxed);
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
    pub async fn connect(server: SocketAddr, subflows: usize) -> std::io::Result<Arc<Self>> {
        let subflows = subflows.max(1);
        let (inbound_tx, inbound_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);

        let mut slots: Vec<Option<mpsc::Sender<Vec<u8>>>> = Vec::with_capacity(subflows);
        let mut readers: Vec<tokio::task::JoinHandle<std::io::Result<()>>> =
            Vec::with_capacity(subflows);
        let mut local = None;

        for idx in 0..subflows {
            let (tx, addr, reader) = Self::dial(server, &inbound_tx).await?;
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
    ) -> std::io::Result<(
        mpsc::Sender<Vec<u8>>,
        Option<SocketAddr>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let stream = connect_tcp_stream(server).await?;
        let local = stream.local_addr().ok();
        let (reader, writer) = stream.into_split();

        let (out_tx, out_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        tokio::spawn(tcp_write_loop(writer, out_rx));

        let tx = inbound_tx.clone();
        let reader_task = tokio::spawn(tcp_read_loop(
            reader,
            tx,
            |p| p,
            MAX_TCP_FRAME + crate::protocol::TCP_LEN_PREFIX,
        ));

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
        let spin = self.spins.fetch_add(1, Ordering::Relaxed);
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
            match TcpClient::dial(server, &inbound_tx).await {
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

    /// Start a TCP listener bound to `addr`; `buf_len` sizes per-connection read
    /// buffers.
    pub async fn tcp_server(addr: SocketAddr, buf_len: usize) -> std::io::Result<Self> {
        Ok(Transport::TcpServer(TcpHub::bind(addr, buf_len).await?))
    }

    /// Dial a TCP server at `addr` with `subflows` parallel connections.
    pub async fn tcp_client(addr: SocketAddr, subflows: usize) -> std::io::Result<Self> {
        Ok(Transport::TcpClient(TcpClient::connect(addr, subflows).await?))
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
