//! Carrier transport: UDP (original) or TCP (new), selected by configuration.
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
//! and are dropped with a warning (`read_frame` skips them rather than
//! desynchronising the stream).
//!
//! # Peer identity
//!
//! TCP is connection-oriented, but the relay loops identify peers by
//! [`SocketAddr`] (that is what NAT / lease / route tables are keyed on). A TCP
//! connection's remote `SocketAddr` is unique while the connection lives — the
//! OS never hands the same local ephemeral port to two live sockets to the same
//! destination — so `accept()`'s peer address is a safe per-connection key.
//!
//! # Layout
//!
//! * [`Transport::Udp`] — wraps the original `Arc<UdpSocket>`; unchanged
//!   behaviour (including the connected-socket fast path used by the client).
//! * [`Transport::TcpServer`] — a [`TcpHub`]: one accept loop, one reader task
//!   per connection, and one writer task per connection. All connections' frames
//!   are funnelled into a single inbound channel, so the existing
//!   "reader → processor" pipeline keeps working unchanged.
//! * [`Transport::TcpClient`] — a [`TcpClient`] holding one connection to the
//!   server, with automatic reconnect when it drops.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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
/// which case the packet is dropped (see [`read_frame`]).
pub const MAX_TCP_FRAME: usize = u16::MAX as usize;

/// Accept-queue backlog for the server's TCP listener.
pub const TCP_BACKLOG: u32 = 1024;

/// Per-connection outbound queue depth, and the depth of the hub's aggregated
/// inbound channel. Bounded so a stalled peer applies backpressure instead of
/// growing the heap without limit.
pub const TCP_CHANNEL_DEPTH: usize = 512;

/// How long the accept loop backs off after a transient `accept()` failure.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// How long to wait between client reconnect attempts.
const RECONNECT_DELAY: Duration = Duration::from_millis(500);

/// How many consecutive reconnect attempts the client makes before giving up
/// (and letting the process exit so a supervisor can restart it).
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Read one length-prefixed frame from `reader` into `buf`.
///
/// Returns the number of payload bytes written to `buf`. A frame whose declared
/// length exceeds `buf.len()` is drained and skipped (returning `Ok(0)`) so the
/// stream stays synchronised; `Ok(0)` is also returned for a zero-length frame.
/// `Err` means the connection is broken (EOF or a real IO error).
async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut len_bytes = [0u8; TCP_LEN_PREFIX];
    reader.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    if len == 0 {
        return Ok(0);
    }
    if len > buf.len() {
        // Drain the oversized frame so the next read starts on a clean boundary.
        let mut sink = vec![0u8; len];
        reader.read_exact(&mut sink).await?;
        warn!("dropping oversized {len}-byte TCP frame (buffer is {} bytes)", buf.len());
        return Ok(0);
    }
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// Build the wire bytes for a frame: 2-byte big-endian length + payload.
///
/// Returns `None` (and the caller must drop the packet) when the payload is too
/// large to be framed.
fn encode_frame(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_TCP_FRAME {
        return None;
    }
    let mut out = Vec::with_capacity(TCP_LEN_PREFIX + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// Pump framed payloads off one connection's read half into `inbound`.
async fn tcp_read_loop(
    mut reader: OwnedReadHalf,
    peer: SocketAddr,
    inbound: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    buf_len: usize,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; buf_len];
    loop {
        let n = read_frame(&mut reader, &mut buf).await?;
        if n == 0 {
            continue;
        }
        if inbound.send((peer, buf[..n].to_vec())).await.is_err() {
            return Ok(());
        }
    }
}

/// Pump outbound payloads onto one connection's write half.
async fn tcp_write_loop(mut writer: OwnedWriteHalf, mut outbound: mpsc::Receiver<Vec<u8>>) {
    while let Some(payload) = outbound.recv().await {
        let frame = match encode_frame(&payload) {
            Some(f) => f,
            None => {
                warn!(
                    "dropping {}-byte packet: too large for a TCP frame (max {})",
                    payload.len(),
                    MAX_TCP_FRAME
                );
                continue;
            }
        };
        if let Err(e) = writer.write_all(&frame).await {
            debug!("tcp write to peer failed: {e}");
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
pub struct TcpHub {
    /// Aggregated inbound frames from every connection.
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    /// Per-peer outbound queue handles, replaced as connections come and go.
    outbound: RwLock<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

impl TcpHub {
    /// Bind a listener on `addr` and start the accept loop.
    pub async fn bind(addr: SocketAddr, buf_len: usize) -> std::io::Result<Arc<Self>> {
        let listener: TcpListener = bind_tcp_listener(addr)?;
        let (tx, rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        let hub = Arc::new(Self {
            inbound: Mutex::new(rx),
            outbound: RwLock::new(HashMap::new()),
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
                                tcp_read_loop(reader, peer, inbound_tx, buf_len).await
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
        let tx = {
            let outbound = self.outbound.read().await;
            match outbound.get(peer) {
                Some(tx) => tx.clone(),
                None => {
                    debug!("tcp: no live connection for {peer}, dropping packet");
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

/// Client-side TCP carrier: one connection to the server, auto-reconnecting.
///
/// A background **supervisor** task owns the connection: it dials, spawns the
/// connection's reader and writer tasks, waits for the reader to report the
/// connection has ended, and dials again. Keeping the connection in a task —
/// rather than handing the read half to whoever calls `recv` — matters: the
/// relay loops call `recv` and `send` concurrently, and holding the connection
/// lock across a `recv().await` would stall every outbound packet whenever the
/// server had nothing to say.
///
/// Inbound frames and the outbound handle are therefore separate:
///
/// * `inbound` — one channel that every successive connection's reader feeds;
/// * `outbound` — the *current* connection's writer handle, swapped on
///   reconnect (and `None` while a reconnect is in flight, in which case
///   packets are dropped rather than buffered without bound).
pub struct TcpClient {
    /// The server address, used both to dial and as the peer identity reported
    /// by [`Transport::recv`] (the client has exactly one peer).
    server: SocketAddr,
    /// The local address of the first (successful) connection. The client pins
    /// direct/domestic DNS to this address, so it must stay stable across
    /// reconnects — a rebinding would silently change the physical source IP.
    local: Option<SocketAddr>,
    /// Frames received from the server, across all reconnects.
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Writer handle for the live connection, or `None` while reconnecting.
    outbound: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
}

impl TcpClient {
    /// Dial `server` eagerly and start the supervisor.
    ///
    /// The connection must exist *before* the TUN device is brought up, for the
    /// same source-address-selection reason the UDP path `connect()`s early (see
    /// `bin/client.rs`).
    pub async fn connect(server: SocketAddr) -> std::io::Result<Arc<Self>> {
        let (inbound_tx, inbound_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        let (outbound, local, reader) = Self::dial(server, &inbound_tx).await?;

        let client = Arc::new(Self {
            server,
            local,
            inbound: Mutex::new(inbound_rx),
            outbound: RwLock::new(Some(outbound)),
        });

        let supervisor = Arc::clone(&client);
        tokio::spawn(supervise(server, supervisor, inbound_tx, reader));
        Ok(client)
    }

    /// Open one connection: spawn its writer task and its reader task, and
    /// return the writer handle, the local address, and the reader's join
    /// handle (which resolves when the connection ends).
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
        let (mut reader, writer) = stream.into_split();

        let (out_tx, out_rx) = mpsc::channel(TCP_CHANNEL_DEPTH);
        tokio::spawn(tcp_write_loop(writer, out_rx));

        let tx = inbound_tx.clone();
        let reader_task = tokio::spawn(async move {
            // Sized for the largest frame the wire protocol allows.
            let mut buf = vec![0u8; MAX_TCP_FRAME];
            loop {
                let n = read_frame(&mut reader, &mut buf).await?;
                if n == 0 {
                    continue;
                }
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return Ok(());
                }
            }
        });

        Ok((out_tx, local, reader_task))
    }

    /// Receive the next frame from the server.
    ///
    /// Blocks until one arrives; errors once the supervisor has given up and
    /// every connection is gone (which ends the client, letting a supervisor
    /// restart it).
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

    /// Queue `wire` for the server.
    ///
    /// While a reconnect is in flight there is no connection to write to; the
    /// packet is dropped (with a debug log) rather than buffered, so a long
    /// outage cannot grow the heap without bound. The next keepalive re-arms
    /// the path as soon as the connection is back.
    async fn send(&self, wire: &[u8]) -> std::io::Result<()> {
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
        let tx = {
            let outbound = self.outbound.read().await;
            match outbound.as_ref() {
                Some(tx) => tx.clone(),
                None => {
                    debug!("tcp: no live connection to {}, dropping packet", self.server);
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

/// Keep a client connection up: wait for the current one to end, then redial.
///
/// `reader` resolves when the live connection's read loop finishes (EOF or a
/// real IO error). After [`MAX_RECONNECT_ATTEMPTS`] consecutive failures this
/// returns, dropping its `inbound_tx` clone so [`TcpClient::recv`] reports the
/// transport as closed and the process exits for its supervisor to restart.
async fn supervise(
    server: SocketAddr,
    client: Arc<TcpClient>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    reader: tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let mut reader = reader;
    let mut attempts = 0u32;

    loop {
        // Wait for the live connection to end.
        match (&mut reader).await {
            Ok(Ok(())) => debug!("tcp: connection to {server} closed by peer"),
            Ok(Err(e)) => debug!("tcp: connection to {server} ended: {e}"),
            Err(e) => warn!("tcp: reader task for {server} panicked: {e}"),
        }
        *client.outbound.write().await = None;

        // Redial, backing off between attempts.
        let (outbound, _local, next_reader) = loop {
            attempts += 1;
            match TcpClient::dial(server, &inbound_tx).await {
                Ok(v) => break v,
                Err(e) => {
                    if attempts >= MAX_RECONNECT_ATTEMPTS {
                        warn!(
                            "tcp: giving up on {server} after {attempts} attempts: {e}"
                        );
                        return;
                    }
                    warn!(
                        "tcp: reconnect to {server} failed ({attempts}/{MAX_RECONNECT_ATTEMPTS}): {e}"
                    );
                    tokio::time::sleep(RECONNECT_DELAY).await;
                }
            }
        };

        attempts = 0;
        *client.outbound.write().await = Some(outbound);
        reader = next_reader;
        info!("tcp: connected to {server}");
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
    /// Client-side TCP: one connection to the server.
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

    /// Dial a TCP server at `addr`.
    pub async fn tcp_client(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Transport::TcpClient(TcpClient::connect(addr).await?))
    }

    /// Receive the next tunnelled datagram (UDP) or frame (TCP) into `buf`,
    /// returning its length and the peer it came from.
    ///
    /// For UDP this is `recv_from`; for TCP it is the next length-prefixed frame
    /// from any (server) or the (client) connection.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            Transport::Udp { socket } => socket.recv_from(buf).await,
            Transport::TcpServer(hub) => hub.recv(buf).await,
            Transport::TcpClient(client) => client.recv(buf).await,
        }
    }

    /// Send `wire` (an obfuscated, encrypted-or-plaintext datagram) to `peer`.
    /// Server-side API; the client uses [`Transport::send`].
    pub async fn send_to(&self, wire: &[u8], peer: &SocketAddr) -> std::io::Result<()> {
        match self {
            Transport::Udp { socket } => {
                socket.send_to(wire, peer).await.map(|_| ())
            }
            Transport::TcpServer(hub) => hub.send_to(wire, peer).await,
            Transport::TcpClient(client) => client.send(wire).await,
        }
    }

    /// Send `wire` to the peer this transport is bound/connected to. Client-side
    /// API (the UDP socket is `connect()`ed; the TCP client has one connection).
    pub async fn send(&self, wire: &[u8]) -> std::io::Result<()> {
        match self {
            Transport::Udp { socket } => socket.send(wire).await.map(|_| ()),
            Transport::TcpClient(client) => client.send(wire).await,
            Transport::TcpServer(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a TCP server must address a specific peer; use send_to",
            )),
        }
    }

    /// The local address of this end of the carrier, when it has one.
    ///
    /// The client uses it to pin direct (domestic) DNS to the physical source
    /// address the OS chose, so it must reflect the *outbound* socket. A TCP
    /// hub has many connections and therefore no single answer.
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

    #[test]
    fn frame_encoding_round_trips() {
        let payload = b"hello tunnel";
        let frame = encode_frame(payload).expect("frame");
        assert_eq!(&frame[..TCP_LEN_PREFIX], &(payload.len() as u16).to_be_bytes());
        assert_eq!(&frame[TCP_LEN_PREFIX..], payload);
    }

    #[test]
    fn oversized_and_empty_payloads_are_not_framed() {
        assert!(encode_frame(&[]).is_none());
        assert!(encode_frame(&vec![0u8; MAX_TCP_FRAME + 1]).is_none());
        assert!(encode_frame(&vec![0u8; MAX_TCP_FRAME]).is_some());
    }

    #[tokio::test]
    async fn read_frame_handles_coalesced_and_split_frames() {
        // Two frames written back-to-back (a "coalesced" write) then read one at
        // a time — the TCP case where several frames arrive in one segment.
        let a = encode_frame(b"one").unwrap();
        let b = encode_frame(b"two!").unwrap();
        let mut stream: &[u8] = {
            let mut v = Vec::new();
            v.extend_from_slice(&a);
            v.extend_from_slice(&b);
            // Leak to 'static for the slice reader; test-only.
            Box::leak(v.into_boxed_slice())
        };
        let mut buf = [0u8; 64];
        let n = read_frame(&mut stream, &mut buf).await.expect("first frame");
        assert_eq!(&buf[..n], b"one");
        let n = read_frame(&mut stream, &mut buf).await.expect("second frame");
        assert_eq!(&buf[..n], b"two!");
    }

    #[tokio::test]
    async fn read_frame_skips_oversized_frames_without_desync() {
        let big = encode_frame(&vec![0xAAu8; 128]).unwrap();
        let small = encode_frame(b"ok").unwrap();
        let mut v = Vec::new();
        v.extend_from_slice(&big);
        v.extend_from_slice(&small);
        let mut stream: &[u8] = Box::leak(v.into_boxed_slice());

        let mut buf = [0u8; 16]; // too small for the 128-byte frame
        let n = read_frame(&mut stream, &mut buf).await.expect("oversized frame is skipped");
        assert_eq!(n, 0);
        // The small frame after it is still readable: the stream is in sync.
        let n = read_frame(&mut stream, &mut buf).await.expect("following frame");
        assert_eq!(&buf[..n], b"ok");
    }
}
