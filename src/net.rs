//! UDP and TCP socket construction with enlarged kernel buffers.
//!
//! The default per-socket send/receive buffers (often ~200 KB) are far smaller
//! than the bandwidth-delay product of a fast tunnel: at multi-hundred-Mbit
//! rates the single receive task can fall behind for a few hundred microseconds
//! and the kernel silently drops the overflow. Enlarging `SO_RCVBUF`/`SO_SNDBUF`
//! gives the data plane headroom to absorb those bursts (and lets TCP *inside*
//! the tunnel open a larger window), which together with the pipelined relay
//! loops is what keeps the carrier from dropping packets under load.
//!
//! Sizing is best-effort: the OS may clamp the request (on Linux to
//! `net.core.{r,w}mem_max`), and that is fine — a clamped-but-larger buffer is
//! still better than the default, and the relay loops do not depend on an exact
//! size.
//!
//! The TCP carrier (see [`crate::transport`]) reuses these settings through
//! [`configure_tcp_stream`], [`bind_tcp_listener`] and [`connect_tcp_stream`].
//! TCP additionally needs `TCP_NODELAY`: tunnel traffic is a stream of small IP
//! packets, and Nagle's algorithm would hold them back waiting for an ACK,
//! adding latency (and, in the worst case, a stall) to every interactive packet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::policy::dns;

/// Requested size, in bytes, for each UDP socket's send and receive buffers.
/// 4 MiB comfortably covers a ~300 Mbit/s tunnel at tens of milliseconds RTT.
pub const UDP_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Requested size, in bytes, for each TCP subflow's **receive** buffer.
///
/// A connection cannot move faster than `receive_window / RTT`, so this is the
/// single most important knob for throughput — and the easiest one to get
/// wrong. See [`apply_tcp_buffers`] for why merely *calling* `SO_RCVBUF` can
/// make throughput dramatically **worse**: the request is clamped to
/// `net.core.rmem_max` (208 KiB by default) *and* the call disables the
/// kernel's window auto-tuning, locking the window at a few hundred KiB. On a
/// 66 ms path that is ~50 Mbit/s no matter how fast the link is.
///
/// 4 MiB is enough for ~500 Mbit/s at 66 ms RTT, and ~1 Gbit/s at 33 ms.
pub const TCP_RCVBUF_BYTES: usize = 4 * 1024 * 1024;

/// Requested size, in bytes, for each TCP subflow's **send** buffer.
///
/// Bounds how much unacknowledged data a subflow may have in flight, so it
/// caps throughput the same way the receive window does — from the other end.
pub const TCP_SNDBUF_BYTES: usize = 4 * 1024 * 1024;

/// Congestion-control algorithm requested for the outer TCP connections.
///
/// **This matters most for latency-sensitive traffic inside the tunnel.** A
/// loss-based algorithm (Cubic/Reno) halves its window on a single dropped
/// segment and rebuilds it over many round trips. When the payload is itself a
/// congestion-controlled protocol — QUIC, or an inner TCP stream — both layers
/// back off at once and the inner one measures a stall as a huge RTT spike, so
/// recovery takes even longer. BBR models the path's bandwidth and RTT instead
/// of reacting to loss, so one lost segment costs a retransmit rather than a
/// throughput collapse, and it does not fill the bottleneck queue (which is
/// what makes the inner protocol's RTT estimates unstable in the first place).
///
/// Best-effort: kernels without BBR, or without permission to switch, stay on
/// the default. Failure is logged at debug level and ignored.
pub const TCP_CC_NAME: &str = "bbr";

/// Cap on bytes sitting in the send queue that have *not* yet been handed to
/// the NIC ([`TCP_NOTSENT_LOWAT`]).
///
/// Without this, "sent" means "copied into a multi-megabyte socket buffer", so
/// the kernel can hold seconds of traffic on a congested path. That is
/// bufferbloat: latency explodes while throughput looks fine on average — and
/// any protocol inside the tunnel that measures RTT (QUIC, inner TCP) sees the
/// queue, conservatively backs off, and never uses the available bandwidth.
///
/// Capping it makes the socket report "not writable" while only a small amount
/// is genuinely unsent, which pushes backpressure upstream into our own queues
/// where we can see it and react to it (see [`crate::transport`]'s subflow
/// selection). Small enough to keep latency honest, large enough to keep the
/// pipe full.
/// 512 KiB, not 32 KiB: the cap is on bytes queued but not yet handed to the
/// NIC, so too small a value makes the socket report "not writable" while the
/// pipe still has room and the writer task cannot feed it fast enough — the
/// path then idles between app writes. 512 KiB is ~8 ms of data at 500 Mbit/s,
/// frequent enough to stay responsive and deep enough to keep the pipe full.
/// Lower it (toward 64 KiB) only if latency matters more than throughput.
pub const TCP_NOTSENT_LOWAT_BYTES: u32 = 512 * 1024;

/// `TCP_CONGESTION` / `TCP_NOTSENT_LOWAT` option numbers on Linux.
///
/// Pinned here rather than taken from `libc` because they are stable kernel ABI
/// but not universally wrapped by every libc release we build against.
#[cfg(target_os = "linux")]
mod linux_tcp {
    pub const TCP_CONGESTION: libc::c_int = 13;
    pub const TCP_NOTSENT_LOWAT: libc::c_int = 25;
    /// Like `SO_RCVBUF` but ignores `net.core.rmem_max`; needs `CAP_NET_ADMIN`.
    /// VPN processes normally run as root, so this is usually available.
    pub const SO_RCVBUFFORCE: libc::c_int = 33;
    /// Like `SO_SNDBUF` but ignores `net.core.wmem_max`; needs `CAP_NET_ADMIN`.
    pub const SO_SNDBUFFORCE: libc::c_int = 32;
}

/// Set a `u32` socket option; `false` if the kernel refused it.
#[cfg(target_os = "linux")]
fn set_opt_u32(fd: libc::c_int, opt: libc::c_int, val: u32) -> bool {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &val as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        ) == 0
    }
}

/// Read a `u32` socket option back, so we can log what actually took effect.
#[cfg(target_os = "linux")]
fn get_opt_u32(fd: libc::c_int, opt: libc::c_int) -> Option<u32> {
    unsafe {
        let mut val: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &mut val as *mut u32 as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            Some(val)
        } else {
            None
        }
    }
}

/// Size the TCP buffers for one subflow.
///
/// **Why this is not just `set_recv_buffer_size()`:** two Linux behaviours
/// combine to make the naive call a throughput trap.
///
/// 1. `SO_RCVBUF` is clamped to `net.core.rmem_max` (208 KiB by default), so a
///    4 MiB request silently becomes 208 KiB.
/// 2. Setting it at all sets `SOCK_RCVBUF_LOCK`, which **disables** TCP receive
///    window auto-tuning. Auto-tuning would otherwise grow the window to
///    `net.ipv4.tcp_rmem[2]` — 6 MiB by default, ~30x the clamped value.
///
/// Doing both at once locks the window at a few hundred KiB and pins
/// throughput at `window / RTT`. That is the whole "50 Mbit/s" symptom.
///
/// So: try `SO_RCVBUFFORCE` first (ignores the clamp, still locks auto-tuning,
/// but at the full requested size, which is what we want anyway). If it is
/// unavailable — no `CAP_NET_ADMIN`, container without the capability — then
/// **set nothing at all** and let auto-tuning do its job, which is far better
/// than a locked 208 KiB window.
///
/// The send buffer has no equivalent auto-tuning to lose, so a clamped value
/// is still an improvement and the plain option is fine as a fallback.
#[cfg(target_os = "linux")]
fn apply_tcp_buffers(fd: libc::c_int) {
    let rcv_ok = set_opt_u32(fd, linux_tcp::SO_RCVBUFFORCE, TCP_RCVBUF_BYTES as u32);
    let snd_ok = set_opt_u32(fd, linux_tcp::SO_SNDBUFFORCE, TCP_SNDBUF_BYTES as u32);

    if !rcv_ok {
        // Deliberately NOT falling back to SO_RCVBUF: see the doc comment.
        // Auto-tuning (bounded by net.ipv4.tcp_rmem[2], 6 MiB by default) beats
        // a locked, clamped window by an order of magnitude.
        log::debug!(
            "could not force SO_RCVBUF to {} bytes (needs CAP_NET_ADMIN);              leaving it unset so TCP window auto-tuning stays active.              For very long RTT paths raise net.core.rmem_max and net.ipv4.tcp_rmem",
            TCP_RCVBUF_BYTES
        );
    }
    if !snd_ok {
        // No auto-tuning to lose here, so take whatever the kernel allows.
        let _ = set_opt_u32(fd, libc::SO_SNDBUF, TCP_SNDBUF_BYTES as u32);
    }

    // Report what actually took effect — the number that bounds throughput.
    // Linux reports sk_rcvbuf, which is 2x the value it was given.
    if let Some(got) = get_opt_u32(fd, libc::SO_RCVBUF) {
        let effective = got / 2;
        if effective < TCP_RCVBUF_BYTES as u32 {
            let mbit_at_100ms = (got as u64 * 8) / 100_000; // bytes/100ms -> Mbit/s
            log::warn!(
                "TCP receive window is only ~{} KiB (asked for {} KiB); \
                 this caps a single subflow at roughly {} Mbit/s per 100 ms of RTT. \
                 Raise net.core.rmem_max / net.ipv4.tcp_rmem, or run as root so \
                 SO_RCVBUFFORCE can bypass the limit",
                effective / 1024,
                TCP_RCVBUF_BYTES / 1024,
                mbit_at_100ms
            );
        }
    }
}

/// Apply the Linux-only TCP tuning that needs raw `setsockopt`.
///
/// Both options are advisory: an older kernel, a container that forbids
/// switching congestion control, or a non-Linux target all fall through
/// silently. The tunnel works without them — just not as well.
#[cfg(target_os = "linux")]
fn tune_tcp_linux(fd: std::os::fd::RawFd) {
    use std::ffi::CString;
    // Note: `AsRawFd` lives in `std::os::fd` on unix only; Windows would need
    // `AsRawSocket`, which is why the whole path above is `cfg`-gated.

    unsafe {
        // Switch the connection's congestion control to BBR.
        if let Ok(name) = CString::new(TCP_CC_NAME) {
            let rc = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                linux_tcp::TCP_CONGESTION,
                name.as_ptr() as *const libc::c_void,
                name.as_bytes().len() as libc::socklen_t,
            );
            if rc != 0 {
                log::debug!(
                    "could not set TCP congestion control to {TCP_CC_NAME}: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        // Cap unsent bytes so the send queue stays shallow.
        let lowat: u32 = TCP_NOTSENT_LOWAT_BYTES;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            linux_tcp::TCP_NOTSENT_LOWAT,
            &lowat as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        if rc != 0 {
            log::debug!(
                "could not set TCP_NOTSENT_LOWAT: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    apply_tcp_buffers(fd);
}

/// Apply the tuning to an established stream.
#[cfg(target_os = "linux")]
fn tune_stream(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    tune_tcp_linux(stream.as_raw_fd());
    Ok(())
}

/// Off Linux there is no `TCP_CONGESTION`/`TCP_NOTSENT_LOWAT`, and no
/// `SO_RCVBUFFORCE`; plain buffer sizing is all we can do (and no
/// auto-tuning-locking caveat applies the same way).
#[cfg(not(target_os = "linux"))]
fn tune_stream(stream: &TcpStream) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(TCP_RCVBUF_BYTES);
    let _ = sock.set_send_buffer_size(TCP_SNDBUF_BYTES);
    Ok(())
}

/// Same, for a socket that has not been `connect()`ed yet — the point where the
/// receive window is still negotiable.
#[cfg(target_os = "linux")]
fn tune_socket(sock: &Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    tune_tcp_linux(sock.as_raw_fd());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn tune_socket(sock: &Socket) -> std::io::Result<()> {
    let _ = sock.set_recv_buffer_size(TCP_RCVBUF_BYTES);
    let _ = sock.set_send_buffer_size(TCP_SNDBUF_BYTES);
    Ok(())
}

/// Transaction id for the bootstrap server-resolution query. The socket is
/// connected to a single upstream and only one query is in flight, so the exact
/// value does not matter; a fixed non-zero id keeps things deterministic.
const SERVER_QUERY_ID: u16 = 0x5650; // "VP"

/// Receive buffer for a server-resolution DNS response. An `A` answer is tiny;
/// this is generous headroom.
const RESOLVE_BUF_BYTES: usize = 4096;

/// Bind a non-blocking [`UdpSocket`] to `addr` with enlarged send/receive
/// buffers ([`UDP_BUFFER_BYTES`], best-effort).
///
/// Returns a tokio socket ready to use with the current runtime; on the client
/// it is subsequently `connect()`ed to the server.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Best-effort: a clamp (e.g. to net.core.rmem_max) is not an error.
    let _ = sock.set_recv_buffer_size(UDP_BUFFER_BYTES);
    let _ = sock.set_send_buffer_size(UDP_BUFFER_BYTES);

    // tokio requires the underlying socket to be non-blocking.
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into())
}

/// Bind a non-blocking [`TcpListener`] to `addr`.
///
/// The listening socket inherits the buffer tuning from
/// [`configure_tcp_socket`], which accepted connections then carry over via
/// `SO_RCVBUF`/`SO_SNDBUF` inheritance on Linux and macOS.
pub fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    configure_tcp_socket(&sock)?;

    // A listener that can be restarted promptly after a crash is worth the
    // (minor, same-process) risk of rebinding a TIME_WAIT address.
    let _ = sock.set_reuse_address(true);
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(crate::transport::TCP_BACKLOG as i32)?;

    TcpListener::from_std(sock.into())
}

/// Open a non-blocking TCP connection to `addr`.
///
/// The connect is started on the raw (non-blocking) socket and completed inside
/// the tokio reactor by `TcpStream::connect`, which yields a socket whose
/// readability/writability is driven by the runtime — the `tokio::net` type is
/// what the relay loops need, so this wraps it back into one.
pub async fn connect_tcp_stream(addr: SocketAddr) -> std::io::Result<TcpStream> {
    // Hand-rolled connect rather than `TcpStream::connect`, because the socket
    // buffers must be raised *before* the handshake: the receive window is
    // negotiated in the SYN, and setting SO_RCVBUF afterwards only helps the
    // steady state, not the window scale the peer sees.
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    configure_tcp_socket(&sock)?;

    sock.set_nonblocking(true)?;
    match sock.connect(&addr.into()) {
        Ok(()) => {}
        // A non-blocking connect completes "in progress" (EINPROGRESS); on
        // Windows the same condition surfaces as WOULDBLOCK.
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.raw_os_error() == Some(libc::EINPROGRESS) =>
        {
            // Wait for completion below.
        }
        Err(e) => return Err(e),
    }

    let stream = TcpStream::from_std(std::net::TcpStream::from(sock))?;
    // Wait until the connect resolves, then surface any pending error (a
    // refused or unreachable connect reports itself here, not above).
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    configure_tcp_stream(&stream)?;
    Ok(stream)
}

/// Apply the tuning every TCP connection in the tunnel wants.
///
/// [`configure_tcp_socket`] covers what can only be set before the socket is in
/// use; this adds what must be set *after* a socket exists — most importantly
/// `TCP_NODELAY`, which turns off Nagle coalescing so each tunnelled IP packet
/// goes out on the wire immediately.
pub fn configure_tcp_stream(stream: &TcpStream) -> std::io::Result<()> {
    // Turn off Nagle: tunnel traffic is a stream of small IP packets, and
    // coalescing them adds a round trip to every interactive packet.
    stream.set_nodelay(true)?;
    // Buffers, congestion control, and the unsent-bytes watermark. Applied even
    // if `configure_tcp_socket` already ran before the handshake, because that
    // is the only point at which an accepted socket is guaranteed to be tuned.
    tune_stream(stream)?;
    Ok(())
}

/// Best-effort buffer sizing and address reuse on a freshly created TCP socket.
///
/// Larger buffers let TCP-inside-the-tunnel open a bigger window and absorb
/// bursts; failures are logged (via the caller) and never fatal.
fn configure_tcp_socket(sock: &Socket) -> std::io::Result<()> {
    // Everything (buffers included) is handled by `tune_socket`: on Linux a
    // plain `SO_RCVBUF` here would be counter-productive — see
    // `apply_tcp_buffers`.
    tune_socket(sock)?;
    Ok(())
}

/// Resolve a `host:port` server address to a concrete [`SocketAddr`] using a
/// built-in DNS client that queries `upstreams` directly over UDP, bypassing
/// the OS stub resolver.
///
/// The client connects to the server *before* the tunnel is up, so the only
/// reachable resolvers are the ones on the physical network. Going through the
/// OS resolver here is fragile: a previous run (or another tool) may have
/// pinned the system DNS at a split-DNS proxy on `127.0.0.1` that is not yet
/// listening — or at any other stale/dirty entry — leaving `getaddrinfo` to
/// fail or hang and the tunnel unable to bootstrap. Querying a known-clean
/// upstream ourselves sidesteps that dirty local state entirely.
///
/// `upstreams` are tried in order; the first one to return an `A` record wins.
/// A literal `ip:port` (or bare-IP host) short-circuits with no query at all.
pub async fn resolve_server(
    server: &str,
    upstreams: &[SocketAddr],
    timeout: Duration,
) -> std::io::Result<SocketAddr> {
    // Already a literal `ip:port`? Nothing to resolve.
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Split off the `:port`; the remainder is the host to resolve.
    let (host, port) = server
        .rsplit_once(':')
        .ok_or_else(|| resolve_err(format!("server `{server}` is missing a `:port`")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| resolve_err(format!("server `{server}` has an invalid port")))?;

    // A bare IP host needs no DNS either.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    if upstreams.is_empty() {
        return Err(resolve_err(
            "no DNS upstreams configured to resolve the server".into(),
        ));
    }

    let query = dns::build_query(SERVER_QUERY_ID, host);
    for &upstream in upstreams {
        match query_a(upstream, &query, timeout).await {
            Ok(Some(ip)) => return Ok(SocketAddr::new(IpAddr::V4(ip), port)),
            Ok(None) => {
                log::debug!("internal resolver: {upstream} returned no A record for {host}")
            }
            Err(e) => log::debug!("internal resolver: {upstream} failed for {host}: {e}"),
        }
    }

    Err(resolve_err(format!(
        "internal resolver could not resolve `{host}` via any upstream ({upstreams:?})"
    )))
}

/// Send a single `A` query to `upstream` over a fresh UDP socket and return the
/// first IPv4 address in the response, or `None` if the answer has no `A` record.
async fn query_a(
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> std::io::Result<Option<Ipv4Addr>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;

    let mut buf = vec![0u8; RESOLVE_BUF_BYTES];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| resolve_err(format!("DNS upstream {upstream} timed out")))??;
    buf.truncate(n);
    Ok(dns::a_records(&buf).into_iter().next())
}

/// Build an `io::Error` for a resolution failure.
fn resolve_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_addr_short_circuits() {
        // `ip:port` returns verbatim with no DNS query (unreachable upstream).
        let bogus = "192.0.2.1:9".parse().unwrap();
        let got = resolve_server("157.245.227.200:443", &[bogus], Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(got, "157.245.227.200:443".parse().unwrap());
    }

    #[tokio::test]
    async fn bare_ip_host_short_circuits() {
        let bogus = "192.0.2.1:9".parse().unwrap();
        let got = resolve_server("10.9.0.1:1234", &[bogus], Duration::from_millis(1))
            .await
            .unwrap();
        assert_eq!(
            got,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 1234)
        );
    }

    #[tokio::test]
    async fn missing_port_is_an_error() {
        assert!(resolve_server("example.com", &[], Duration::from_millis(1))
            .await
            .is_err());
    }
}
