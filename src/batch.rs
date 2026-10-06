//! Batch plumbing for the data plane.
//!
//! ## Why this exists
//!
//! After the buffer pool removed the per-packet allocations, what is left on
//! the hot path is **per-packet synchronisation**: every packet costs one
//! channel send (atomic op + possible wakeup) on the reader side and one
//! channel receive on the worker side, plus one trip through the tokio reactor
//! per `recv`/`send` await.
//!
//! At ~45k packets/s those per-packet costs dominate: they are not doing work,
//! they are coordinating. Batching amortises them over a group of packets —
//! the reader hands over up to [`BATCH_MAX`] packets in one channel send, and
//! the worker drains several batches per wakeup with `recv_many`.
//!
//! ## What batching cannot do
//!
//! It does **not** reduce syscalls. A TUN device delivers exactly one packet
//! per `read`, and `writev` on TUN concatenates its iovecs into *one* packet
//! rather than writing several — so there is no way to move multiple packets
//! with one syscall on that device. What batching removes is the tokio-level
//! coordination around those syscalls.

use std::time::Duration;

/// Packets per hand-off batch.
///
/// Large enough to amortise the channel wakeup, small enough that a batch is
/// drained well within a scheduling tick (~32 x 1400 B ≈ 45 KB).
pub const BATCH_MAX: usize = 32;

/// How long the reader waits for a *further* packet before shipping a partial
/// batch.
///
/// Under load the socket always has another packet ready, so this never fires
/// and batches fill completely. When traffic is sparse it bounds the extra
/// latency to well under a millisecond — far below the RTT this traffic is
/// already subject to.
pub const BATCH_SPIN: Duration = Duration::from_micros(50);

/// Batches a worker takes per wakeup.
///
/// Multiplying by [`BATCH_MAX`], one wakeup can retire ~256 packets.
pub const BATCH_RECV: usize = 8;

/// Fan a batch out into `slots` per-destination batches, preserving order
/// within each slot.
///
/// The reader decides the destination per packet (by shard, or by inner-flow
/// hash); this regroups them so each downstream worker receives one batch
/// instead of a stream of single packets.
pub fn fan_out<T>(slots: usize, batch: Vec<(usize, T)>) -> Vec<Vec<T>> {
    let mut out: Vec<Vec<T>> = (0..slots).map(|_| Vec::new()).collect();
    for (slot, item) in batch {
        out[slot % slots].push(item);
    }
    out
}
