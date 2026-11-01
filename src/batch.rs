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
/// batch, **when the path looks busy** (see [`Batcher`]).
///
/// Under sustained load the socket always has another packet ready, so this
/// never fires and batches fill completely.
pub const BATCH_SPIN: Duration = Duration::from_micros(50);

/// Decides whether to wait for more packets, from recent history.
///
/// ## Why a plain spin is wrong for latency-sensitive traffic
///
/// Waiting unconditionally costs `BATCH_SPIN` on **every** batch — including
/// the ones that never get a second packet. Sparse, interactive traffic
/// (QUIC handshakes and ACKs, DNS, SSH keystrokes, game state) mostly sends
/// one packet at a time, so it pays the full spin and receives nothing for it:
/// a pure latency tax on exactly the traffic that cares most.
///
/// So the wait is made conditional: only keep waiting while batches are
/// actually filling. A batch of one is evidence the source is not producing a
/// stream right now, so the next one ships immediately. A batch that filled
/// means the path is busy, so waiting will pay off.
///
/// This self-corrects in both directions — the first packet after an idle gap
/// costs one spin at most, and a bulk transfer loses nothing because every
/// batch after the first is full.
#[derive(Debug, Default)]
pub struct Batcher {
    /// Whether recent batches have been filling.
    busy: bool,
}

impl Batcher {
    /// Whether to wait for further packets on this batch.
    pub fn should_wait(&self) -> bool {
        self.busy
    }

    /// Record how large the batch turned out, and update the estimate.
    pub fn record(&mut self, len: usize) {
        // One full batch flips to busy; a single packet flips back. The
        // asymmetry is deliberate: it takes only one idle batch to stop
        // penalising interactive traffic, and only one full batch to resume
        // amortising for bulk traffic.
        if len >= 2 {
            self.busy = true;
        } else if len == 1 {
            self.busy = false;
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A sparse source (one packet per batch) must stop being charged the spin:
    /// this is the QUIC-handshake / interactive case.
    #[test]
    fn batcher_goes_quiet_when_sparse() {
        let mut b = Batcher::default();
        assert!(!b.should_wait(), "should not wait before any evidence");
        b.record(1);
        assert!(!b.should_wait(), "a lone packet means sparse; do not spin");
        b.record(1);
        assert!(!b.should_wait());
    }

    /// A busy source flips back to waiting, so bulk transfers keep amortising.
    #[test]
    fn batcher_waits_when_busy() {
        let mut b = Batcher::default();
        b.record(BATCH_MAX);
        assert!(b.should_wait());
        // Still busy after a merely decent batch.
        b.record(3);
        assert!(b.should_wait());
        // One idle batch is enough to release interactive traffic again.
        b.record(1);
        assert!(!b.should_wait());
    }

    /// An empty batch (nothing read) must not be treated as evidence either
    /// way, or a paused stream would flip state spuriously.
    #[test]
    fn batcher_ignores_empty_batch() {
        let mut b = Batcher::default();
        b.record(BATCH_MAX);
        assert!(b.should_wait());
        b.record(0);
        assert!(b.should_wait(), "empty batch must not clear busy");
    }
}
