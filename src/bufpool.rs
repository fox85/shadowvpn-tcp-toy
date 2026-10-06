//! Zero-copy buffer pool for the data plane.
//!
//! ## Why this exists
//!
//! The relay loops move every packet through several owned buffers: the reader
//! does `buf[..n].to_vec()`, decryption allocates a fresh `Vec`, and (on the
//! send path) obfuscation allocates another one. That is **up to five
//! allocations plus five copies per packet**, and at 500 Mbit/s of 1400-byte
//! frames the data plane handles on the order of 90,000 packets/s in both
//! directions combined.
//!
//! This module removes them by recycling a fixed set of buffers instead of
//! allocating per packet. A [`Buf`] is a window (`len`) into a pooled
//! allocation; when it is dropped the allocation goes back to the pool.
//!
//! ## Why the length is tracked separately
//!
//! The obvious implementation — `truncate(n)` after reading, `resize(cap, 0)`
//! before the next read — re-zeroes the tail on every reuse, turning the
//! "optimisation" into a memset of up to 64 KiB per packet. So the backing
//! `Vec` keeps its full length and [`Buf`] carries the valid prefix length.
//! Reuse is then genuinely free.

use std::ops::Deref;
use std::sync::{Arc, Mutex};

/// A recycled packet buffer: `data[..len]` is the live packet.
///
/// Sending one through a channel moves it — no copy. Dropping it returns the
/// allocation to the originating [`BufPool`].
pub struct Buf {
    data: Option<Vec<u8>>,
    len: usize,
    pool: Arc<BufPool>,
}

impl Buf {
    /// Capacity of the backing allocation, i.e. the largest packet that fits.
    pub fn capacity(&self) -> usize {
        self.data.as_ref().map_or(0, |v| v.len())
    }

    /// The whole backing allocation as a mutable slice, for filling by a read.
    ///
    /// Valid bytes are then declared with [`Buf::set_len`].
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut().expect("buf is live").as_mut_slice()
    }

    /// Declare the first `n` bytes valid. Panics if `n` exceeds the capacity.
    pub fn set_len(&mut self, n: usize) {
        assert!(n <= self.capacity(), "buf len {n} exceeds capacity");
        self.len = n;
    }

    /// The live packet as a mutable slice, for in-place rewriting (NAT).
    pub fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.data.as_mut().expect("buf is live")[..len]
    }

    /// Take the allocation out of the pool permanently.
    ///
    /// Used when a buffer has to escape the data plane (for example a packet
    /// handed to code that keeps it); it will not be recycled.
    pub fn detach(mut self) -> Vec<u8> {
        let mut v = self.data.take().expect("buf is live");
        v.truncate(self.len);
        v
    }
}

impl Deref for Buf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.data {
            Some(v) => &v[..self.len],
            None => &[],
        }
    }
}

impl AsRef<[u8]> for Buf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        if let Some(v) = self.data.take() {
            self.pool.put(v);
        }
    }
}

/// A shared pool of recycled packet buffers.
///
/// Clone the `Arc` across tasks; buffers return to the pool they came from
/// regardless of which task drops them.
pub struct BufPool {
    free: Mutex<Vec<Vec<u8>>>,
    cap: usize,
    /// Upper bound on retained buffers, so a burst cannot grow memory
    /// without limit — excess allocations are simply dropped to the allocator.
    high: usize,
    created: std::sync::atomic::AtomicUsize,
}

impl BufPool {
    /// Create a pool whose buffers each hold `cap` bytes, pre-allocating
    /// `prealloc` of them and retaining at most `high` on return.
    pub fn new(cap: usize, prealloc: usize, high: usize) -> Arc<Self> {
        let cap = cap.max(1);
        let mut free = Vec::with_capacity(prealloc);
        for _ in 0..prealloc {
            free.push(vec![0u8; cap]);
        }
        Arc::new(Self {
            free: Mutex::new(free),
            cap,
            high: high.max(prealloc),
            created: std::sync::atomic::AtomicUsize::new(prealloc),
        })
    }

    /// Take a buffer, recycling one or allocating a new one if the pool is dry.
    pub fn take(self: &Arc<Self>) -> Buf {
        let data = match self.free.lock().unwrap().pop() {
            Some(v) => v,
            None => {
                self.created
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                vec![0u8; self.cap]
            }
        };
        Buf {
            data: Some(data),
            len: 0,
            pool: Arc::clone(self),
        }
    }

    /// How many buffers this pool has ever allocated. Falls back to a plain
    /// allocation only while the pool is undersized; if it keeps climbing, the
    /// pool is too small for the concurrency.
    pub fn allocated(&self) -> usize {
        self.created.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn put(&self, v: Vec<u8>) {
        // A buffer that grew past the pool's size (an over-large packet) is not
        // worth keeping: retaining it would let one big packet inflate the
        // pool's memory for the rest of the run.
        if v.len() > self.cap {
            return;
        }
        let mut free = self.free.lock().unwrap();
        if free.len() < self.high {
            free.push(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_are_recycled_not_reallocated() {
        let pool = BufPool::new(64, 2, 4);
        let base = pool.allocated();

        for i in 0..50 {
            let mut b = pool.take();
            b.as_mut_slice()[0] = i;
            b.set_len(1);
            assert_eq!(&*b, &[i]);
        }
        // Every take/drop cycle reused a buffer: no new allocations.
        assert_eq!(pool.allocated(), base);
    }

    #[test]
    fn length_is_a_window_not_a_resize() {
        let pool = BufPool::new(8, 1, 1);
        let mut b = pool.take();
        assert_eq!(b.capacity(), 8);
        b.as_mut_slice()[..3].copy_from_slice(b"abc");
        b.set_len(3);
        assert_eq!(&*b, b"abc");
        // Backing allocation keeps its full length across reuse.
        b.set_len(8);
        assert_eq!(b.capacity(), 8);
    }

    #[test]
    fn capacity_matches_the_request() {
        let pool = BufPool::new(1500, 1, 1);
        assert_eq!(pool.take().capacity(), 1500);
    }

    #[test]
    fn detach_returns_just_the_valid_prefix() {
        let pool = BufPool::new(16, 1, 1);
        let mut b = pool.take();
        b.as_mut_slice()[..4].copy_from_slice(b"wxyz");
        b.set_len(4);
        assert_eq!(b.detach(), b"wxyz".to_vec());
    }
}
