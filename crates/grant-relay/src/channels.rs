//! The channel accounts and which of them is in use.
//!
//! A request holds a [`Lease`] on one channel from before its transaction is
//! built until the transaction settles (included, or past its validity
//! window). Dropping the lease frees the channel, so every early return frees
//! it. While a channel is leased no other request builds a transaction from
//! it, which is what makes reading its sequence number from the ledger at
//! lease time correct.

use std::sync::{Arc, Mutex, PoisonError};

/// The channel accounts, by Ed25519 public key.
pub struct ChannelPool {
    channels: Vec<[u8; 32]>,
    state: Mutex<PoolState>,
}

struct PoolState {
    busy: Vec<bool>,
    /// Where the next search for a free channel starts, so load spreads over
    /// the channels.
    next: usize,
}

impl ChannelPool {
    #[must_use]
    pub fn new(channels: Vec<[u8; 32]>) -> Arc<Self> {
        let busy = vec![false; channels.len()];
        Arc::new(Self {
            channels,
            state: Mutex::new(PoolState { busy, next: 0 }),
        })
    }

    /// Lease a free channel, or `None` when every channel is in use.
    #[must_use]
    pub fn lease(self: &Arc<Self>) -> Option<Lease> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let n = self.channels.len();
        let start = state.next;
        let index = (0..n).map(|i| (start + i) % n).find(|&i| !state.busy[i])?;
        state.busy[index] = true;
        state.next = (index + 1) % n;
        Some(Lease {
            pool: Arc::clone(self),
            index,
        })
    }

    /// How many channels are leased.
    #[must_use]
    pub fn in_use(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.busy.iter().filter(|b| **b).count()
    }

    /// Every channel's public key.
    #[must_use]
    pub fn channels(&self) -> &[[u8; 32]] {
        &self.channels
    }
}

/// Exclusive use of one channel until dropped.
pub struct Lease {
    pool: Arc<ChannelPool>,
    index: usize,
}

impl Lease {
    /// The leased channel's public key.
    #[must_use]
    pub fn account(&self) -> [u8; 32] {
        self.pool.channels[self.index]
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.busy[self.index] = false;
    }
}
