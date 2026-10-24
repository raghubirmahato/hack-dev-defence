//! `Bus`: publish/subscribe with revisioned messages and gap detection (C18.3, B5.12).
//!
//! Every message of a channel carries a revision that grows by exactly one per publish. A subscriber that sees a revision other
//! than `last + 1`, that falls behind its bounded buffer, or that reconnects gets a [`BusEvent::Resync`] and must reload its
//! state from Postgres immediately instead of waiting for a timer. Buffers are bounded; messages a slow subscriber misses are
//! counted, never queued without limit.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::broadcast;

use super::{KvError, KvResult, check_key, check_value};

/// Why a subscriber must reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncReason {
    /// The subscriber fell behind its buffer and `missed` messages were dropped.
    Lagged {
        /// How many messages it missed.
        missed: u64,
    },
    /// A revision was skipped.
    Gap {
        /// The revision that should have come next.
        expected: u64,
        /// The revision that arrived.
        got: u64,
    },
    /// The connection to the backend was re-established.
    Reconnected,
}

/// What a subscriber receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusEvent {
    /// A message in order.
    Message {
        /// Revision of the channel.
        revision: u64,
        /// The payload.
        payload: Vec<u8>,
    },
    /// Reload now; messages may have been lost.
    Resync(ResyncReason),
    /// The channel was closed (the bus was dropped).
    Closed,
}

/// Publish/subscribe with revisions.
pub trait Bus: Send + Sync {
    /// Publish; returns the revision assigned to the message.
    fn publish(&self, channel: &str, payload: &[u8]) -> impl Future<Output = KvResult<u64>> + Send;
    /// Subscribe to a channel; only messages published afterwards are delivered.
    fn subscribe(&self, channel: &str) -> impl Future<Output = KvResult<Subscription>> + Send;
}

/// A source of `(revision, payload)` pairs for a [`Subscription`].
pub(crate) enum Source {
    Memory(broadcast::Receiver<(u64, Arc<[u8]>)>),
    #[cfg(feature = "redis")]
    Redis(tokio::sync::mpsc::Receiver<super::redis::RawBusMessage>),
}

/// One subscriber.
pub struct Subscription {
    source: Source,
    last: Option<u64>,
    pending: Option<(u64, Vec<u8>)>,
    resyncs: u64,
}

impl Subscription {
    pub(crate) fn new(source: Source) -> Subscription {
        Subscription {
            source,
            last: None,
            pending: None,
            resyncs: 0,
        }
    }

    /// Number of resync signals delivered so far.
    pub fn resyncs(&self) -> u64 {
        self.resyncs
    }

    /// Wait for the next event.
    pub async fn recv(&mut self) -> BusEvent {
        if let Some((revision, payload)) = self.pending.take() {
            return BusEvent::Message { revision, payload };
        }
        let next = match &mut self.source {
            Source::Memory(rx) => match rx.recv().await {
                Ok((rev, payload)) => Next::Message(rev, payload.to_vec()),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    Next::Resync(ResyncReason::Lagged { missed: n })
                }
                Err(broadcast::error::RecvError::Closed) => Next::Closed,
            },
            #[cfg(feature = "redis")]
            Source::Redis(rx) => match rx.recv().await {
                Some(super::redis::RawBusMessage::Message { revision, payload }) => {
                    Next::Message(revision, payload)
                }
                Some(super::redis::RawBusMessage::Reconnected) => {
                    Next::Resync(ResyncReason::Reconnected)
                }
                None => Next::Closed,
            },
        };
        match next {
            Next::Message(rev, payload) => {
                if let Some(last) = self.last
                    && rev != last.wrapping_add(1)
                {
                    self.last = Some(rev);
                    self.pending = Some((rev, payload));
                    self.resyncs += 1;
                    return BusEvent::Resync(ResyncReason::Gap {
                        expected: last.wrapping_add(1),
                        got: rev,
                    });
                }
                self.last = Some(rev);
                BusEvent::Message {
                    revision: rev,
                    payload,
                }
            }
            Next::Resync(reason) => {
                // The baseline is unknown after a lag or a reconnect: the next message sets it.
                self.last = None;
                self.resyncs += 1;
                BusEvent::Resync(reason)
            }
            Next::Closed => BusEvent::Closed,
        }
    }
}

enum Next {
    Message(u64, Vec<u8>),
    Resync(ResyncReason),
    Closed,
}

struct Channel {
    /// Held while the revision is assigned and the message is sent, so the order of revisions is the order of delivery.
    revision: Mutex<u64>,
    tx: broadcast::Sender<(u64, Arc<[u8]>)>,
}

/// The in-process bus.
pub struct MemoryBus {
    channels: Mutex<HashMap<String, Arc<Channel>>>,
    capacity: usize,
    max_channels: usize,
    published: AtomicU64,
}

impl MemoryBus {
    /// A bus with `capacity` buffered messages per subscriber (at least 1) and at most 4,096 channels.
    pub fn new(capacity: usize) -> MemoryBus {
        MemoryBus {
            channels: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
            max_channels: 4096,
            published: AtomicU64::new(0),
        }
    }

    /// Messages published since the bus was created.
    pub fn published_total(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    fn channel(&self, name: &str) -> KvResult<Arc<Channel>> {
        check_key(name)?;
        let mut map = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = map.get(name) {
            return Ok(Arc::clone(c));
        }
        if map.len() >= self.max_channels {
            return Err(KvError::Full);
        }
        let (tx, _) = broadcast::channel(self.capacity);
        let c = Arc::new(Channel {
            revision: Mutex::new(0),
            tx,
        });
        map.insert(name.to_owned(), Arc::clone(&c));
        Ok(c)
    }

    fn send(&self, name: &str, payload: &[u8], force: Option<u64>) -> KvResult<u64> {
        check_value(payload)?;
        let c = self.channel(name)?;
        let mut rev = c.revision.lock().unwrap_or_else(PoisonError::into_inner);
        *rev = force.unwrap_or(rev.wrapping_add(1));
        // Sending fails only when nobody is subscribed; the revision still advances.
        let _ = c.tx.send((*rev, Arc::from(payload)));
        self.published.fetch_add(1, Ordering::Relaxed);
        Ok(*rev)
    }

    /// Publish with an explicit revision, to force a gap (conformance suite and tests only).
    #[cfg(any(test, feature = "conformance"))]
    pub fn publish_with_revision(
        &self,
        name: &str,
        revision: u64,
        payload: &[u8],
    ) -> KvResult<u64> {
        self.send(name, payload, Some(revision))
    }
}

impl Bus for MemoryBus {
    async fn publish(&self, channel: &str, payload: &[u8]) -> KvResult<u64> {
        self.send(channel, payload, None)
    }

    async fn subscribe(&self, channel: &str) -> KvResult<Subscription> {
        let c = self.channel(channel)?;
        Ok(Subscription::new(Source::Memory(c.tx.subscribe())))
    }
}
