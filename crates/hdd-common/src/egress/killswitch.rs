//! The kill switch (section 2.3, T-0009 step 5): a file whose existence aborts every long-running tool.
//!
//! The switch is latched: once the file has been seen the switch stays tripped for the life of the process, so removing the
//! file in a hurry does not silently resume a test. Tools call [`KillSwitch::check`] (it re-reads the file at most every poll
//! interval) or await [`KillSwitch::tripped`] with the optional background poller; either way they stop within the poll
//! interval, which defaults to 100 ms, well inside the one-second requirement.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Default poll interval.
pub const DEFAULT_POLL: Duration = Duration::from_millis(100);

/// Returned when the kill switch is tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aborted;

impl fmt::Display for Aborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aborted: kill-switch file present")
    }
}

impl std::error::Error for Aborted {}

struct Inner {
    path: PathBuf,
    tripped: AtomicBool,
    notify: Notify,
    started: Instant,
    last_check_ms: AtomicU64,
    poll_ms: u64,
}

/// A cheap handle to the kill switch; clones share state.
#[derive(Clone)]
pub struct KillSwitch {
    inner: Arc<Inner>,
}

/// The conventional location on servers (section 2.3).
pub const UNIX_DEFAULT_PATH: &str = "/var/run/hdd-acceptance.stop";

impl KillSwitch {
    /// A switch watching `path`, re-reading it at most every `poll` interval.
    pub fn new(path: impl Into<PathBuf>, poll: Duration) -> Self {
        KillSwitch {
            inner: Arc::new(Inner {
                path: path.into(),
                tripped: AtomicBool::new(false),
                notify: Notify::new(),
                started: Instant::now(),
                last_check_ms: AtomicU64::new(0),
                poll_ms: u64::try_from(poll.as_millis()).unwrap_or(100).max(1),
            }),
        }
    }

    /// The default path: `/var/run/hdd-acceptance.stop` on Unix, `hdd-acceptance.stop` in the temp directory elsewhere.
    pub fn default_path() -> PathBuf {
        if cfg!(unix) {
            PathBuf::from(UNIX_DEFAULT_PATH)
        } else {
            std::env::temp_dir().join("hdd-acceptance.stop")
        }
    }

    /// The watched path.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.inner.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Look at the file now and latch if it exists.
    pub fn poll_now(&self) -> bool {
        // fail closed: only "not found" means "not set"; a file that cannot be examined (permissions, I/O error) trips the switch
        match std::fs::metadata(&self.inner.path) {
            Ok(_) => self.trip(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => self.trip(),
        }
        self.inner
            .last_check_ms
            .store(self.now_ms().saturating_add(1), Ordering::Relaxed);
        self.is_tripped()
    }

    fn trip(&self) {
        if !self.inner.tripped.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    /// True when the switch has been tripped (does not touch the file system).
    pub fn is_tripped(&self) -> bool {
        self.inner.tripped.load(Ordering::SeqCst)
    }

    /// Err(`Aborted`) when tripped. Re-reads the file when the last read is older than the poll interval, so a tool that
    /// never starts the poller still stops within one interval.
    pub fn check(&self) -> Result<(), Aborted> {
        if self.is_tripped() {
            return Err(Aborted);
        }
        let last = self.inner.last_check_ms.load(Ordering::Relaxed);
        let now = self.now_ms();
        if last == 0 || now.saturating_sub(last.saturating_sub(1)) >= self.inner.poll_ms {
            self.poll_now();
        }
        if self.is_tripped() {
            Err(Aborted)
        } else {
            Ok(())
        }
    }

    /// Resolves when the switch trips (immediately if it already has). It watches the file itself every poll interval, so a
    /// caller does not need to start the background poller for the one-second guarantee to hold.
    pub async fn tripped(&self) {
        let every = Duration::from_millis(self.inner.poll_ms);
        loop {
            let waiter = self.inner.notify.notified();
            tokio::pin!(waiter);
            // register interest before re-checking, so a trip between the check and the await is not missed
            waiter.as_mut().enable();
            if self.is_tripped() || self.poll_now() {
                return;
            }
            let _ = tokio::time::timeout(every, waiter).await;
        }
    }

    /// Start a background task that polls the file every `interval`. Abort the returned handle to stop it.
    pub fn spawn_poller(&self, interval: Duration) -> JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                if me.poll_now() {
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hdd-killswitch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir.join("stop")
    }

    #[test]
    fn a_blocking_tool_aborts_within_one_second_of_the_file_appearing() {
        let path = temp_path("sync");
        let ks = KillSwitch::new(&path, DEFAULT_POLL);
        let toucher_path = path.clone();
        let started = Instant::now();
        let toucher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            std::fs::write(&toucher_path, b"stop").expect("touch");
            Instant::now()
        });
        let mut iterations = 0u64;
        let outcome = loop {
            if let Err(a) = ks.check() {
                break a;
            }
            iterations += 1;
            std::thread::sleep(Duration::from_millis(10));
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "tool was never aborted"
            );
        };
        let touched_at = toucher.join().expect("thread");
        let latency = Instant::now().saturating_duration_since(touched_at);
        assert_eq!(outcome, Aborted);
        assert!(
            iterations > 5,
            "the tool really ran before the file appeared"
        );
        assert!(
            latency < Duration::from_secs(1),
            "aborted {latency:?} after the file appeared"
        );
    }

    #[tokio::test]
    async fn an_async_tool_with_the_poller_aborts_within_one_second() {
        let path = temp_path("async");
        let ks = KillSwitch::new(&path, DEFAULT_POLL);
        let poller = ks.spawn_poller(Duration::from_millis(50));
        let tool = {
            let ks = ks.clone();
            tokio::spawn(async move {
                let mut work = 0u64;
                loop {
                    tokio::select! {
                        () = ks.tripped() => return (work, Instant::now()),
                        () = tokio::time::sleep(Duration::from_millis(20)) => work += 1,
                    }
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(250)).await;
        let touched_at = Instant::now();
        std::fs::write(&path, b"stop").expect("touch");
        let (work, stopped_at) = tokio::time::timeout(Duration::from_secs(1), tool)
            .await
            .expect("aborted within one second")
            .expect("task");
        assert!(work > 3, "the tool really ran");
        assert!(stopped_at.saturating_duration_since(touched_at) < Duration::from_secs(1));
        poller.abort();
    }

    #[test]
    fn the_switch_latches_even_if_the_file_is_removed() {
        let path = temp_path("latch");
        let ks = KillSwitch::new(&path, Duration::from_millis(1));
        assert!(ks.check().is_ok());
        std::fs::write(&path, b"x").expect("touch");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(ks.check(), Err(Aborted));
        std::fs::remove_file(&path).expect("remove");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            ks.check(),
            Err(Aborted),
            "removing the file does not resume a stopped tool"
        );
    }

    #[tokio::test]
    async fn tripped_watches_the_file_without_a_background_poller() {
        let path = temp_path("nopoller");
        let ks = KillSwitch::new(&path, Duration::from_millis(50));
        let waiter = {
            let ks = ks.clone();
            tokio::spawn(async move {
                ks.tripped().await;
                Instant::now()
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let touched = Instant::now();
        std::fs::write(&path, b"stop").expect("touch");
        let stopped = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("tripped within one second")
            .expect("task");
        assert!(stopped.saturating_duration_since(touched) < Duration::from_secs(1));
    }

    #[test]
    fn a_path_that_cannot_be_examined_trips_the_switch() {
        // a NUL byte in the path makes the metadata call fail with an error that is not NotFound on every platform
        let ks = KillSwitch::new("bad\0path", Duration::from_millis(1));
        assert!(ks.poll_now(), "an unreadable switch path fails closed");
        let missing = KillSwitch::new(temp_path("missing"), Duration::from_millis(1));
        assert!(
            !missing.poll_now(),
            "a missing file simply means the switch is not set"
        );
    }

    #[tokio::test]
    async fn tripped_resolves_immediately_when_already_set() {
        let path = temp_path("already");
        std::fs::write(&path, b"x").expect("touch");
        let ks = KillSwitch::new(&path, DEFAULT_POLL);
        assert!(ks.poll_now());
        tokio::time::timeout(Duration::from_millis(100), ks.tripped())
            .await
            .expect("immediate");
    }

    #[test]
    fn default_path_is_the_conventional_one_on_unix() {
        if cfg!(unix) {
            assert_eq!(KillSwitch::default_path(), PathBuf::from(UNIX_DEFAULT_PATH));
        } else {
            assert!(KillSwitch::default_path().ends_with("hdd-acceptance.stop"));
        }
    }
}
