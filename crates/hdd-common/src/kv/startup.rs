//! Startup refusal of T-0562 step 7: the in-process store is one process's memory, so it cannot serve a hosted deployment that
//! runs more than one service process.

use crate::profile::env::KvBackend;
use crate::profile::types::RuntimeProfile;

use super::{KvError, KvResult};

/// How many service processes are registered (proxy, dns, api, worker, ... each count once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRegistry {
    /// Registered service processes.
    pub processes: usize,
}

/// Refuse `memory` with `hosted` when more than one service process is registered.
pub fn startup_check(
    backend: KvBackend,
    runtime: RuntimeProfile,
    services: ServiceRegistry,
) -> KvResult<()> {
    if backend == KvBackend::Memory && runtime == RuntimeProfile::Hosted && services.processes > 1 {
        return Err(KvError::MemoryBackendRefused(format!(
            "HDD_KV_BACKEND=memory is refused in the hosted profile with {} service processes: each process would see its own copy of bans, limits and sessions. Set HDD_KV_BACKEND=redis (ERR-HOSTING-001).",
            services.processes
        )));
    }
    Ok(())
}
