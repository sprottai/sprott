//! Retry timers for connect work a run leaves behind.
//!
//! Two jobs can be left unfinished with nothing else to bring them back (no
//! write happens, so no sync event fires for them):
//! - [`Job::CodeExchange`]: an OAuth code exchange that failed transiently
//!   (network, provider 5xx, rate limit). Retried until the code's plausible
//!   lifetime runs out, then the connection is marked failed
//!   (`connect::CODE_EXCHANGE_WINDOW`).
//! - [`Job::RotationStore`]: a provider-rotated refresh token the vault store
//!   could not take (an environmental failure: the store unreadable or not
//!   writable). The session keeps using it meanwhile.
//!
//! Each job owns a per-vault timer with capped backoff (5 s, 15 s, 45 s, 2 min,
//! then every 5 min), independent of sync: a retry never pulls, because no
//! pull resolves either failure. One timer per (vault, job) at most; a run
//! that leaves nothing settles the job, so the next failure starts at 5 s.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

/// The wait before each attempt, by attempt number; the last repeats.
pub(crate) const BACKOFF: [Duration; 5] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(45),
    Duration::from_secs(120),
    Duration::from_secs(300),
];

/// The wait before attempt `attempt` (0-based) (pure).
pub(crate) fn backoff(attempt: u32) -> Duration {
    BACKOFF[(attempt as usize).min(BACKOFF.len() - 1)]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Job {
    CodeExchange,
    RotationStore,
}

#[derive(Debug, Default, Clone, Copy)]
struct Entry {
    /// Attempts already made by this job's timer.
    attempt: u32,
    /// A timer is waiting to fire.
    armed: bool,
}

/// One vault's retry state (lives on its runtime).
#[derive(Debug, Default)]
pub struct Retries {
    jobs: HashMap<Job, Entry>,
}

impl Retries {
    /// Arm `job`'s next attempt: the wait for a timer to start now, or `None`
    /// when one is already waiting.
    pub fn arm(&mut self, job: Job) -> Option<Duration> {
        let e = self.jobs.entry(job).or_default();
        if e.armed {
            return None;
        }
        e.armed = true;
        Some(backoff(e.attempt))
    }

    /// The timer fired: one more attempt is under way.
    pub fn fired(&mut self, job: Job) {
        if let Some(e) = self.jobs.get_mut(&job) {
            e.armed = false;
            e.attempt = e.attempt.saturating_add(1);
        }
    }

    /// Nothing is left for `job`: forget its attempts.
    pub fn settle(&mut self, job: Job) {
        self.jobs.remove(&job);
    }

    /// Is a timer waiting for `job`?
    pub fn armed(&self, job: Job) -> bool {
        self.jobs.get(&job).is_some_and(|e| e.armed)
    }
}

/// Make sure a timer is waiting to retry `job` for `vault` (no-op when one
/// already is, the vault has no runtime, or no async runtime is running).
pub(crate) fn schedule(state: &Arc<AppState>, vault: &str, job: Job) {
    let Some(runtime) = state.runtime_if_present(vault) else {
        return;
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let Some(delay) = runtime.retries.lock().unwrap().arm(job) else {
        return;
    };
    tracing::debug!(vault = %vault, ?job, wait_secs = delay.as_secs(), "connect retry armed");
    let state = state.clone();
    let vault = vault.to_string();
    handle.spawn(async move {
        tokio::time::sleep(delay).await;
        // A vault torn down meanwhile has nothing left to retry.
        let Some(runtime) = state.runtime_if_present(&vault) else {
            return;
        };
        runtime.retries.lock().unwrap().fired(job);
        drop(runtime);
        match job {
            // The whole connect pass: it re-arms or settles this job itself.
            Job::CodeExchange => {
                crate::auth::connect::process_vault_connects(&state, &vault, None).await;
            }
            Job::RotationStore => {
                crate::auth::connect::retry_pending_rotations(&state, &vault).await;
            }
        }
    });
}

/// `job` has nothing left for `vault`.
pub(crate) fn settle(state: &AppState, vault: &str, job: Job) {
    if let Some(runtime) = state.runtime_if_present(vault) {
        runtime.retries.lock().unwrap().settle(job);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_caps() {
        let secs: Vec<u64> = (0..8).map(|a| backoff(a).as_secs()).collect();
        assert_eq!(secs, vec![5, 15, 45, 120, 300, 300, 300, 300]);
    }

    #[test]
    fn one_timer_per_job_and_settle_starts_over() {
        let mut r = Retries::default();
        assert_eq!(r.arm(Job::CodeExchange), Some(Duration::from_secs(5)));
        // Already waiting: no second timer.
        assert_eq!(r.arm(Job::CodeExchange), None);
        assert!(r.armed(Job::CodeExchange));
        // Jobs are independent.
        assert_eq!(r.arm(Job::RotationStore), Some(Duration::from_secs(5)));
        // Each fired attempt backs the next one off.
        r.fired(Job::CodeExchange);
        assert!(!r.armed(Job::CodeExchange));
        assert_eq!(r.arm(Job::CodeExchange), Some(Duration::from_secs(15)));
        r.fired(Job::CodeExchange);
        assert_eq!(r.arm(Job::CodeExchange), Some(Duration::from_secs(45)));
        // Drained: the next failure starts at 5 s again.
        r.settle(Job::CodeExchange);
        assert!(!r.armed(Job::CodeExchange));
        assert_eq!(r.arm(Job::CodeExchange), Some(Duration::from_secs(5)));
        assert!(r.armed(Job::RotationStore));
    }
}
