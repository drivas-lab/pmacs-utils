//! Connection state machine for tray controller.
//!
//! Replaces the ad-hoc `USER_DISCONNECT_IN_PROGRESS` AtomicBool and
//! `was_connected` bool with a proper state machine shared between
//! the command handler thread and health monitor async task.

use std::sync::{Arc, Mutex};

/// Current phase of the VPN connection lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionPhase {
    /// No connection active or pending.
    Idle,
    /// Connection attempt in progress.
    Connecting,
    /// Connected and healthy.
    Connected,
    /// User-initiated disconnect in progress.
    Disconnecting,
    /// Auto-reconnect in progress after unexpected disconnect.
    Reconnecting { attempt: u32 },
}

/// Thread-safe handle to the connection phase.
#[derive(Clone)]
pub struct PhaseTracker {
    phase: Arc<Mutex<ConnectionPhase>>,
}

impl PhaseTracker {
    pub fn new() -> Self {
        Self {
            phase: Arc::new(Mutex::new(ConnectionPhase::Idle)),
        }
    }

    /// Get current phase (cloned).
    /// Recovers from mutex poisoning (a prior thread panicked while holding the lock).
    pub fn get(&self) -> ConnectionPhase {
        self.phase.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Set phase unconditionally.
    pub fn set(&self, new: ConnectionPhase) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = new;
    }

    /// Compare-and-swap: set to `new` only if current phase matches `expected`.
    /// Returns true if swap succeeded.
    pub fn transition(&self, expected: &ConnectionPhase, new: ConnectionPhase) -> bool {
        let mut guard = self.phase.lock().unwrap_or_else(|e| e.into_inner());
        if *guard == *expected {
            *guard = new;
            true
        } else {
            false
        }
    }

    /// Returns true if the current phase is one that should prevent
    /// the health monitor from triggering a reconnect.
    pub fn is_user_action_in_progress(&self) -> bool {
        matches!(
            self.get(),
            ConnectionPhase::Idle
                | ConnectionPhase::Connecting
                | ConnectionPhase::Disconnecting
                | ConnectionPhase::Reconnecting { .. }
        )
    }
}

impl Default for PhaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_phase_is_idle() {
        let tracker = PhaseTracker::new();
        assert_eq!(tracker.get(), ConnectionPhase::Idle);
    }

    #[test]
    fn test_set_and_get() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Connected);
        assert_eq!(tracker.get(), ConnectionPhase::Connected);
    }

    #[test]
    fn test_transition_succeeds_on_match() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Connected);
        let ok = tracker.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
        );
        assert!(ok);
        assert_eq!(tracker.get(), ConnectionPhase::Disconnecting);
    }

    #[test]
    fn test_transition_fails_on_mismatch() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Idle);
        let ok = tracker.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
        );
        assert!(!ok);
        assert_eq!(tracker.get(), ConnectionPhase::Idle);
    }

    #[test]
    fn test_reconnecting_equality() {
        let a = ConnectionPhase::Reconnecting { attempt: 1 };
        let b = ConnectionPhase::Reconnecting { attempt: 1 };
        assert_eq!(a, b);

        let c = ConnectionPhase::Reconnecting { attempt: 2 };
        assert_ne!(a, c);
    }

    #[test]
    fn test_is_user_action_in_progress() {
        let tracker = PhaseTracker::new();

        // Idle — health monitor should not reconnect
        assert!(tracker.is_user_action_in_progress());

        // Connected — health monitor CAN reconnect
        tracker.set(ConnectionPhase::Connected);
        assert!(!tracker.is_user_action_in_progress());

        // Disconnecting — health monitor should not reconnect
        tracker.set(ConnectionPhase::Disconnecting);
        assert!(tracker.is_user_action_in_progress());
    }

    #[test]
    fn test_clone_is_independent() {
        let t1 = PhaseTracker::new();
        let t2 = t1.clone();
        t1.set(ConnectionPhase::Connected);
        // t2 shares the Arc, so it should see the change
        assert_eq!(t2.get(), ConnectionPhase::Connected);
    }
}
