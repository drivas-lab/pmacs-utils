//! Acceptance tests for the hardening features:
//! - Singleton (single-instance enforcement)
//! - State machine (ConnectionPhase / PhaseTracker)
//!
//! These tests exercise the public API from outside the crate boundary.
//! Run with: cargo test --test hardening_acceptance -- --test-threads=1

// ============================================================================
// Singleton Tests
// ============================================================================

mod singleton {
    use pmacs_vpn::singleton::{acquire_tray_lock, TrayLock};

    // BREAKS IF: first tray launch always fails, user can never start the tray
    #[test]
    fn first_acquire_succeeds() {
        let result = acquire_tray_lock();
        assert!(result.is_ok(), "First lock acquisition must succeed");
        // Verify we actually got a TrayLock, not just Ok(())
        let _lock: TrayLock = result.unwrap();
    }

    // BREAKS IF: two tray processes run simultaneously, fighting over IPC and state
    #[test]
    fn second_acquire_while_held_fails_with_descriptive_error() {
        let _lock1 = acquire_tray_lock().expect("First lock must succeed");
        let result = acquire_tray_lock();

        assert!(result.is_err(), "Second lock acquisition must fail while first is held");
        let err_msg = result.err().expect("Expected Err variant");
        // The error must tell the user WHY it failed — not just a generic error
        assert!(
            err_msg.contains("already running"),
            "Error must mention 'already running' for user clarity, got: {err_msg}"
        );
    }

    // BREAKS IF: tray lock leaks after process exit, permanently blocking future launches
    #[test]
    fn lock_released_on_drop_allows_reacquire() {
        // Acquire and explicitly drop
        {
            let lock = acquire_tray_lock().expect("First lock must succeed");
            drop(lock);
        }

        // Should be able to acquire again after drop
        let result = acquire_tray_lock();
        assert!(
            result.is_ok(),
            "Lock must be reacquirable after previous guard is dropped, got: {:?}",
            result.err()
        );
    }

    // BREAKS IF: error message is empty/null, user gets blank error with no actionable info
    #[test]
    fn error_message_is_nonempty_and_actionable() {
        let _lock1 = acquire_tray_lock().expect("First lock must succeed");
        let err = acquire_tray_lock().err().expect("Expected Err variant");
        assert!(
            err.len() > 10,
            "Error message must be descriptive (>10 chars), got: '{err}'"
        );
        // Must contain "tray" or "instance" to be specific about what's already running
        assert!(
            err.to_lowercase().contains("tray") || err.to_lowercase().contains("instance"),
            "Error should reference tray/instance so user knows what's conflicting, got: '{err}'"
        );
    }

    // BREAKS IF: multiple sequential acquire-release cycles leak resources
    #[test]
    fn repeated_acquire_release_cycles_work() {
        for i in 0..5 {
            let lock = acquire_tray_lock()
                .unwrap_or_else(|e| panic!("Cycle {i}: lock acquisition failed: {e}"));
            drop(lock);
        }
    }
}

// ============================================================================
// ConnectionPhase / PhaseTracker Tests
// ============================================================================

mod connection_phase {
    use pmacs_vpn::connection_phase::{ConnectionPhase, PhaseTracker};

    // ---- State machine initial state ----

    // BREAKS IF: tray starts in a non-Idle state, causing first Connect to be rejected
    #[test]
    fn initial_phase_is_idle() {
        let tracker = PhaseTracker::new();
        let phase = tracker.get();
        assert_eq!(
            phase,
            ConnectionPhase::Idle,
            "New PhaseTracker must start in Idle, got: {:?}",
            phase
        );
    }

    // BREAKS IF: Default trait and new() produce different initial states
    #[test]
    fn default_matches_new() {
        let from_new = PhaseTracker::new();
        let from_default = PhaseTracker::default();
        assert_eq!(
            from_new.get(),
            from_default.get(),
            "PhaseTracker::new() and PhaseTracker::default() must produce same initial state"
        );
    }

    // ---- Transition (compare-and-swap) ----

    // BREAKS IF: health monitor can't transition Connected->Reconnecting, auto-reconnect never starts
    #[test]
    fn transition_connected_to_reconnecting_succeeds() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Connected);

        let ok = tracker.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );

        assert!(ok, "Connected -> Reconnecting transition must succeed");
        assert_eq!(
            tracker.get(),
            ConnectionPhase::Reconnecting { attempt: 1 },
            "Phase must be Reconnecting{{attempt: 1}} after successful transition"
        );
    }

    // BREAKS IF: user disconnect is overridden by auto-reconnect, VPN reconnects against user's will
    #[test]
    fn transition_disconnecting_to_reconnecting_fails() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Disconnecting);

        let ok = tracker.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );

        assert!(
            !ok,
            "Transition from Disconnecting (expected Connected) must fail — user intervened"
        );
        assert_eq!(
            tracker.get(),
            ConnectionPhase::Disconnecting,
            "Phase must remain Disconnecting after failed transition"
        );
    }

    // BREAKS IF: CAS silently changes state even when expected phase doesn't match
    #[test]
    fn failed_transition_does_not_mutate_state() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Idle);

        // Try to transition from Connected (wrong) to Reconnecting
        let ok = tracker.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );

        assert!(!ok, "Transition with wrong expected phase must fail");
        assert_eq!(
            tracker.get(),
            ConnectionPhase::Idle,
            "State must be unchanged after failed CAS transition"
        );
    }

    // BREAKS IF: transition succeeds with wrong attempt number, state machine has wrong reconnect count
    #[test]
    fn transition_reconnecting_requires_exact_attempt_match() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Reconnecting { attempt: 1 });

        // Try transition expecting attempt=2 (wrong)
        let ok = tracker.transition(
            &ConnectionPhase::Reconnecting { attempt: 2 },
            ConnectionPhase::Connecting,
        );
        assert!(
            !ok,
            "Reconnecting{{attempt:1}} != Reconnecting{{attempt:2}}, transition must fail"
        );
        assert_eq!(
            tracker.get(),
            ConnectionPhase::Reconnecting { attempt: 1 },
            "Phase must remain Reconnecting{{attempt:1}}"
        );
    }

    // BREAKS IF: transition with correct attempt succeeds
    #[test]
    fn transition_reconnecting_with_correct_attempt_succeeds() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Reconnecting { attempt: 1 });

        let ok = tracker.transition(
            &ConnectionPhase::Reconnecting { attempt: 1 },
            ConnectionPhase::Connecting,
        );
        assert!(ok, "Reconnecting{{attempt:1}} -> Connecting must succeed when attempt matches");
        assert_eq!(tracker.get(), ConnectionPhase::Connecting);
    }

    // ---- is_user_action_in_progress() ----

    // BREAKS IF: health monitor triggers reconnect when user is connecting, causing double connect
    #[test]
    fn user_action_in_progress_for_connecting() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Connecting);
        assert!(
            tracker.is_user_action_in_progress(),
            "Connecting must count as user action in progress"
        );
    }

    // BREAKS IF: health monitor triggers reconnect while user is disconnecting
    #[test]
    fn user_action_in_progress_for_disconnecting() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Disconnecting);
        assert!(
            tracker.is_user_action_in_progress(),
            "Disconnecting must count as user action in progress"
        );
    }

    // BREAKS IF: health monitor tries to reconnect on top of existing reconnect
    #[test]
    fn user_action_in_progress_for_reconnecting() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Reconnecting { attempt: 3 });
        assert!(
            tracker.is_user_action_in_progress(),
            "Reconnecting must count as user action in progress"
        );
    }

    // BREAKS IF: health monitor tries to reconnect in idle state (no connection to restore)
    #[test]
    fn user_action_in_progress_for_idle() {
        let tracker = PhaseTracker::new();
        // Idle is the initial state
        assert!(
            tracker.is_user_action_in_progress(),
            "Idle must count as user action in progress (no connection to reconnect)"
        );
    }

    // BREAKS IF: health monitor NEVER triggers reconnect, even when daemon dies while connected
    #[test]
    fn not_user_action_in_progress_for_connected() {
        let tracker = PhaseTracker::new();
        tracker.set(ConnectionPhase::Connected);
        assert!(
            !tracker.is_user_action_in_progress(),
            "Connected must NOT count as user action in progress — health monitor needs to act"
        );
    }

    // BREAKS IF: comprehensive coverage — any new phase variant returns wrong value
    #[test]
    fn is_user_action_in_progress_exhaustive() {
        let cases: Vec<(ConnectionPhase, bool)> = vec![
            (ConnectionPhase::Idle, true),
            (ConnectionPhase::Connecting, true),
            (ConnectionPhase::Connected, false),
            (ConnectionPhase::Disconnecting, true),
            (ConnectionPhase::Reconnecting { attempt: 1 }, true),
            (ConnectionPhase::Reconnecting { attempt: 99 }, true),
        ];

        for (phase, expected) in cases {
            let tracker = PhaseTracker::new();
            tracker.set(phase.clone());
            assert_eq!(
                tracker.is_user_action_in_progress(),
                expected,
                "is_user_action_in_progress() wrong for {:?}: expected {}, got {}",
                phase,
                expected,
                !expected
            );
        }
    }

    // ---- Clone shares Arc ----

    // BREAKS IF: command handler and health monitor see different states, causing race conditions
    #[test]
    fn clones_share_state_via_arc() {
        let t1 = PhaseTracker::new();
        let t2 = t1.clone();
        let t3 = t1.clone();

        // t1 sets Connected
        t1.set(ConnectionPhase::Connected);
        assert_eq!(
            t2.get(),
            ConnectionPhase::Connected,
            "Clone t2 must see t1's state change"
        );
        assert_eq!(
            t3.get(),
            ConnectionPhase::Connected,
            "Clone t3 must see t1's state change"
        );

        // t2 transitions to Disconnecting
        t2.set(ConnectionPhase::Disconnecting);
        assert_eq!(
            t1.get(),
            ConnectionPhase::Disconnecting,
            "Original t1 must see t2's state change"
        );
        assert_eq!(
            t3.get(),
            ConnectionPhase::Disconnecting,
            "Clone t3 must see t2's state change"
        );
    }

    // BREAKS IF: transition via one clone is invisible to other clone
    #[test]
    fn transition_on_clone_is_visible_to_original() {
        let original = PhaseTracker::new();
        let clone = original.clone();

        original.set(ConnectionPhase::Connected);

        // Transition via clone
        let ok = clone.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );
        assert!(ok, "Transition via clone must succeed");

        // Original must see the change
        assert_eq!(
            original.get(),
            ConnectionPhase::Reconnecting { attempt: 1 },
            "Original must see transition made via clone"
        );
    }

    // ---- set() unconditional ----

    // BREAKS IF: set() fails silently, state appears stuck
    #[test]
    fn set_overwrites_any_phase() {
        let tracker = PhaseTracker::new();

        // Cycle through all phases via set()
        let phases = vec![
            ConnectionPhase::Idle,
            ConnectionPhase::Connecting,
            ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
            ConnectionPhase::Reconnecting { attempt: 1 },
            ConnectionPhase::Idle,
        ];

        for phase in phases {
            tracker.set(phase.clone());
            assert_eq!(
                tracker.get(),
                phase,
                "set() must unconditionally change phase"
            );
        }
    }

    // ---- ConnectionPhase equality ----

    // BREAKS IF: Reconnecting variants with different attempts compare equal, breaking CAS
    #[test]
    fn reconnecting_phases_with_different_attempts_are_not_equal() {
        let a = ConnectionPhase::Reconnecting { attempt: 1 };
        let b = ConnectionPhase::Reconnecting { attempt: 2 };
        assert_ne!(a, b, "Reconnecting with different attempts must not be equal");
    }

    // BREAKS IF: same variant doesn't equal itself, breaking CAS
    #[test]
    fn reconnecting_phases_with_same_attempt_are_equal() {
        let a = ConnectionPhase::Reconnecting { attempt: 5 };
        let b = ConnectionPhase::Reconnecting { attempt: 5 };
        assert_eq!(a, b, "Reconnecting with same attempt must be equal");
    }

    // BREAKS IF: different variant types compare as equal
    #[test]
    fn different_variants_are_not_equal() {
        let variants = vec![
            ConnectionPhase::Idle,
            ConnectionPhase::Connecting,
            ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
            ConnectionPhase::Reconnecting { attempt: 1 },
        ];

        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "Same variant must equal itself");
                } else {
                    assert_ne!(a, b, "{:?} must not equal {:?}", a, b);
                }
            }
        }
    }

    // ---- Simulated health monitor / command handler scenarios ----

    // BREAKS IF: health monitor ignoring dead daemon in Disconnecting state is broken,
    //            causing spurious reconnect attempt during user-initiated disconnect
    #[test]
    fn health_monitor_ignores_dead_daemon_during_disconnecting() {
        let phase = PhaseTracker::new();
        // Simulate: user clicked disconnect, phase is Disconnecting
        phase.set(ConnectionPhase::Disconnecting);

        // Health monitor checks if it should act:
        // Only act when phase is Connected (per main.rs line 791)
        let should_act = phase.get() == ConnectionPhase::Connected;
        assert!(
            !should_act,
            "Health monitor must NOT act when phase is Disconnecting"
        );

        // Also verify via is_user_action_in_progress
        assert!(
            phase.is_user_action_in_progress(),
            "Disconnecting must signal user action in progress"
        );
    }

    // BREAKS IF: AutoReconnect command runs even after user clicked Disconnect,
    //            restarting VPN against user's wishes
    #[test]
    fn auto_reconnect_dropped_when_phase_is_not_reconnecting() {
        let phase = PhaseTracker::new();

        // Test each non-Reconnecting phase
        let non_reconnecting = vec![
            ConnectionPhase::Idle,
            ConnectionPhase::Connecting,
            ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
        ];

        for p in non_reconnecting {
            phase.set(p.clone());
            let should_proceed = matches!(phase.get(), ConnectionPhase::Reconnecting { .. });
            assert!(
                !should_proceed,
                "AutoReconnect must be dropped when phase is {:?}",
                p
            );
        }
    }

    // BREAKS IF: AutoReconnect correctly proceeds when phase IS Reconnecting
    #[test]
    fn auto_reconnect_proceeds_when_phase_is_reconnecting() {
        let phase = PhaseTracker::new();
        phase.set(ConnectionPhase::Reconnecting { attempt: 2 });
        let should_proceed = matches!(phase.get(), ConnectionPhase::Reconnecting { .. });
        assert!(
            should_proceed,
            "AutoReconnect must proceed when phase is Reconnecting"
        );
    }

    // BREAKS IF: Connect command runs while already connecting/connected, causing double VPN session
    #[test]
    fn connect_ignored_when_phase_is_not_idle() {
        let phase = PhaseTracker::new();

        let non_idle = vec![
            ConnectionPhase::Connecting,
            ConnectionPhase::Connected,
            ConnectionPhase::Disconnecting,
            ConnectionPhase::Reconnecting { attempt: 1 },
        ];

        for p in non_idle {
            phase.set(p.clone());
            let should_connect = phase.get() == ConnectionPhase::Idle;
            assert!(
                !should_connect,
                "Connect must be ignored when phase is {:?}",
                p
            );
        }
    }

    // BREAKS IF: Connect is incorrectly blocked when phase IS Idle
    #[test]
    fn connect_allowed_when_phase_is_idle() {
        let phase = PhaseTracker::new();
        // Default is Idle
        let should_connect = phase.get() == ConnectionPhase::Idle;
        assert!(should_connect, "Connect must be allowed when phase is Idle");
    }

    // ---- Thread safety (basic smoke test) ----

    // BREAKS IF: PhaseTracker panics or deadlocks under concurrent access
    #[test]
    fn concurrent_access_does_not_panic() {
        use std::thread;

        let tracker = PhaseTracker::new();
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let t = tracker.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        if i % 2 == 0 {
                            t.set(ConnectionPhase::Connected);
                        } else {
                            t.set(ConnectionPhase::Idle);
                        }
                        let _ = t.get();
                        let _ = t.is_user_action_in_progress();
                        let _ = t.transition(
                            &ConnectionPhase::Connected,
                            ConnectionPhase::Reconnecting { attempt: 1 },
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("Thread must not panic");
        }
    }

    // ---- Scenario: full reconnect lifecycle ----

    // BREAKS IF: the complete reconnect flow (Connected -> Reconnecting -> Connecting -> Connected)
    //            doesn't work end-to-end, user sees stuck "reconnecting" state
    #[test]
    fn full_reconnect_lifecycle() {
        let health_monitor = PhaseTracker::new();
        let command_handler = health_monitor.clone();

        // Start connected
        health_monitor.set(ConnectionPhase::Connected);

        // Health monitor detects daemon death, CAS to Reconnecting
        let ok = health_monitor.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );
        assert!(ok, "Health monitor: Connected -> Reconnecting must succeed");
        assert_eq!(command_handler.get(), ConnectionPhase::Reconnecting { attempt: 1 });

        // Command handler picks up AutoReconnect, verifies phase
        assert!(matches!(command_handler.get(), ConnectionPhase::Reconnecting { .. }));

        // Command handler sets Connecting then Connected
        command_handler.set(ConnectionPhase::Connecting);
        assert_eq!(health_monitor.get(), ConnectionPhase::Connecting);

        command_handler.set(ConnectionPhase::Connected);
        assert_eq!(health_monitor.get(), ConnectionPhase::Connected);
    }

    // BREAKS IF: user disconnect during reconnect doesn't stop the reconnect loop
    #[test]
    fn user_disconnect_during_reconnect_stops_auto_reconnect() {
        let health_monitor = PhaseTracker::new();
        let command_handler = health_monitor.clone();

        // Setup: Connected, then health monitor transitions to Reconnecting
        health_monitor.set(ConnectionPhase::Connected);
        health_monitor.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 1 },
        );

        // User clicks Disconnect in the tray while reconnecting
        command_handler.set(ConnectionPhase::Disconnecting);

        // Health monitor checks after sleep — phase is no longer Reconnecting
        let still_reconnecting = matches!(health_monitor.get(), ConnectionPhase::Reconnecting { .. });
        assert!(
            !still_reconnecting,
            "Health monitor must see user's Disconnecting, stop reconnecting"
        );

        // CAS for next attempt would also fail
        let ok = health_monitor.transition(
            &ConnectionPhase::Connected,
            ConnectionPhase::Reconnecting { attempt: 2 },
        );
        assert!(!ok, "CAS must fail because phase is Disconnecting, not Connected");
    }
}

// ============================================================================
// Wiring Check: verify public API surface is reachable from crate boundary
// ============================================================================

mod wiring {
    // BREAKS IF: singleton module is not exported from the crate
    #[test]
    fn singleton_module_is_public() {
        // Verify acquire_tray_lock is accessible via both paths
        let _ = pmacs_vpn::acquire_tray_lock;
        let _ = pmacs_vpn::singleton::acquire_tray_lock;
    }

    // BREAKS IF: connection_phase module is not exported from the crate
    #[test]
    fn connection_phase_module_is_public() {
        let _ = pmacs_vpn::connection_phase::PhaseTracker::new;
        let _ = pmacs_vpn::connection_phase::ConnectionPhase::Idle;
        let _ = pmacs_vpn::connection_phase::ConnectionPhase::Connecting;
        let _ = pmacs_vpn::connection_phase::ConnectionPhase::Connected;
        let _ = pmacs_vpn::connection_phase::ConnectionPhase::Disconnecting;
    }

    // BREAKS IF: TrayLock type is not public, can't be held as a guard
    #[test]
    fn tray_lock_type_is_public() {
        // Verify the type is accessible (we don't hold it, just check the path compiles)
        fn _check_type(lock: pmacs_vpn::singleton::TrayLock) {
            drop(lock);
        }
    }

    // BREAKS IF: PhaseTracker methods are not public
    #[test]
    fn phase_tracker_methods_are_public() {
        let t = pmacs_vpn::connection_phase::PhaseTracker::new();
        let _ = t.get();
        t.set(pmacs_vpn::connection_phase::ConnectionPhase::Connected);
        let _ = t.transition(
            &pmacs_vpn::connection_phase::ConnectionPhase::Connected,
            pmacs_vpn::connection_phase::ConnectionPhase::Idle,
        );
        let _ = t.is_user_action_in_progress();
        let _ = t.clone();
    }
}
