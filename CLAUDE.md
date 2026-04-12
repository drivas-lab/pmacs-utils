# pmacs-vpn -- Claude Code Project Guide

## Release Process

Releases are fully automated via GitHub Actions (`.github/workflows/ci.yml`).

**Steps to release:**

1. Bump version in `Cargo.toml` (line 3)
2. Commit: `git commit -am "Bump version to X.Y.Z"`
3. Push: `git push` (triggers CI: quality gate + multi-platform build)
4. Tag: `git tag vX.Y.Z && git push --tags` (triggers release stage)

The release stage builds binaries for Windows, macOS (Intel + ARM), and Linux, then creates a GitHub release with auto-generated notes and attached binaries.

**Version convention:** Semantic versioning. Patch bump for bug fixes and hardening. Minor bump for new features. Check existing tags with `git tag -l`.

**Quality gate:** `./scripts/quality-gate.sh` runs formatting, compilation, clippy, and tests. CI runs this automatically; no need to run locally before push unless you want early feedback.

## Testing

```bash
cargo test -- --test-threads=1    # full suite (singleton tests need serial execution)
cargo test --test hardening_acceptance -- --test-threads=1  # acceptance tests only
cargo test --lib                  # unit tests only
```

Singleton tests use the production Windows named mutex / Unix flock. They will fail if a tray instance is running.

## Architecture

- `src/lib.rs` -- crate root, module exports
- `src/main.rs` -- CLI entry point, tray mode, daemon spawning
- `src/singleton.rs` -- single-instance enforcement (Win32 mutex / flock)
- `src/connection_phase.rs` -- ConnectionPhase state machine for tray controller
- `src/gp/` -- GlobalProtect protocol (auth, tunnel, packets)
- `src/ipc/` -- IPC between tray and daemon (named pipes / Unix sockets)
- `src/vpn/` -- routing and hosts file management
- `src/tray.rs` -- system tray UI
- `src/platform/` -- cross-platform routing abstractions
- `scripts/*.ps1` -- Windows helper scripts
- `scripts/*.sh` -- Linux/macOS helper scripts
- `tests/` -- integration/acceptance tests

## Key Patterns

- **Tray state machine:** `PhaseTracker` (Arc<Mutex<ConnectionPhase>>) shared between command handler thread and health monitor async task. All state transitions use CAS (`transition()`) to prevent races.
- **Singleton:** Platform-native lock held for tray process lifetime. Guard is RAII -- dropped on exit.
- **Daemon lifecycle:** Parent authenticates, spawns child with token. Child does IPC pre-flight check before starting server.
