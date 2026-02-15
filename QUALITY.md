# Quality Guardrails

This document defines the baseline quality bar for local development and PRs.

## Principles

1. Behavioral parity first:
   - Tray actions (`Connect`, `Disconnect`, `Reconnect`, `Exit`) must remain consistent across Windows and macOS.
   - Platform differences must be explicit and documented.
2. Least surprise startup behavior:
   - Login auto-start launches tray only.
   - Login auto-start does not auto-connect.
3. Privilege UX:
   - macOS should prompt for admin only on one-time privileged setup/update paths.
   - Routine tray operations should avoid repeated password prompts.
4. Safety over convenience:
   - Favor explicit errors + diagnostics over silent fallback.
   - Keep cleanup paths idempotent.

## Required Checks

Run before pushing:

```bash
./scripts/quality-gate.sh
```

Fast pre-commit variant:

```bash
./scripts/quality-gate.sh --quick
```

Optional (host-dependent) Windows cross checks:

```bash
PMACS_ENABLE_WINDOWS_CROSS_CHECKS=1 ./scripts/quality-gate.sh --quick
```

## Release Behavior Invariants

1. Tray startup:
   - Manual tray launch can auto-connect when configured.
   - Login/autostart launch never auto-connects.
2. macOS privileged connect:
   - First connect after install/update may prompt to install/update LaunchDaemon.
   - Subsequent connects should run without repeated admin prompts.
3. IPC ownership (macOS):
   - Root daemon must expose IPC socket ownership to tray user.
   - Tray disconnect/status actions must work after daemon start.

## Change Hygiene

1. Keep formatting-only changes in separate commits.
2. Keep platform behavior changes and docs in the same PR/commit set.
3. Include explicit verification notes in commit/PR description:
   - commands run
   - pass/fail summary
   - known environment limitations
