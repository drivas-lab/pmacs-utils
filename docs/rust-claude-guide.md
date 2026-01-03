# Rust Development with Claude Code

Source: [claude-flow Rust template](https://github.com/ruvnet/claude-flow/wiki/CLAUDE-MD-Rust)

## Core Principle

**Batch all Rust operations in single messages.** Cargo builds, tests, and checks should run together, not sequentially.

## Best Practices

### Memory Safety
- Understand borrowing and lifetimes
- Use `Result` and `Option` for error handling
- Prefer safe code over `unsafe`

### Tooling
- `rustfmt` - code formatting
- `clippy` - linting with `--deny warnings`
- `cargo audit` - security vulnerability scanning
- `cargo deny` - dependency policy enforcement

### Testing
- Unit tests inline with `#[cfg(test)]`
- Integration tests in `tests/`
- Property-based testing with `proptest`
- Benchmarks with `criterion`

### CI/CD
```yaml
# Example GitHub Actions
- cargo fmt --check
- cargo clippy --deny warnings
- cargo test
- cargo audit
```

## Project Structure

```
src/
├── main.rs          # Binary entry point
├── lib.rs           # Library root (if dual-purpose)
├── config.rs        # Configuration handling
├── platform/
│   ├── mod.rs
│   ├── mac.rs       # macOS-specific code
│   ├── linux.rs
│   └── windows.rs
└── vpn/
    ├── mod.rs
    ├── routing.rs   # Route table manipulation
    └── hosts.rs     # /etc/hosts management
```

## Cross-Compilation

```bash
# Add targets
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu

# Build for Windows
cargo build --release --target x86_64-pc-windows-gnu

# Build for Linux
cargo build --release --target x86_64-unknown-linux-gnu
```

## Useful Crates (for our project)

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `tokio` | Async runtime |
| `trust-dns-resolver` | DNS lookups |
| `nix` | Unix system calls (routes, etc.) |
| `windows` | Windows API bindings |
| `serde` + `toml` | Config file parsing |
| `thiserror` | Error handling |
| `tracing` | Logging/diagnostics |
