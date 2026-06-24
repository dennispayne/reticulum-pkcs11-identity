# Developer Documentation

This directory contains technical documentation for developers and maintainers.

## Architecture & Design

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Architecture documentation
  - Core interception points (RNS.Identity.from_file)
  - Provider detection and prioritization
  - Token discovery
  - The single hardware identity model (shared across apps via RNS aspects)
  - Pin caching and token monitoring
  - Cross-node identity discovery
  - Design decisions and rationale

> The opt-in multi-identity / per-app-slot machinery is experimental and lives
> under `reticulum_pkcs11_identity.experimental`. It is disabled by default.

## Integration

- **[INTEGRATION.md](INTEGRATION.md)** — Path for integrating into mainline Reticulum
  - Current standalone approach
  - Proposed mainline integration
  - Minimal core changes needed
  - API additions and backward compatibility
  - Long-term vision

## For Users

User-facing documentation is in [../README.md](../README.md) — information about setup, configuration, and usage for Reticulum app users.
