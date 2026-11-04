# Changelog

## Unreleased

Optional verified streaming download example: pinned HTTP/FS composition,
bounded incremental hashing and writes, cooperative SIGINT/SIGTERM cleanup,
checked synchronization and no-replace publication. Separate real-TLS integration
and GCC/Clang sanitizer checks cover cancellation and publication failures.

## 0.1.0-alpha.1 — 2026-11-04

Initial experimental interface: SHA-256 one-shot/incremental hashing, strict
hexadecimal encoding/decoding and pure detached Ed25519 verification through
system libsodium. Caller-owned bounded state, overlap rejection and unchanged
state/output on every failure. Linux x86-64 validation only.

Includes public JIT/native/debug regressions, independent hashing/signature
oracles, GCC/Clang sanitizers, seeded fuzzing and reproducible benchmarks.
