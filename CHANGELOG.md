# Changelog

## Unreleased

Initial experimental interface: SHA-256 one-shot/incremental hashing, strict
hexadecimal encoding/decoding and pure detached Ed25519 verification through
system libsodium. Caller-owned bounded state, overlap rejection and unchanged
state/output on every failure. Linux x86-64 validation only.

Includes public JIT/native/debug regressions, independent hashing/signature
oracles, GCC/Clang sanitizers, seeded fuzzing and reproducible benchmarks.
