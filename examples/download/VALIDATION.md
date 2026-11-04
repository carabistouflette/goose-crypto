# Streaming download validation — 2026-11-05

Validated implementation and harness:
`8a6b653d6d4a338cd3eac3ff04acfa29ee4ba3a2`, with a clean working tree.
This record and raw results were added afterward without changing executable
sources. Hosted CI checks the PR independently.

All 61 scenarios passed in each configuration:

- [GCC release](results/2026-11-05/release.json)
- [GCC ASan/UBSan](results/2026-11-05/gcc-sanitize.json)
- [Clang ASan/UBSan](results/2026-11-05/clang-sanitize.json)

The records include every source-file hash, the exact source commit and declared
public dependency pins, compiler and Goose binary hashes/versions, backend version
metadata, per-invocation compiler commands, consumer binary hashes and individual
scenario diagnostics. Inputs and binaries were checked again after execution.
Backend version strings cannot detect a same-version library replacement.

Environment: Linux x86-64/glibc, GCC 16.2.1, Clang 23.1.4, libsodium 1.0.22,
libcurl 8.23.0. Goose pin `eadca409f68210893f366e60d0c2f0dc29a339be`.
HTTP pin `aa915a0b21db1129f85e6e339a6f0171bcac0e77` and FS pin
`cd0bd29c78c435caaebf75bfecd8e3e2083636eb` are public, owner-approved sources.
Tests ran with affinity 0,1,2,5,6,7 to avoid other owners' measured work. No timing
or performance ranking is claimed; child RSS samples are observations only.

Coverage includes large/empty/tiny-chunk transfers, authenticated input rejection,
existing-name preservation, body/header limits, production TLS rejection,
truncation and abortive TCP reset with matching signed prefix digests,
SIGINT/SIGTERM at headers/body and publication boundaries, short/zero writes,
ENOSPC, failed creation inspection, sync and consumed-close failures, cleanup
failures, and NotAttempted/Applied/Unknown publication outcomes.

The successful-transfer fixture withholds the final byte until the harness sees
the staged prefix and confirms final-name absence. The reset fixture waits until
all signed prefix bytes are staged before aborting TCP. Exact exit codes, stages,
request counts, final bytes and residue policy are asserted. Surviving-process
digest/write failure loops each execute 20 iterations after warmup and preserve
the descriptor baseline; process exit cannot hide leaked handles.

The signal guard's native tests pass in release and both sanitizer configurations,
including real/repeated signals, partial handler installation and restoration
failures. Sanitizers instrument generated Goose/runtime C and native C/C++
adapters; C++ vptr instrumentation and mixed C-driver final linkage have a separate
preflight. The production TLS binary is release-built without the fixture shim.
Installed system libraries are outside sanitizer instrumentation.

[Core regression log](results/2026-11-05/core.log): `make format check test` passed,
including public JIT/debug/native checks, independent hashing/signature oracles,
ownership regressions and injected native backend failures. Final independent
security and test-quality reviews found no remaining blocking defects. Reviews
corrected canonical filename handling, transfer barriers and result provenance.

This is finite Linux regression coverage under the private-parent/no-other-writers
and nonaliasing-name assumptions. It does not establish crash cleanup, hard wall
deadlines, universal filesystem durability or application trust/freshness policy.
The immutable core release tag and parent registration are unchanged.
