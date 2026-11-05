# Historical core validation — 2026-11-04

These records keep their original tested identities. See [AUDIT.md](AUDIT.md)
for current/released code matches and checked examples.

Validated implementation: `fc3ba768dd4d00fc8592873810ffe4f1be722564`.
This document and the recorded artifacts were added afterward without changing
production code. This records passing initial local validation; it is not a
hosted CI report. Later publication checks run independently in GitHub Actions.

Environment: Linux x86-64/glibc 2.44, Intel Core Ultra 7 258V, GCC 16.2.1,
Clang 23, libsodium 1.0.22. Goose source pin
`eadca409f68210893f366e60d0c2f0dc29a339be` (binary reports `eadca40`, runtime
`3025e5810379`). The existing matching compiler was selected explicitly with
`GOOSE=/absolute/path/to/goose`; its source checkout was clean at that full pin.
Full benchmark compiler/platform/binary provenance is in
[raw.json](../bench/results/2026-11-04/raw.json).

## Passing checks

- `make format check test`: format/native fingerprint checks, public JIT/debug
  JIT/native/debug-standalone execution, example, independent oracles, caller
  storage reuse, native regression tests and injected backend failures.
- SHA-256 oracle: 1,159 deterministic Python hashlib cases in each of JIT,
  native and debug modes. Includes binary data, padding/block boundaries and
  one million bytes; compares one-shot and varying-chunk incremental results.
- Ed25519 oracle: 400 cases (100 valid, 300 invalid) in each execution mode,
  generated and independently verified by cryptography 50.0.2 / OpenSSL 3.6.5.
  Corpus fingerprint:
  `68592b17ec5bdd9e73b229a4d991ffeaf2e5324bf65c489b3aa66e40e4f4e946`.
  No production signing interface is exposed.
- Native tests: SHA known answers, all binary lengths 0–4097, state lifecycle,
  forks/reset, total-byte limit, malformed/count-corrupted state, overlap and
  pointer-range rejection, output/state atomicity, unaligned storage, protected
  page endpoints, eight-thread first initialization, RFC 8032 signatures,
  message/key/signature mutations, noncanonical scalars/points and small order.
- `make sanitize SANITIZER_CC=gcc` and `clang`: ASan/UBSan native tests plus
  initialization and operation failure injection. Wrappers deliberately scribble
  temporary buffers before returning failure; caller state/output stay unchanged
  and operation retries succeed. Initialization failure is cached process-wide.
- `make public-sanitize SANITIZER_CC=gcc` and `clang`: instrumented generated
  Goose/runtime C and native adapter through a compiler-specific hashed wrapper;
  debug standalone public regressions pass with strict ASan/UBSan settings.
- `make fuzz FUZZ_RUNS=10000`: Clang libFuzzer + ASan/UBSan, seed 491,
  max_len 65536, per-input timeout 5 seconds. Forty nonempty boundary/binary/zero
  seeds from 1–65536 bytes; completed 10,000 runs, 90 coverage counters and 301
  feature counters. These counters describe this build, not percentage coverage.
- Fresh standalone local Git clone at the validated commit:
  `make check test GOOSE=/absolute/path/to/matching/goose` passes independently
  of sibling library sources. Cold compiler bootstrap was not repeated.
- Two independent design reviews and two rounds of two independent code reviews.
  Final reviewers reported no remaining correctness/security/quality findings.
  Reviews corrected overlap assumptions, state sensitivity documentation, native
  range validation consistency and effective benchmark compiler provenance.

Raw [public](../tests/results/2026-11-04/public.log),
[GCC sanitizer](../tests/results/2026-11-04/sanitize-gcc.log),
[Clang sanitizer](../tests/results/2026-11-04/sanitize-clang.log) and
[fuzz](../tests/results/2026-11-04/fuzz.log) logs retain executed commands/results.

## Performance record

The clean validated commit was measured with GCC using 1,000 iterations per
fixture and five alternating paired samples, preserving raw order/checksums.
The recorder forces `-O2 -UNDEBUG` for the public generated C/runtime and native
adapter, capturing exact compiler invocations. Direct libsodium uses `-O2` with
assertions enabled. See [methodology](../bench/README.md) and
[recorded result](../bench/results/2026-11-04/README.md).

## Limits

These finite checks are not a security proof or certification. System libsodium
is trusted and was not rebuilt with sanitizer instrumentation. Fuzzing exercises
the native adapter, not every generated Goose path; public hex has exhaustive
byte-class/position regressions rather than a coverage-guided Goose fuzzer.
The signature oracle covers canonical generated signatures and ordinary
mutations, not every difference between Ed25519 implementations. SHA overflow
checks use synthetic count-consistent state; processing exabytes was not tested.
No Windows/macOS/other-architecture claim. Secure erasure, backend upgrade safety,
trust policy, key discovery and installation authorization remain outside scope.
Backend allocation/OS behavior is not an adapter allocation guarantee.

## Public publication checks — 2026-11-04

Published Apache-2.0 source: [carabistouflette/goose-crypto](https://github.com/carabistouflette/goose-crypto).
Public `main` source `c6774f59f8d5a4e46c247ededd6d9ecdcd5c6502` passed
[hosted CI](https://github.com/carabistouflette/goose-crypto/actions/runs/41897070185),
including cold compiler bootstrap, public-interface tests/oracles, GCC/Clang
native and generated-Goose sanitizer runs, seeded fuzzing and benchmark smoke.

An anonymous HTTPS clone, checked out at the publication-documentation candidate
`26724a8`, independently passed `make check test` with the matching compiler.
An external consumer using the README's full `c6774f5` remote import fetched the
public package and produced the expected SHA-256 of `abc`. Private vulnerability
reporting is enabled. GitHub recognizes the repository's Apache-2.0 license.

Publication review inspected the complete tracked archive (42 files at the
candidate), documented Ubuntu dependency/API compatibility and checked action
pins. No generated compiler state or credentials were found. Release-candidate
checks are separate from the immutable initial-main CI evidence linked above;
the final release notes identify the exact tested head and release commit.
