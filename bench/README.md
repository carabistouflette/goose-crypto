# Performance measurements

From the repository root, after `make setup` and native source fingerprint refresh:

```sh
python3 bench/measure.py --goose .toolchain/goose/build/goose --cc gcc --iterations 1000 --samples 5
```

The default output `.build/bench.json` is ignored. For a reviewable result, copy
that file to `bench/results/<date>/raw.json` after source edits have settled and
retain the measured commit. The script rejects source changes during the run.
It records HEAD, dirty status, a content fingerprint and per-file hashes, full
build commands, compiler and Goose versions, pinned compiler revision, libsodium
version, binary hashes, CPU model, OS and scheduling affinity. A dirty measurement
is explicitly labeled; it does not identify an uncommitted tree as a clean commit.
Only files considered source by Git (including untracked nonignored files) enter
the fingerprint. Generated binaries, compiler checkouts and ignored outputs do not.

`bench.goose` measures the public interface; `direct.c` measures the same fixtures
through system libsodium. Each process first checks SHA-256 of `abc` and the
signature corpus is RFC 8032 section 7.1 test 1. Hash fixture bytes are `i % 251`.
Every timed operation checks status and consumes digest bytes or verification
results. SHA-256 digest equality and hex round trips are checked outside timing.
Initialization, one discarded warmup process per implementation, allocation,
source compilation, and process launch are excluded from reported batch timings.
Successful signature verification includes repeated calls after backend startup.

One-shot SHA-256 sizes are 0, 32, 64, 1,024 and 65,536 bytes. Incremental cases hash
1,024 bytes in one-byte chunks and 65,536 bytes in 64-byte and 4,096-byte chunks.
They include init, every update and finish per message in both implementations.
The one-byte case uses the smaller message deliberately to bound harness runtime.
Hex encode/decode use 32- and 1,024-byte decoded messages and have no direct baseline.
Signature cases use an empty message with a valid signature, a same-sized invalid
signature (bit 0 flipped), and a 63-byte wrong-length signature. Malformed-length timing is public-only: libsodium has no length parameter and
an invariant C length check can be hoisted outside the loop. Goose hex decoding validates before writing and traverses input twice.

The script alternates implementation order between paired samples. It preserves
unsorted sample order, total elapsed nanoseconds, iteration counts, checksums and
raw stdout. The clock is monotonic (`os::clock_ns` / `CLOCK_MONOTONIC`); per-call
values are derived from whole-batch durations. A fresh compiler wrapper forces `-O2 -UNDEBUG` for generated Goose/runtime C and
the native CMake adapter, overriding CMake Release defaults. Exact compiler
invocations, selected build environment and executable linkage are recorded.
Direct C uses `-O2` with assertions enabled. Native
adapter validation, initialization guards and state serialization remain part of
public-call costs. Direct C omits Goose/native seam checks and state serialization.
These are wrapper-overhead observations, not independent cryptographic algorithms.
No CPU pinning, frequency control, process isolation or cache flushing is imposed.
Shared-host load and thermal state can dominate small differences. Very short
rejection cases can be compiler optimized and need enough iterations to measure.
CI should smoke-test execution only, never enforce timing thresholds or rankings.
