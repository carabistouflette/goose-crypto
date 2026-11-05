# Crypto wrapper measurements

The committed results measure the public Goose wrapper against direct calls to
the same libsodium backend, not competing cryptographic algorithms.
[The source check](../docs/AUDIT.md) covers unchanged core/benchmark code.
They are historical observations for the recorded toolchain/backend, not
current-host speed or a library ranking. The backend version was recorded,
but its binary was not hashed; matching version strings alone cannot prove
identical backend builds. There is no end-to-end crypto or download speed claim here. These observations
are not asserted to be timings for another backend build.

Recorded environment: Intel Core Ultra 7 258V, Linux 7.2.11-arch1-1 x86-64,
glibc 2.44, GCC 16.2.1 20260810, libsodium 1.0.22, Goose
`eadca409f68210893f366e60d0c2f0dc29a339be` (runtime `3025e5810379`).
The raw record contains compiler binary hashes and actual commands.

From a clean repository checkout after `make setup`:

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
raw stdout. The clock is monotonic (`clock_ns()` / `CLOCK_MONOTONIC`); per-call
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

## Inspect all sample ranges without rerunning

From the repository root, this prints every recorded case in ns/call. Each group
contains five retained samples; the minimum/maximum show the full observed range,
not a confidence interval or filtered result. Public-only cases have no direct
libsodium comparison.

```sh
python3 - <<'PYRANGES'
import json, statistics
from collections import defaultdict
from pathlib import Path
groups = defaultdict(list)
record = json.loads(Path("bench/results/2026-11-04/raw.json").read_text())
for sample in record["samples"]:
    for row in sample["rows"]:
        key = (sample["implementation"], row["fixture"], row["bytes"],
               row["chunk_or_signature_bytes"])
        groups[key].append(row["ns_per_call"])
for key, values in sorted(groups.items()):
    print(key, "n=", len(values), "median/min/max ns/call=",
          statistics.median(values), min(values), max(values))
PYRANGES
```

Run new measurements only in a finite coordinated window, keeping the source,
tools, backend and protocol frozen. A new output belongs to its actual source
and does not replace these historical samples.
