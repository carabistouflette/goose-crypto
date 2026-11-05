# Documentation and source check

## Released core and current main

The core prerelease alpha.1 is immutable at
`a4643f62bd5e76b371054c6537a95169a7930101`. The published main used for this
audit is `b0deb95f6e7fe82aa1e38fad8ca24d69c6a31c7d`; it adds the buffered
artifact and streaming download examples. This docs update changes no executable
source, dependency pin or test. It moves no tag.

README, API/design, security, contributing/setup, notices, changelog, benchmark
guides and both examples' README/design/validation pages were checked. Detailed
historical validation stays separate from current setup instructions.

## Example checks

The exact README quickstart ran successfully and printed the documented SHA-256.
`make check` passed. Both documented GCC integration commands passed all 22
buffered-artifact and all 61 streaming-download cases on the documentation
working tree. No executable source was changed for these checks.
The exact README import pins released a464. Example implementations/imports use
published main's immutable HTTP/FS/JSON/archive identities. The production CLI
invocations are templates requiring independently trusted signatures/keys/URLs;
the documented integration commands generate complete signed loopback fixtures.

The buffered example's old 22-case record predates the mixed-C++ sanitizer-link
fix. It remains historical. Current published main's artifact workflow
[41931999228](https://github.com/carabistouflette/goose-crypto/actions/runs/41931999228)
passed the current release/GCC/Clang matrices. The streaming example's eleven
code/harness files match recorded `8a6b653d6d4a338cd3eac3ff04acfa29ee4ba3a2`;
published main's workflow
[41931998894](https://github.com/carabistouflette/goose-crypto/actions/runs/41931998894)
also passed. Records keep their actual source/compiler identities.

## Benchmark currentness

The recorded primitive benchmark measured clean
`fc3ba768dd4d00fc8592873810ffe4f1be722564`. All 23 recorded core/native/build,
benchmark, example-hash and test source files match that commit, released a464,
published main b0deb95 and this checkout byte for byte. This includes
`crypto.goose`, `crypto.build`, `CMakeLists.txt`, `GOOSE_REVISION`, all three native
files, `bench/bench.goose`, `bench/direct.c` and `bench/measure.py`.
Recorded Goose and GCC executable SHA-256 values still match the available
binaries. The system libsodium version matches recorded 1.0.22, but no backend
binary hash was recorded. Version equality does not establish identical builds.

The raw wrapper/direct measurements remain historical observations for their
recorded backend/toolchain. We make no current-host numerical speed claim and
no algorithm-ranking claim: both paths call libsodium. An end-to-end download
throughput benchmark is N/A: these examples demonstrate authentication,
publication and failure handling, with no useful claimed transport-speed win.
Their RSS samples are observations, not hard memory ceilings or a benchmark
advertisement. No new measurement was needed for these documentation claims.

Measured environment: Intel Core Ultra 7 258V, Linux 7.2.11-arch1-1 x86-64,
glibc 2.44, Goose eadca409f68210893f366e60d0c2f0dc29a339be / runtime 3025e5810379,
GCC 16.2.1 20260810, libsodium 1.0.22. See [bench/README.md](../bench/README.md)
for workloads, ns/call units, warmups, five paired samples, compiler flags,
raw data and sample ranges. It explains checks included only in the wrapper and
shared-host/no-isolation limits. Historical raw samples are unchanged.

Check relevant source matches from a full clone:

```sh
git diff --exit-code fc3ba768dd4d00fc8592873810ffe4f1be722564 HEAD -- \
  crypto.goose crypto.build CMakeLists.txt GOOSE_REVISION native \
  bench/bench.goose bench/direct.c bench/measure.py
```
