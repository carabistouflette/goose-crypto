# Contributing

Keep the interface small, explicit and bounded. Applications own I/O and trust;
system libsodium owns crypto. Never add bespoke crypto or silently substitute
algorithms. Preserve lengths, overlap checks, state lifecycle and atomic failures.

Use focused branches and Conventional Commits with imperative subjects:
`feat: add ...`, `fix: reject ...`, `test: cover ...`, `docs: clarify ...`,
`chore: update ...`. One coherent change per commit. No stable interface promise
before 1.0. Never commit credentials, generated outputs, toolchains or private notes.

Behavior changes require public regressions for malformed input, lifecycle and
aliasing. Run `make format check test` and `git diff --check`. Native changes also
require GCC/Clang `make sanitize public-sanitize` plus `make fuzz`. Request
independent correctness, security and performance reviews; fix findings and keep
CI passing. Compiler upgrades require a full reviewed upstream pin and validation.

Profile before optimizing. Preserve validation and retain raw samples with exact
source/compiler/backend/platform provenance and limitations. CI checks execution,
not timing thresholds. No universal rankings from microbenchmarks. Report
vulnerabilities privately using SECURITY.md.

## Build and test

Use Git, Make, CMake >=3.27, pkg-config, a C/C++20 toolchain, Python >=3.11 with
cryptography, libsodium development headers >=1.0.18, and Clang for sanitizers
and fuzzing. Ubuntu packages:

```sh
sudo apt-get install git build-essential cmake ninja-build pkg-config python3 python3-cryptography libsodium-dev clang
make setup
make check test
make sanitize public-sanitize SANITIZER_CC=gcc
make sanitize public-sanitize SANITIZER_CC=clang
make fuzz
```

`make setup` builds the exact compiler in GOOSE_REVISION. An existing matching
compiler can be selected with `GOOSE=/absolute/path/to/goose`. The optional
examples list their additional HTTP/archive dependencies separately. Benchmark
runs require a clean checkout and a scheduled shared-machine window.
