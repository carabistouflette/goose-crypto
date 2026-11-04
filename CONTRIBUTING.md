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
