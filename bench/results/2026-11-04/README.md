# Initial performance record

[raw.json](raw.json) records clean source commit
`fc3ba768dd4d00fc8592873810ffe4f1be722564`, 1,000 iterations per fixture and five
unsorted alternating paired samples. It includes effective compiler commands,
source/binary fingerprints, libsodium/compiler versions and machine provenance.
All matching public/direct checksums agreed.

Reproduce using [bench/README.md](../../README.md). Results distinguish the public
Goose interface from direct calls to the same libsodium backend; they do not
compare independent crypto implementations. Small incremental chunks include
validation and state-copy overhead on every update. Use larger chunks (for
example 4 KiB) when callers can naturally buffer that amount. The public-only
malformed-length path is not a direct crypto baseline. No timing thresholds,
CPU isolation or universal performance claims are implied by this shared-host run.
