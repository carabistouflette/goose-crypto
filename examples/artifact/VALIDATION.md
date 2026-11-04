# Artifact consumer validation — 2026-11-04

Validated example implementation: `7cd52c6b6385ed80396e26f3608c79c5c7e129fd`.
Result records were added afterward without changing consumer/harness code.

All 22 real loopback HTTPS cases passed with GCC release, GCC ASan/UBSan and
Clang ASan/UBSan. [Raw logs, compiler commands and fingerprints](results/2026-11-04/provenance.json)
record the source, binaries, backend versions and generated/native compiler flags.
The source pin and full claims are independent of later hosted CI.

The suite covers successful extraction; altered metadata/wrong keys; malformed
signature/key hex; caller URL mismatch/non-HTTPS; signed invalid JSON, unknown
fields and duplicate digest; invalid/short digest; metadata cap; wrong artifact
digest; traversal archive; existing destination; HTTP status/redirect; body/header
caps; and production rejection of the untrusted fixture certificate.

Failures require exactly exit 1 and the expected stage diagnostic, not merely
nonzero exit. Assertions count requests and destination writes, preserve existing
sentinels and verify successful file bytes. A shim error or crash cannot stand in
for a policy rejection. Two independent production/design reviews and a final
harness review reported no remaining findings after this check was strengthened.

Sanitizer compiler transcripts show generated Goose/runtime C and native C/C++
adapters, including goose-json's accelerated.cpp, compiled with trailing
`-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined`. The production TLS
rejection binary is separately release-built without fixture CA injection.
System libraries were not rebuilt with sanitizers. Clang++ preserves its invoked
name so C++ runtime linkage remains correct. GCC/Clang compiler wrappers have
separate identities including their paths, versions and binary fingerprints.

This is finite regression coverage, not proof of a complete secure updater. See
[README.md](README.md) for buffering, deadlines, partial extraction and caller
trust/freshness/rollback/authorization responsibilities. No performance claim is
made for the composed example. No external artifact service is contacted by the
integration tests; pinned source fetching during build does require network access.
