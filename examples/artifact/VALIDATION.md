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

## Mixed C/C++ sanitizer link regression

Ubuntu's Clang 18 CI exposed missing C++ UBSan virtual-type runtime symbols at
the final Goose C-driver link. Instrumented JSON C++ objects need that runtime;
linking the C++ standard library alone is insufficient. Earlier local Clang 23
runs did not expose it because vptr was not part of their default undefined group.

The harness now explicitly enables C++ vptr instrumentation and requests Clang's
C++ sanitizer runtime plus libstdc++ at sanitized final links. Generated Goose C
remains C and no sanitizer checks are disabled. The flags are documented in the
[Clang 18 command reference](https://releases.llvm.org/18.1.8/tools/clang/docs/ClangCommandLineReference.html#cmdoption-clang-fsanitize-link-c-runtime).

Before the full build, a regression compiles an explicitly vptr-instrumented C++
virtual dispatch object and links it with a C source through the actual fixture
wrappers. It reproduced the same missing symbols before the fix and passes after
it. This catches the failure across compiler versions, independently of their
default sanitizer groups. The complete 22-case suites pass with Clang 23 and
GCC 16 sanitizers, including explicit C++ vptr checks. An independent focused
review approved the fix. Hosted Clang 18 validation is required before merge.
