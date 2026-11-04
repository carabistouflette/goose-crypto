# Verified streaming download example

This optional Linux command authenticates metadata, streams HTTPS bytes through
SHA-256 into an exclusively created staging file, and publishes verified bytes
with a no-replace rename. It does not buffer the complete artifact, extract it,
install it or execute it. Core goose-crypto remains independent of I/O.

The example pins reviewed public sources: HTTP streaming at
[`aa915a0`](https://github.com/carabistouflette/goose-http/blob/aa915a0b21db1129f85e6e339a6f0171bcac0e77/docs/API.md)
and filesystem retained I/O and checked rename at
[`cd0bd29`](https://github.com/carabistouflette/goose-fs/blob/cd0bd29c78c435caaebf75bfecd8e3e2083636eb/docs/RENAME.md).

## Build and run

Requirements: the pinned Goose compiler, Linux x86-64/glibc, C/C++17 compilers,
CMake, pkg-config, libsodium >=1.0.18, libcurl >=7.85 with TLS and asynchronous DNS.
Ubuntu development packages include `libsodium-dev libcurl4-openssl-dev` plus the
usual Goose build prerequisites. Python cryptography is used only by the tests.

```sh
.toolchain/goose/build/goose build examples/download/main.goose -o .build/download
mkdir -m 700 /absolute/private-parent
.build/download /absolute/metadata.json SIGNATURE_HEX TRUSTED_PUBLIC_KEY_HEX \
  https://authorized-origin.example/artifact.bin /absolute/private-parent \
  staging.part artifact.bin 67108864
```

Arguments are the metadata file, 128-character detached Ed25519 signature,
64-character public key selected through your trust process, exact authorized
HTTPS URL, private parent directory, distinct staging/final leaves and decimal
cumulative byte limit. The limit is 0..1 GiB. Parent and metadata paths must be
strict absolute paths with no symlink components, `.` or `..` components, or
repeated separators. The parent must have no group/other permission bits and no
other writers for the entire operation, including same-UID writers.

Leaf names use canonical lower-case ASCII: `[a-z0-9][a-z0-9._-]*`, at most 255
bytes and no trailing dot. Uppercase, Unicode, tildes and identical names are
rejected. The filesystem must give the two names distinct nonaliasing lookups;
exotic name-aliasing filesystems are outside the contract. This is not confinement
against a hostile same-UID process, a source-inode-pinning rename, or a snapshot.

Metadata is at most 16 KiB and has exactly two fields:

```json
{"url":"https://authorized-origin.example/artifact.bin","sha256":"64 hexadecimal characters"}
```

Sign the exact document bytes, including whitespace and field order. The digest
placeholder above is not a valid test digest. The command verifies the signature
before parsing or making network/file-mutation calls, rejects unknown/duplicate/
missing JSON fields, and requires the signed URL to equal the independently
supplied URL. The supplied key is an application trust anchor; downloading a key
from the artifact origin does not establish trust. Applications still own key
rotation, expiry, freshness, rollback prevention, protocol context, origin/DNS
policy and installation authorization.

## Resource and publication contract

The consumer uses bounded chunks, an incremental SHA-256 state and a retained
regular file. It enforces the cumulative body limit separately from per-call
filesystem writes. Each write is no larger than FS's 1 MiB maximum and must
complete successfully. The HTTP stream uses fixed bounded queues/backpressure,
HTTP/1.1, identity encoding, verified TLS, no redirect, proxy or credentials.
Headers are capped at 16 KiB. Only clean terminal HTTP 200 permits digest use;
an early 200 or a digest matching a truncated transfer does not authorize bytes.

A private 0600 staging regular file is created with CreateNew after checking
absence under the no-other-writers assumption. A failed open can still create an
entry, so possible ownership is tracked even when no File token is returned.
Existing staging and final entries are never reused, truncated or removed.

After terminal success and digest equality, the command checks file-data sync
and closes the File exactly once. It then requests `NoReplace` rename with
checked parent synchronization. A failed close consumes its File token and is
never retried. Cleanup happens on normal return before CLI exit: HTTP handles,
File, Root and Context are explicitly closed, and only owned pre-publication
staging names are candidates for unlink.

Publication and cleanup results remain separate:

- `NotAttempted`: publication did not run; owned staging cleanup is attempted.
- `Applied`: the rename succeeded; later sync/close errors do not roll it back.
- `Unknown`: the syscall was attempted and returned an error; it may have moved
  bytes. Neither namespace entries nor publication are speculatively retried or
  rolled back. This conservative result also covers a raced EEXIST. Verified
  staging may remain, even when the final entry was actually created.

The fixed `download:` diagnostic contains stage, publication, primary errno,
separate cleanup statuses, byte counts, sync result and whether staging may
remain. It does not echo URLs, keys, signatures or untrusted filenames. An unlink
error means residue *may* remain, not proof that it still exists. A published
file can coexist with a nonzero exit: inspect publication/outcome fields.
Successful sync reflects filesystem/kernel promises, not universal crash durability.

## Cancellation

SIGINT and SIGTERM handlers only update a lock-free flag. The caller checks it
before mutation/network setup, between bounded pump steps and before publication;
resource cleanup runs outside the handler. Previous handlers are restored, and
repeated signals follow the same cooperative cleanup path. SIGINT exits 130 and
SIGTERM exits 143 after cleanup when cancellation is observed.

The last check immediately before rename is the publication commitment boundary.
A signal arriving afterward cannot revoke an attempted publication: Applied and
Unknown outcomes are preserved and verified final bytes are never rolled back.
Cancellation is best effort, not SIGKILL/crash/abort-safe. Transfer and connection
budgets and 20 ms pump waits are not hard wall deadlines: DNS cleanup, filesystem
writes, sync and close can wait longer.

## Validation harness

```sh
python3 examples/download/integration.py --goose .toolchain/goose/build/goose --cc gcc
python3 examples/download/integration.py --goose .toolchain/goose/build/goose --cc gcc --sanitize
python3 examples/download/integration.py --goose .toolchain/goose/build/goose --cc clang --sanitize
```

Tests create signed metadata and a real loopback TLS server. Fixture-only compiler
wrappers inject its CA for the exact localhost URL; peer/hostname checks remain
intact. A separate production binary has no injection and rejects that CA. Fault
wrappers are linked only at final Goose program links, never CMake probes or
production. Clang's mixed C/C++ sanitizer-link preflight preserves explicit vptr
checks. Generated Goose/runtime C and native C/C++ adapters are instrumented in
sanitizer runs; separately installed system libraries are not.

The matrix covers large/empty/tiny-chunk success, signature/schema/URL rejection,
HTTP/body/header limits, matching-digest truncated transfers, redirects/TLS,
SIGINT/SIGTERM during headers/body, cancellation before/after the publication
boundary, partial writes/ENOSPC/zero writes, failed post-create fstat, sync/consumed
close failures, unlink failure, and NotAttempted/Applied/Unknown rename outcomes.
Native hooks test late errors with and without actual movement. Exact exits and
stages are required; a crash or fixture exit cannot count as expected rejection.
Existing bytes and staging-residue policy are checked. Surviving-process loops
repeat digest and write failures while asserting stable descriptor counts, so
process exit cannot hide missing cleanup.

The server generates bodies in fixed chunks. Child RSS is sampled for 8 MiB and
64 MiB totals and recorded as observations, not hard process-memory thresholds or
universal performance claims. Results, source/binary fingerprints and compiler
transcripts default to ignored `.build/` outputs. This is regression coverage of
a composition, not certification of a complete secure update protocol.

The successful-transfer gate includes a withheld-last-byte barrier: the fixture
waits until the prefix is written and confirms that no final entry exists before
releasing the last byte. The reset case waits for every signed prefix byte to be
written before an abortive TCP close. Source, compiler and consumer binary hashes
and backend version metadata are checked before and after execution; changes
reject the result rather than attributing observations to a moving tree. Backend
version strings do not detect replacement of a library with the same version.
Compiler transcripts contain only commands issued during that invocation; cached
objects can omit compilation commands.
