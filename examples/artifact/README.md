# Bounded artifact verification example

This optional Linux command composes the public crypto, HTTP, JSON, filesystem
and archive libraries. It downloads and extracts an explicitly authorized archive
after verifying signed metadata and its SHA-256. It never installs or executes
extracted files. External libraries are pinned in main.goose; crypto uses this
checkout. These example-only dependencies do not affect ordinary crypto consumers.

## Build and run

Add system libcurl >=7.85 with TLS/asynchronous DNS/thread-safe initialization,
libarchive >=3.6, zlib >=1.2.11 and a C++17 runtime/compiler to crypto's development
prerequisites. Ubuntu packages: `libcurl4-openssl-dev libarchive-dev zlib1g-dev`.
The pinned compiler fetches public commits during build. Linux x86-64/glibc is
the validated platform.

From the repository root:

```sh
.toolchain/goose/build/goose build examples/artifact/main.goose -o .build/artifact
.build/artifact /absolute/metadata.json SIGNATURE_HEX TRUSTED_KEY_HEX \
  https://your-authorized-origin.example/artifact.tar.gz /absolute/new-directory
```

Supply an already obtained metadata file, 128-character detached Ed25519 signature,
64-character public key selected through your trust process, exact authorized
HTTPS URL, and fresh destination in a parent directory you control. Metadata and
destination paths use strict absolute-path rules: no symlink components, repeated
separators, `.` or `..` components.

Signed metadata contains exactly two fields:

```json
{"url":"https://your-authorized-origin.example/artifact.tar.gz","sha256":"64 hexadecimal characters"}
```

The displayed digest is a placeholder. Sign every byte of the actual document,
including whitespace and field order. Unknown/duplicate/missing fields and invalid
UTF-8 are rejected. Hex accepts upper/lowercase but no whitespace/prefixes.

## Operation order and bounds

1. Validate arguments; read at most 16 KiB of regular-file metadata.
2. Verify its exact original bytes using pure detached Ed25519. Signature
   rejection and backend failure produce distinct errors.
3. Parse authenticated JSON, decode its exact 32-byte digest and require its URL
   to equal the caller-authorized HTTPS URL byte for byte.
4. One GET, no redirects/proxies/credentials. Require HTTP 200; compressed body
   <=4 MiB, header callback bytes <=16 KiB, transfer timeout 5,000 ms.
5. Hash downloaded bytes incrementally in 4 KiB chunks, compare the signed digest.
6. Pass authenticated bytes to archive::extract, which validates before creating
   the fresh tree. Limits: tar 16 MiB, 128 entries, 8 MiB/file, total 16 MiB,
   depth 16, manifest 256 KiB. Existing destinations are never overwritten.

HTTP is **buffered**, not streamed. Incremental hashing demonstrates bounded
updates; it does not remove the 4 MiB response allocation. Archive parsing may
require further bounded storage. Timeout is not a hard wall deadline: DNS cleanup
may wait longer. File syscalls have no hard deadline. Extraction filesystem errors
can leave a private partial tree; no automatic publication or cleanup occurs.

A valid signature is not a complete update protocol. Applications own key trust/
rotation, freshness/expiry, rollback prevention, protocol context, origin/DNS
policy, destination authorization and installation. A downloaded key is not a
trust anchor. This two-field schema deliberately supplies none of those policies.
The example is not integrated into Honk.

## Integration checks

Python cryptography generates test-only signatures, archives and a temporary
localhost certificate. Tests use real loopback HTTPS, with no external artifact
requests. An isolated compiler wrapper links transport.c only into the fixture
binary. It installs that temporary CA for the exact expected localhost URL and
preserves peer/hostname verification. A separate production binary has no shim
or fixture-environment handling and must reject the untrusted certificate.

```sh
python3 examples/artifact/integration.py --goose .toolchain/goose/build/goose --cc gcc
python3 examples/artifact/integration.py --goose .toolchain/goose/build/goose --cc gcc --sanitize
python3 examples/artifact/integration.py --goose .toolchain/goose/build/goose --cc clang --sanitize
```

Cases check successful contents and signature/key/metadata/digest rejection,
strict JSON schema, URL mismatch, unsafe archive paths, existing destinations,
redirect/status, body/header caps and untrusted TLS. Assertions check no request
before authentication/schema/URL validation and no tree on rejected verification,
digest, limits or archive validation. Existing destination sentinel stays intact.
Sanitizers instrument the fixture generated Goose/runtime and C/C++ native adapters
through matching compiler wrappers; the production TLS-rejection binary remains
an ordinary release build. System backends
remain uninstrumented. Generated keys/certificates/binaries stay ignored or temporary.
