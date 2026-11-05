# Bounded artifact verification example

This optional Linux command composes the public crypto, HTTP, JSON, filesystem
and archive libraries. It downloads and extracts an explicitly authorized archive
after verifying signed metadata and its SHA-256. It never installs or executes
extracted files. External libraries are pinned in main.goose; crypto uses this
checkout. These example-only dependencies do not affect ordinary crypto consumers.

## Build and run

Add system libcurl >=7.85 with TLS/asynchronous DNS/thread-safe initialization,
libarchive >=3.6, zlib >=1.2.11 and a C++20 runtime/compiler to crypto's development
prerequisites. Ubuntu packages: `libcurl4-openssl-dev libarchive-dev zlib1g-dev`.
The pinned compiler fetches public commits during build. Linux x86-64/glibc is
the validated platform.

From the repository root:

```sh
mkdir -p .build
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


## Runnable local demonstration

The production invocation above is a template: replace every path, signature,
key and URL with your independently authorized inputs. For a complete local run,
the integration harness generates signed metadata and a loopback TLS fixture:

```sh
python3 examples/artifact/integration.py --goose .toolchain/goose/build/goose --cc gcc
```

This needs Python cryptography and the build dependencies above. It fetches pinned
source packages but does not contact an external artifact service. The fixture
CA is injected only into its test binary; the production binary must reject it.
See [VALIDATION.md](VALIDATION.md) for scenarios, sanitizer commands, raw results
and limits. [AUDIT.md](../../docs/AUDIT.md) distinguishes current main from the
release and records checked commands. RSS observations are not an allocator/RSS
ceiling or throughput measurement.
