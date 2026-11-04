# goose-crypto

SHA-256, strict hex conversion and detached Ed25519 verification for
[Goose](https://github.com/aardappel/goose), backed by system libsodium.
Apache-2.0. Experimental interface; no release yet.

```goose
import crypto from "../goose-crypto";
import std;
fn main() {
    var digest: u8[32] = [0; 32];
    var hex: u8[64] = [0; 64];
    assert(crypto::sha256("abc", digest[..]) == crypto::Error.None);
    assert(crypto::hex_encode(digest[..], hex[..]) == crypto::Error.None);
    print(hex[..]);
}
```

Declare the package in the application's root source. This uses a sibling
checkout; a pinned remote import will follow publication. Namespace: `crypto`.

## Development

Ubuntu dependencies: Git, CMake >=3.27, Make, pkg-config, C/C++20 toolchain,
Python >=3.11, libsodium development headers >=1.0.18, Clang for fuzzing.

```sh
sudo apt-get install build-essential cmake ninja-build pkg-config python3 libsodium-dev clang
make setup
make format check test
make sanitize public-sanitize SANITIZER_CC=gcc
make sanitize public-sanitize SANITIZER_CC=clang
make fuzz
make bench
```

Setup builds exact GOOSE_REVISION with optional builtins disabled. Select a
matching compiler with `GOOSE=/absolute/path/to/goose`. Initial target: Linux
x86-64/glibc; other platforms unverified. System libsodium is required at link
and run time. No backend code is vendored.

## Interface

Every function returns `crypto::Error`. Only `Error.None` means success.

| Function | Contract |
| --- | --- |
| `sha256(message, digest)` | Hash bytes into exactly 32 output bytes |
| `init(state)` | Initialize/reset caller-owned `Sha256` |
| `update(state, bytes)` | Append bytes to active state |
| `finish(state, digest)` | Write exactly 32 bytes, clear/deactivate state |
| `verify_ed25519(message, signature, public_key)` | Verify exact bytes; signature 64 bytes, key 32 bytes |
| `hex_encode(bytes, output)` | Lowercase hex, exactly twice as many output bytes |
| `hex_decode(text, output)` | Upper/lowercase hex, exactly half as many output bytes |

Inputs are binary, including NUL. Empty messages/chunks/hex are valid. Hex rejects
whitespace, prefixes, separators, non-ASCII and odd lengths. No buffers grow.
Writable spans must be disjoint from all readable spans and each other; runtime
checks reject exact/partial overlap. Every failure leaves state/output unchanged.

Errors: InvalidInput (sizes/overlap/hex), InvalidState (inactive/detectably corrupted
state), InvalidSignature (correct lengths but verification fails), BackendFailure
(backend/init), LimitExceeded (SHA-256 exceeds 2^61-1 total bytes). Precedence for
multiple invalid arguments is unspecified.

A default `Sha256 { .. }` is inactive: call init, update zero or more times, then
finish. Reinitialize before reuse. Copying active state forks its prefix.
`_state` and native/helper functions are implementation details. Never modify,
persist or exchange state bytes. They depend on backend/platform and can contain
original input. Clearing live state does not securely erase stack/compiler/caller
copies. Independent states may run concurrently; shared-state mutation may not.

Hash/verification work is O(message bytes), with bounded adapter stack storage;
state is 128 bytes. Hex is O(input bytes), validating before decode writes. The
adapter allocates no per-call storage and retains no pointers. First crypto use
calls thread-safe sodium_init, which may perform OS/randomness initialization.
Hex does not initialize the backend. Goose allocation failure follows its runtime.

## Trust and limits

Checksums authenticate bytes only with a trusted expected checksum. Signatures
verify exact bytes under a caller-trusted key. Applications own key discovery,
serialization, expiry, rollback protection, authorization and installation.
Verify signed metadata bytes before parsing them.

Acceptance follows libsodium's strict pure Ed25519 detached verifier (including
noncanonical scalar/small-order rejection), not Ed25519ph/Ed25519ctx. Never
substitute a digest unless the signing protocol specifies it. No streaming
signatures, signing, encryption, password hashing, RNG interface or I/O. Keep
system dependencies patched. SHA-256 is unkeyed; do not use secret-prefix SHA-256
as a MAC or use SHA-256 for passwords. No secure-memory guarantee.

See [validation](docs/validation.md), [benchmarks](bench/README.md),
[contributing](CONTRIBUTING.md), [security](SECURITY.md), and
[notices](THIRD_PARTY_NOTICES.md).
