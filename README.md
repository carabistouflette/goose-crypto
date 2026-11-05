# goose-crypto

Hash bytes with SHA-256, convert strict hexadecimal strings, and verify detached
Ed25519 signatures in Goose. Uses system libsodium; Apache-2.0.

Experimental API, tested on Linux x86-64/glibc. The released core is
[v0.1.0-alpha.1](https://github.com/carabistouflette/goose-crypto/releases/tag/v0.1.0-alpha.1)
at `a4643f62bd5e76b371054c6537a95169a7930101`. Main also contains optional
network/file examples that are absent from that release. The core implementation
is unchanged; see [the source check](docs/AUDIT.md).

## Quickstart

Install libsodium development headers (>=1.0.18), pkg-config, CMake and a C
compiler, and use the Goose revision in [GOOSE_REVISION](GOOSE_REVISION).
On Ubuntu, the native dependency is `sudo apt-get install libsodium-dev pkg-config`.
Save this as `main.goose`, then run `goose run main.goose`:

```goose
import crypto from "carabistouflette/goose-crypto@a4643f62bd5e76b371054c6537a95169a7930101";
import std;
fn main() {
    var digest: u8[32] = [0; 32];
    var hex: u8[64] = [0; 64];
    assert(crypto::sha256("abc", digest[..]) == crypto::Error.None);
    assert(crypto::hex_encode(digest[..], hex[..]) == crypto::Error.None);
    print(hex[..]);
}
```

The output is the SHA-256 of `abc`:
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
Package imports belong in the application's root source file.

## API

Every function returns `crypto::Error`; only `Error.None` means success.

| Function | Required storage/behavior |
| --- | --- |
| `sha256(message, digest)` | Exactly 32 output bytes |
| `init(state)` | Initialize/reset caller-owned `Sha256` |
| `update(state, bytes)` | Append to an active state |
| `finish(state, digest)` | Write 32 bytes, clear/deactivate the state |
| `verify_ed25519(message, signature, public_key)` | Exact message bytes, 64-byte signature, 32-byte key |
| `hex_encode(bytes, output)` | Lowercase hex; output length is twice the input |
| `hex_decode(text, output)` | Upper/lowercase hex; output length is half the input |

Empty messages, update chunks and hex strings are valid, subject to the required
lengths above. Hex rejects whitespace, prefixes, separators, non-ASCII,
odd lengths and wrong output sizes. Output never grows. Writable spans must not
overlap readable spans or each other; exact/partial overlap is checked at runtime.
Every reported error preserves caller state/output.

Errors distinguish invalid input, inactive or detectably corrupted state,
invalid signature,
backend failure and the SHA-256 total-input limit (2^61−1 bytes). Length/overlap
errors are different from a correctly sized signature that fails verification.

Call `init`, zero or more `update`s, then `finish`. Reset before reuse. Copying an
active state forks its prefix. State is an implementation detail that can contain
original input: do not modify, persist or exchange it. Clearing live storage does
not securely erase caller/compiler copies. Independent states can run concurrently;
shared-state mutation cannot. See [the full contract](docs/design.md).

## Trust

Supply the expected digest and public key through your own trust process.
A downloaded key does not establish trust. Signatures cover exact bytes; verify
signed metadata before parsing it. Applications supply encoding, protocol context,
key rotation, expiry, freshness, rollback prevention and authorization.

Verification follows libsodium's strict pure detached Ed25519, not Ed25519ph/ctx.
Do not replace the message with a digest unless the signing protocol specifies it.
SHA-256 is unkeyed: do not use secret-prefix hashing as a MAC or SHA-256 for
passwords. The module exposes no signing, encryption, RNG, I/O or secure-memory API.

## Examples and development

| Main-only example | Purpose |
| --- | --- |
| [Buffered archive](examples/artifact/README.md) | Verify signed metadata, download at most 4 MiB, then extract into a fresh directory |
| [Streaming download](examples/download/README.md) | Verify metadata, stream to private staging, then publish with checked rename outcomes |

These examples have separate dependencies and trust/filesystem requirements.
For a reusable streaming API, see [goose-artifact](https://github.com/carabistouflette/goose-artifact).

[Contributing](CONTRIBUTING.md) lists build/test prerequisites and commands.
[Validation](docs/validation.md) records tests; [benchmarks](bench/README.md)
explain the historical same-backend overhead measurements and source match.
See also [security](SECURITY.md) and [notices](THIRD_PARTY_NOTICES.md).
