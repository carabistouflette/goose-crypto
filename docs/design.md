# Design contract

Experimental Goose library for byte hashing and public-key signature verification.
Use system libsodium >= 1.0.18. No home-grown cryptographic algorithms.
Initial validation target: Linux x86-64/glibc; other platforms unverified.

Public namespace crypto. SHA-256 digest is exactly 32 bytes, Ed25519 public key
32 bytes, detached signature 64 bytes. Inputs are binary slices, including NUL.
No file I/O, networking, key discovery, signing, random-number interface or global trust policy.
A checksum authenticates an artifact only when the expected checksum is trusted.
Ed25519 verification authenticates exact message bytes under a caller-trusted key;
it supplies no freshness, rollback protection, canonical serialization or key rotation.
Pure Ed25519 only, not Ed25519ph or Ed25519ctx.

Interface:
- sha256(message, digest-output) -> Error
- Sha256 caller-owned incremental state, init(state), update(state, bytes),
  finish(state, digest-output), reset via init. finish consumes active state.
- verify_ed25519(message, signature, public_key) -> Error, distinguishing
  InvalidInput (length), InvalidSignature, BackendFailure and success.
- hex_encode(bytes, exact-sized-output) and hex_decode(text, exact-sized-output)
  -> Error. Hex accepts uppercase/lowercase, rejects whitespace/prefix/odd length.
  Validate all input before writes; leave outputs unchanged on every failure.

Goose validates lengths before native entry; native validates independently.
Native calls use Goose-compatible slice ABI, no retained pointers and no adapter-owned per-operation
allocation. Backend initialization may perform OS/randomness work. State serialized into fixed caller-owned byte storage via memcpy;
never cast arbitrary Goose bytes to an aligned native struct. Include an active
marker and total-byte accounting. Bound SHA-256 total input to 2^61-1 bytes.
Inactive/update-after-finish/double-finish return InvalidState; init always resets.
State may buffer sensitive original input. Successful finish/reset clears live
storage but does not guarantee erasure of temporary or caller copies.
Copying an active state intentionally forks its hash prefix. State bytes are
implementation details, not a persistence/interchange format. Public-state
corruption is unsupported; nevertheless native checks must avoid memory unsafety.

Validation: NIST/RFC known-answer vectors, binary/padding boundaries, differential
hash oracle, signature tampering and malformed lengths, incremental lifecycle and
branching, runtime overlap rejection and caller storage reuse, JIT/native/debug execution, GCC/Clang
ASan/UBSan, guard-page reads and bounded native fuzzing. Benchmarks measure public
Goose calls against direct libsodium with raw samples and full provenance; no
universal performance claims or CI timing thresholds.

All errors preserve state/output, including backend failures. One-shot and
incremental SHA share the total bound and LimitExceeded. All writable ranges
must be disjoint from readable ranges and each other, checked at runtime because
Goose permits fixed-slice aliases. Acceptance follows libsodium strict pure
Ed25519; never substitute streaming Ed25519ph.
