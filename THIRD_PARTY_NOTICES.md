# Third-party notices

Repository code: Apache-2.0, see LICENSE. No backend code is vendored.
System [libsodium](https://github.com/jedisct1/libsodium) is ISC licensed.
Distributors must preserve its applicable copyright/license/component notices
when redistributing it; see upstream LICENSE and AUTHORS.

Development fetches [Goose](https://github.com/aardappel/goose) at GOOSE_REVISION.
Its Apache-2.0 license and third-party notices remain in that checkout. Downloaded
dependencies/generated outputs are not committed.

Tests use SHA-256 known answers and Ed25519 vectors from
[RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
Python hashlib and libsodium are separately installed test dependencies.

Signature differential tests use separately installed Python cryptography
(Apache-2.0/BSD-3-Clause) and its OpenSSL backend under their distribution notices.
No signing capability is exposed by the library.
