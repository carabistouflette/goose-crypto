# Security policy

Experimental prerelease API; no stable compatibility promise before 1.0. Use
reviewed immutable releases and patched system libsodium. Passing checks are not
a security certification.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/carabistouflette/goose-crypto/security/advisories/new).
Do not include vulnerability details in public issues. Include the affected
commit, compiler/backend versions and a minimal reproducer through that private
channel. Coordinate disclosure after a fix. No response-time SLA.

Applications own trust policy, key distribution, rollback protection,
authorization and secret memory management; see README.md.
