# Security policy

Experimental library; no supported release yet. Use reviewed commits and patched
system libsodium. Passing checks is not a security certification.

Report privately through GitHub's Report a vulnerability flow if enabled for the
public repository. Before that exists, request a private channel from the owner
without including details in a public issue. Through that private channel,
include the affected commit, compiler/backend versions and a minimal reproducer.
Coordinate disclosure after a fix. No response-time SLA.

Applications own trust policy, key distribution, rollback protection,
authorization and secret memory management; see README.md.
