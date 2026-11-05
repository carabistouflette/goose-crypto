# Verified streaming download contract

Application example composing Goose crypto, HTTP and filesystem libraries.
Experimental Linux x86-64 target. No installer, extraction or trust-policy API.
Core crypto remains byte-oriented and independent of I/O.

## Trust and ordering

Input: bounded metadata file, detached Ed25519 signature and trusted public-key
hex, exact caller-authorized HTTPS URL, caller-controlled private destination
parent, final leaf name, explicit exclusive staging leaf, and cumulative byte cap.
Verify exact metadata bytes before parsing or making network/file-mutation calls.
Use the existing strict JSON {url, sha256} schema and exact digest conversion.
The independently authorized URL must equal authenticated metadata byte-for-byte.
Signature/key/digest lengths are exact. Caller owns freshness, rollback, origin
policy, key distribution, final-file authorization and staging parent exclusivity.

Open a held parent Root and create a new 0600 staging regular file exclusively.
Check staging absence under the no-other-writers contract before exclusive
creation. Failed create/open can leave a new entry: track possible ownership
from that absence check and attempted creation, not just a valid File token.
Never truncate, reuse or remove a pre-existing staging entry. Staging and final
names are distinct canonical lowercase ASCII leaves ([a-z0-9][a-z0-9._-]*,
no trailing dot, no tilde, at most 255 bytes) in the same held parent. They must
also be filesystem-distinct under non-aliasing lookup semantics; byte-distinctness
alone does not prove this on arbitrary filesystems. Exotic aliasing namespaces
are unsupported. There must be no other writers
for the workflow's duration. This is an explicit private-directory contract, not
confinement against a same-UID adversary or a source-inode-pinning rename API.

Pump bounded HTTP chunks, checking cancellation between steps. Update SHA-256
incrementally and write each accepted chunk through the held file. Enforce a
cumulative body cap without allocating it. Require successful terminal HTTP 200,
no redirect/proxy/credentials and normal TLS peer/hostname verification. Partial
bytes and an early HTTP 200 are never sufficient to authorize publication.

After terminal transport success, finish and compare the trusted expected digest.
Check file data sync and explicit close before attempting no-replace rename.
Publish only verified bytes into a previously absent final name. No automatic
execution or extraction.

## Failure and outcome handling

Before publication: cancel/transport error/interrupted or truncated transfer/
byte cap/hash/write/sync/close failure creates/replaces no final entry and attempts cleanup
of only the exclusively created staging name. Always close HTTP/file/context
resources and report cleanup errors separately; do not mask the primary error or
claim cleanup succeeded merely because it was attempted. Possible staging residue
is reported separately; the caller already knows its leaf. Fixed diagnostics omit
untrusted filenames.

Publication: preserve NoReplace and filesystem RenameResult.outcome semantics.
Applied can coexist with a later sync/close error: report published-with-error,
never roll back the destination. Unknown can mean mutation despite an error:
report uncertainty and do not retry or clean namespace entries speculatively.
Even raced EEXIST follows Unknown: preserve existing final bytes and retain/report
the verified staging entry.
NotAttempted permits ordinary owned-staging cleanup. No universal crash-durability
claim; distinguish file-data sync, parent sync and outcome.

Normal return must run cleanup before CLI exit; Goose defer does not run on
exit/abort. Cancellation mechanism must permit cleanup rather than terminating
inside a signal handler. Define its boundary/latency from HTTP pumping; do not
promise hard wall deadlines for DNS cleanup, file syscalls or sync.

## Tests and cancellation boundary

[VALIDATION.md](VALIDATION.md) records the signed loopback TLS, cancellation,
write/sync/close failure, collision, cleanup and rename-outcome checks. These
checks do not establish hard wall deadlines, crash cleanup or universal
filesystem durability.

The HTTP and FS imports in `main.goose` pin public commits. The last cancellation
check before rename is the publication commitment boundary. Signals after it
cannot promise final absence. Repeated SIGINT/SIGTERM must not skip cooperative
cleanup; SIGKILL, crash and abort cleanup are not guaranteed.
