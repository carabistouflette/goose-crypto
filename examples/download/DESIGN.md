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
execution or extraction. Existing archive size limits remain separate.

## Failure and outcome handling

Before publication: cancel/transport error/interrupted or truncated transfer/
byte cap/hash/write/sync/close failure creates/replaces no final entry and attempts cleanup
of only the exclusively created staging name. Always close HTTP/file/context
resources and report cleanup errors separately; do not mask the primary error or
claim cleanup succeeded merely because it was attempted. Staging residue is
reported with its caller-provided leaf if cleanup fails.

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

## Validation gates

Independent design/security/interface reviews before implementation. Repeated
code reviews after integration. Real loopback HTTPS fixtures: large successful
body beyond buffered-example cap, tiny and empty chunks/body, cancellation at
multiple offsets, stalled server, truncated Content-Length/reset, bad HTTP status,
redirect, TLS rejection, cumulative body/header caps, signed-digest mismatch,
exclusive staging collision, existing final, disk/write/sync/close failure,
publication outcomes and cleanup failures. Assert exact error stage, no premature
final entry, original bytes preserved, residue policy and descriptor cleanup.
Bounded adapter memory must be justified and measured across increasing totals;
streaming does not imply a hard whole-process RSS cap. Retain raw provenance and
avoid universal performance claims or timing thresholds in CI.

HTTP interface and published FS pin are being coordinated with their owners;
consumer implementation must use reviewed published pins, not sibling WIP.

The last cancellation check before rename is the publication commitment boundary.
Signals after it cannot promise final absence. Repeated SIGINT/SIGTERM must not
skip cooperative cleanup; SIGKILL, crash and abort cleanup are not guaranteed.
