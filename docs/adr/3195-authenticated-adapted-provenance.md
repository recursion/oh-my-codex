# ADR 3195: Authenticated adapted provenance is a reviewed fallback

**Status:** Accepted

## Context

ADR 3194 correctly rejects heuristic leader inference on a
`role_routing_unavailable` Codex surface. The operator accepted a deliberately
weaker alternative for specific reviewed plans, not a silent restoration of the
old adapted route.

The exception needs an issuer-controlled trust root that a direct Codex process
cannot relocate by supplying lookalike environment variables or choosing a
different working directory. It also needs to preserve the default-deny result
when that root or any of its artifacts cannot be trusted.

## Decision

Keep typed `agent_type` routing preferred. Permit `omx_adapted` consensus only
when an amended plan explicitly accepts it and an interactive Codex process was
launched by OMX with a private 256-bit launch capability.

### Stable native anchor and launch proof

The trust root is the stable OS-user anchor:

```text
userInfo().homedir/.omx/native-anchor-auth/v1
```

The issuer and installed plugin derive this path from `node:os`
`userInfo().homedir`, rather than `HOME`, `CODEX_HOME`, `OMX_ROOT`, or the
current working directory. The launch-authorization and launch-claim path
helpers deliberately ignore their `cwd` argument when selecting this root.
Consequently, fake `CODEX_HOME`, fake `OMX_ROOT`, or a fake `cwd` cannot select
an alternate trust root. The canonicalized cwd remains a signed *binding* of an
authorization; it is not a locator for its key or artifacts.

Before spawning Codex, the OMX issuer creates the anchor key if needed and
writes a `0600`, HMAC-SHA-256-signed, expiring launch authorization. It binds a
unique authorization id, launch id, SHA-256 of the 256-bit launch capability,
canonical OMX session id, canonical origin cwd, issue time, and expiry. Launch
authorizations are valid for no more than four hours.

The plugin is verify-only with respect to issuer authority: it never creates
the anchor key or a launch authorization. It must first verify the existing
signed authorization and all of its token, session, cwd, time, and signature
bindings. Only then may it create the first `0600` signed launch claim, which
adds the native Codex session id to the same authorization bindings. Later hook
calls must verify that claim; a child `SessionStart` is accepted only when its
transcript proves it was spawned by the claimed leader. A direct Codex launch,
a spoofed `OMX_ENTRY_PATH`, or a launch id/token without an issuer artifact
does not cause the plugin to delegate to OMX or mint a claim.

The plugin fails closed for this exception when the anchor, key,
authorization, or claim is absent, malformed, unsafe, expired, or mismatched.
For an ordinary hook that failure is an inert plugin no-op (and `{}` for a
`Stop` hook), rather than a delegation that could acquire adapted authority.

### Artifact safety

On POSIX, the anchor directory and its checked authorization/claim directories
must be real directories without group or other permission bits (`0700` when
created). The anchor key, launch authorization, and launch claim must be
regular non-symlink files with one link, bounded sizes, and no group or other
permission bits (`0600` when created). Readers reject an unsafe mode, symlink,
hard-linked file, wrong type, oversized artifact, or failed parse/signature
check. The issuer uses exclusive creation for a launch authorization; the
plugin uses exclusive creation for the initial claim, so a pre-existing claim
is verified rather than replaced.

The reviewed-policy and one-use command authorization artifacts are separately
validated for type, symlink, hard-link, size, bindings, expiry, and signature.
They are written `0600`; their readers do not add a POSIX-mode check, so this
ADR does not claim that check for those state-root artifacts.

On Windows, the POSIX permission-bit tests are bypassed. The implementation
does not create or verify a Windows ACL, so the POSIX `0700`/`0600` guarantees
must not be read as Windows access-control guarantees.

### Reviewed policy, one-use commands, and child evidence

Every amended consensus workflow requires the explicit acknowledgement and a
signed policy bound to its scope, policy id, canonical session, canonical cwd,
plan path and SHA-256, launch id, issue time, and expiry. Policy validity is
between one minute and four hours, and plan drift invalidates it.

Only the exact, fresh root `PreToolUse` path may mint the short-lived (30
second), signed command authorization that the CLI consumes. A grant
authorization binds the canonical command digest; a role-intent authorization
binds the installed role and root parent thread. Both bind the canonical and
native session ids, origin cwd, launch id, issue/expiry times, and a unique
authorization id. Consumption atomically renames and unlinks exactly one
matching artifact, preventing replay; it fails if the directory has no match or
contains more than 64 candidate authorization files.

The hook admits this minting path only after it has verified the plugin launch
claim, a verified-root transcript, current session-pointer/native-session
bindings, compatible thread identity, and the absence of conflicting leader
carriers, Team context, child-spawn provenance, or tracked-child status. It
then records a signed leader attestation. This authorization is an exception
for the named operation, not general proof that Codex applied a role, model, or
TOML configuration.

Each child receipt is signed and bound to the policy fields above plus the
leader parent thread, child thread, installed role, and correlation token. The
tracker accepts only the sequential Planner -> Architect -> Critic transition;
the later role cannot start before its predecessor has completed with valid
receipt evidence. The consensus gate accepts only current, matching signed
receipts and rejects replayed, forged, stale, or plan-drifted evidence. Team,
`codex_exec`, child, self-parent, and collision cases remain denied.

### Retention and cleanup

The current issuer does **not** implement bounded cleanup of expired stable
anchor launch authorizations or launch claims. Their four-hour expiry bounds
their authority, not their on-disk retention. The bounded 64-file behavior
above applies only to scanning short-lived, hook-minted command
authorizations; it is not issuer garbage collection. Do not represent this ADR
as providing launch-artifact cleanup until such an implementation is added and
reviewed.

## Consequences

- Each amended Ralplan consensus workflow needs one reviewed plan amendment
  and acknowledgement; its policy is shared only by that policy's sequential
  Planner -> Architect -> Critic receipts.
- Missing, stale, replayed, malformed, or mismatched evidence stops the lane;
  historical artifacts do not acquire authority.
- Read-only Git admin paths and blocked workflow transitions remain independent
  blockers.
- ADR 3194 remains the rule against heuristic identity inference; this ADR is a
  narrowly authenticated exception, not a reversal of that safety boundary.
- This is not a hostile-local-process isolation boundary. A process running as
  the same OS user can read the live real anchor/key and a live launch token,
  then race the ordinary serialized hook-to-command handoff. The mode and
  symlink checks protect the checked POSIX filesystem shape, not a hostile
  principal with the same user's authority. Windows has the additional residual
  risk that this implementation does not establish or verify ACL protections.
