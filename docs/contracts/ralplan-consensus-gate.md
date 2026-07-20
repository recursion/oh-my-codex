# Ralplan Consensus Gate Contract

The `ralplan -> ultragoal` transition requires durable Architect and Critic
approval evidence. Typed `native_subagent` lanes are the preferred proof.
`omx_adapted` lanes are accepted only through the narrow authenticated fallback
defined below; advisory lanes such as Scholastic never replace this gate.

## Required review artifact fields

Each Architect and Critic review must include:

- `agent_role`: `architect` or `critic`
- `provenance_kind`: `native_subagent`, or authenticated `omx_adapted`
- `session_id`: the current transition session id, unless supplied by the
  transition context
- `thread_id`: the native child thread id for that review lane
- `tracker_path`: `.omx/state/subagent-tracking.json`

For an authenticated `omx_adapted` review, it must additionally include:

- `adapted_policy_id`: the exact `policy_id` from
  `sessions[session_id].threads[thread_id].adapted_receipt` in that tracker
- `adapted_receipt_signature`: the exact `signature` from the same receipt

These values are copied from the tracker-owned signed receipt after the child
starts; reviewers and handoff writers must not reconstruct, substitute, or
reuse them from another lane. The gate compares both values to the current
tracker receipt before verifying its signature.

The reviews must approve in strict Architect-before-Critic order and use
distinct completed tracker threads.

## Authenticated adapted provenance

`omx_adapted` is default-deny. It is valid only when all of these are true:

1. The governing `docs/plans/**` file carries the explicit
   `<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="..." -->` amendment.
2. The current interactive, non-Team, non-`codex_exec` launcher authenticated
   an expiring policy created with
   `omx ralplan adapted-provenance grant --plan ... --acknowledge I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE`.
   OMX must have pre-created the private launch capability plus `0600`,
   HMAC-signed pre-launch authorization; the plugin verifies it and never
   self-mints a session claim from environment values.
   The exact root PreToolUse turn mints a short-lived, HMAC-signed, one-use
   authorization that the CLI consumes for that grant and for each exact
   role-intent invocation; a durable attestation or launch claim alone cannot
   create policy or intent state.
3. `omx ralplan preflight --adapted-provenance --json` validates that policy.
   The policy is HMAC-signed and bound to the plan path and SHA-256, scope,
   canonical cwd, session, launch id, issuance time, and expiry.
4. Each Planner, Architect, and Critic child has a unique HMAC-signed tracker
   receipt bound to that policy, the current leader parent, child thread, role,
   and correlation token. The review carries the exact policy id and receipt
   signature.
5. The lanes run sequentially: a signed, completed Planner receipt is required
   before Architect intent; a signed, completed Architect receipt is required
   before Critic intent.

The gate rejects missing, stale, foreign, malformed, replayed, self-parented,
or plan-drifted receipts. It also rejects receipt/review mismatch, Team
contexts, and `codex_exec` root provenance. Historical markers, task-name
carriers, prompt labels, and pending intents alone never grant authority.

This fallback authenticates launcher/policy/receipt provenance; it does **not**
make Codex enforce a requested child `agent_type`, model, or TOML role. It is
plan-scoped and must not be used as a global typed-routing substitute.
Codex exposes no caller-bound transport from PreToolUse to the spawned CLI, so
the one-use handoff is not a hostile same-user/host isolation guarantee.

## Required tracker schema

`.omx/state/subagent-tracking.json` must contain the session and both review
threads. For authenticated adapted evidence, it must additionally preserve each
signed `adapted_receipt`.

```text
sessions["<current_session_id>"].threads["<architect_thread_id>"].kind = "subagent"
sessions["<current_session_id>"].threads["<critic_thread_id>"].kind = "subagent"
both threads have completed_at
architect and critic thread IDs are distinct
```

The transition session is the explicit transition `sessionId` when available;
otherwise it is resolved from the review artifact `session_id` fields.

## Failure diagnostics and remediation

Rejected transitions report the expected tracker schema, session and thread
lookup details, completion/order state, and the blocking policy/receipt reason.
Re-run typed native Architect/Critic reviews where possible. For an explicitly
amended fallback scope, repair the plan/policy and rerun the full authenticated
Planner -> Architect -> Critic sequence; never patch historical evidence.
