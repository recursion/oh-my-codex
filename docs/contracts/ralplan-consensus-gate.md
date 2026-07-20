# Ralplan Consensus Gate Contract

The `ralplan -> ultragoal` transition requires durable Architect and Critic approval evidence from preferred native subagent lanes or the explicit attached-tmux OMX Team fallback. Advisory lanes such as Scholastic do not replace this gate.

## Required review artifact fields

Each review artifact used by the gate must include:

- `agent_role`: `architect` or `critic`
- `provenance_kind`: `native_subagent` from a routing-capable surface, or `omx_team` from the validated attached-tmux fallback; `omx_adapted` remains rejected
- `session_id`: the current transition session id, unless supplied by the transition context
- `thread_id`: the native subagent thread id for that review lane
- `tracker_path`: `.omx/state/subagent-tracking.json`

The Architect and Critic reviews must approve in order and must refer to distinct tracker lanes of the same truthful provenance type.

## Typed OMX Team fallback

When native `agent_type` routing is unavailable, attached tmux may use explicitly installed `architect` and `critic` Team roles. Architect must complete before the Critic task is created. Results are structured JSON approval envelopes bound to the current Ralplan session and the SHA-256 digest of every exact planning input. `omx ralplan team-consensus record` validates Team manifests, task ownership, exact worker/task roles, completion, result schema, session, input digest, distinct lanes, and strict ordering before it records `kind:"team_worker"`, `provenance_kind:"omx_team"` entries through the tracker API. Team is never relabeled as native.

## Unsupported adapted provenance

When the native tool reports `role_routing_unavailable`, Ralplan must fail its explicit preflight before review work. The consensus gate rejects `omx_adapted` review artifacts even when legacy tracker journals or `native-subagent-role-routing.json` markers remain after an upgrade. Prompt labels, task-name carriers, markers, pending intents, and historical adapted ledger records do not grant review authority. Typed `native_subagent` lanes remain subject to the tracker, completion, distinct-thread, role, and strict Architect-before-Critic checks below.

## Required tracker schema

`.omx/state/subagent-tracking.json` must contain the session and both review threads:

```text
sessions["<current_session_id>"].threads["<architect_thread_id>"].kind = "subagent"
sessions["<current_session_id>"].threads["<critic_thread_id>"].kind = "subagent"
both threads have completed_at
architect and critic thread IDs are distinct
```

The transition session is the explicit transition `sessionId` when available; otherwise it is resolved from the review artifact `session_id` fields.

## Failure diagnostics

Rejected transitions include a structured diagnostic object on `RalplanConsensusGateEvidence.diagnostic` and a rendered error with:

- expected tracker schema,
- current session id used for lookup,
- Architect/Critic thread ids,
- whether the tracker session exists,
- whether each thread exists,
- each thread `kind`,
- whether each thread has `completed_at`,
- whether thread ids are distinct,
- remediation steps,
- this docs path.

## Remediation

Re-run native ralplan Architect/Critic reviews, or repair the review artifacts so `agent_role`, `provenance_kind`, `session_id`, `thread_id`, and `tracker_path` point to completed native subagent threads in the current tracker.
