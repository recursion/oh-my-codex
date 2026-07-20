import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  ADAPTED_PROVENANCE_AUTHORIZATION_DIR,
  consumeAdaptedProvenanceAuthorization,
  issueAdaptedProvenanceAuthorization,
  issueAdaptedProvenancePolicy,
  readValidAdaptedProvenancePolicy,
} from '../adapted-provenance-policy.js';
import { buildRalplanConsensusGateFromSources } from '../consensus-gate.js';
import { getBaseStateDir } from '../../state/paths.js';
import { __setNativeAnchorAuthRootForTest, signAdaptedProvenanceReceipt } from '../../subagents/native-anchor-auth.js';

const SCOPE = 'test.adapted-provenance.v1';
const PLAN_PATH = 'docs/plans/parked/candidate.md';

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function declarePlan(cwd: string): Promise<void> {
  await mkdir(join(cwd, 'docs', 'plans', 'parked'), { recursive: true });
  await writeFile(join(cwd, PLAN_PATH), `<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="${SCOPE}" -->\n`);
}

async function prepareNativeAnchor(cwd: string, value: number): Promise<void> {
  const anchorRoot = join(cwd, '.native-anchor');
  __setNativeAnchorAuthRootForTest(anchorRoot);
  await mkdir(anchorRoot, { recursive: true, mode: 0o700 });
  await writeFile(join(anchorRoot, 'key'), Buffer.alloc(32, value), { mode: 0o600 });
}

function receipt(policy: NonNullable<ReturnType<typeof policyOrThrow>>, sessionId: string, parentThreadId: string, childThreadId: string, role: 'planner' | 'architect' | 'critic', correlationToken: string) {
  const unsigned = {
    scope: policy.scope,
    policyId: policy.policyId,
    sessionId,
    originCwd: policy.originCwd,
    planPath: policy.planPath,
    planSha256: policy.planSha256,
    launchId: policy.launchId,
    issuedAt: policy.issuedAt,
    expiresAt: policy.expiresAt,
    parentThreadId,
    childThreadId,
    role,
    correlationToken,
  };
  const signature = signAdaptedProvenanceReceipt(unsigned);
  assert.ok(signature);
  return {
    scope: unsigned.scope,
    policy_id: unsigned.policyId,
    session_id: unsigned.sessionId,
    origin_cwd: unsigned.originCwd,
    plan_path: unsigned.planPath,
    plan_sha256: unsigned.planSha256,
    launch_id: unsigned.launchId,
    issued_at: unsigned.issuedAt,
    expires_at: unsigned.expiresAt,
    parent_thread_id: unsigned.parentThreadId,
    child_thread_id: unsigned.childThreadId,
    role: unsigned.role,
    correlation_token: unsigned.correlationToken,
    signature,
  };
}

function policyOrThrow(result: ReturnType<typeof issueAdaptedProvenancePolicy>) {
  assert.equal(result.ok, true);
  return result.policy;
}

test('adapted policy is default-deny, plan-digest-bound, and expires', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-adapted-policy-'));
  const nowMs = Date.now();
  const previous = { CODEX_HOME: process.env.CODEX_HOME, OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID };
  try {
    process.env.CODEX_HOME = join(cwd, '.codex-home');
    process.env.OMX_CODEX_LAUNCH_ID = 'launch-policy-test';
    await prepareNativeAnchor(cwd, 5);
    await declarePlan(cwd);
    assert.equal(readValidAdaptedProvenancePolicy(cwd, 'session', { nowMs }).ok, false);
    const policy = policyOrThrow(issueAdaptedProvenancePolicy({
      cwd,
      sessionId: 'session',
      planPath: PLAN_PATH,
      acknowledgement: 'I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE',
      ttlMs: 60_000,
      nowMs,
    }));
    assert.equal(readValidAdaptedProvenancePolicy(cwd, 'session', { nowMs: nowMs + 1 }).ok, true);
    await writeFile(join(cwd, PLAN_PATH), `<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="${SCOPE}" -->\nchanged\n`);
    assert.deepEqual(readValidAdaptedProvenancePolicy(cwd, 'session', { nowMs: nowMs + 2 }), { ok: false, reason: 'adapted_provenance_plan_drift' });
    await writeFile(join(cwd, PLAN_PATH), `<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="${SCOPE}" -->\n`);
    assert.deepEqual(readValidAdaptedProvenancePolicy(cwd, 'session', { nowMs: nowMs + 60_000 }), { ok: false, reason: 'stale_adapted_provenance_policy' });
    assert.equal(policy.scope, SCOPE);
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});

test('adapted policy rejects a plan reached through an intermediate symlink', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-adapted-policy-symlink-'));
  const previous = { OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID };
  try {
    process.env.OMX_CODEX_LAUNCH_ID = 'launch-policy-symlink-test';
    await prepareNativeAnchor(cwd, 6);
    await mkdir(join(cwd, 'docs', 'plans'), { recursive: true });
    const outside = join(cwd, 'outside-plans');
    await mkdir(outside, { recursive: true });
    await writeFile(join(outside, 'candidate.md'), `<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="${SCOPE}" -->\n`);
    await symlink(outside, join(cwd, 'docs', 'plans', 'parked'));

    assert.deepEqual(issueAdaptedProvenancePolicy({
      cwd,
      sessionId: 'session',
      planPath: PLAN_PATH,
      acknowledgement: 'I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE',
      ttlMs: 60_000,
    }), { ok: false, reason: 'invalid_adapted_provenance_plan' });
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});

test('hook-minted adapted authorizations are signed, exact-match, and one-use', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-adapted-authorization-'));
  const previous = { CODEX_HOME: process.env.CODEX_HOME, OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID };
  try {
    process.env.CODEX_HOME = join(cwd, '.codex-home');
    process.env.OMX_CODEX_LAUNCH_ID = 'launch-authorization-test';
    await prepareNativeAnchor(cwd, 11);
    const common = { cwd, sessionId: 'session', nativeSessionId: 'native-session', operation: 'grant' as const, commandSha256: 'a'.repeat(64) };
    assert.equal(issueAdaptedProvenanceAuthorization(common), true);
    assert.equal(consumeAdaptedProvenanceAuthorization({ ...common, commandSha256: 'b'.repeat(64) }), false);
    assert.equal(consumeAdaptedProvenanceAuthorization(common), true);
    assert.equal(consumeAdaptedProvenanceAuthorization(common), false);
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});

test('expired authorizations are pruned before the cap while active and symlink entries fail closed', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-adapted-authorization-prune-'));
  const previous = { CODEX_HOME: process.env.CODEX_HOME, OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID, OMX_ROOT: process.env.OMX_ROOT };
  const issuedAtMs = 1_750_000_000_000;
  const freshAtMs = issuedAtMs + 30_001;
  try {
    process.env.CODEX_HOME = join(cwd, '.codex-home');
    process.env.OMX_ROOT = join(cwd, '.omx-root');
    process.env.OMX_CODEX_LAUNCH_ID = 'launch-authorization-prune-test';
    await prepareNativeAnchor(cwd, 13);
    const common = { cwd, sessionId: 'session', nativeSessionId: 'native-session', operation: 'grant' as const, commandSha256: 'a'.repeat(64) };
    for (let index = 0; index <= 64; index += 1) {
      assert.equal(issueAdaptedProvenanceAuthorization({ ...common, nowMs: issuedAtMs }), true);
    }
    assert.equal(issueAdaptedProvenanceAuthorization({ ...common, nowMs: freshAtMs }), true);
    assert.equal(consumeAdaptedProvenanceAuthorization({ ...common, nowMs: freshAtMs }), true);

    for (let index = 0; index < 64; index += 1) {
      assert.equal(issueAdaptedProvenanceAuthorization({ ...common, nowMs: freshAtMs }), true);
    }
    const directory = join(getBaseStateDir(cwd), 'sessions', common.sessionId, ADAPTED_PROVENANCE_AUTHORIZATION_DIR);
    const symlinkPath = join(directory, '00000000-0000-0000-0000-000000000000.json');
    await symlink(join(cwd, 'outside-authorization.json'), symlinkPath);
    assert.equal(consumeAdaptedProvenanceAuthorization({ ...common, nowMs: freshAtMs }), false);
    assert.equal((await lstat(symlinkPath)).isSymbolicLink(), true);
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});

test('consensus accepts only signed current adapted receipts and rejects replay', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-adapted-consensus-'));
  const sessionId = 'session';
  const leader = 'leader';
  const previous = { CODEX_HOME: process.env.CODEX_HOME, OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID };
  try {
    process.env.CODEX_HOME = join(cwd, '.codex-home');
    process.env.OMX_CODEX_LAUNCH_ID = 'launch-consensus-test';
    await prepareNativeAnchor(cwd, 7);
    await declarePlan(cwd);
    const policy = policyOrThrow(issueAdaptedProvenancePolicy({
      cwd,
      sessionId,
      planPath: PLAN_PATH,
      acknowledgement: 'I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE',
      ttlMs: 60_000,
    }));
    const planner = receipt(policy, sessionId, leader, 'planner-thread', 'planner', 'a'.repeat(32));
    const architect = receipt(policy, sessionId, leader, 'architect-thread', 'architect', 'b'.repeat(32));
    const critic = receipt(policy, sessionId, leader, 'critic-thread', 'critic', 'c'.repeat(32));
    await writeJson(join(cwd, '.omx', 'state', 'session.json'), { session_id: sessionId, native_session_id: leader, cwd });
    await writeJson(join(cwd, '.omx', 'state', 'subagent-tracking.json'), {
      schemaVersion: 1,
      sessions: {
        [sessionId]: {
          session_id: sessionId,
          leader_thread_id: leader,
          updated_at: '2026-07-19T20:00:00.000Z',
          threads: {
            [leader]: { thread_id: leader, kind: 'leader', first_seen_at: '2026-07-19T20:00:00.000Z', last_seen_at: '2026-07-19T20:00:00.000Z', turn_count: 1 },
            'planner-thread': { thread_id: 'planner-thread', kind: 'subagent', role: 'planner', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:01.000Z', last_seen_at: '2026-07-19T20:00:02.000Z', completed_at: '2026-07-19T20:00:02.000Z', turn_count: 1, adapted_receipt: planner },
            'architect-thread': { thread_id: 'architect-thread', kind: 'subagent', role: 'architect', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:03.000Z', last_seen_at: '2026-07-19T20:00:04.000Z', completed_at: '2026-07-19T20:00:04.000Z', turn_count: 1, adapted_receipt: architect },
            'critic-thread': { thread_id: 'critic-thread', kind: 'subagent', role: 'critic', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:05.000Z', last_seen_at: '2026-07-19T20:00:06.000Z', completed_at: '2026-07-19T20:00:06.000Z', turn_count: 1, adapted_receipt: critic },
          },
        },
      },
      pending_role_intents: [],
    });
    const review = (role: 'architect' | 'critic', threadId: string, signedReceipt: ReturnType<typeof receipt>, completedAt: string) => ({
      agent_role: role,
      provenance_kind: 'omx_adapted',
      verdict: 'approve',
      session_id: sessionId,
      thread_id: threadId,
      tracker_path: '.omx/state/subagent-tracking.json',
      completed_at: completedAt,
      adapted_policy_id: signedReceipt.policy_id,
      adapted_receipt_signature: signedReceipt.signature,
    });
    const evidence = buildRalplanConsensusGateFromSources([{
      source: 'test',
      value: { ralplan_consensus_gate: { complete: true, sequence: ['architect-review', 'critic-review'], ralplan_architect_review: review('architect', 'architect-thread', architect, '2026-07-19T20:00:04.000Z'), ralplan_critic_review: review('critic', 'critic-thread', critic, '2026-07-19T20:00:06.000Z') } },
    }], { cwd, sessionId, requireNativeSubagents: true });
    assert.equal(evidence.complete, true);
    await writeJson(join(cwd, '.omx', 'state', 'subagent-tracking.json'), {
      schemaVersion: 1,
      sessions: {
        [sessionId]: {
          session_id: sessionId,
          leader_thread_id: leader,
          updated_at: '2026-07-19T20:00:00.000Z',
          threads: {
            [leader]: { thread_id: leader, kind: 'leader', first_seen_at: '2026-07-19T20:00:00.000Z', last_seen_at: '2026-07-19T20:00:00.000Z', turn_count: 1 },
            'architect-thread': { thread_id: 'architect-thread', kind: 'subagent', role: 'architect', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:03.000Z', last_seen_at: '2026-07-19T20:00:04.000Z', completed_at: '2026-07-19T20:00:04.000Z', turn_count: 1, adapted_receipt: architect },
            'critic-thread': { thread_id: 'critic-thread', kind: 'subagent', role: 'critic', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:05.000Z', last_seen_at: '2026-07-19T20:00:06.000Z', completed_at: '2026-07-19T20:00:06.000Z', turn_count: 1, adapted_receipt: critic },
          },
        },
      },
      pending_role_intents: [],
    });
    const missingPlanner = buildRalplanConsensusGateFromSources([{
      source: 'missing-planner',
      value: { ralplan_consensus_gate: { complete: true, sequence: ['architect-review', 'critic-review'], ralplan_architect_review: review('architect', 'architect-thread', architect, '2026-07-19T20:00:04.000Z'), ralplan_critic_review: review('critic', 'critic-thread', critic, '2026-07-19T20:00:06.000Z') } },
    }], { cwd, sessionId, requireNativeSubagents: true });
    assert.equal(missingPlanner.complete, false);
    assert.match(missingPlanner.blockedDetails?.join('\n') ?? '', /missing a completed signed Planner receipt/i);
    const replayed = { ...critic, child_thread_id: 'critic-thread', signature: architect.signature };
    await writeJson(join(cwd, '.omx', 'state', 'subagent-tracking.json'), {
      schemaVersion: 1,
      sessions: {
        [sessionId]: {
          session_id: sessionId,
          leader_thread_id: leader,
          updated_at: '2026-07-19T20:00:00.000Z',
          threads: {
            [leader]: { thread_id: leader, kind: 'leader', first_seen_at: '2026-07-19T20:00:00.000Z', last_seen_at: '2026-07-19T20:00:00.000Z', turn_count: 1 },
            'planner-thread': { thread_id: 'planner-thread', kind: 'subagent', role: 'planner', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:01.000Z', last_seen_at: '2026-07-19T20:00:02.000Z', completed_at: '2026-07-19T20:00:02.000Z', turn_count: 1, adapted_receipt: planner },
            'architect-thread': { thread_id: 'architect-thread', kind: 'subagent', role: 'architect', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:03.000Z', last_seen_at: '2026-07-19T20:00:04.000Z', completed_at: '2026-07-19T20:00:04.000Z', turn_count: 1, adapted_receipt: architect },
            'critic-thread': { thread_id: 'critic-thread', kind: 'subagent', role: 'critic', provenance_kind: 'omx_adapted', first_seen_at: '2026-07-19T20:00:05.000Z', last_seen_at: '2026-07-19T20:00:06.000Z', completed_at: '2026-07-19T20:00:06.000Z', turn_count: 1, adapted_receipt: replayed },
          },
        },
      },
      pending_role_intents: [],
    });
    const rejected = buildRalplanConsensusGateFromSources([{
      source: 'replayed',
      value: { ralplan_consensus_gate: { complete: true, sequence: ['architect-review', 'critic-review'], ralplan_architect_review: review('architect', 'architect-thread', architect, '2026-07-19T20:00:04.000Z'), ralplan_critic_review: review('critic', 'critic-thread', replayed, '2026-07-19T20:00:06.000Z') } },
    }], { cwd, sessionId, requireNativeSubagents: true });
    assert.equal(rejected.complete, false);
    assert.match(rejected.blockedDetails?.join('\n') ?? '', /does not match|signature|replayed/);
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});
