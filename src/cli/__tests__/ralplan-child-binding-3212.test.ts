import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { ralplanCommand } from '../ralplan.js';
import { issueAdaptedProvenancePolicy } from '../../ralplan/adapted-provenance-policy.js';
import { buildRalplanConsensusGateFromSources } from '../../ralplan/consensus-gate.js';
import { dispatchCodexNativeHook } from '../../scripts/codex-native-hook.js';
import {
  __setNativeAnchorAuthRootForTest,
  issueNativeLaunchAuthorization,
  nativeLaunchClaimPath,
  OMX_CODEX_LAUNCH_TOKEN_ENV,
  signNativeLaunchClaim,
} from '../../subagents/native-anchor-auth.js';
import { recordSubagentTurnForSession } from '../../subagents/tracker.js';

async function writeJson(path: string, value: unknown): Promise<void> {
  const parent = join(path, '..');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await chmod(parent, 0o700);
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

test('#3212 binds an attested receipt to child SessionStart and releases the next role', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-3212-child-bind-'));
  const canonical = 'omx-child-bind-3212';
  const native = 'native-child-bind-leader-3212';
  const plannerChild = 'native-child-bind-planner-3212';
  const architectChild = 'native-child-bind-architect-3212';
  const criticChild = 'native-child-bind-critic-3212';
  const launchId = 'launch-child-bind-3212';
  const previous = {
    CODEX_HOME: process.env.CODEX_HOME,
    OMX_ROOT: process.env.OMX_ROOT,
    OMX_ENTRY_PATH: process.env.OMX_ENTRY_PATH,
    OMX_CODEX_LAUNCH_ID: process.env.OMX_CODEX_LAUNCH_ID,
    OMX_SESSION_ID: process.env.OMX_SESSION_ID,
    [OMX_CODEX_LAUNCH_TOKEN_ENV]: process.env[OMX_CODEX_LAUNCH_TOKEN_ENV],
  };
  try {
    const codexHome = join(cwd, '.codex-home');
    const anchorRoot = join(cwd, '.native-anchor');
    __setNativeAnchorAuthRootForTest(anchorRoot);
    await mkdir(anchorRoot, { recursive: true, mode: 0o700 });
    await chmod(anchorRoot, 0o700);
    await writeFile(join(anchorRoot, 'key'), Buffer.alloc(32, 13), { mode: 0o600 });
    await chmod(join(anchorRoot, 'key'), 0o600);
    process.env.CODEX_HOME = codexHome;
    delete process.env.OMX_ROOT;
    process.env.OMX_ENTRY_PATH = join(process.cwd(), 'dist', 'cli', 'omx.js');
    process.env.OMX_CODEX_LAUNCH_ID = launchId;
    process.env.OMX_SESSION_ID = canonical;
    process.env[OMX_CODEX_LAUNCH_TOKEN_ENV] = 'b'.repeat(64);
    const authorization = issueNativeLaunchAuthorization({
      cwd,
      sessionId: canonical,
      launchId,
      token: process.env[OMX_CODEX_LAUNCH_TOKEN_ENV]!,
    });
    assert.ok(authorization);
    await writeJson(join(cwd, '.omx', 'state', 'session.json'), { session_id: canonical, native_session_id: native, cwd });
    const claimPath = nativeLaunchClaimPath(cwd, launchId);
    assert.ok(claimPath);
    await writeJson(claimPath, {
      schema_version: 1,
      nativeSessionId: native,
      signature: signNativeLaunchClaim({ ...authorization, nativeSessionId: native }),
    });
    await mkdir(join(cwd, 'docs', 'plans', 'parked'), { recursive: true });
    await writeFile(join(cwd, 'docs', 'plans', 'parked', 'candidate.md'), '<!-- OMX:AUTHENTICATED-ADAPTED-PROVENANCE scope="test.ralplan.binding.v1" -->\n');
    assert.equal(issueAdaptedProvenancePolicy({
      cwd,
      sessionId: canonical,
      planPath: 'docs/plans/parked/candidate.md',
      acknowledgement: 'I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE',
      ttlMs: 60_000,
    }).ok, true);
    const rootTranscript = join(cwd, 'root.jsonl');
    await writeJson(rootTranscript, { type: 'session_meta', payload: { id: native, session_id: native, cwd, originator: 'codex', source: 'interactive', thread_source: 'user' } });
    const authorizeRoleIntent = async (role: 'planner' | 'architect' | 'critic') => {
      const preTool = await dispatchCodexNativeHook({
        hook_event_name: 'PreToolUse', cwd, session_id: native, transcript_path: rootTranscript,
        tool_name: 'Bash', tool_input: { command: `omx ralplan role-intent write --role ${role} --parent-thread "$CODEX_THREAD_ID" --json` },
      }, { cwd });
      assert.equal(preTool.outputJson, null);
    };
    await authorizeRoleIntent('planner');
    const afterPreTool = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(afterPreTool.sessions[canonical].leader_thread_id, native);
    assert.ok(afterPreTool.sessions[canonical].leader_attest_signature);

    const stdout: string[] = [];
    const resolveSessionScope = async (_cwd?: string, requestedSessionId?: string) => ({
      cwd,
      stateDir: join(cwd, '.omx', 'state', 'sessions', requestedSessionId ?? canonical),
      sessionId: requestedSessionId ?? canonical,
      metadata: { sessionId: canonical, nativeSessionId: native },
    }) as never;
    await ralplanCommand(['role-intent', 'write', '--role', 'planner', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => stdout.push(line),
      generateCorrelationToken: () => 'd'.repeat(32),
      resolveSessionScope,
    });
    const plannerSpawnTaskName = JSON.parse(stdout[0]!).spawn_task_name as string;
    const beforeSelf = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(beforeSelf.pending_role_intents.length, 1, stdout[0]);
    const selfTranscript = join(cwd, 'self-child.jsonl');
    await writeJson(selfTranscript, { type: 'session_meta', payload: { id: native, session_id: native, source: { subagent: { thread_spawn: { parent_thread_id: native, task_name: plannerSpawnTaskName } } } } });
    await dispatchCodexNativeHook({ hook_event_name: 'SessionStart', cwd, session_id: native, transcript_path: selfTranscript }, { cwd });
    const afterSelf = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(afterSelf.pending_role_intents.length, 1);
    assert.equal(afterSelf.sessions[canonical].threads[native]?.adapted_receipt, undefined);
    const childTranscript = join(cwd, 'child.jsonl');
    await writeJson(childTranscript, { type: 'session_meta', payload: { id: plannerChild, session_id: plannerChild, source: { subagent: { thread_spawn: { parent_thread_id: native, task_name: plannerSpawnTaskName } } } } });
    await dispatchCodexNativeHook({ hook_event_name: 'SessionStart', cwd, session_id: plannerChild, transcript_path: childTranscript }, { cwd });

    const tracker = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(tracker.sessions[canonical].threads[plannerChild].role, 'planner');
    assert.equal(tracker.sessions[canonical].threads[plannerChild].provenance_kind, 'omx_adapted');
    assert.ok(tracker.sessions[canonical].threads[plannerChild].adapted_receipt?.signature);
    assert.equal(tracker.pending_role_intents.length, 0);
    const beforePlannerCompletion: string[] = [];
    await authorizeRoleIntent('architect');
    await ralplanCommand(['role-intent', 'write', '--role', 'architect', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => beforePlannerCompletion.push(line),
      generateCorrelationToken: () => 'e'.repeat(32),
      resolveSessionScope,
    });
    assert.equal(JSON.parse(beforePlannerCompletion[0]!).reason, 'invalid_adapted_provenance_transition');
    process.exitCode = undefined;

    const completedPlanner = await recordSubagentTurnForSession(cwd, {
      sessionId: canonical,
      threadId: plannerChild,
      kind: 'subagent',
      completed: true,
      preserveCompletionEvidence: true,
    });
    assert.ok(completedPlanner.sessions[canonical].threads[plannerChild].completed_at);
    assert.ok(completedPlanner.sessions[canonical].threads[plannerChild].adapted_receipt?.signature);
    const forged = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    forged.sessions[canonical].threads[plannerChild].adapted_receipt.signature = '0'.repeat(64);
    await writeFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), `${JSON.stringify(forged)}\n`);
    const denied: string[] = [];
    await authorizeRoleIntent('architect');
    await ralplanCommand(['role-intent', 'write', '--role', 'architect', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => denied.push(line),
      generateCorrelationToken: () => 'e'.repeat(32),
      resolveSessionScope,
    });
    assert.equal(JSON.parse(denied[0]!).reason, 'invalid_adapted_provenance_transition');
    process.exitCode = undefined;
    forged.sessions[canonical].threads[plannerChild].adapted_receipt.signature = tracker.sessions[canonical].threads[plannerChild].adapted_receipt.signature;
    await writeFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), `${JSON.stringify(forged)}\n`);
    const architectIntent: string[] = [];
    await authorizeRoleIntent('architect');
    await ralplanCommand(['role-intent', 'write', '--role', 'architect', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => architectIntent.push(line),
      generateCorrelationToken: () => 'e'.repeat(32),
      resolveSessionScope,
    });
    const architectReceipt = JSON.parse(architectIntent[0]!);
    assert.equal(architectReceipt.intent.role, 'architect');
    const architectTranscript = join(cwd, 'architect-child.jsonl');
    await writeJson(architectTranscript, { type: 'session_meta', payload: { id: architectChild, session_id: architectChild, source: { subagent: { thread_spawn: { parent_thread_id: native, task_name: architectReceipt.spawn_task_name } } } } });
    await dispatchCodexNativeHook({ hook_event_name: 'SessionStart', cwd, session_id: architectChild, transcript_path: architectTranscript }, { cwd });

    const afterArchitectStart = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(afterArchitectStart.sessions[canonical].threads[architectChild].role, 'architect');
    assert.equal(afterArchitectStart.sessions[canonical].threads[architectChild].provenance_kind, 'omx_adapted');
    assert.ok(afterArchitectStart.sessions[canonical].threads[architectChild].adapted_receipt?.signature);
    assert.equal(afterArchitectStart.sessions[canonical].threads[architectChild].completed_at, undefined);
    assert.equal(afterArchitectStart.pending_role_intents.length, 0);

    const beforeArchitectCompletion: string[] = [];
    await authorizeRoleIntent('critic');
    await ralplanCommand(['role-intent', 'write', '--role', 'critic', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => beforeArchitectCompletion.push(line),
      generateCorrelationToken: () => 'f'.repeat(32),
      resolveSessionScope,
    });
    assert.equal(JSON.parse(beforeArchitectCompletion[0]!).reason, 'invalid_adapted_provenance_transition');
    process.exitCode = undefined;

    const completedArchitect = await recordSubagentTurnForSession(cwd, {
      sessionId: canonical,
      threadId: architectChild,
      kind: 'subagent',
      completed: true,
      preserveCompletionEvidence: true,
    });
    assert.ok(completedArchitect.sessions[canonical].threads[architectChild].completed_at);
    assert.ok(completedArchitect.sessions[canonical].threads[architectChild].adapted_receipt?.signature);
    const criticIntent: string[] = [];
    await authorizeRoleIntent('critic');
    await ralplanCommand(['role-intent', 'write', '--role', 'critic', '--parent-thread', native, '--session', canonical, '--json'], {
      cwd: () => cwd,
      stdout: (line) => criticIntent.push(line),
      generateCorrelationToken: () => 'f'.repeat(32),
      resolveSessionScope,
    });
    const criticReceipt = JSON.parse(criticIntent[0]!);
    assert.equal(criticReceipt.intent.role, 'critic');
    const criticTranscript = join(cwd, 'critic-child.jsonl');
    await writeJson(criticTranscript, { type: 'session_meta', payload: { id: criticChild, session_id: criticChild, source: { subagent: { thread_spawn: { parent_thread_id: native, task_name: criticReceipt.spawn_task_name } } } } });
    await dispatchCodexNativeHook({ hook_event_name: 'SessionStart', cwd, session_id: criticChild, transcript_path: criticTranscript }, { cwd });

    const afterCriticStart = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    assert.equal(afterCriticStart.sessions[canonical].threads[criticChild].role, 'critic');
    assert.equal(afterCriticStart.sessions[canonical].threads[criticChild].provenance_kind, 'omx_adapted');
    assert.ok(afterCriticStart.sessions[canonical].threads[criticChild].adapted_receipt?.signature);
    assert.equal(afterCriticStart.pending_role_intents.length, 0);

    await recordSubagentTurnForSession(cwd, {
      sessionId: canonical,
      threadId: criticChild,
      kind: 'subagent',
      completed: true,
      preserveCompletionEvidence: true,
    });
    const completedTracker = JSON.parse(await readFile(join(cwd, '.omx', 'state', 'subagent-tracking.json'), 'utf8'));
    const adaptedReview = (role: 'architect' | 'critic', threadId: string) => {
      const thread = completedTracker.sessions[canonical].threads[threadId];
      const receipt = thread.adapted_receipt;
      return {
        agent_role: role,
        provenance_kind: 'omx_adapted',
        verdict: 'approve',
        session_id: canonical,
        thread_id: threadId,
        tracker_path: '.omx/state/subagent-tracking.json',
        completed_at: thread.completed_at,
        adapted_policy_id: receipt.policy_id,
        adapted_receipt_signature: receipt.signature,
      };
    };
    const consensus = buildRalplanConsensusGateFromSources([{
      source: 'authenticated-child-binding',
      value: {
        ralplan_consensus_gate: {
          complete: true,
          sequence: ['architect-review', 'critic-review'],
          ralplan_architect_review: adaptedReview('architect', architectChild),
          ralplan_critic_review: adaptedReview('critic', criticChild),
        },
      },
    }], { cwd, sessionId: canonical, requireNativeSubagents: true });
    assert.equal(consensus.complete, true);
  } finally {
    __setNativeAnchorAuthRootForTest();
    for (const [key, value] of Object.entries(previous)) value === undefined ? delete process.env[key] : process.env[key] = value;
    await rm(cwd, { recursive: true, force: true });
  }
});
