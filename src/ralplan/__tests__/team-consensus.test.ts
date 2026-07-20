import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { recordTeamRalplanConsensus } from '../team-consensus.js';
import { subagentTrackingPath } from '../../subagents/tracker.js';
import { buildRalplanConsensusGateForCwd } from '../consensus-gate.js';
import { validateRalplanTerminalConsensus } from '../../state/operations.js';

async function fixture(overrides: Record<string, unknown> = {}) {
  const cwd = await mkdtemp(join(tmpdir(), 'omx-team-ralplan-'));
  const sessionId = `session-${cwd.split('/').at(-1)!.replace(/[^A-Za-z0-9_-]/g, '')}`;
  const digest = 'a'.repeat(64);
  const base = {
    cwd,
    sessionId,
    inputDigest: digest,
    roleInstalled: () => true,
    architect: {
      teamName: 'ralplan-architect', taskId: '1', worker: 'worker-1', workerRole: 'architect', taskRole: 'architect',
      leaderSessionId: sessionId, taskCreatedAt: '2026-07-20T12:00:00.000Z', completedAt: '2026-07-20T12:02:00.000Z',
      result: JSON.stringify({ schema_version: 1, agent_role: 'architect', verdict: 'approve', session_id: sessionId, input_digest: digest }),
    },
    critic: {
      teamName: 'ralplan-critic', taskId: '1', worker: 'worker-1', workerRole: 'critic', taskRole: 'critic',
      leaderSessionId: sessionId, taskCreatedAt: '2026-07-20T12:03:00.000Z', completedAt: '2026-07-20T12:04:00.000Z',
      result: JSON.stringify({ schema_version: 1, agent_role: 'critic', verdict: 'approve', session_id: sessionId, input_digest: digest }),
    },
    ...overrides,
  };
  return base;
}

describe('team-backed ralplan consensus', () => {
  it('records truthful sequential Architect then Critic Team evidence without relabeling it native', async () => {
    const input = await fixture();
    const evidence = await recordTeamRalplanConsensus(input);
    assert.equal(evidence.complete, true);
    assert.equal(evidence.ralplan_architect_review.provenance_kind, 'omx_team');
    const tracker = JSON.parse(await readFile(subagentTrackingPath(input.cwd), 'utf8'));
    assert.equal(tracker.sessions[input.sessionId].threads['team:ralplan-architect:1'].kind, 'team_worker');
    const terminalGate = buildRalplanConsensusGateForCwd(input.cwd, { sessionId: input.sessionId, requireNativeSubagents: true });
    assert.equal(terminalGate.complete, true, JSON.stringify(terminalGate));
    const terminalError = validateRalplanTerminalConsensus(input.cwd, {
      mode: 'ralplan', active: false, current_phase: 'complete', session_id: input.sessionId,
      native_subagent_support: { status: 'unsupported', reason: 'role_routing_unavailable' },
    }, input.sessionId, { requireNativeSubagents: true });
    assert.equal(terminalError, null);
  });

  for (const [name, mutate, reason] of [
    ['untyped worker', (x: any) => { x.architect.workerRole = 'executor'; }, /worker role/i],
    ['prompt label', (x: any) => { x.architect.workerRole = ''; x.architect.taskRole = 'architect'; }, /worker role/i],
    ['cross session', (x: any) => { x.critic.leaderSessionId = 'other'; }, /session/i],
    ['stale result', (x: any) => { x.critic.result = JSON.stringify({ schema_version: 1, agent_role: 'critic', verdict: 'approve', session_id: x.sessionId, input_digest: 'b'.repeat(64) }); }, /digest/i],
    ['wrong order', (x: any) => { x.critic.taskCreatedAt = x.architect.completedAt; }, /strictly after/i],
    ['incomplete', (x: any) => { x.critic.completedAt = ''; }, /completed/i],
    ['non approval', (x: any) => { x.critic.result = JSON.stringify({ schema_version: 1, agent_role: 'critic', verdict: 'reject', session_id: x.sessionId, input_digest: x.inputDigest }); }, /approve/i],
  ] as const) {
    it(`rejects ${name}`, async () => {
      const input: any = await fixture();
      mutate(input);
      await assert.rejects(recordTeamRalplanConsensus(input), reason);
    });
  }

  it('rejects missing installed roles', async () => {
    const input = await fixture({ roleInstalled: (role: string) => role !== 'critic' });
    await assert.rejects(recordTeamRalplanConsensus(input), /installed Critic role/i);
  });

  it('rejects a fabricated artifact whose digest is not bound by the Team tracker scope', async () => {
    const input = await fixture();
    await recordTeamRalplanConsensus(input);
    const path = subagentTrackingPath(input.cwd);
    const tracker = JSON.parse(await readFile(path, 'utf8'));
    tracker.sessions[input.sessionId].threads['team:ralplan-critic:1'].scope = `ralplan:${'b'.repeat(64)}`;
    await writeFile(path, JSON.stringify(tracker));
    const gate = buildRalplanConsensusGateForCwd(input.cwd, { sessionId: input.sessionId, requireNativeSubagents: true });
    assert.equal(gate.complete, false);
    assert.match(gate.blockedDetails?.join(' ') ?? '', /scope does not match/i);
  });
});
