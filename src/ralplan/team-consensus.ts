import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { getBaseStateDir } from '../state/paths.js';
import { OMX_TEAM_PROVENANCE, recordSubagentTurnForSession, subagentTrackingPath } from '../subagents/tracker.js';
import { readTask, readTeamManifestV2 } from '../team/state.js';
import { codexAgentsDir, projectCodexAgentsDir } from '../utils/paths.js';

export type RalplanTeamRole = 'architect' | 'critic';

export interface RalplanTeamLaneInput {
  teamName: string;
  taskId: string;
  worker: string;
  workerRole: string;
  taskRole: string;
  leaderSessionId: string;
  taskCreatedAt: string;
  completedAt: string;
  result: string;
}

export interface RecordTeamRalplanConsensusInput {
  cwd: string;
  sessionId: string;
  inputDigest: string;
  architect: RalplanTeamLaneInput;
  critic: RalplanTeamLaneInput;
  roleInstalled?: (role: RalplanTeamRole) => boolean;
}

export interface RecordTeamRalplanConsensusFromStateInput {
  cwd: string;
  sessionId: string;
  inputPaths: string[];
  architect: { teamName: string; taskId: string };
  critic: { teamName: string; taskId: string };
  codexHome?: string;
}

export interface RalplanTeamReviewEvidence extends Record<string, unknown> {
  agent_role: RalplanTeamRole;
  provenance_kind: 'omx_team';
  session_id: string;
  thread_id: string;
  tracker_path: string;
  team_name: string;
  task_id: string;
  worker: string;
  input_digest: string;
  verdict: 'approve';
  created_at: string;
  completed_at: string;
}

function validTimestamp(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a valid timestamp`);
  return parsed;
}

function validateLane(
  lane: RalplanTeamLaneInput,
  role: RalplanTeamRole,
  input: RecordTeamRalplanConsensusInput,
): RalplanTeamReviewEvidence {
  if (input.roleInstalled && !input.roleInstalled(role)) throw new Error(`Ralplan Team consensus requires an explicitly installed ${role === 'architect' ? 'Architect' : 'Critic'} role`);
  if (lane.workerRole !== role) throw new Error(`${role} Team worker role must be exactly ${role}`);
  if (lane.taskRole !== role) throw new Error(`${role} Team task role must be exactly ${role}`);
  if (lane.leaderSessionId !== input.sessionId) throw new Error(`${role} Team leader session does not match the current Ralplan session`);
  if (!lane.completedAt) throw new Error(`${role} Team review is not completed`);
  validTimestamp(lane.taskCreatedAt, `${role} task created_at`);
  validTimestamp(lane.completedAt, `${role} completed_at`);

  let result: Record<string, unknown>;
  try { result = JSON.parse(lane.result) as Record<string, unknown>; }
  catch { throw new Error(`${role} Team result must be a structured JSON approval envelope`); }
  if (result.schema_version !== 1) throw new Error(`${role} Team result has unsupported schema_version`);
  if (result.agent_role !== role) throw new Error(`${role} Team result agent_role is not ${role}`);
  if (result.verdict !== 'approve' || result.approved === false || result.blocking === true || result.clean === false) {
    throw new Error(`${role} Team result is not an unqualified approve verdict`);
  }
  if (result.session_id !== input.sessionId) throw new Error(`${role} Team result session does not match the current Ralplan session`);
  if (result.input_digest !== input.inputDigest) throw new Error(`${role} Team result input digest does not match the current planning inputs`);

  const threadId = `team:${lane.teamName}:${lane.taskId}`;
  return {
    agent_role: role,
    provenance_kind: OMX_TEAM_PROVENANCE,
    session_id: input.sessionId,
    thread_id: threadId,
    tracker_path: subagentTrackingPath(input.cwd),
    team_name: lane.teamName,
    task_id: lane.taskId,
    worker: lane.worker,
    input_digest: input.inputDigest,
    verdict: 'approve',
    created_at: lane.taskCreatedAt,
    completed_at: lane.completedAt,
  };
}

async function writeAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(temporary, path);
}

export function teamRalplanConsensusArtifactPath(cwd: string, sessionId: string): string {
  return join(getBaseStateDir(cwd), 'sessions', sessionId, 'ralplan-team-consensus.json');
}

export async function digestRalplanInputs(paths: string[]): Promise<string> {
  if (paths.length === 0) throw new Error('At least one exact Ralplan planning input path is required');
  const hash = createHash('sha256');
  for (const path of [...new Set(paths)].sort()) {
    hash.update(path); hash.update('\0'); hash.update(await readFile(path)); hash.update('\0');
  }
  return hash.digest('hex');
}

function installedRoleFile(role: RalplanTeamRole, codexHome: string | undefined, cwd: string): boolean {
  return [codexAgentsDir(codexHome), projectCodexAgentsDir(cwd)].some((dir) => existsSync(join(dir, `${role}.toml`)));
}

export function hasInstalledRalplanTeamRoles(cwd: string, codexHome?: string): boolean {
  return installedRoleFile('architect', codexHome, cwd) && installedRoleFile('critic', codexHome, cwd);
}

async function readLaneFromTeamState(
  cwd: string,
  role: RalplanTeamRole,
  ref: { teamName: string; taskId: string },
): Promise<RalplanTeamLaneInput> {
  const [manifest, task] = await Promise.all([
    readTeamManifestV2(ref.teamName, cwd),
    readTask(ref.teamName, ref.taskId, cwd),
  ]);
  if (!manifest) throw new Error(`${role} Team manifest is missing`);
  if (!task) throw new Error(`${role} Team task is missing`);
  if (task.status !== 'completed' || !task.completed_at) throw new Error(`${role} Team review is not completed`);
  const owner = task.owner?.trim() ?? '';
  const worker = manifest.workers.find((candidate) => candidate.name === owner);
  if (!worker) throw new Error(`${role} Team task owner is not a manifest worker`);
  return {
    teamName: ref.teamName,
    taskId: ref.taskId,
    worker: owner,
    workerRole: worker.role,
    taskRole: task.role?.trim() ?? '',
    leaderSessionId: manifest.leader.session_id,
    taskCreatedAt: task.created_at,
    completedAt: task.completed_at,
    result: task.result ?? '',
  };
}

export async function recordTeamRalplanConsensusFromState(input: RecordTeamRalplanConsensusFromStateInput) {
  const inputDigest = await digestRalplanInputs(input.inputPaths);
  const [architect, critic] = await Promise.all([
    readLaneFromTeamState(input.cwd, 'architect', input.architect),
    readLaneFromTeamState(input.cwd, 'critic', input.critic),
  ]);
  return recordTeamRalplanConsensus({
    cwd: input.cwd,
    sessionId: input.sessionId,
    inputDigest,
    architect,
    critic,
    roleInstalled: (role) => installedRoleFile(role, input.codexHome, input.cwd),
  });
}

export async function recordTeamRalplanConsensus(input: RecordTeamRalplanConsensusInput) {
  if (!/^[a-f0-9]{64}$/.test(input.inputDigest)) throw new Error('Ralplan planning input digest must be a lowercase SHA-256 hex value');
  const architect = validateLane(input.architect, 'architect', input);
  const critic = validateLane(input.critic, 'critic', input);
  if (architect.thread_id === critic.thread_id) throw new Error('Architect and Critic Team reviews must use distinct lanes');
  if (validTimestamp(input.critic.taskCreatedAt, 'critic task created_at') <= validTimestamp(input.architect.completedAt, 'architect completed_at')) {
    throw new Error('Critic Team task must be created strictly after Architect completion');
  }

  for (const review of [architect, critic]) {
    await recordSubagentTurnForSession(input.cwd, {
      sessionId: input.sessionId,
      threadId: review.thread_id,
      timestamp: review.created_at,
      kind: 'team_worker',
      role: review.agent_role,
      provenanceKind: OMX_TEAM_PROVENANCE,
      laneId: review.team_name,
      scope: `ralplan:${review.input_digest}`,
      status: 'available',
    });
    await recordSubagentTurnForSession(input.cwd, {
      sessionId: input.sessionId,
      threadId: review.thread_id,
      timestamp: review.completed_at,
      kind: 'team_worker',
      role: review.agent_role,
      provenanceKind: OMX_TEAM_PROVENANCE,
      laneId: review.team_name,
      scope: `ralplan:${review.input_digest}`,
      completed: true,
      completionSource: 'omx_team_task',
      status: 'closed',
    });
  }

  const evidence = {
    complete: true,
    sequence: ['architect-review', 'critic-review'] as const,
    input_digest: input.inputDigest,
    ralplan_architect_review: architect,
    ralplan_critic_review: critic,
  };
  await writeAtomic(teamRalplanConsensusArtifactPath(input.cwd, input.sessionId), evidence);
  return evidence;
}
