import { createHash, randomUUID } from 'node:crypto';

import { buildRoleIntentSpawnTaskName, isAppCompatibleSpawnTaskName, parseRoleIntentCorrelationToken, ROLE_INTENT_CORRELATION_TOKEN_PATTERN } from '../leader/contract.js';
import { resolveRuntimeStateScope } from '../mcp/state-paths.js';
import { cancelMode } from '../modes/base.js';
import {
  ADAPTED_PROVENANCE_ACKNOWLEDGEMENT,
  consumeAdaptedProvenanceAuthorization,
  issueAdaptedProvenancePolicy,
  readValidAdaptedProvenancePolicy,
} from '../ralplan/adapted-provenance-policy.js';
import { isCodex01445AdaptedProvenanceGrantCommand } from '../ralplan/documented-leader-preflight.js';
import { digestRalplanInputs, hasInstalledRalplanTeamRoles, recordTeamRalplanConsensusFromState } from '../ralplan/team-consensus.js';
import { hasVerifiedPluginLaunchClaim } from '../subagents/native-anchor-auth.js';
import { ensureLeaderAndRecordIntent, hasLeaderSubagentCollision, hasVerifiedLeaderAttestation, type PendingRoleIntent, readSubagentTrackingStateStrict, resolveInstalledRoleName } from '../subagents/tracker.js';

const MAX_ADAPTED_PROVENANCE_GRANT_ATTESTATION_AGE_MS = 60_000;

export const RALPLAN_HELP = `omx ralplan - RALPLAN consensus support commands

Usage:
  omx ralplan preflight [--adapted-provenance] [--json]
  omx ralplan team-consensus digest --input <path> [--input <path> ...] [--json]
  omx ralplan team-consensus record --session <id> --input <path> [--input <path> ...] --architect-team <name> --architect-task <id> --critic-team <name> --critic-task <id> [--json]
  omx ralplan adapted-provenance grant --plan <repo-relative-plan-path> --acknowledge ${ADAPTED_PROVENANCE_ACKNOWLEDGEMENT} [--ttl-ms <n>] [--json]
  omx ralplan role-intent write --role <role> --parent-thread <id> [--session <id>] [--ttl-ms <n>] [--json]
`;

type RoleIntentFailureReason = 'unknown_role' | 'invalid_correlation_token' | 'invalid_origin' | 'single_flight_conflict' | 'session_not_current' | 'spawn_task_name_unsupported' | 'native_anchor_unavailable' | 'native_anchor_mismatch' | 'unsupported_documented_leader_proof' | 'adapted_provenance_policy_required' | 'invalid_adapted_provenance_policy' | 'invalid_adapted_provenance_policy_signature' | 'foreign_adapted_provenance_policy' | 'stale_adapted_provenance_policy' | 'adapted_provenance_plan_drift' | 'adapted_provenance_plan_amendment_required' | 'invalid_adapted_provenance_plan_path' | 'invalid_adapted_provenance_plan' | 'invalid_policy_session' | 'invalid_policy_clock' | 'adapted_provenance_acknowledgement_required' | 'invalid_adapted_provenance_policy_ttl' | 'adapted_provenance_policy_write_failed' | 'invalid_adapted_provenance_transition';

interface ParsedRoleIntentWriteArgs {
  role: string;
  parentThreadId: string;
  sessionId?: string;
  ttlMs?: number;
  json: boolean;
}

interface ParsedAdaptedProvenanceGrantArgs {
  planPath: string;
  acknowledgement: string;
  ttlMs: number;
  json: boolean;
}

interface ParsedPreflightArgs {
  requireAdaptedProvenance: boolean;
  json: boolean;
}

function isSupportedCorrelationToken(token: string): boolean {
  const taskName = buildRoleIntentSpawnTaskName(token);
  return ROLE_INTENT_CORRELATION_TOKEN_PATTERN.test(token)
    && isAppCompatibleSpawnTaskName(taskName)
    && parseRoleIntentCorrelationToken(taskName) === token;
}

export interface RalplanCommandDependencies {
  cwd?: () => string;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  resolveSessionScope?: typeof resolveRuntimeStateScope;
  resolveInstalledRoleName?: typeof resolveInstalledRoleName;
  readTrackingState?: typeof readSubagentTrackingStateStrict;
  verifyLeaderAttestation?: typeof hasVerifiedLeaderAttestation;
  verifyPluginLaunchClaim?: typeof hasVerifiedPluginLaunchClaim;
  readAdaptedProvenancePolicy?: typeof readValidAdaptedProvenancePolicy;
  issueAdaptedProvenancePolicy?: typeof issueAdaptedProvenancePolicy;
  consumeAdaptedProvenanceAuthorization?: typeof consumeAdaptedProvenanceAuthorization;
  ensureLeaderAndRecordIntent?: typeof ensureLeaderAndRecordIntent;
  generateCorrelationToken?: () => string;
  cancelRalplan?: (cwd?: string) => Promise<void>;
  hasInstalledRalplanTeamRoles?: typeof hasInstalledRalplanTeamRoles;
  recordTeamRalplanConsensusFromState?: typeof recordTeamRalplanConsensusFromState;
  digestRalplanInputs?: typeof digestRalplanInputs;
  isAttachedTmux?: () => boolean;
}

export async function ralplanCommand(args: string[], deps: RalplanCommandDependencies = {}): Promise<void> {
  const stdout = deps.stdout ?? ((line: string) => console.log(line));
  const stderr = deps.stderr ?? ((line: string) => console.error(line));
  if (args.length === 0 || args.some((arg) => arg === '--help' || arg === '-h' || arg === 'help')) {
    stdout(RALPLAN_HELP);
    return;
  }
  if (args[0] === 'preflight') {
    const { requireAdaptedProvenance, json } = parsePreflightArgs(args.slice(1));
    const cwd = (deps.cwd ?? process.cwd)();
    const scope = await (deps.resolveSessionScope ?? resolveRuntimeStateScope)(cwd);
    const tracking = await (deps.readTrackingState ?? readSubagentTrackingStateStrict)(cwd);
    const leader = scope.sessionId && tracking.ok ? tracking.state.sessions[scope.sessionId]?.leader_thread_id?.trim() : undefined;
    const attested = scope.sessionId && tracking.ok ? (deps.verifyLeaderAttestation ?? hasVerifiedLeaderAttestation)(scope.sessionId, tracking.state.sessions[scope.sessionId]) : false;
    const collision = tracking.ok && leader ? hasLeaderSubagentCollision(tracking.state, leader) : true;
    if (scope.sessionId && leader && attested && !collision) {
      if (requireAdaptedProvenance) {
        const policy = (deps.readAdaptedProvenancePolicy ?? readValidAdaptedProvenancePolicy)(scope.cwd, scope.sessionId);
        if (!policy.ok) {
          await (deps.cancelRalplan ?? ((value?: string) => cancelMode('ralplan', value)))(cwd);
          emitRoleIntentFailure(policy.reason as RoleIntentFailureReason, json, stdout, stderr);
          return;
        }
      }
      if (json) stdout(JSON.stringify({ ok: true, session_id: scope.sessionId, leader_thread_id: leader }));
      else stdout(`ralplan preflight authenticated: session=${scope.sessionId} leader-thread=${leader}`);
      return;
    }
    if (!requireAdaptedProvenance
      && (deps.isAttachedTmux ?? (() => Boolean(process.env.TMUX)))()
      && (deps.hasInstalledRalplanTeamRoles ?? hasInstalledRalplanTeamRoles)(cwd, process.env.CODEX_HOME)) {
      const capability = { ok: true, provenance_kind: 'omx_team', native_preferred: true, sequence: ['architect-review', 'critic-review'] };
      if (json) stdout(JSON.stringify(capability));
      else stdout('ralplan preflight: authenticated native/adapted routing unavailable; typed OMX Team Architect -> Critic fallback is available');
      return;
    }
    await (deps.cancelRalplan ?? ((value?: string) => cancelMode('ralplan', value)))(cwd);
    emitRoleIntentFailure('unsupported_documented_leader_proof', json, stdout, stderr);
    return;
  }
  if (args[0] === 'team-consensus' && args[1] === 'digest') {
    const { inputPaths, json } = parseTeamConsensusDigestArgs(args.slice(2));
    const inputDigest = await (deps.digestRalplanInputs ?? digestRalplanInputs)(inputPaths);
    stdout(json ? JSON.stringify({ ok: true, input_digest: inputDigest }) : inputDigest);
    return;
  }
  if (args[0] === 'team-consensus' && args[1] === 'record') {
    const parsed = parseTeamConsensusRecordArgs(args.slice(2));
    const cwd = (deps.cwd ?? process.cwd)();
    const evidence = await (deps.recordTeamRalplanConsensusFromState ?? recordTeamRalplanConsensusFromState)({
      cwd, sessionId: parsed.sessionId, inputPaths: parsed.inputPaths,
      architect: { teamName: parsed.architectTeam, taskId: parsed.architectTask },
      critic: { teamName: parsed.criticTeam, taskId: parsed.criticTask },
      codexHome: process.env.CODEX_HOME,
    });
    stdout(parsed.json ? JSON.stringify({ ok: true, evidence }) : 'recorded tracker-backed OMX Team Ralplan consensus');
    return;
  }
  if (args[0] === 'adapted-provenance' && args[1] === 'grant') {
    const parsed = parseAdaptedProvenanceGrantArgs(args.slice(2));
    const cwd = (deps.cwd ?? process.cwd)();
    const scope = await (deps.resolveSessionScope ?? resolveRuntimeStateScope)(cwd);
    if (!scope.sessionId || !scope.metadata || scope.metadata.sessionId !== scope.sessionId) {
      emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
      return;
    }
    const tracking = await (deps.readTrackingState ?? readSubagentTrackingStateStrict)(scope.cwd);
    const session = tracking.ok ? tracking.state.sessions[scope.sessionId] : undefined;
    const attested = tracking.ok && session
      ? (deps.verifyLeaderAttestation ?? hasVerifiedLeaderAttestation)(scope.sessionId, session)
      : false;
    if (!session || !attested || !hasFreshAdaptedProvenanceLauncher(scope.cwd, scope.metadata.nativeSessionId, session.leader_attested_at, deps)
      || hasLeaderSubagentCollision(tracking.ok ? tracking.state : { schemaVersion: 1, sessions: {}, pending_role_intents: [] }, session.leader_thread_id ?? '')) {
      emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
      return;
    }
    if (!(deps.consumeAdaptedProvenanceAuthorization ?? consumeAdaptedProvenanceAuthorization)({
      cwd: scope.cwd,
      sessionId: scope.sessionId,
      nativeSessionId: scope.metadata.nativeSessionId!,
      operation: 'grant',
      commandSha256: createHash('sha256').update(['omx', 'ralplan', ...args].join(' ')).digest('hex'),
    })) {
      emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
      return;
    }
    const issued = (deps.issueAdaptedProvenancePolicy ?? issueAdaptedProvenancePolicy)({
      cwd: scope.cwd,
      sessionId: scope.sessionId,
      planPath: parsed.planPath,
      acknowledgement: parsed.acknowledgement,
      ttlMs: parsed.ttlMs,
    });
    if (!issued.ok) {
      emitRoleIntentFailure(issued.reason as RoleIntentFailureReason, parsed.json, stdout, stderr);
      return;
    }
    const receipt = {
      ok: true,
      policy: {
        scope: issued.policy.scope,
        policy_id: issued.policy.policyId,
        session_id: issued.policy.sessionId,
        plan_path: issued.policy.planPath,
        plan_sha256: issued.policy.planSha256,
        expires_at: issued.policy.expiresAt,
      },
    };
    if (parsed.json) stdout(JSON.stringify(receipt));
    else stdout(`adapted provenance granted: scope=${issued.policy.scope} session=${issued.policy.sessionId} plan=${issued.policy.planPath} expires-at=${issued.policy.expiresAt}`);
    return;
  }
  if (args[0] !== 'role-intent' || args[1] !== 'write') throw new Error(`Unknown ralplan command: ${args.join(' ')}\n${RALPLAN_HELP}`);

  const parsed = parseRoleIntentWriteArgs(args.slice(2));
  const cwd = (deps.cwd ?? process.cwd)();
  const installedRole = (deps.resolveInstalledRoleName ?? resolveInstalledRoleName)(parsed.role, undefined, cwd);
  if (!installedRole) {
    emitRoleIntentFailure('unknown_role', parsed.json, stdout, stderr);
    return;
  }
  const resolveSessionScope = deps.resolveSessionScope ?? resolveRuntimeStateScope;
  const currentScope = await resolveSessionScope(cwd);
  if (!currentScope.sessionId || !currentScope.metadata || currentScope.metadata.sessionId !== currentScope.sessionId) {
    emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
    return;
  }
  if (parsed.sessionId !== undefined && (await resolveSessionScope(cwd, parsed.sessionId)).sessionId !== currentScope.sessionId) {
    emitRoleIntentFailure('session_not_current', parsed.json, stdout, stderr);
    return;
  }
  const anchorTracking = await (deps.readTrackingState ?? readSubagentTrackingStateStrict)(currentScope.cwd);
  const anchorSession = anchorTracking.ok ? anchorTracking.state.sessions[currentScope.sessionId] : undefined;
  const anchorAttested = anchorTracking.ok && anchorSession
    ? (deps.verifyLeaderAttestation ?? hasVerifiedLeaderAttestation)(currentScope.sessionId, anchorSession)
    : false;
  if (!anchorSession || !anchorAttested
    || !hasFreshAdaptedProvenanceLauncher(currentScope.cwd, currentScope.metadata?.nativeSessionId, anchorSession.leader_attested_at, deps)
    || anchorSession.leader_thread_id !== parsed.parentThreadId
    || hasLeaderSubagentCollision(anchorTracking.ok ? anchorTracking.state : { schemaVersion: 1, sessions: {}, pending_role_intents: [] }, parsed.parentThreadId)) {
    emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
    return;
  }
  if (!(deps.consumeAdaptedProvenanceAuthorization ?? consumeAdaptedProvenanceAuthorization)({
    cwd: currentScope.cwd,
    sessionId: currentScope.sessionId,
    nativeSessionId: currentScope.metadata!.nativeSessionId!,
    operation: 'role-intent',
    role: installedRole,
    parentThreadId: parsed.parentThreadId,
  })) {
    emitRoleIntentFailure('native_anchor_unavailable', parsed.json, stdout, stderr);
    return;
  }
  const policy = (deps.readAdaptedProvenancePolicy ?? readValidAdaptedProvenancePolicy)(currentScope.cwd, currentScope.sessionId);
  if (!policy.ok) {
    emitRoleIntentFailure(policy.reason as RoleIntentFailureReason, parsed.json, stdout, stderr);
    return;
  }
  const correlationToken = (deps.generateCorrelationToken ?? (() => randomUUID().replace(/-/g, '')))();
  if (!isSupportedCorrelationToken(correlationToken)) {
    emitRoleIntentFailure('spawn_task_name_unsupported', parsed.json, stdout, stderr);
    return;
  }
  const result = (deps.ensureLeaderAndRecordIntent ?? ensureLeaderAndRecordIntent)(currentScope.cwd, {
    role: installedRole,
    sessionId: currentScope.sessionId,
    parentThreadId: parsed.parentThreadId,
    correlationToken,
    ...(parsed.ttlMs === undefined ? {} : { ttlMs: parsed.ttlMs }),
    adaptedPolicy: {
      scope: policy.policy.scope,
      policy_id: policy.policy.policyId,
      origin_cwd: policy.policy.originCwd,
      plan_path: policy.policy.planPath,
      plan_sha256: policy.policy.planSha256,
      launch_id: policy.policy.launchId,
      issued_at: policy.policy.issuedAt,
      expires_at: policy.policy.expiresAt,
    },
  });
  if (!result.ok) {
    emitRoleIntentFailure(result.reason, parsed.json, stdout, stderr);
    return;
  }
  const intent: PendingRoleIntent = result.intent;
  const spawnTaskName = buildRoleIntentSpawnTaskName(intent.correlation_token);
  if (!isSupportedCorrelationToken(intent.correlation_token)) {
    emitRoleIntentFailure('spawn_task_name_unsupported', parsed.json, stdout, stderr);
    return;
  }
  const receipt = {
    ok: true,
    intent: {
      role: intent.role,
      session_id: intent.session_id,
      parent_thread_id: intent.parent_thread_id,
      correlation_token: intent.correlation_token,
      expires_at: intent.expires_at,
    },
    spawn_task_name: spawnTaskName,
  };
  if (parsed.json) stdout(JSON.stringify(receipt));
  else stdout(`role-intent recorded: role=${intent.role} session=${intent.session_id} parent-thread=${intent.parent_thread_id} correlation-token=${intent.correlation_token} spawn-task-name=${spawnTaskName} expires-at=${intent.expires_at}`);
}

function parseTeamConsensusDigestArgs(args: string[]) {
  const inputPaths: string[] = [];
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--json') { json = true; continue; }
    if (arg !== '--input') throw new Error(`Unknown team-consensus digest argument: ${arg}`);
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error('Missing value after --input.');
    inputPaths.push(value);
  }
  if (inputPaths.length === 0) throw new Error('Missing required --input.');
  return { inputPaths, json };
}

function parseTeamConsensusRecordArgs(args: string[]) {
  const values: Record<string, string> = {};
  const inputPaths: string[] = [];
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === '--json') { json = true; continue; }
    if (!['--session', '--input', '--architect-team', '--architect-task', '--critic-team', '--critic-task'].includes(arg)) throw new Error(`Unknown team-consensus argument: ${arg}`);
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Missing value after ${arg}.`);
    if (arg === '--input') inputPaths.push(value); else values[arg] = value;
  }
  for (const key of ['--session', '--architect-team', '--architect-task', '--critic-team', '--critic-task']) if (!values[key]) throw new Error(`Missing required ${key}.`);
  if (inputPaths.length === 0) throw new Error('Missing required --input.');
  return { sessionId: values['--session']!, inputPaths, architectTeam: values['--architect-team']!, architectTask: values['--architect-task']!, criticTeam: values['--critic-team']!, criticTask: values['--critic-task']!, json };
}

function parsePreflightArgs(args: string[]): ParsedPreflightArgs {
  let requireAdaptedProvenance = false;
  let json = false;
  for (const arg of args) {
    if (arg === '--adapted-provenance') {
      if (requireAdaptedProvenance) throw new Error(`Duplicate ralplan preflight argument: ${arg}`);
      requireAdaptedProvenance = true;
      continue;
    }
    if (arg === '--json') {
      if (json) throw new Error(`Duplicate ralplan preflight argument: ${arg}`);
      json = true;
      continue;
    }
    throw new Error(`Unknown ralplan preflight argument: ${arg}`);
  }
  return { requireAdaptedProvenance, json };
}

function hasFreshAdaptedProvenanceLauncher(
  cwd: string,
  nativeSessionId: string | undefined,
  attestedAt: string | undefined,
  deps: RalplanCommandDependencies,
): boolean {
  const attestedAtMs = Date.parse(attestedAt ?? '');
  const nowMs = Date.now();
  return Boolean(nativeSessionId
    && Number.isFinite(attestedAtMs)
    && attestedAtMs <= nowMs
    && nowMs - attestedAtMs <= MAX_ADAPTED_PROVENANCE_GRANT_ATTESTATION_AGE_MS
    && (deps.verifyPluginLaunchClaim ?? hasVerifiedPluginLaunchClaim)(cwd, nativeSessionId));
}

function parseAdaptedProvenanceGrantArgs(args: string[]): ParsedAdaptedProvenanceGrantArgs {
  const command = ['omx', 'ralplan', 'adapted-provenance', 'grant', ...args].join(' ');
  if (!isCodex01445AdaptedProvenanceGrantCommand(command)) {
    throw new Error('Adapted-provenance grant must use the canonical --plan <path> --acknowledge I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE [--ttl-ms <n>] [--json] form.');
  }
  const planPath = args[1]!;
  const acknowledgement = args[3]!;
  let ttlMs = 30 * 60_000;
  let json = false;
  for (let index = 4; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') { json = true; continue; }
    if (arg === '--ttl-ms') {
      ttlMs = parseTtlMs(args[index + 1]!);
      index += 1;
      continue;
    }
    throw new Error(`Unknown adapted-provenance grant argument: ${arg}`);
  }
  return { planPath, acknowledgement, ttlMs, json };
}

function parseRoleIntentWriteArgs(args: string[]): ParsedRoleIntentWriteArgs {
  let role: string | undefined;
  let parentThreadId: string | undefined;
  let sessionId: string | undefined;
  let ttlMs: number | undefined;
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') { json = true; continue; }
    if (arg === '--role' || arg === '--parent-thread' || arg === '--session' || arg === '--ttl-ms') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`Missing value after ${arg}.`);
      if (arg === '--role') role = value;
      if (arg === '--parent-thread') parentThreadId = value;
      if (arg === '--session') sessionId = value;
      if (arg === '--ttl-ms') ttlMs = parseTtlMs(value);
      index += 1;
      continue;
    }
    if (arg.startsWith('--role=')) role = arg.slice('--role='.length);
    else if (arg.startsWith('--parent-thread=')) parentThreadId = arg.slice('--parent-thread='.length);
    else if (arg.startsWith('--session=')) sessionId = arg.slice('--session='.length);
    else if (arg.startsWith('--ttl-ms=')) ttlMs = parseTtlMs(arg.slice('--ttl-ms='.length));
    else throw new Error(`Unknown role-intent write argument: ${arg}`);
  }
  if (!role?.trim()) throw new Error('Missing --role.');
  if (!parentThreadId?.trim()) throw new Error('Missing --parent-thread.');
  return { role, parentThreadId, ...(sessionId === undefined ? {} : { sessionId }), ...(ttlMs === undefined ? {} : { ttlMs }), json };
}

function parseTtlMs(value: string): number {
  const ttlMs = Number(value);
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('--ttl-ms must be a positive integer.');
  return ttlMs;
}

function emitRoleIntentFailure(reason: RoleIntentFailureReason, json: boolean, stdout: (line: string) => void, stderr: (line: string) => void): void {
  const failure = { ok: false, reason };
  if (json) stdout(JSON.stringify(failure));
  else stderr(`role-intent write failed: ${reason}`);
  process.exitCode = 1;
}
