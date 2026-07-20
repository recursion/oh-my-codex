import { resolveInstalledRoleName } from '../subagents/tracker.js';
import { cancelMode } from '../modes/base.js';
import { digestRalplanInputs, hasInstalledRalplanTeamRoles, recordTeamRalplanConsensusFromState } from '../ralplan/team-consensus.js';

export const RALPLAN_HELP = `omx ralplan - RALPLAN consensus support commands

Usage:
  omx ralplan preflight [--json]
  omx ralplan team-consensus record --session <id> --input <path> [--input <path> ...] --architect-team <name> --architect-task <id> --critic-team <name> --critic-task <id> [--json]
  omx ralplan team-consensus digest --input <path> [--input <path> ...] [--json]
  omx ralplan role-intent write --role <role> --parent-thread <id> [--session <id>] [--ttl-ms <n>] [--json]

Native agent_type routing remains preferred. On attached tmux, preflight may authorize the explicitly typed OMX Team fallback.
`;

type RoleIntentFailureReason = 'unknown_role' | 'unsupported_documented_leader_proof';

interface ParsedRoleIntentWriteArgs {
  role: string;
  parentThreadId: string;
  sessionId?: string;
  ttlMs?: number;
  json: boolean;
}

export interface RalplanCommandDependencies {
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  resolveInstalledRoleName?: typeof resolveInstalledRoleName;
  cancelRalplan?: (cwd?: string) => Promise<void>;
  hasInstalledRalplanTeamRoles?: typeof hasInstalledRalplanTeamRoles;
  recordTeamRalplanConsensusFromState?: typeof recordTeamRalplanConsensusFromState;
  digestRalplanInputs?: typeof digestRalplanInputs;
  isAttachedTmux?: () => boolean;
}

export async function ralplanCommand(
  args: string[],
  deps: RalplanCommandDependencies = {},
): Promise<void> {
  const stdout = deps.stdout ?? ((line: string) => console.log(line));
  const stderr = deps.stderr ?? ((line: string) => console.error(line));
  if (args.length === 0 || args.some((arg) => arg === '--help' || arg === '-h' || arg === 'help')) {
    stdout(RALPLAN_HELP);
    return;
  }
  if (args[0] === 'preflight') {
    const json = args.length === 2 && args[1] === '--json';
    if ((args.length !== 1 && !json)) throw new Error(`Unknown ralplan preflight argument: ${args.slice(1).join(' ')}`);
    if ((deps.isAttachedTmux ?? (() => Boolean(process.env.TMUX)))()
      && (deps.hasInstalledRalplanTeamRoles ?? hasInstalledRalplanTeamRoles)(process.cwd(), process.env.CODEX_HOME)) {
      const capability = { ok: true, provenance_kind: 'omx_team', native_preferred: true, sequence: ['architect-review', 'critic-review'] };
      if (json) stdout(JSON.stringify(capability));
      else stdout('ralplan preflight: native routing unavailable; typed OMX Team Architect -> Critic fallback is available');
      return;
    }
    await (deps.cancelRalplan ?? ((cwd?: string) => cancelMode('ralplan', cwd)))(process.cwd());
    const failure = { ok: false, reason: 'unsupported_documented_leader_proof' as const };
    if (json) stdout(JSON.stringify(failure));
    else stderr('ralplan preflight failed: unsupported_documented_leader_proof');
    process.exitCode = 1;
    return;
  }

  if (args[0] === 'team-consensus' && args[1] === 'record') {
    const parsed = parseTeamConsensusRecordArgs(args.slice(2));
    const evidence = await (deps.recordTeamRalplanConsensusFromState ?? recordTeamRalplanConsensusFromState)({
      cwd: process.cwd(), sessionId: parsed.sessionId, inputPaths: parsed.inputPaths,
      architect: { teamName: parsed.architectTeam, taskId: parsed.architectTask },
      critic: { teamName: parsed.criticTeam, taskId: parsed.criticTask },
      codexHome: process.env.CODEX_HOME,
    });
    stdout(parsed.json ? JSON.stringify({ ok: true, evidence }) : 'recorded tracker-backed OMX Team Ralplan consensus');
    return;
  }
  if (args[0] === 'team-consensus' && args[1] === 'digest') {
    const { inputPaths, json } = parseTeamConsensusDigestArgs(args.slice(2));
    const inputDigest = await (deps.digestRalplanInputs ?? digestRalplanInputs)(inputPaths);
    stdout(json ? JSON.stringify({ ok: true, input_digest: inputDigest }) : inputDigest);
    return;
  }

  if (args[0] !== 'role-intent' || args[1] !== 'write') {
    throw new Error(`Unknown ralplan command: ${args.join(' ')}\n${RALPLAN_HELP}`);
  }

  const parsed = parseRoleIntentWriteArgs(args.slice(2));
  const role = (deps.resolveInstalledRoleName ?? resolveInstalledRoleName)(parsed.role);
  emitRoleIntentFailure(
    role ? 'unsupported_documented_leader_proof' : 'unknown_role',
    parsed.json,
    stdout,
    stderr,
  );
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
    if (!['--session', '--input', '--architect-team', '--architect-task', '--critic-team', '--critic-task'].includes(arg)) {
      throw new Error(`Unknown team-consensus argument: ${arg}`);
    }
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Missing value after ${arg}.`);
    if (arg === '--input') inputPaths.push(value); else values[arg] = value;
  }
  for (const key of ['--session', '--architect-team', '--architect-task', '--critic-team', '--critic-task']) {
    if (!values[key]) throw new Error(`Missing required ${key}.`);
  }
  if (inputPaths.length === 0) throw new Error('Missing required --input.');
  return {
    sessionId: values['--session']!, inputPaths,
    architectTeam: values['--architect-team']!, architectTask: values['--architect-task']!,
    criticTeam: values['--critic-team']!, criticTask: values['--critic-task']!, json,
  };
}

function parseRoleIntentWriteArgs(args: string[]): ParsedRoleIntentWriteArgs {
  let role: string | undefined;
  let parentThreadId: string | undefined;
  let sessionId: string | undefined;
  let ttlMs: number | undefined;
  let json = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') {
      json = true;
      continue;
    }
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
    if (arg.startsWith('--role=')) {
      role = arg.slice('--role='.length);
      continue;
    }
    if (arg.startsWith('--parent-thread=')) {
      parentThreadId = arg.slice('--parent-thread='.length);
      continue;
    }
    if (arg.startsWith('--session=')) {
      sessionId = arg.slice('--session='.length);
      continue;
    }
    if (arg.startsWith('--ttl-ms=')) {
      ttlMs = parseTtlMs(arg.slice('--ttl-ms='.length));
      continue;
    }
    throw new Error(`Unknown role-intent write argument: ${arg}`);
  }

  if (!role?.trim()) throw new Error('Missing --role.');
  if (!parentThreadId?.trim()) throw new Error('Missing --parent-thread.');
  return {
    role,
    parentThreadId,
    ...(sessionId === undefined ? {} : { sessionId }),
    ...(ttlMs === undefined ? {} : { ttlMs }),
    json,
  };
}

function parseTtlMs(value: string): number {
  const ttlMs = Number(value);
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new Error('--ttl-ms must be a positive integer.');
  }
  return ttlMs;
}

function emitRoleIntentFailure(
  reason: RoleIntentFailureReason,
  json: boolean,
  stdout: (line: string) => void,
  stderr: (line: string) => void,
): void {
  const failure = { ok: false, reason };
  if (json) stdout(JSON.stringify(failure));
  else stderr(`role-intent write failed: ${reason}`);
  process.exitCode = 1;
}
