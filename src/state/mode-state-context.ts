import { randomUUID } from 'crypto';
import { readExactPaneProofSync } from '../team/exact-pane.js';
import { spawnPlatformCommandSync } from '../utils/platform-command.js';
import { parseExactTmuxAuthorityScalar } from '../hud/tmux.js';


import { execFileSync } from 'child_process';

export interface ModeStateContextLike {
  active?: unknown;
  mode?: unknown;
  tmux_pane_id?: unknown;
  tmux_pane_pid?: unknown;
  tmux_pane_owner_id?: unknown;
  tmux_pane_set_at?: unknown;
  tmux_session_name?: unknown;
  tmux_window_id?: unknown;
  [key: string]: unknown;
}

export function captureTmuxPaneFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const value = env.TMUX_PANE;
  if (typeof value !== 'string') return null;
  const pane = value.trim();
  return pane.length > 0 ? pane : null;
}

export function captureTmuxWindowForPane(pane: string, env: NodeJS.ProcessEnv = process.env): string | null {
  if (!pane || !env.TMUX || env.OMX_TMUX_HUD_OWNER !== '1') return null;
  try {
    const tmux = env.TMUX_BINARY || 'tmux';
    const windowId = execFileSync(tmux, ['display-message', '-p', '-t', pane, '#{window_id}'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
      windowsHide: true,
    }).trim();
    return windowId.length > 0 ? windowId : null;
  } catch {
    return null;
  }
}

function hasNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.trim() !== '';
}

export const OMX_RALPH_PANE_OWNER_OPTION = '@omx_ralph_pane_owner_id';

export interface RalphExpectedAuthority {
  pane_id: string;
  pane_pid: number;
  session_name: string;
  pane_instance_id: string;
  pane_owner_id: string;
}

interface RalphPaneBinding {
  paneId: string;
  panePid: number;
  sessionName: string;
  paneOwnerId: string;
  expectedAuthority: RalphExpectedAuthority;
}

function exactNonEmptyTmuxScalar(value: unknown): string | null {
  return typeof value === 'string' ? parseExactTmuxAuthorityScalar(value) : null;
}


function clearRalphPaneBinding(state: ModeStateContextLike): void {
  delete state.tmux_pane_id;
  delete state.tmux_pane_pid;
  delete state.tmux_pane_owner_id;
  delete state.tmux_session_name;
  delete state.tmux_pane_set_at;
  delete state.tmux_window_id;
  delete state.ralph_expected_authority;
}

function setRalphExpectedAuthority(state: ModeStateContextLike, authority: RalphExpectedAuthority): void {
  state.ralph_expected_authority = authority;
}


function isSafeRalphTmuxAuthorityToken(value: string): boolean {
  return /^[A-Za-z0-9_.:-]+$/.test(value);
}

function captureRalphPaneBinding(paneId: string): RalphPaneBinding | null {
  const initialProof = readExactPaneProofSync(paneId);
  if (initialProof.status !== 'live') return null;

  const snapshot = spawnPlatformCommandSync(
    'tmux',
    ['display-message', '-p', '-t', initialProof.paneId, '#{pane_id}\t#{pane_dead}\t#{pane_pid}\t#{session_name}\t#{@omx_pane_instance_id}'],
    { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).result;
  const snapshotLine = exactNonEmptyTmuxScalar(snapshot.stdout);
  const fields = snapshotLine?.split('\t');
  if (
    snapshot.error || snapshot.status !== 0 || !fields || fields.length !== 5
    || fields[0] !== initialProof.paneId || fields[1] !== '0' || fields[2] !== String(initialProof.pid)
    || !isSafeRalphTmuxAuthorityToken(fields[3]) || !isSafeRalphTmuxAuthorityToken(fields[4])
  ) return null;
  const [, , , sessionName, paneInstanceId] = fields;

  const paneOwnerId = `ralph:${randomUUID()}`;
  const receipt = randomUUID().replace(/-/g, '');
  const authority = `#{&&:#{&&:#{&&:#{==:#{pane_id},${initialProof.paneId}},#{==:#{pane_dead},0}},#{==:#{pane_pid},${initialProof.pid}}},#{&&:#{==:#{session_name},${sessionName}},#{==:#{@omx_pane_instance_id},${paneInstanceId}}}}`;
  const tagged = spawnPlatformCommandSync(
    'tmux',
    ['if-shell', '-t', initialProof.paneId, '-F', authority, `set-option -p -t ${initialProof.paneId} ${OMX_RALPH_PANE_OWNER_OPTION} ${paneOwnerId}; display-message -p ${receipt}`, ''],
    { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).result;
  if (tagged.error || tagged.status !== 0 || exactNonEmptyTmuxScalar(tagged.stdout) !== receipt) return null;

  const owner = spawnPlatformCommandSync(
    'tmux',
    ['show-option', '-qv', '-p', '-t', initialProof.paneId, OMX_RALPH_PANE_OWNER_OPTION],
    { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).result;
  if (owner.error || owner.status !== 0 || exactNonEmptyTmuxScalar(owner.stdout) !== paneOwnerId) return null;

  const finalProof = readExactPaneProofSync(initialProof.paneId);
  if (finalProof.status !== 'live' || finalProof.pid !== initialProof.pid) return null;
  const finalSnapshot = spawnPlatformCommandSync(
    'tmux',
    ['display-message', '-p', '-t', finalProof.paneId, '#{pane_id}\t#{pane_dead}\t#{pane_pid}\t#{session_name}\t#{@omx_pane_instance_id}'],
    { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] },
  ).result;
  if (finalSnapshot.error || finalSnapshot.status !== 0 || exactNonEmptyTmuxScalar(finalSnapshot.stdout) !== snapshotLine) return null;

  return {
    paneId: finalProof.paneId,
    panePid: finalProof.pid,
    sessionName,
    paneOwnerId,
    expectedAuthority: {
      pane_id: finalProof.paneId,
      pane_pid: finalProof.pid,
      session_name: sessionName,
      pane_instance_id: paneInstanceId,
      pane_owner_id: paneOwnerId,
    },
  };
}

export function captureRalphExpectedAuthority(paneId: string): RalphExpectedAuthority | null {
  return captureRalphPaneBinding(paneId)?.expectedAuthority ?? null;
}

export function withModeRuntimeContext<T extends ModeStateContextLike>(
  existing: ModeStateContextLike,
  next: T,
  options?: { env?: NodeJS.ProcessEnv; nowIso?: string }
): T {
  const env = options?.env ?? process.env;
  const nowIso = options?.nowIso ?? new Date().toISOString();
  const wasActive = existing.active === true;
  const isActive = next.active === true;
  const isRalphActivation = !wasActive && isActive && next.mode === 'ralph';

  if (isRalphActivation) clearRalphPaneBinding(next);

  const hasPane = hasNonEmptyString(next.tmux_pane_id);
  if (isActive && (!wasActive || !hasPane)) {
    const pane = captureTmuxPaneFromEnv(env);
    if (pane) {
      next.tmux_pane_id = pane;
      const windowId = captureTmuxWindowForPane(pane, env);
      if (windowId) next.tmux_window_id = windowId;
      if (!hasNonEmptyString(next.tmux_pane_set_at)) {
        next.tmux_pane_set_at = nowIso;
      }
    }
  }

  const ralphPaneId = typeof next.tmux_pane_id === 'string' ? next.tmux_pane_id : '';
  if (isRalphActivation && ralphPaneId) {
    const binding = captureRalphPaneBinding(ralphPaneId);
    if (binding) {
      next.tmux_pane_id = binding.paneId;
      next.tmux_pane_pid = binding.panePid;
      next.tmux_session_name = binding.sessionName;
      next.tmux_pane_owner_id = binding.paneOwnerId;
      setRalphExpectedAuthority(next, binding.expectedAuthority);
    } else {
      clearRalphPaneBinding(next);
    }
  }

  return next;
}
