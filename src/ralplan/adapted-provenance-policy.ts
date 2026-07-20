import { createHash, randomUUID } from 'node:crypto';
import { linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import { canonicalizeOriginCwd } from '../leader/contract.js';
import { getBaseStateDir } from '../state/paths.js';
import {
  signAdaptedProvenancePolicy,
  signAdaptedProvenanceAuthorization,
  verifyAdaptedProvenancePolicy,
  verifyAdaptedProvenanceAuthorization,
  type AdaptedProvenanceAuthorizationSignatureInput,
  type AdaptedProvenancePolicySignatureInput,
} from '../subagents/native-anchor-auth.js';

export const ADAPTED_PROVENANCE_PLAN_MARKER = 'OMX:AUTHENTICATED-ADAPTED-PROVENANCE';
export const ADAPTED_PROVENANCE_ACKNOWLEDGEMENT = 'I_ACCEPT_AUTHENTICATED_ADAPTED_PROVENANCE';
export const ADAPTED_PROVENANCE_POLICY_FILE = 'adapted-provenance-policy.json';
export const ADAPTED_PROVENANCE_AUTHORIZATION_DIR = 'adapted-provenance-authorizations';
export const MIN_ADAPTED_PROVENANCE_POLICY_TTL_MS = 60_000;
export const MAX_ADAPTED_PROVENANCE_POLICY_TTL_MS = 4 * 60 * 60_000;
export const ADAPTED_PROVENANCE_AUTHORIZATION_TTL_MS = 30_000;

export interface AdaptedProvenancePolicy extends AdaptedProvenancePolicySignatureInput {
  schema_version: 1;
  acknowledgement: string;
  signature: string;
}

export type AdaptedProvenancePolicyResult =
  | { ok: true; policy: AdaptedProvenancePolicy }
  | { ok: false; reason: string };

export interface IssueAdaptedProvenancePolicyInput {
  cwd: string;
  sessionId: string;
  planPath: string;
  acknowledgement: string;
  ttlMs: number;
  nowMs?: number;
  env?: NodeJS.ProcessEnv;
}

export interface AdaptedProvenanceAuthorization extends AdaptedProvenanceAuthorizationSignatureInput {
  schema_version: 1;
  signature: string;
}

export interface IssueAdaptedProvenanceAuthorizationInput {
  cwd: string;
  sessionId: string;
  nativeSessionId: string;
  operation: 'grant' | 'role-intent';
  commandSha256?: string;
  role?: string;
  parentThreadId?: string;
  nowMs?: number;
  env?: NodeJS.ProcessEnv;
}

export interface ConsumeAdaptedProvenanceAuthorizationInput {
  cwd: string;
  sessionId: string;
  nativeSessionId: string;
  operation: 'grant' | 'role-intent';
  commandSha256?: string;
  role?: string;
  parentThreadId?: string;
  nowMs?: number;
  env?: NodeJS.ProcessEnv;
}

const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_LAUNCH_ID = /^[A-Za-z0-9._-]{1,128}$/;
const SAFE_SCOPE = /^[A-Za-z0-9._:-]{1,160}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SAFE_AUTHORIZATION_ID = /^[a-f0-9-]{36}$/;
const SAFE_ROLE = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_THREAD_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const MAX_AUTHORIZATION_FILES = 64;
const PLAN_MARKER = new RegExp(`<!--\\s*${ADAPTED_PROVENANCE_PLAN_MARKER}\\s+scope="([A-Za-z0-9._:-]{1,160})"\\s*-->`);

export function adaptedProvenancePolicyPath(cwd: string, sessionId: string): string | null {
  if (!SAFE_SESSION_ID.test(sessionId.trim())) return null;
  return join(getBaseStateDir(cwd), 'sessions', sessionId.trim(), ADAPTED_PROVENANCE_POLICY_FILE);
}

function adaptedProvenanceAuthorizationDirectory(cwd: string, sessionId: string): string | null {
  const policyPath = adaptedProvenancePolicyPath(cwd, sessionId);
  return policyPath ? join(dirname(policyPath), ADAPTED_PROVENANCE_AUTHORIZATION_DIR) : null;
}

export function issueAdaptedProvenanceAuthorization(input: IssueAdaptedProvenanceAuthorizationInput): boolean {
  const nowMs = input.nowMs ?? Date.now();
  const normalized = normalizeAuthorizationInput(input, nowMs);
  if (!normalized) return false;
  const authorization: AdaptedProvenanceAuthorization = {
    schema_version: 1,
    authorizationId: randomUUID(),
    operation: normalized.operation,
    sessionId: normalized.sessionId,
    nativeSessionId: normalized.nativeSessionId,
    originCwd: normalized.originCwd,
    launchId: normalized.launchId,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + ADAPTED_PROVENANCE_AUTHORIZATION_TTL_MS).toISOString(),
    commandSha256: normalized.commandSha256,
    role: normalized.role,
    parentThreadId: normalized.parentThreadId,
    signature: '',
  };
  const signature = signAdaptedProvenanceAuthorization(authorization);
  if (!signature) return false;
  authorization.signature = signature;
  const directory = adaptedProvenanceAuthorizationDirectory(input.cwd, authorization.sessionId);
  if (!directory) return false;
  try {
    mkdirSync(directory, { recursive: true });
    const path = join(directory, `${authorization.authorizationId}.json`);
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(authorization)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
    return true;
  } catch {
    return false;
  }
}

/** Consume exactly one fresh hook-minted authorization for the current CLI invocation. */
export function consumeAdaptedProvenanceAuthorization(input: ConsumeAdaptedProvenanceAuthorizationInput): boolean {
  const nowMs = input.nowMs ?? Date.now();
  const normalized = normalizeAuthorizationInput(input, nowMs);
  if (!normalized) return false;
  const directory = adaptedProvenanceAuthorizationDirectory(input.cwd, normalized.sessionId);
  if (!directory) return false;
  let names = listAuthorizationNames(directory);
  if (!names) return false;
  if (names.length > MAX_AUTHORIZATION_FILES) {
    pruneExpiredAdaptedProvenanceAuthorizations(directory, names, normalized, nowMs);
    names = listAuthorizationNames(directory);
    if (!names) return false;
  }
  if (names.length === 0 || names.length > MAX_AUTHORIZATION_FILES) return false;
  for (const name of names) {
    const path = join(directory, name);
    const authorization = readAuthorization(path);
    if (!authorization || !matchesAuthorization(authorization, normalized, nowMs)) continue;
    const consumedPath = `${path}.${process.pid}.${randomUUID()}.consumed`;
    try {
      renameSync(path, consumedPath);
      unlinkSync(consumedPath);
      return true;
    } catch {
      // A competing process consumed it first; look for another exact fresh authorization.
    }
  }
  return false;
}

export function issueAdaptedProvenancePolicy(input: IssueAdaptedProvenancePolicyInput): AdaptedProvenancePolicyResult {
  const nowMs = input.nowMs ?? Date.now();
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) return { ok: false, reason: 'invalid_policy_clock' };
  if (!SAFE_SESSION_ID.test(input.sessionId.trim())) return { ok: false, reason: 'invalid_policy_session' };
  if (input.acknowledgement !== ADAPTED_PROVENANCE_ACKNOWLEDGEMENT) return { ok: false, reason: 'adapted_provenance_acknowledgement_required' };
  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < MIN_ADAPTED_PROVENANCE_POLICY_TTL_MS || input.ttlMs > MAX_ADAPTED_PROVENANCE_POLICY_TTL_MS) {
    return { ok: false, reason: 'invalid_adapted_provenance_policy_ttl' };
  }
  const plan = readDeclaredPlan(input.cwd, input.planPath);
  if (!plan.ok) return plan;
  const originCwd = canonicalizeOriginCwd(input.cwd);
  const launchId = input.env?.OMX_CODEX_LAUNCH_ID?.trim() ?? process.env.OMX_CODEX_LAUNCH_ID?.trim() ?? '';
  if (!originCwd || !SAFE_LAUNCH_ID.test(launchId)) return { ok: false, reason: 'native_anchor_unavailable' };
  const issuedAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + input.ttlMs).toISOString();
  const unsigned: AdaptedProvenancePolicySignatureInput = {
    scope: plan.scope,
    policyId: randomUUID(),
    sessionId: input.sessionId.trim(),
    originCwd,
    planPath: plan.path,
    planSha256: plan.sha256,
    launchId,
    issuedAt,
    expiresAt,
  };
  const signature = signAdaptedProvenancePolicy(unsigned);
  if (!signature) return { ok: false, reason: 'native_anchor_unavailable' };
  const policy: AdaptedProvenancePolicy = {
    schema_version: 1,
    ...unsigned,
    acknowledgement: ADAPTED_PROVENANCE_ACKNOWLEDGEMENT,
    signature,
  };
  const path = adaptedProvenancePolicyPath(input.cwd, unsigned.sessionId);
  if (!path) return { ok: false, reason: 'invalid_policy_session' };
  try {
    mkdirSync(dirname(path), { recursive: true });
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(policy)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
    return { ok: true, policy };
  } catch {
    return { ok: false, reason: 'adapted_provenance_policy_write_failed' };
  }
}

export function readValidAdaptedProvenancePolicy(
  cwd: string,
  sessionId: string,
  options: { nowMs?: number; env?: NodeJS.ProcessEnv } = {},
): AdaptedProvenancePolicyResult {
  const nowMs = options.nowMs ?? Date.now();
  const path = adaptedProvenancePolicyPath(cwd, sessionId);
  if (!path) return { ok: false, reason: 'invalid_policy_session' };
  let parsed: unknown;
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size <= 0 || info.size > 16 * 1024) {
      return { ok: false, reason: 'invalid_adapted_provenance_policy' };
    }
    parsed = JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return { ok: false, reason: 'adapted_provenance_policy_required' };
  }
  const policy = asPolicy(parsed);
  if (!policy) return { ok: false, reason: 'invalid_adapted_provenance_policy' };
  if (policy.sessionId !== sessionId.trim()) return { ok: false, reason: 'foreign_adapted_provenance_policy' };
  const originCwd = canonicalizeOriginCwd(cwd);
  if (!originCwd || policy.originCwd !== originCwd) return { ok: false, reason: 'foreign_adapted_provenance_policy' };
  const now = Number.isSafeInteger(nowMs) ? nowMs : NaN;
  const issuedAtMs = Date.parse(policy.issuedAt);
  const expiresAtMs = Date.parse(policy.expiresAt);
  if (!Number.isFinite(now) || !Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)
    || issuedAtMs > now || expiresAtMs <= now || expiresAtMs - issuedAtMs > MAX_ADAPTED_PROVENANCE_POLICY_TTL_MS) {
    return { ok: false, reason: 'stale_adapted_provenance_policy' };
  }
  const launchId = options.env?.OMX_CODEX_LAUNCH_ID?.trim() ?? process.env.OMX_CODEX_LAUNCH_ID?.trim() ?? '';
  if (!SAFE_LAUNCH_ID.test(launchId) || policy.launchId !== launchId) return { ok: false, reason: 'foreign_adapted_provenance_policy' };
  const plan = readDeclaredPlan(cwd, policy.planPath);
  if (!plan.ok) return plan;
  if (plan.scope !== policy.scope || plan.sha256 !== policy.planSha256) return { ok: false, reason: 'adapted_provenance_plan_drift' };
  const unsigned: AdaptedProvenancePolicySignatureInput = {
    scope: policy.scope,
    policyId: policy.policyId,
    sessionId: policy.sessionId,
    originCwd: policy.originCwd,
    planPath: policy.planPath,
    planSha256: policy.planSha256,
    launchId: policy.launchId,
    issuedAt: policy.issuedAt,
    expiresAt: policy.expiresAt,
  };
  if (!verifyAdaptedProvenancePolicy(unsigned, policy.signature)) return { ok: false, reason: 'invalid_adapted_provenance_policy_signature' };
  return { ok: true, policy };
}

function readDeclaredPlan(cwd: string, planPath: string): { ok: true; scope: string; path: string; sha256: string } | { ok: false; reason: string } {
  const normalizedPath = planPath.trim().replace(/\\/g, '/');
  if (!normalizedPath.startsWith('docs/plans/') || normalizedPath.includes('..') || normalizedPath.startsWith('/')) {
    return { ok: false, reason: 'invalid_adapted_provenance_plan_path' };
  }
  const originCwd = canonicalizeOriginCwd(cwd);
  if (!originCwd) return { ok: false, reason: 'invalid_adapted_provenance_plan_path' };
  const absolute = resolve(originCwd, normalizedPath);
  const relativePath = relative(originCwd, absolute).replace(/\\/g, '/');
  if (!relativePath || relativePath.startsWith('../') || relativePath === '..') return { ok: false, reason: 'invalid_adapted_provenance_plan_path' };
  try {
    const segments = normalizedPath.split('/');
    let current = originCwd;
    for (let index = 0; index < segments.length; index += 1) {
      current = join(current, segments[index]!);
      const info = lstatSync(current);
      const terminal = index === segments.length - 1;
      if (info.isSymbolicLink() || (terminal ? !info.isFile() : !info.isDirectory())) {
        return { ok: false, reason: 'invalid_adapted_provenance_plan' };
      }
      if (terminal && (info.nlink !== 1 || info.size <= 0 || info.size > 4 * 1024 * 1024)) {
        return { ok: false, reason: 'invalid_adapted_provenance_plan' };
      }
    }
    if (current !== absolute) {
      return { ok: false, reason: 'invalid_adapted_provenance_plan' };
    }
    const contents = readFileSync(absolute);
    const scope = PLAN_MARKER.exec(contents.toString('utf-8'))?.[1] ?? '';
    if (!SAFE_SCOPE.test(scope)) return { ok: false, reason: 'adapted_provenance_plan_amendment_required' };
    return { ok: true, scope, path: normalizedPath, sha256: createHash('sha256').update(contents).digest('hex') };
  } catch {
    return { ok: false, reason: 'invalid_adapted_provenance_plan' };
  }
}

function asPolicy(value: unknown): AdaptedProvenancePolicy | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const strings = ['scope', 'policyId', 'sessionId', 'originCwd', 'planPath', 'planSha256', 'launchId', 'issuedAt', 'expiresAt', 'acknowledgement', 'signature'];
  if (candidate.schema_version !== 1 || strings.some((key) => typeof candidate[key] !== 'string' || !(candidate[key] as string).trim())) return null;
  const policy: AdaptedProvenancePolicy = {
    schema_version: 1,
    scope: String(candidate.scope).trim(),
    policyId: String(candidate.policyId).trim(),
    sessionId: String(candidate.sessionId).trim(),
    originCwd: String(candidate.originCwd).trim(),
    planPath: String(candidate.planPath).trim(),
    planSha256: String(candidate.planSha256).trim(),
    launchId: String(candidate.launchId).trim(),
    issuedAt: String(candidate.issuedAt).trim(),
    expiresAt: String(candidate.expiresAt).trim(),
    acknowledgement: String(candidate.acknowledgement).trim(),
    signature: String(candidate.signature).trim(),
  };
  if (!SAFE_SCOPE.test(policy.scope) || !SAFE_SESSION_ID.test(policy.sessionId) || !SAFE_LAUNCH_ID.test(policy.launchId)
    || !SHA256.test(policy.planSha256) || policy.acknowledgement !== ADAPTED_PROVENANCE_ACKNOWLEDGEMENT) return null;
  return policy;
}

function normalizeAuthorizationInput(
  input: IssueAdaptedProvenanceAuthorizationInput | ConsumeAdaptedProvenanceAuthorizationInput,
  nowMs: number,
): Omit<AdaptedProvenanceAuthorizationSignatureInput, 'authorizationId' | 'issuedAt' | 'expiresAt'> | null {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0 || !SAFE_SESSION_ID.test(input.sessionId.trim())
    || !SAFE_THREAD_ID.test(input.nativeSessionId.trim())) return null;
  const originCwd = canonicalizeOriginCwd(input.cwd);
  const launchId = input.env?.OMX_CODEX_LAUNCH_ID?.trim() ?? process.env.OMX_CODEX_LAUNCH_ID?.trim() ?? '';
  if (!originCwd || !SAFE_LAUNCH_ID.test(launchId)) return null;
  const commandSha256 = input.commandSha256?.trim() ?? '';
  const role = input.role?.trim() ?? '';
  const parentThreadId = input.parentThreadId?.trim() ?? '';
  if (input.operation === 'grant') {
    if (!SHA256.test(commandSha256) || role || parentThreadId) return null;
  } else if (!SAFE_ROLE.test(role) || !SAFE_THREAD_ID.test(parentThreadId) || commandSha256) {
    return null;
  }
  return {
    operation: input.operation,
    sessionId: input.sessionId.trim(),
    nativeSessionId: input.nativeSessionId.trim(),
    originCwd,
    launchId,
    commandSha256,
    role,
    parentThreadId,
  };
}

function readAuthorization(path: string): AdaptedProvenanceAuthorization | null {
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size <= 0 || info.size > 8 * 1024) return null;
    return asAuthorization(JSON.parse(readFileSync(path, 'utf8')));
  } catch {
    return null;
  }
}

function listAuthorizationNames(directory: string): string[] | null {
  try {
    return readdirSync(directory).filter((name) => /^[a-f0-9-]{36}\.json$/.test(name)).sort();
  } catch {
    return null;
  }
}

function pruneExpiredAdaptedProvenanceAuthorizations(
  directory: string,
  names: readonly string[],
  expected: Omit<AdaptedProvenanceAuthorizationSignatureInput, 'authorizationId' | 'issuedAt' | 'expiresAt'>,
  nowMs: number,
): void {
  for (const name of names) {
    const path = join(directory, name);
    const authorizationId = name.slice(0, -'.json'.length);
    if (!isPrunableExpiredAuthorization(readAuthorization(path), authorizationId, expected, nowMs)) continue;
    const claimedPath = `${path}.${process.pid}.${randomUUID()}.expired`;
    try {
      renameSync(path, claimedPath);
    } catch {
      continue;
    }
    if (!isPrunableExpiredAuthorization(readAuthorization(claimedPath), authorizationId, expected, nowMs)) {
      restoreUnprunedAuthorization(claimedPath, path);
      continue;
    }
    try {
      unlinkSync(claimedPath);
    } catch {
      // An unlink failure leaves the claimed expired authorization in place.
    }
  }
}

function isPrunableExpiredAuthorization(
  authorization: AdaptedProvenanceAuthorization | null,
  authorizationId: string,
  expected: Omit<AdaptedProvenanceAuthorizationSignatureInput, 'authorizationId' | 'issuedAt' | 'expiresAt'>,
  nowMs: number,
): boolean {
  if (!authorization || authorization.authorizationId !== authorizationId
    || authorization.sessionId !== expected.sessionId || authorization.originCwd !== expected.originCwd
    || !verifyAdaptedProvenanceAuthorization(authorization, authorization.signature)) return false;
  const issuedAtMs = Date.parse(authorization.issuedAt);
  const expiresAtMs = Date.parse(authorization.expiresAt);
  const lifetimeMs = expiresAtMs - issuedAtMs;
  return Number.isSafeInteger(nowMs) && Number.isFinite(issuedAtMs) && Number.isFinite(expiresAtMs)
    && lifetimeMs > 0 && lifetimeMs <= ADAPTED_PROVENANCE_AUTHORIZATION_TTL_MS && expiresAtMs <= nowMs;
}

function restoreUnprunedAuthorization(claimedPath: string, path: string): void {
  try {
    const info = lstatSync(claimedPath);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) return;
    linkSync(claimedPath, path);
    unlinkSync(claimedPath);
  } catch {
    // Preserve an unrecognized claimed entry rather than replacing another process's file.
  }
}

function asAuthorization(value: unknown): AdaptedProvenanceAuthorization | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const strings = ['authorizationId', 'operation', 'sessionId', 'nativeSessionId', 'originCwd', 'launchId', 'issuedAt', 'expiresAt', 'commandSha256', 'role', 'parentThreadId', 'signature'];
  if (candidate.schema_version !== 1 || strings.some((key) => typeof candidate[key] !== 'string')) return null;
  const authorization: AdaptedProvenanceAuthorization = {
    schema_version: 1,
    authorizationId: String(candidate.authorizationId).trim(),
    operation: String(candidate.operation).trim() as AdaptedProvenanceAuthorization['operation'],
    sessionId: String(candidate.sessionId).trim(),
    nativeSessionId: String(candidate.nativeSessionId).trim(),
    originCwd: String(candidate.originCwd).trim(),
    launchId: String(candidate.launchId).trim(),
    issuedAt: String(candidate.issuedAt).trim(),
    expiresAt: String(candidate.expiresAt).trim(),
    commandSha256: String(candidate.commandSha256).trim(),
    role: String(candidate.role).trim(),
    parentThreadId: String(candidate.parentThreadId).trim(),
    signature: String(candidate.signature).trim(),
  };
  if (!SAFE_AUTHORIZATION_ID.test(authorization.authorizationId)
    || (authorization.operation !== 'grant' && authorization.operation !== 'role-intent')
    || !SAFE_SESSION_ID.test(authorization.sessionId)
    || !SAFE_THREAD_ID.test(authorization.nativeSessionId)
    || !SAFE_LAUNCH_ID.test(authorization.launchId)) return null;
  if (authorization.operation === 'grant') {
    if (!SHA256.test(authorization.commandSha256) || authorization.role || authorization.parentThreadId) return null;
  } else if (!SAFE_ROLE.test(authorization.role) || !SAFE_THREAD_ID.test(authorization.parentThreadId) || authorization.commandSha256) {
    return null;
  }
  return authorization;
}

function matchesAuthorization(
  authorization: AdaptedProvenanceAuthorization,
  expected: Omit<AdaptedProvenanceAuthorizationSignatureInput, 'authorizationId' | 'issuedAt' | 'expiresAt'>,
  nowMs: number,
): boolean {
  const issuedAtMs = Date.parse(authorization.issuedAt);
  const expiresAtMs = Date.parse(authorization.expiresAt);
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)
    || issuedAtMs > nowMs || expiresAtMs <= nowMs || expiresAtMs - issuedAtMs > ADAPTED_PROVENANCE_AUTHORIZATION_TTL_MS) return false;
  if (authorization.operation !== expected.operation || authorization.sessionId !== expected.sessionId
    || authorization.nativeSessionId !== expected.nativeSessionId || authorization.originCwd !== expected.originCwd
    || authorization.launchId !== expected.launchId || authorization.commandSha256 !== expected.commandSha256
    || authorization.role !== expected.role || authorization.parentThreadId !== expected.parentThreadId) return false;
  return verifyAdaptedProvenanceAuthorization(authorization, authorization.signature);
}
