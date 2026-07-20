import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { canonicalizeOriginCwd } from '../leader/contract.js';

const KEY_BYTES = 32;
const HEX_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_LAUNCH_ID = /^[A-Za-z0-9._-]{1,128}$/;
const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_AUTHORIZATION_ID = /^[a-f0-9-]{36}$/;
const SAFE_LAUNCH_TOKEN = /^[a-f0-9]{64}$/;
const NATIVE_LAUNCH_AUTHORIZATION_MAX_BYTES = 4096;
const NATIVE_LAUNCH_CLAIM_MAX_BYTES = 4096;

/** Private per-launch capability, intentionally absent from direct Codex launches. */
export const OMX_CODEX_LAUNCH_TOKEN_ENV = 'OMX_CODEX_LAUNCH_TOKEN';
export const NATIVE_LAUNCH_AUTHORIZATION_TTL_MS = 4 * 60 * 60_000;
export const NATIVE_ANCHOR_AUTH_ROOT_DIR = 'native-anchor-auth';
export const NATIVE_ANCHOR_AUTH_ROOT_VERSION = 'v1';
export const NATIVE_LAUNCH_AUTHORIZATION_DIR = 'launch-authorizations';
export const NATIVE_LAUNCH_CLAIM_DIR = 'launch-claims';

let nativeAnchorAuthRootForTest: string | undefined;

export interface NativeLaunchAuthorizationSignatureInput {
  authorizationId: string;
  launchId: string;
  tokenSha256: string;
  sessionId: string;
  originCwd: string;
  issuedAt: string;
  expiresAt: string;
}

export interface NativeLaunchAuthorization extends NativeLaunchAuthorizationSignatureInput {
  schema_version: 1;
  signature: string;
}

export interface NativeLaunchClaimSignatureInput extends NativeLaunchAuthorizationSignatureInput {
  nativeSessionId: string;
}

export interface IssueNativeLaunchAuthorizationInput {
  cwd: string;
  sessionId: string;
  launchId: string;
  token: string;
  nowMs?: number;
  env?: NodeJS.ProcessEnv;
}

/**
 * Test-only dependency injection for in-process unit fixtures. The plugin is
 * a separate process and never reads this value, so it is not a launch-time
 * configuration surface.
 */
export function __setNativeAnchorAuthRootForTest(root?: string): void {
  nativeAnchorAuthRootForTest = root ? resolve(root) : undefined;
}

function nativeAnchorAuthRoot(): string | null {
  try {
    if (nativeAnchorAuthRootForTest) return nativeAnchorAuthRootForTest;
    // Unlike os.homedir(), userInfo().homedir is not selected by HOME or a
    // Codex launch environment. The anchor must remain outside CODEX_HOME and
    // every OMX state-root override.
    const home = userInfo().homedir;
    return home ? join(home, '.omx', NATIVE_ANCHOR_AUTH_ROOT_DIR, NATIVE_ANCHOR_AUTH_ROOT_VERSION) : null;
  } catch {
    return null;
  }
}

export function nativeAnchorAuthKeyPath(): string | null {
  const root = nativeAnchorAuthRoot();
  return root ? join(root, 'key') : null;
}

function isPrivateDirectory(path: string): boolean {
  try {
    const info = lstatSync(path);
    return info.isDirectory() && !info.isSymbolicLink()
      && (process.platform === 'win32' || (info.mode & 0o077) === 0);
  } catch {
    return false;
  }
}

function ensurePrivateDirectory(path: string): boolean {
  try {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    if (process.platform !== 'win32') chmodSync(path, 0o700);
    return isPrivateDirectory(path);
  } catch {
    return false;
  }
}

function readNativeAnchorKey(): Buffer | null {
  try {
    const path = nativeAnchorAuthKeyPath();
    if (!path || !isPrivateDirectory(dirname(path))) return null;
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== KEY_BYTES
      || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) return null;
    const key = readFileSync(path);
    return key.length === KEY_BYTES ? key : null;
  } catch {
    return null;
  }
}

/**
 * The OMX launcher, rather than a plugin hook, is the only key creator.  The
 * plugin is deliberately verify-only so a direct Codex process cannot mint a
 * trusted launch by supplying lookalike environment variables.
 */
function readOrCreateNativeAnchorKey(): Buffer | null {
  const path = nativeAnchorAuthKeyPath();
  const existing = readNativeAnchorKey();
  if (existing) return existing;
  if (!path || !ensurePrivateDirectory(dirname(path))) return null;
  try {
    writeFileSync(path, randomBytes(KEY_BYTES), { mode: 0o600, flag: 'wx' });
  } catch {
    // A concurrent OMX launch may have won the create race. Re-read below.
  }
  return readNativeAnchorKey();
}

function sign(parts: string[]): string | null {
  const key = readNativeAnchorKey();
  return key ? createHmac('sha256', key).update(parts.join('\0')).digest('hex') : null;
}

function verify(signature: string | undefined, expected: string | null): boolean {
  if (!signature || !expected || !HEX_SHA256.test(signature) || !HEX_SHA256.test(expected)) return false;
  return timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
}

export function nativeLaunchAuthorizationPath(cwd: string, launchId: string): string | null {
  void cwd;
  if (!SAFE_LAUNCH_ID.test(launchId.trim())) return null;
  const root = nativeAnchorAuthRoot();
  return root ? join(root, NATIVE_LAUNCH_AUTHORIZATION_DIR, `${launchId.trim()}.json`) : null;
}

export function nativeLaunchClaimPath(cwd: string, launchId: string): string | null {
  void cwd;
  if (!SAFE_LAUNCH_ID.test(launchId.trim())) return null;
  const root = nativeAnchorAuthRoot();
  return root ? join(root, NATIVE_LAUNCH_CLAIM_DIR, `${launchId.trim()}.json`) : null;
}

export function signNativeLaunchAuthorization(
  input: NativeLaunchAuthorizationSignatureInput,
): string | null {
  return sign([
    'native-launch-authorization-v1',
    input.authorizationId,
    input.launchId,
    input.tokenSha256,
    input.sessionId,
    input.originCwd,
    input.issuedAt,
    input.expiresAt,
  ]);
}

export function verifyNativeLaunchAuthorization(
  input: NativeLaunchAuthorizationSignatureInput,
  signature: string | undefined,
): boolean {
  return verify(signature, signNativeLaunchAuthorization(input));
}

export function signNativeLaunchClaim(
  input: NativeLaunchClaimSignatureInput,
): string | null {
  return sign([
    'native-launch-claim-v2',
    input.authorizationId,
    input.launchId,
    input.tokenSha256,
    input.sessionId,
    input.originCwd,
    input.issuedAt,
    input.expiresAt,
    input.nativeSessionId,
  ]);
}

export function verifyNativeLaunchClaim(
  input: NativeLaunchClaimSignatureInput,
  signature: string | undefined,
): boolean {
  return verify(signature, signNativeLaunchClaim(input));
}

export function issueNativeLaunchAuthorization(
  input: IssueNativeLaunchAuthorizationInput,
): NativeLaunchAuthorization | null {
  const nowMs = input.nowMs ?? Date.now();
  const launchId = input.launchId.trim();
  const token = input.token.trim();
  const sessionId = input.sessionId.trim();
  const originCwd = canonicalizeOriginCwd(input.cwd);
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0 || !SAFE_LAUNCH_ID.test(launchId)
    || !SAFE_LAUNCH_TOKEN.test(token) || !SAFE_SESSION_ID.test(sessionId) || !originCwd) return null;
  const unsigned: NativeLaunchAuthorizationSignatureInput = {
    authorizationId: randomUUID(),
    launchId,
    tokenSha256: createHash('sha256').update(token).digest('hex'),
    sessionId,
    originCwd,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + NATIVE_LAUNCH_AUTHORIZATION_TTL_MS).toISOString(),
  };
  if (!readOrCreateNativeAnchorKey()) return null;
  const signature = signNativeLaunchAuthorization(unsigned);
  const path = nativeLaunchAuthorizationPath(input.cwd, launchId);
  if (!signature || !path) return null;
  const authorization: NativeLaunchAuthorization = { schema_version: 1, ...unsigned, signature };
  try {
    if (!ensurePrivateDirectory(dirname(path))) return null;
    writeFileSync(path, `${JSON.stringify(authorization)}\n`, { mode: 0o600, flag: 'wx' });
    return authorization;
  } catch {
    return null;
  }
}

/**
 * A policy grant is valid only from the active plugin launch that signed the
 * current root session. This prevents a durable leader attestation alone from
 * authorizing a direct or unrelated CLI process.
 */
export function hasVerifiedPluginLaunchClaim(cwd: string, nativeSessionId: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const launchId = env.OMX_CODEX_LAUNCH_ID?.trim() ?? '';
  const entryPath = env.OMX_ENTRY_PATH?.trim() ?? '';
  const token = env[OMX_CODEX_LAUNCH_TOKEN_ENV]?.trim() ?? '';
  const canonicalSessionId = env.OMX_SESSION_ID?.trim() ?? '';
  if (!entryPath || !SAFE_LAUNCH_ID.test(launchId) || !SAFE_LAUNCH_TOKEN.test(token)
    || !SAFE_SESSION_ID.test(canonicalSessionId) || !nativeSessionId.trim()) return false;
  const authorizationPath = nativeLaunchAuthorizationPath(cwd, launchId);
  const claimPath = nativeLaunchClaimPath(cwd, launchId);
  if (!authorizationPath || !claimPath) return false;
  try {
    if (!isPrivateDirectory(dirname(authorizationPath)) || !isPrivateDirectory(dirname(claimPath))) return false;
    const authorizationInfo = lstatSync(authorizationPath);
    if (!authorizationInfo.isFile() || authorizationInfo.isSymbolicLink() || authorizationInfo.nlink !== 1
      || authorizationInfo.size <= 0 || authorizationInfo.size > NATIVE_LAUNCH_AUTHORIZATION_MAX_BYTES
      || (process.platform !== 'win32' && (authorizationInfo.mode & 0o077) !== 0)) return false;
    const authorization = asNativeLaunchAuthorization(JSON.parse(readFileSync(authorizationPath, 'utf8')));
    if (!authorization || authorization.launchId !== launchId || authorization.sessionId !== canonicalSessionId
      || authorization.originCwd !== canonicalizeOriginCwd(cwd)
      || authorization.tokenSha256 !== createHash('sha256').update(token).digest('hex')) return false;
    const issuedAtMs = Date.parse(authorization.issuedAt);
    const expiresAtMs = Date.parse(authorization.expiresAt);
    const nowMs = Date.now();
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs) || issuedAtMs > nowMs || expiresAtMs <= nowMs
      || expiresAtMs - issuedAtMs > NATIVE_LAUNCH_AUTHORIZATION_TTL_MS
      || !verifyNativeLaunchAuthorization(authorization, authorization.signature)) return false;
    const info = lstatSync(claimPath);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size <= 0 || info.size > NATIVE_LAUNCH_CLAIM_MAX_BYTES
      || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) return false;
    const claim = JSON.parse(readFileSync(claimPath, 'utf8')) as { schema_version?: unknown; nativeSessionId?: unknown; signature?: unknown };
    const sessionId = typeof claim.nativeSessionId === 'string' ? claim.nativeSessionId.trim() : '';
    const signature = typeof claim.signature === 'string' ? claim.signature.trim() : undefined;
    return claim.schema_version === 1 && sessionId === nativeSessionId.trim()
      && verifyNativeLaunchClaim({ ...authorization, nativeSessionId: sessionId }, signature);
  } catch {
    return false;
  }
}

function asNativeLaunchAuthorization(value: unknown): NativeLaunchAuthorization | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const strings = ['authorizationId', 'launchId', 'tokenSha256', 'sessionId', 'originCwd', 'issuedAt', 'expiresAt', 'signature'];
  if (candidate.schema_version !== 1 || strings.some((key) => typeof candidate[key] !== 'string')) return null;
  const authorization: NativeLaunchAuthorization = {
    schema_version: 1,
    authorizationId: String(candidate.authorizationId).trim(),
    launchId: String(candidate.launchId).trim(),
    tokenSha256: String(candidate.tokenSha256).trim(),
    sessionId: String(candidate.sessionId).trim(),
    originCwd: String(candidate.originCwd).trim(),
    issuedAt: String(candidate.issuedAt).trim(),
    expiresAt: String(candidate.expiresAt).trim(),
    signature: String(candidate.signature).trim(),
  };
  if (!SAFE_AUTHORIZATION_ID.test(authorization.authorizationId) || !SAFE_LAUNCH_ID.test(authorization.launchId)
    || !HEX_SHA256.test(authorization.tokenSha256) || !SAFE_SESSION_ID.test(authorization.sessionId)
    || !authorization.originCwd || !authorization.signature) return null;
  return authorization;
}

export function signNativeLeaderAttestation(sessionId: string, leaderThreadId: string, attestedAt: string, source: string): string | null {
  return sign(['leader-attestation-v1', sessionId, leaderThreadId, attestedAt, source]);
}

export function verifyNativeLeaderAttestation(sessionId: string, leaderThreadId: string, attestedAt: string, source: string, signature: string | undefined): boolean {
  return verify(signature, signNativeLeaderAttestation(sessionId, leaderThreadId, attestedAt, source));
}

export interface AdaptedProvenancePolicySignatureInput {
  scope: string;
  policyId: string;
  sessionId: string;
  originCwd: string;
  planPath: string;
  planSha256: string;
  launchId: string;
  issuedAt: string;
  expiresAt: string;
}

export interface AdaptedProvenanceReceiptSignatureInput extends AdaptedProvenancePolicySignatureInput {
  parentThreadId: string;
  childThreadId: string;
  role: string;
  correlationToken: string;
}

export interface AdaptedProvenanceAuthorizationSignatureInput {
  authorizationId: string;
  operation: 'grant' | 'role-intent';
  sessionId: string;
  nativeSessionId: string;
  originCwd: string;
  launchId: string;
  issuedAt: string;
  expiresAt: string;
  commandSha256: string;
  role: string;
  parentThreadId: string;
}

export function signAdaptedProvenancePolicy(input: AdaptedProvenancePolicySignatureInput): string | null {
  return sign([
    'adapted-provenance-policy-v1',
    input.scope,
    input.policyId,
    input.sessionId,
    input.originCwd,
    input.planPath,
    input.planSha256,
    input.launchId,
    input.issuedAt,
    input.expiresAt,
  ]);
}

export function verifyAdaptedProvenancePolicy(input: AdaptedProvenancePolicySignatureInput, signature: string | undefined): boolean {
  return verify(signature, signAdaptedProvenancePolicy(input));
}

export function signAdaptedProvenanceReceipt(input: AdaptedProvenanceReceiptSignatureInput): string | null {
  return sign([
    'adapted-provenance-receipt-v1',
    input.scope,
    input.policyId,
    input.sessionId,
    input.originCwd,
    input.planPath,
    input.planSha256,
    input.launchId,
    input.issuedAt,
    input.expiresAt,
    input.parentThreadId,
    input.childThreadId,
    input.role,
    input.correlationToken,
  ]);
}

export function verifyAdaptedProvenanceReceipt(input: AdaptedProvenanceReceiptSignatureInput, signature: string | undefined): boolean {
  return verify(signature, signAdaptedProvenanceReceipt(input));
}

export function signAdaptedProvenanceAuthorization(input: AdaptedProvenanceAuthorizationSignatureInput): string | null {
  return sign([
    'adapted-provenance-authorization-v1',
    input.authorizationId,
    input.operation,
    input.sessionId,
    input.nativeSessionId,
    input.originCwd,
    input.launchId,
    input.issuedAt,
    input.expiresAt,
    input.commandSha256,
    input.role,
    input.parentThreadId,
  ]);
}

export function verifyAdaptedProvenanceAuthorization(input: AdaptedProvenanceAuthorizationSignatureInput, signature: string | undefined): boolean {
  return verify(signature, signAdaptedProvenanceAuthorization(input));
}
