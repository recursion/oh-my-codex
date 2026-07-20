import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ralplanCommand, type RalplanCommandDependencies } from '../ralplan.js';

async function invoke(args: string[], deps: RalplanCommandDependencies = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const previous = process.exitCode;
  try {
    process.exitCode = undefined;
    await ralplanCommand(args, { ...deps, stdout: (line) => stdout.push(line), stderr: (line) => stderr.push(line) });
    return { stdout, stderr, exitCode: process.exitCode };
  } finally {
    process.exitCode = previous;
  }
}

describe('#3194 ralplan CLI unsupported-only surface', () => {
  it('fails the explicit adapted-surface preflight and neutralizes routing-only Ralplan state', async () => {
    let resolved = false;
    let cancelled = false;
    const result = await invoke(['preflight', '--json'], {
      resolveInstalledRoleName: () => { resolved = true; return 'architect'; },
      cancelRalplan: async () => { cancelled = true; },
      isAttachedTmux: () => false,
    });
    assert.equal(result.exitCode, 1);
    assert.equal(resolved, false);
    assert.equal(cancelled, true);
    assert.deepEqual(result.stderr, []);
    assert.deepEqual(JSON.parse(result.stdout.join('\n')), { ok: false, reason: 'unsupported_documented_leader_proof' });
  });
  it('offers truthful typed Team fallback only in attached tmux with both roles installed', async () => {
    let cancelled = false;
    const result = await invoke(['preflight', '--json'], {
      isAttachedTmux: () => true,
      hasInstalledRalplanTeamRoles: () => true,
      cancelRalplan: async () => { cancelled = true; },
    });
    assert.equal(result.exitCode, undefined);
    assert.equal(cancelled, false);
    assert.deepEqual(JSON.parse(result.stdout.join('\n')), {
      ok: true,
      provenance_kind: 'omx_team',
      native_preferred: true,
      sequence: ['architect-review', 'critic-review'],
    });
  });
  it('validates malformed arguments before resolving a role', async () => {
    let resolved = false;
    await assert.rejects(() => invoke(['role-intent', 'write', '--role', 'architect', '--json'], {
      resolveInstalledRoleName: () => { resolved = true; return 'architect'; },
    }), /Missing --parent-thread/);
    assert.equal(resolved, false);
  });
  it('computes the exact planning input digest before Team reviews launch', async () => {
    const result = await invoke(['team-consensus', 'digest', '--input', 'plan.md', '--input', 'test.md', '--json'], {
      digestRalplanInputs: async (paths) => {
        assert.deepEqual(paths, ['plan.md', 'test.md']);
        return 'a'.repeat(64);
      },
    });
    assert.deepEqual(JSON.parse(result.stdout.join('\n')), { ok: true, input_digest: 'a'.repeat(64) });
  });

  it('returns unknown_role for a syntactically valid uninstalled role', async () => {
    const result = await invoke(['role-intent', 'write', '--role', 'synthetic-unknown', '--parent-thread', 'synthetic-parent', '--json'], {
      resolveInstalledRoleName: () => null,
    });
    assert.equal(result.exitCode, 1);
    assert.deepEqual(result.stderr, []);
    assert.deepEqual(JSON.parse(result.stdout.join('\n')), { ok: false, reason: 'unknown_role' });
  });

  it('denies installed roles before any runtime state dependency is consulted', async () => {
    const result = await invoke(['role-intent', 'write', '--role', 'architect', '--parent-thread', 'synthetic-parent', '--session', 'synthetic-session', '--ttl-ms', '1', '--json'], {
      resolveInstalledRoleName: (role) => role.toLowerCase() === 'architect' ? 'architect' : null,
    });
    assert.equal(result.exitCode, 1);
    assert.deepEqual(result.stderr, []);
    assert.deepEqual(JSON.parse(result.stdout.join('\n')), { ok: false, reason: 'unsupported_documented_leader_proof' });
  });
});
