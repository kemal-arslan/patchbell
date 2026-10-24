import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startFakeApis, type FakeApis } from './fake-apis.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const execFileAsync = promisify(execFile);

let apis: FakeApis;
let home: string;

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs the real CLI against the fake APIs, with its own PATCHBELL_HOME. */
async function cli(args: string[], env: Record<string, string> = {}): Promise<Run> {
  const { NVD_API_KEY: _, GITHUB_TOKEN: __, GITHUB_REPOSITORY: ___, ...base } = process.env as Record<string, string>;
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      cwd: ROOT,
      env: { ...base, ...apis.env, PATCHBELL_HOME: home, NO_COLOR: '1', ...env },
      timeout: 60_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failed = error as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof failed.code === 'number' ? failed.code : 1, stdout: failed.stdout ?? '', stderr: failed.stderr ?? '' };
  }
}

/** Forget cached feeds, as if a day had passed. */
const expireCache = () => rm(join(home, 'cache'), { recursive: true, force: true });

beforeAll(async () => {
  apis = await startFakeApis();
  home = await mkdtemp(join(tmpdir(), 'patchbell-e2e-'));
});

afterAll(async () => {
  await apis?.close();
  await rm(home, { recursive: true, force: true });
});

describe('patchbell CLI', () => {
  it('sets up notification channels', async () => {
    expect((await cli(['notify', 'desktop', 'off'])).code).toBe(0);
    expect((await cli(['notify', 'ntfy', 'pb-test-topic', '--server', `${apis.url}/ntfy`])).code).toBe(0);
    expect((await cli(['notify', 'webhook', `${apis.url}/hook`])).code).toBe(0);
    const test = await cli(['notify', 'test']);
    expect(test.stderr).toContain('✓ ntfy');
    expect(test.stderr).toContain('✓ webhook');
    expect(apis.ntfy.at(-1)).toMatchObject({ topic: 'pb-test-topic', title: 'Patchbell test' });
    const config = JSON.parse(await readFile(join(home, 'config.json'), 'utf8')) as { channels: Record<string, unknown> };
    expect(config.channels).toMatchObject({ desktop: false, ntfy: { topic: 'pb-test-topic' }, webhook: { url: `${apis.url}/hook` } });
    apis.ntfy.length = 0;
    apis.webhook.length = 0;
  });

  it('adds items by name, package and CPE', async () => {
    expect((await cli(['add', 'php 8.3.10', '--no-check'])).stderr).toContain('Added php: PHP 8.3.10');
    expect((await cli(['add', 'plex', '1.41.2', '--no-check'])).stderr).toContain('Added plex: Plex Media Server 1.41.2');
    expect((await cli(['add', 'npm:express@4.17.1', '--no-check', '--updates'])).stderr).toContain('Added express: express 4.17.1');
    const list = JSON.parse((await cli(['list', '--json'])).stdout) as { id: string }[];
    expect(list.map((item) => item.id)).toEqual(['php', 'plex', 'express']);
  });

  it('asks which product when a name is ambiguous', async () => {
    const ambiguous = await cli(['add', 'acme widget 1.0', '--no-check']);
    expect(ambiguous.code).toBe(1);
    expect(ambiguous.stderr).toContain('Acme Widget Pro');
    expect(ambiguous.stderr).toContain('Acme Widget Lite');
    const picked = await cli(['add', 'acme widget 1.0', '--no-check', '--pick', '2']);
    expect(picked.stderr).toContain('Added acme-widget-lite: Acme Widget Lite 1.0');
    expect((await cli(['remove', 'acme-widget-lite'])).code).toBe(0);
  });

  it('checks, alerts at the chosen level and notifies once per item', async () => {
    const run = await cli(['check']);
    expect(run.code).toBe(0);
    // PHP2Shell, the exploited Plex CVEs, a brand-new Plex CVE from its cve.org record, and a critical npm advisory.
    expect(run.stderr).toContain('CVE-2026-109618');
    expect(run.stderr).toContain('CVE-2026-96656');
    expect(run.stderr).toContain('CVE-2026-999001');
    expect(run.stderr).toContain('CVE-2026-50000');
    expect(run.stderr).toContain('Fix: Update to 8.3.36 or later.');
    expect(run.stderr).toContain('Fix: Update to 1.44.0 or later.');
    // Below the level, or not about Plex at all.
    expect(run.stderr).not.toContain('CVE-2024-11111');
    expect(run.stderr).not.toContain('CVE-2026-999002');
    expect(run.stderr).toContain('Newest release: 5.2.1');

    expect(apis.ntfy.map((message) => message.title)).toEqual([
      'PHP 8.3.10: 1 critical vulnerability',
      'Plex Media Server 1.41.2: 2 actively exploited vulnerabilities',
      'express 4.17.1: 1 critical vulnerability',
      'express 5.2.1 is out',
    ]);
    expect(apis.ntfy[1]).toMatchObject({ priority: 5, click: 'https://nvd.nist.gov/vuln/detail/CVE-2026-96656' });
    expect(apis.webhook).toHaveLength(4);
  });

  it('stays quiet when nothing changed', async () => {
    const before = apis.ntfy.length;
    const run = await cli(['check', '--quiet']);
    expect(apis.ntfy.length).toBe(before);
    // Quiet runs still print when there are alerts, for the log.
    expect(run.stderr).toContain('alerts across 3 items');
  });

  it('notifies again when a known issue starts being exploited', async () => {
    apis.kev.push({ cveID: 'CVE-2026-109618', vulnerabilityName: 'PHP RCE', dateAdded: '2026-10-25', dueDate: '2026-11-15', knownRansomwareCampaignUse: 'Known', requiredAction: 'Apply updates.' });
    await expireCache();
    const before = apis.ntfy.length;
    await cli(['check', 'php']);
    expect(apis.ntfy.slice(before).map((message) => message.title)).toEqual(['PHP 8.3.10: actively exploited vulnerability']);
    expect(String(apis.ntfy.at(-1)!.message)).toContain('Now exploited: CVE-2026-109618');
    expect(String(apis.ntfy.at(-1)!.message)).toContain('including ransomware');
  });

  it('clears an item after the user upgrades', async () => {
    expect((await cli(['set', 'php', '8.3.36'])).stderr).toContain('Updated php: PHP 8.3.36');
    const before = apis.ntfy.length;
    const run = await cli(['check', 'php']);
    expect(run.stderr).toContain('✓ PHP 8.3.36  nothing at your alert level');
    expect(apis.ntfy.length).toBe(before);
  });

  it('answers "am I affected?" for one CVE', async () => {
    const answer = JSON.parse((await cli(['cve', 'cve-2026-109618', '--json'])).stdout) as {
      kev?: unknown;
      verdicts: { item: { id: string }; status: string }[];
    };
    expect(answer.kev).toBeDefined();
    expect(answer.verdicts.map((verdict) => [verdict.item.id, verdict.status])).toEqual([
      ['php', 'not-affected'],
      ['plex', 'not-affected'],
      ['express', 'not-affected'],
    ]);
    const plex = JSON.parse((await cli(['cve', 'CVE-2026-999001', '--json'])).stdout) as { verdicts: { item: { id: string }; status: string; fixedIn?: string }[] };
    expect(plex.verdicts.find((verdict) => verdict.item.id === 'plex')).toMatchObject({ status: 'affected', fixedIn: '1.44.0' });
    expect((await cli(['cve', 'not-a-cve'])).code).toBe(1);
  });

  it('runs from a watchlist file in CI and opens deduplicated GitHub issues', async () => {
    const file = join(home, 'patchbell.yml');
    expect((await cli(['export', '--out', file])).code).toBe(0);
    const env = { GITHUB_TOKEN: 'test-token', GITHUB_REPOSITORY: 'me/infra' };

    const first = await cli(['check', '--watchlist', file, '--github-issues'], env);
    expect(first.stderr).toContain('GitHub issues: 4 opened');
    expect(apis.issues.map((issue) => issue.title).sort()).toEqual([
      'Plex Media Server 1.41.2: CVE-2026-96655 is actively exploited',
      'Plex Media Server 1.41.2: CVE-2026-96656 is actively exploited',
      'Plex Media Server 1.41.2: CVE-2026-999001 (critical 9.1)',
      'express 4.17.1: CVE-2026-50000 (critical)',
    ]);

    // Dismissed by the user: closed issues stay closed…
    apis.issues.find((issue) => issue.title.includes('CVE-2026-999001'))!.state = 'closed';
    const second = await cli(['check', '--watchlist', file, '--github-issues'], env);
    expect(second.stderr).toContain('GitHub issues: 0 opened, 0 updated');
    expect(apis.issues).toHaveLength(4);

    // …until attackers start using it.
    apis.kev.push({ cveID: 'CVE-2026-999001', vulnerabilityName: 'Plex RCE', dateAdded: '2026-10-26', dueDate: '2026-11-16', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Apply updates.' });
    await expireCache();
    const third = await cli(['check', '--watchlist', file, '--github-issues'], env);
    expect(third.stderr).toContain('1 updated');
    const reopened = apis.issues.find((issue) => issue.title.includes('CVE-2026-999001'))!;
    expect(reopened).toMatchObject({ state: 'open', title: 'Plex Media Server 1.41.2: CVE-2026-999001 is actively exploited' });
    expect(reopened.comments[0]).toContain('now being exploited');

    const failOn = await cli(['check', '--watchlist', file, '--fail-on-alerts', '--json']);
    expect(failOn.code).toBe(2);
    expect(JSON.parse(failOn.stdout)).toHaveLength(3);
  });

  it('explains bad input', async () => {
    expect((await cli(['set', 'nope', '1.0'])).stderr).toContain('No item "nope"');
    expect((await cli(['add', 'php 8', '--level', 'loud'])).stderr).toContain('Unknown level "loud"');
    const bad = join(home, 'bad.yml');
    await writeFile(bad, 'items:\n  - acme widget\n');
    expect((await cli(['check', '--watchlist', bad])).stderr).toContain('could be several products');
  });
});
