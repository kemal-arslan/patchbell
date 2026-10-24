import { describe, expect, it } from 'vitest';
import { buildMessages, diffResults } from '../../src/alerts.js';
import { issueBody, issueTitle } from '../../src/notify/github.js';
import { eolFor, type EolProduct } from '../../src/sources/eol.js';
import { osvFixedIn, type OsvVuln } from '../../src/sources/osv.js';
import type { State } from '../../src/store.js';
import type { Finding, ItemResult, WatchItem } from '../../src/types.js';

const php: WatchItem = { id: 'php', name: 'PHP', version: '8.3.10', source: { kind: 'cpe', part: 'a', vendor: 'php', product: 'php' }, eol: 'php', addedAt: '2026-10-24T00:00:00Z' };
const kev = { cve: 'CVE-2026-109618', name: 'PHP RCE', dateAdded: '2026-10-25', dueDate: '2026-11-15', ransomware: false, action: 'Apply updates.' };

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id,
  aliases: [],
  title: `${id} title`,
  status: 'affected',
  cvss: { score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  cwes: ['CWE-416'],
  fixedIn: '8.3.36',
  reason: 'NVD: 8.3.0 to before 8.3.36',
  url: `https://nvd.nist.gov/vuln/detail/${id}`,
  ...extra,
});

const result = (item: WatchItem, alerts: Finding[], extra: Partial<ItemResult> = {}): ItemResult => ({ item, findings: alerts, alerts, ...extra });
const empty: State = { items: {} };

describe('diffResults', () => {
  it('reports new alerts once', () => {
    const first = diffResults([result(php, [finding('CVE-2026-109618')])], empty);
    expect(first.alerts.map((alert) => alert.finding.id)).toEqual(['CVE-2026-109618']);
    const second = diffResults([result(php, [finding('CVE-2026-109618')])], first.state);
    expect(second.alerts).toEqual([]);
  });

  it('reports again when a known issue becomes exploited or confirmed', () => {
    const { state } = diffResults([result(php, [finding('CVE-2026-109618'), finding('CVE-2026-2', { status: 'unconfirmed' })])], empty);
    const next = diffResults([result(php, [finding('CVE-2026-109618', { kev }), finding('CVE-2026-2')])], state);
    expect(next.alerts.map((alert) => [alert.finding.id, alert.escalated])).toEqual([
      ['CVE-2026-109618', true],
      ['CVE-2026-2', true],
    ]);
  });

  it('starts over when the version changes, and skips failed checks', () => {
    const { state } = diffResults([result(php, [finding('CVE-2026-109618')])], empty);
    const upgraded = { ...php, version: '8.3.20' };
    expect(diffResults([result(upgraded, [finding('CVE-2026-109618')])], state).alerts).toHaveLength(1);
    expect(diffResults([result(php, [finding('CVE-2026-109618')], { error: 'down' })], empty).alerts).toHaveLength(0);
  });

  it('tells you once when a release line reaches end of life, and about new releases', () => {
    const eol = { cycle: '8.1', isEol: true, eolFrom: '2025-12-31', latest: '8.5.12', url: 'https://endoflife.date/php' };
    const old = { ...php, version: '8.1.2', updates: true };
    const first = diffResults([result(old, [], { eol, latest: '8.5.12' })], empty);
    expect(first.notices.map((notice) => notice.title)).toEqual(['PHP 8.1 no longer gets security fixes', 'PHP 8.5.12 is out']);
    expect(diffResults([result(old, [], { eol, latest: '8.5.12' })], first.state).notices).toEqual([]);
  });
});

describe('buildMessages', () => {
  it('groups an item’s alerts into one message, most urgent first', () => {
    const alerts = ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4'].map((id, index) => ({ item: php, finding: finding(id, index === 0 ? { kev } : {}), escalated: false }));
    const [message] = buildMessages(alerts, []);
    expect(message).toMatchObject({ title: 'PHP 8.3.10: actively exploited vulnerability', priority: 'urgent', itemId: 'php' });
    expect(message!.body).toContain('CVE-2026-1 (critical 9.8, exploited)');
    expect(message!.body).toContain('Fix: Update to 8.3.36 or later.');
    expect(message!.body).toContain('…and 1 more. Run: patchbell check');
  });

  it('names critical findings when nothing is exploited', () => {
    const [message] = buildMessages([{ item: php, finding: finding('CVE-2026-1'), escalated: false }], []);
    expect(message).toMatchObject({ title: 'PHP 8.3.10: 1 critical vulnerability', priority: 'high' });
  });
});

describe('GitHub issues', () => {
  it('carries a hidden marker so it is never opened twice', () => {
    const body = issueBody(php, finding('CVE-2026-109618', { kev }));
    expect(body).toContain('<!-- patchbell:php:CVE-2026-109618 -->');
    expect(body).toContain('<!-- patchbell-kev:1 -->');
    expect(body).toContain('buymeacoffee.com/kemalarslan');
    expect(issueTitle(php, finding('CVE-2026-109618', { kev }))).toBe('PHP 8.3.10: CVE-2026-109618 is actively exploited');
    expect(issueTitle(php, finding('CVE-2026-109618'))).toBe('PHP 8.3.10: CVE-2026-109618 (critical 9.8)');
  });
});

describe('end of life', () => {
  const product: EolProduct = {
    name: 'php',
    label: 'PHP',
    releases: [
      { name: '8.5', isEol: false, eolFrom: '2029-12-31', latest: { name: '8.5.12' } },
      { name: '8.3', isEol: false, eolFrom: '2027-12-31', latest: { name: '8.3.36' } },
      { name: '8.1', isEol: true, eolFrom: '2025-12-31', latest: { name: '8.1.34' } },
    ],
  };
  it('finds the release line of a version', () => {
    expect(eolFor(product, '8.3.10')).toMatchObject({ cycle: '8.3', isEol: false, latestInCycle: '8.3.36', latest: '8.5.12' });
    expect(eolFor(product, '8.1.2')).toMatchObject({ cycle: '8.1', isEol: true, eolFrom: '2025-12-31' });
    expect(eolFor(product, '7.4.33')).toBeUndefined();
  });
});

describe('osvFixedIn', () => {
  const vuln: OsvVuln = {
    id: 'GHSA-x',
    affected: [
      { package: { ecosystem: 'npm', name: 'express' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.20.0' }] }] },
      { package: { ecosystem: 'npm', name: 'express' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '5.0.0-alpha.1' }, { fixed: '5.0.0' }] }] },
      { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
    ],
  };
  it('picks the fix for the range containing the version', () => {
    expect(osvFixedIn(vuln, 'npm', 'express', '4.17.1')).toBe('4.20.0');
    expect(osvFixedIn(vuln, 'npm', 'express', '5.0.0-beta.1')).toBe('5.0.0');
    expect(osvFixedIn(vuln, 'npm', 'express', '5.1.0')).toBeUndefined();
  });
});
