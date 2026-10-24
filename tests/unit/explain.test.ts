import { describe, expect, it } from 'vitest';
import { cvss3Score, severityOf } from '../../src/cvss.js';
import { describeAttack, fixAdvice, severityWord, whyItMatters } from '../../src/explain.js';
import { byUrgency, meetsLevel } from '../../src/filter.js';
import type { Finding } from '../../src/types.js';

const finding = (extra: Partial<Finding> = {}): Finding => ({
  id: 'CVE-2026-1',
  aliases: [],
  title: 'Something bad',
  status: 'affected',
  cwes: [],
  reason: 'test',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1',
  ...extra,
});

describe('cvss3Score', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s → %s', (vector, score) => {
    expect(cvss3Score(vector)).toBe(score);
  });

  it('rejects incomplete and other versions', () => {
    expect(cvss3Score('CVSS:3.1/AV:N/AC:L')).toBeUndefined();
    expect(cvss3Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeUndefined();
    expect(severityOf(9.8)).toBe('critical');
    expect(severityOf(4)).toBe('medium');
  });
});

describe('explanations', () => {
  it('turns a vector and CWE into a sentence', () => {
    expect(describeAttack({ cvss: { score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, cwes: ['CWE-78'] })).toBe(
      'An attacker can run commands on it over the network without logging in.',
    );
    expect(describeAttack({ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', cwes: [] })).toBe(
      'An attacker can read sensitive data over the network with a normal account, if someone opens a link or file.',
    );
    expect(describeAttack({ cwes: [] })).toBeUndefined();
  });

  it('leads with exploitation', () => {
    const lines = whyItMatters(finding({ kev: { cve: 'CVE-2026-1', name: 'x', dateAdded: '2026-10-20', dueDate: '2026-11-10', ransomware: true, action: 'Apply updates.' }, epss: { score: 0.42, percentile: 0.99 } }));
    expect(lines[0]).toBe('Attackers are already using it (CISA, since Oct 20, 2026, including ransomware).');
    expect(lines.at(-1)).toBe('Estimated 42% chance of attacks in the next 30 days (EPSS).');
  });

  it('gives fix advice from the data it has', () => {
    expect(fixAdvice(finding({ fixedIn: '8.3.36' }))).toBe('Update to 8.3.36 or later.');
    expect(fixAdvice(finding(), '1.0')).toBe('No fixed version is listed yet; see the advisory.');
    expect(severityWord(finding({ cvss: { score: 9.8, version: '3.1' } }))).toBe('critical 9.8');
    expect(severityWord(finding({ severity: 'moderate' }))).toBe('moderate');
  });
});

describe('levels', () => {
  const kev = { cve: 'CVE-2026-1', name: 'x', dateAdded: '2026-10-20', dueDate: '2026-11-10', ransomware: false, action: '' };
  it.each([
    [finding({ kev, cvss: { score: 5, version: '3.1' } }), [true, true, true, true]],
    [finding({ cvss: { score: 9.8, version: '3.1' } }), [false, true, true, true]],
    [finding({ cvss: { score: 7.5, version: '3.1' } }), [false, false, true, true]],
    [finding({ cvss: { score: 5, version: '3.1' }, epss: { score: 0.2, percentile: 0.99 } }), [false, true, true, true]],
    [finding({ severity: 'high' }), [false, false, true, true]],
    [finding({ severity: 'low' }), [false, false, false, true]],
  ])('%#', (subject, expected) => {
    expect((['exploited', 'critical', 'high', 'all'] as const).map((level) => meetsLevel(subject, level))).toEqual(expected);
  });

  it('sorts exploited first, then by score', () => {
    const list = [finding({ id: 'a', cvss: { score: 9.8, version: '3.1' } }), finding({ id: 'b', kev, cvss: { score: 5, version: '3.1' } }), finding({ id: 'c', cvss: { score: 10, version: '3.1' } })];
    expect(list.sort(byUrgency).map((entry) => entry.id)).toEqual(['b', 'c', 'a']);
  });
});
