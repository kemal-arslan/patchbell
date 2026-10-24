import { describe, expect, it } from 'vitest';
import { describesProduct, matchCve5, type Cve5Affected } from '../../src/cve5.js';

const PHP = { vendor: 'php', product: 'php' };

/** The CNA's affected data for CVE-2026-109618, as published on cve.org. */
const php2shell: Cve5Affected[] = [
  {
    vendor: 'PHP Group',
    product: 'PHP',
    packageName: 'php-src',
    versions: [
      { status: 'affected', version: '8.2.*', lessThan: '8.2.35', versionType: 'semver' },
      { status: 'affected', version: '8.3.*', lessThan: '8.3.36', versionType: 'semver' },
      { status: 'affected', version: '8.4.*', lessThan: '8.4.27', versionType: 'semver' },
      { status: 'affected', version: '8.5.*', lessThan: '8.5.12', versionType: 'semver' },
    ],
    defaultStatus: 'unaffected',
  },
];

describe('matchCve5', () => {
  it('understands wildcard release lines', () => {
    expect(matchCve5(php2shell, PHP, ['PHP'], '8.3.10')).toEqual({ status: 'affected', reason: 'CVE record: affected before 8.3.36', fixedIn: '8.3.36' });
    expect(matchCve5(php2shell, PHP, ['PHP'], '8.3.36')).toMatchObject({ status: 'not-affected' });
    expect(matchCve5(php2shell, PHP, ['PHP'], '8.1.2')).toMatchObject({ status: 'not-affected' });
  });

  it('returns product-level matches without a version', () => {
    expect(matchCve5(php2shell, PHP, ['PHP'])).toMatchObject({ status: 'product' });
  });

  it('matches products by name when vendors use other words', () => {
    const plex: Cve5Affected = { vendor: 'Plex', product: 'Media Server', versions: [{ version: '0', lessThan: '1.44.0', status: 'affected' }] };
    const target = { vendor: 'plex', product: 'media_server' };
    expect(describesProduct(plex, target, ['Plex Media Server'])).toBe(true);
    expect(matchCve5([plex], target, ['Plex Media Server'], '1.41.2')).toMatchObject({ status: 'affected', fixedIn: '1.44.0' });
    expect(matchCve5([{ vendor: 'n/a', product: 'n/a' }], target, ['Plex Media Server'], '1.41.2')).toEqual({ status: 'no-match' });
    expect(matchCve5([{ vendor: 'Other', product: 'Some Plugin' }], target, ['Plex Media Server'], '1.41.2')).toEqual({ status: 'no-match' });
  });

  it('matches by CPE when the record lists one', () => {
    const entry: Cve5Affected = { vendor: 'x', product: 'y', cpes: ['cpe:2.3:a:plex:media_server:*:*:*:*:*:*:*:*'], versions: [{ version: '1.0', status: 'affected' }] };
    expect(matchCve5([entry], { vendor: 'plex', product: 'media_server' }, [], '1.0')).toMatchObject({ status: 'affected' });
  });

  it('lets "unaffected" ranges override broader "affected" ones', () => {
    const entry: Cve5Affected = {
      product: 'Tool',
      versions: [
        { version: '0', lessThan: '*', status: 'affected' },
        { version: '2.5.1', lessThan: '2.5.*', status: 'unaffected' },
      ],
    };
    expect(matchCve5([entry], { vendor: 'acme', product: 'tool' }, ['Tool'], '2.5.3')).toMatchObject({ status: 'not-affected' });
    expect(matchCve5([entry], { vendor: 'acme', product: 'tool' }, ['Tool'], '2.4.0')).toMatchObject({ status: 'affected' });
  });

  it('is honest when versions are not given', () => {
    const entry: Cve5Affected = { vendor: 'Acme', product: 'Tool', versions: [{ version: 'n/a', status: 'affected' }] };
    expect(matchCve5([entry], { vendor: 'acme', product: 'tool' }, ['Tool'], '1.0')).toMatchObject({ status: 'unconfirmed' });
    expect(matchCve5([{ product: 'Tool', defaultStatus: 'affected' }], { vendor: 'acme', product: 'tool' }, ['Tool'], '1.0')).toMatchObject({ status: 'affected' });
  });
});
