import { describe, expect, it } from 'vitest';
import { matchCpe, parseCpe, type CpeMatch } from '../../src/cpe.js';

const PHP = { vendor: 'php', product: 'php' };

/** CVE-2026-109618 (PHP2Shell) as NVD lists it. */
const php2shell: CpeMatch[] = [
  { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vulnerable: true, startIncluding: '7.3.0', endExcluding: '8.2.35' },
  { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vulnerable: true, startIncluding: '8.3.0', endExcluding: '8.3.36' },
  { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vulnerable: true, startIncluding: '8.4.0', endExcluding: '8.4.27' },
  { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vulnerable: true, startIncluding: '8.5.0', endExcluding: '8.5.12' },
  { criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h3:*:*:*:*:*:*', vulnerable: true },
  { criteria: 'cpe:2.3:o:paloaltonetworks:pan-os:-:*:*:*:*:*:*:*', vulnerable: true, conditional: true },
  { criteria: 'cpe:2.3:h:paloaltonetworks:panorama_m-200:-:*:*:*:*:*:*:*', vulnerable: false, conditional: true },
];

describe('parseCpe', () => {
  it('splits fields and unescapes punctuation', () => {
    expect(parseCpe('cpe:2.3:o:tp-link:archer_c7_\\(2.0\\)_firmware:141110:*:*:*:*:*:*:*')).toMatchObject({
      part: 'o',
      vendor: 'tp-link',
      product: 'archer_c7_(2.0)_firmware',
      version: '141110',
    });
    expect(parseCpe('cpe:/a:php:php')).toBeNull();
  });
});

describe('matchCpe', () => {
  it('finds the range that contains the version and its fix', () => {
    expect(matchCpe(php2shell, PHP, '8.3.10')).toEqual({ status: 'affected', reason: 'NVD: 8.3.0 to before 8.3.36', conditional: false, fixedIn: '8.3.36' });
    expect(matchCpe(php2shell, PHP, '8.1.2')).toMatchObject({ status: 'affected', fixedIn: '8.2.35' });
  });

  it('clears fixed versions', () => {
    expect(matchCpe(php2shell, PHP, '8.3.36')).toMatchObject({ status: 'not-affected' });
    expect(matchCpe(php2shell, PHP, '7.2.34')).toMatchObject({ status: 'not-affected' });
  });

  it('ignores other products and non-vulnerable platforms', () => {
    expect(matchCpe(php2shell, { vendor: 'nginx', product: 'nginx' }, '1.26.2')).toEqual({ status: 'no-match' });
    expect(matchCpe(php2shell, { vendor: 'paloaltonetworks', product: 'panorama_m-200' }, '1')).toEqual({ status: 'no-match' });
  });

  it('matches exact versions with their update field', () => {
    const panos = { vendor: 'paloaltonetworks', product: 'pan-os' };
    expect(matchCpe(php2shell, panos, '10.2.7-h3')).toMatchObject({ status: 'affected', conditional: true });
    // Versioned entries win over the "-" entry: 11.1.17 isn't listed, so it isn't affected.
    expect(matchCpe(php2shell, panos, '11.1.17')).toMatchObject({ status: 'not-affected' });
  });

  it('reports product-level matches without a version', () => {
    expect(matchCpe(php2shell, PHP)).toMatchObject({ status: 'product', reason: expect.stringContaining('8.3.0 to before 8.3.36') });
  });

  it('treats "*" without a range as all versions and "-" as unknown', () => {
    expect(matchCpe([{ criteria: 'cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*', vulnerable: true }], { vendor: 'acme', product: 'tool' }, '3.1')).toMatchObject({
      status: 'affected',
      reason: 'NVD: all versions',
    });
    expect(matchCpe([{ criteria: 'cpe:2.3:o:acme:fw:-:*:*:*:*:*:*:*', vulnerable: true }], { vendor: 'acme', product: 'fw' }, '3.1')).toMatchObject({
      status: 'unconfirmed',
    });
  });

  it('matches any update of an exact version when the update is "*"', () => {
    const matches = [{ criteria: 'cpe:2.3:a:acme:tool:2.4.1:*:*:*:*:*:*:*', vulnerable: true }];
    expect(matchCpe(matches, { vendor: 'acme', product: 'tool' }, '2.4.1-h2')).toMatchObject({ status: 'affected' });
    expect(matchCpe(matches, { vendor: 'acme', product: 'tool' }, '2.4.1.5')).toMatchObject({ status: 'not-affected' });
  });

  it('suggests the later fix when ranges overlap', () => {
    const matches = [
      { criteria: 'cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*', vulnerable: true, startIncluding: '1.0', endExcluding: '1.4' },
      { criteria: 'cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*', vulnerable: true, endExcluding: '1.9' },
    ];
    expect(matchCpe(matches, { vendor: 'acme', product: 'tool' }, '1.2')).toMatchObject({ fixedIn: '1.9' });
  });
});
