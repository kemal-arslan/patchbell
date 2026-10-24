import { describe, expect, it } from 'vitest';
import { findInCatalog } from '../../src/catalog.js';
import { parseCpeSpec, parsePackage, slugify, splitNameVersion } from '../../src/parse.js';
import { newId, resolve } from '../../src/resolve.js';
import { parseSelection } from '../../src/util.js';

describe('parsePackage', () => {
  it.each([
    ['npm:express@4.19.2', { ecosystem: 'npm', name: 'express', version: '4.19.2' }],
    ['npm:@scope/pkg@1.0.0', { ecosystem: 'npm', name: '@scope/pkg', version: '1.0.0' }],
    ['npm:@scope/pkg', { ecosystem: 'npm', name: '@scope/pkg' }],
    ['pypi:Django_REST.framework@3.15', { ecosystem: 'PyPI', name: 'django-rest-framework', version: '3.15' }],
    ['maven:org.apache.logging.log4j:log4j-core@2.14.1', { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' }],
    ['go:golang.org/x/net@v0.17.0', { ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.17.0' }],
    ['osv:Debian:12/openssl@3.0.15-1~deb12u1', { ecosystem: 'Debian:12', name: 'openssl', version: '3.0.15-1~deb12u1' }],
  ])('%s', (spec, expected) => {
    expect(parsePackage(spec)).toEqual(expected);
  });

  it('ignores things that are not packages', () => {
    expect(parsePackage('plex')).toBeNull();
    expect(parsePackage('cpe:2.3:a:php:php')).toBeNull();
    expect(parsePackage('unknown:thing@1')).toBeNull();
  });
});

describe('parseCpeSpec', () => {
  it('accepts full, partial and short forms', () => {
    expect(parseCpeSpec('cpe:2.3:a:f5:nginx')).toEqual({ part: 'a', vendor: 'f5', product: 'nginx' });
    expect(parseCpeSpec('cpe:2.3:o:qnap:qts:5.1.0:*:*:*:*:*:*:*')).toEqual({ part: 'o', vendor: 'qnap', product: 'qts', version: '5.1.0' });
    expect(parseCpeSpec('cpe:plex:media_server')).toEqual({ part: 'a', vendor: 'plex', product: 'media_server' });
    expect(parseCpeSpec('cpe:2.3:*:*:nginx')).toBeNull();
  });
});

describe('splitNameVersion', () => {
  it.each([
    ['plex media server 1.41.2', { name: 'plex media server', version: '1.41.2' }],
    ['Home Assistant v2026.10.1', { name: 'Home Assistant', version: '2026.10.1' }],
    ['php@8.3.10', { name: 'php', version: '8.3.10' }],
    ['tp-link archer ax55', { name: 'tp-link archer ax55' }],
    ['openssl 1.0.1u', { name: 'openssl', version: '1.0.1u' }],
  ])('%s', (text, expected) => {
    expect(splitNameVersion(text)).toEqual(expected);
  });
});

describe('catalog and resolve', () => {
  it('knows common products and their end-of-life data', () => {
    expect(findInCatalog('php')).toMatchObject({ vendor: 'php', product: 'php', eol: 'php' });
    expect(findInCatalog('Plex Media Server')).toMatchObject({ slug: 'plex', vendor: 'plex', product: 'media_server' });
    expect(findInCatalog('node')).toMatchObject({ slug: 'nodejs' });
    expect(findInCatalog('mikrotik')).toMatchObject({ slug: 'routeros' });
  });

  it('resolves names, packages and CPEs without asking NVD', async () => {
    await expect(resolve('plex 1.41.2')).resolves.toMatchObject({
      kind: 'resolved',
      how: 'catalog',
      idHint: 'plex',
      item: { name: 'Plex Media Server', version: '1.41.2', keyword: 'Plex Media Server', source: { kind: 'cpe', vendor: 'plex', product: 'media_server' } },
    });
    await expect(resolve('npm:express@4.19.2', { level: 'high' })).resolves.toMatchObject({
      item: { name: 'express', version: '4.19.2', level: 'high', source: { kind: 'package', ecosystem: 'npm', name: 'express' } },
    });
    // nginx moved from nginx:nginx to f5:nginx; both are checked.
    await expect(resolve('cpe:2.3:a:f5:nginx 1.26.2')).resolves.toMatchObject({
      idHint: 'nginx',
      item: { name: 'nginx', version: '1.26.2', eol: 'nginx', source: { vendor: 'f5', product: 'nginx', also: [{ vendor: 'nginx', product: 'nginx' }] } },
    });
  });

  it('makes readable unique IDs', () => {
    const item = { name: 'Plex Media Server', source: { kind: 'cpe' as const, part: 'a' as const, vendor: 'plex', product: 'media_server' } };
    expect(newId(item, [])).toBe('plex-media-server');
    expect(newId(item, ['plex'], 'plex')).toBe('plex-2');
    expect(newId({ name: 'openssl (Debian:12)', source: { kind: 'package', ecosystem: 'Debian:12', name: 'openssl' } }, [])).toBe('debian-12-openssl');
    expect(slugify('!!!')).toBe('item');
  });
});

describe('parseSelection', () => {
  it('reads lists and ranges', () => {
    expect(parseSelection('1,3, 5-7', 8)).toEqual([0, 2, 4, 5, 6]);
    expect(parseSelection('all', 3)).toEqual([0, 1, 2]);
    expect(parseSelection('', 3)).toEqual([]);
    expect(() => parseSelection('9', 3)).toThrow(/between 1 and 3/);
  });
});
