import { describe, expect, it } from 'vitest';
import { compareVersions, describeRange, hasPrefix, inRange, looksLikeVersion } from '../../src/versions.js';

describe('compareVersions', () => {
  it.each([
    ['8.3.10', '8.3.36', -1],
    ['8.3.36', '8.3.36', 0],
    ['8.10.0', '8.9.9', 1],
    ['1.0', '1.0.0', 0],
    ['1.0.0-rc1', '1.0.0', -1],
    ['1.0.0-beta.2', '1.0.0-rc.1', -1],
    ['1.0.0', '1.0.1-alpha', -1],
    ['1.0.1u', '1.0.1', 1],
    ['1.0.1u', '1.0.1v', -1],
    ['10.2.7-h3', '10.2.7', 1],
    ['10.2.7-h3', '10.2.8', -1],
    ['10.2.7-h3', '10.2.7-h10', -1],
    ['v2.4.58', '2.4.58', 0],
    ['1.41.2.9200', '1.43.3.10861', -1],
    ['9.8p1', '9.8', 1],
    ['9.8p1', '9.9', -1],
    ['2026.10.1', '2026.9.4', 1],
    ['5.0.0-alpha.1', '4.21.2', 1],
  ])('%s vs %s → %i', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(-expected || 0);
  });
});

describe('ranges', () => {
  it('honours inclusive and exclusive bounds', () => {
    const range = { startIncluding: '8.3.0', endExcluding: '8.3.36' };
    expect(inRange('8.3.0', range)).toBe(true);
    expect(inRange('8.3.35', range)).toBe(true);
    expect(inRange('8.3.36', range)).toBe(false);
    expect(inRange('8.2.99', range)).toBe(false);
    expect(inRange('2.0', { startExcluding: '1.0', endIncluding: '2.0' })).toBe(true);
    expect(inRange('1.0', { startExcluding: '1.0', endIncluding: '2.0' })).toBe(false);
    expect(inRange('0.1', { startIncluding: '0', endExcluding: '1' })).toBe(true);
  });

  it('describes ranges in words', () => {
    expect(describeRange({ startIncluding: '8.3.0', endExcluding: '8.3.36' })).toBe('8.3.0 to before 8.3.36');
    expect(describeRange({ endIncluding: '2.1' })).toBe('versions up to 2.1');
    expect(describeRange({ startExcluding: '3' })).toBe('after 3 and later');
    expect(describeRange({})).toBe('all versions');
  });

  it('matches prefixes at token boundaries', () => {
    expect(hasPrefix('8.3.10', '8.3')).toBe(true);
    expect(hasPrefix('8.30.1', '8.3')).toBe(false);
    expect(hasPrefix('8.3', '8.3.1')).toBe(false);
  });
});

describe('looksLikeVersion', () => {
  it.each(['1.41.2', 'v2.4', '8', '1.0.1u', '10.2.7-h3', '2026.10.1', '1.41.2.9200-c26e2b1b8'])('accepts %s', (value) => {
    expect(looksLikeVersion(value)).toBe(true);
  });
  it.each(['server', 'ax55', 'media', ''])('rejects %s', (value) => {
    expect(looksLikeVersion(value)).toBe(false);
  });
});
