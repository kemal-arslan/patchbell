/**
 * A forgiving version comparison for the formats vulnerability records use:
 * 1.41.2.9200, 8.3.0-rc1, 1.0.1u, 10.2.7-h3, v2.4.58, 2026.10.1.
 */
type Token = number | string;

/** Markers that sort before the release they precede (1.0.0-rc1 < 1.0.0). */
const PRE = ['dev', 'snapshot', 'alpha', 'a', 'beta', 'b', 'pre', 'preview', 'rc', 'c'];

export function normalizeVersion(version: string): string {
  return version.trim().toLowerCase().replace(/^v(?=\d)/, '').replace(/\+.*$/, '');
}

export function tokenize(version: string): Token[] {
  const tokens: Token[] = [];
  for (const match of normalizeVersion(version).matchAll(/\d+|[a-z]+/g)) {
    tokens.push(/^\d/.test(match[0]) ? Number(match[0]) : match[0]);
  }
  return tokens;
}

const preRank = (token: string) => PRE.indexOf(token);

function compareTokens(a: Token, b: Token): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'string' && typeof b === 'string') {
    const ra = preRank(a);
    const rb = preRank(b);
    if (ra >= 0 && rb >= 0) return ra - rb;
    if (ra >= 0) return -1;
    if (rb >= 0) return 1;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  // A letter where the other side has a number: 1.0.0-rc1 < 1.0.0.1, and 1.0.1u < 1.0.1.1.
  return typeof a === 'string' ? -1 : 1;
}

/** What it means to have extra tokens after a common prefix: pre-release, zeros, or later. */
function tailSign(tail: Token[]): number {
  for (const token of tail) {
    if (typeof token === 'string') return preRank(token) >= 0 ? -1 : 1;
    if (token !== 0) return 1;
  }
  return 0;
}

export function compareVersions(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const length = Math.min(ta.length, tb.length);
  for (let index = 0; index < length; index += 1) {
    const result = compareTokens(ta[index]!, tb[index]!);
    if (result !== 0) return Math.sign(result);
  }
  if (ta.length === tb.length) return 0;
  return ta.length > tb.length ? tailSign(ta.slice(length)) : -tailSign(tb.slice(length)) || 0;
}

/** Whether `version` starts with `prefix` at a token boundary: 8.3.10 has prefix 8.3, 8.30 doesn't. */
export function hasPrefix(version: string, prefix: string): boolean {
  const tv = tokenize(version);
  const tp = tokenize(prefix);
  return tp.length <= tv.length && tp.every((token, index) => token === tv[index]);
}

export interface Range {
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

const isOpen = (bound: string | undefined) => bound === undefined || ['', '*', '-', '0'].includes(bound.trim());

export function inRange(version: string, range: Range): boolean {
  if (!isOpen(range.startIncluding) && compareVersions(version, range.startIncluding!) < 0) return false;
  if (range.startExcluding !== undefined && compareVersions(version, range.startExcluding) <= 0) return false;
  if (range.endIncluding !== undefined && compareVersions(version, range.endIncluding) > 0) return false;
  if (range.endExcluding !== undefined && compareVersions(version, range.endExcluding) >= 0) return false;
  return true;
}

/** "8.3.0 to before 8.3.36", "versions up to 2.1", "all versions". */
export function describeRange(range: Range): string {
  const from = !isOpen(range.startIncluding) ? range.startIncluding! : range.startExcluding ? `after ${range.startExcluding}` : '';
  const to = range.endExcluding ? `before ${range.endExcluding}` : range.endIncluding ? `up to ${range.endIncluding}` : '';
  if (from && to) return `${from} to ${to}`;
  if (to) return `versions ${to}`;
  if (from) return `${from} and later`;
  return 'all versions';
}

export const looksLikeVersion = (value: string) => /^v?\d+([.\-_+~:][0-9a-z]+)*$/i.test(value) || /^v?\d+[a-z]$/i.test(value);
