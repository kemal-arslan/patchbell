import type { Product } from './cpe.js';
import { compareVersions, hasPrefix } from './versions.js';

/** The parts of a CVE JSON 5 record (cve.org) that say which versions are affected. */
export interface Cve5Version {
  version: string;
  status: 'affected' | 'unaffected' | 'unknown';
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
}

export interface Cve5Affected {
  vendor?: string;
  product?: string;
  packageName?: string;
  cpes?: string[];
  versions?: Cve5Version[];
  defaultStatus?: 'affected' | 'unaffected' | 'unknown';
}

export type Cve5Verdict =
  | { status: 'no-match' }
  | { status: 'not-affected'; reason: string }
  | { status: 'affected' | 'unconfirmed' | 'product'; reason: string; fixedIn?: string };

const norm = (value: string | undefined) => (value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const PLACEHOLDER = new Set(['', 'na', 'unspecified', 'unknown', 'all', '*', '0']);
const isWildcard = (value: string) => /(^|\.)(\*|x)$/i.test(value.trim());
const stripWildcard = (value: string) => value.trim().replace(/\.?(\*|x)$/i, '');

/** Whether an affected entry describes the watched product. */
export function describesProduct(entry: Cve5Affected, target: Product, names: readonly string[]): boolean {
  if (entry.cpes?.some((cpe) => cpe.toLowerCase().split(':').slice(3, 5).join(':') === `${target.vendor}:${target.product}`)) return true;
  const wanted = new Set([norm(target.product), norm(`${target.vendor}${target.product}`), ...names.map(norm)].filter((name) => name.length > 1));
  const product = norm(entry.product);
  if (PLACEHOLDER.has(product)) return false;
  return wanted.has(product) || wanted.has(norm(entry.packageName)) || wanted.has(norm(`${entry.vendor ?? ''}${entry.product ?? ''}`));
}

function lowerBoundOk(version: string, lower: string): boolean {
  if (isWildcard(lower)) {
    const prefix = stripWildcard(lower);
    return !prefix || hasPrefix(version, prefix);
  }
  return PLACEHOLDER.has(norm(lower)) || compareVersions(version, lower) >= 0;
}

function entryStatus(entry: Cve5Version, version: string): { hit: boolean; fixedIn?: string } {
  if (entry.lessThan !== undefined || entry.lessThanOrEqual !== undefined) {
    if (!lowerBoundOk(version, entry.version)) return { hit: false };
    const upper = entry.lessThan ?? entry.lessThanOrEqual!;
    if (isWildcard(upper)) return { hit: hasPrefix(version, stripWildcard(upper)) || !stripWildcard(upper) };
    const cmp = compareVersions(version, upper);
    const hit = entry.lessThan !== undefined ? cmp < 0 : cmp <= 0;
    return hit && entry.lessThan !== undefined ? { hit, fixedIn: entry.lessThan } : { hit };
  }
  if (isWildcard(entry.version)) return { hit: hasPrefix(version, stripWildcard(entry.version)) };
  if (PLACEHOLDER.has(norm(entry.version))) return { hit: false };
  return { hit: compareVersions(version, entry.version) === 0 };
}

/**
 * Decides whether a version is affected according to the CVE record's own "affected" data,
 * which CNAs publish before NVD adds CPE ranges.
 */
export function matchCve5(affected: readonly Cve5Affected[], target: Product, names: readonly string[], version?: string): Cve5Verdict {
  const entries = affected.filter((entry) => describesProduct(entry, target, names));
  if (entries.length === 0) return { status: 'no-match' };
  const label = entries[0]!.product ?? target.product;
  if (!version) return { status: 'product', reason: `CVE record lists ${label}` };

  let affectedHit: { fixedIn?: string } | undefined;
  let unaffectedHit = false;
  let unknownAffected = false;
  let defaultStatus: string | undefined;
  for (const entry of entries) {
    defaultStatus ??= entry.defaultStatus;
    for (const range of entry.versions ?? []) {
      if (range.versionType === 'git') continue;
      if (range.status === 'affected' && PLACEHOLDER.has(norm(range.version)) && range.lessThan === undefined && range.lessThanOrEqual === undefined) {
        unknownAffected = true;
        continue;
      }
      const { hit, fixedIn } = entryStatus(range, version);
      if (!hit) continue;
      if (range.status === 'unaffected') unaffectedHit = true;
      else if (range.status === 'affected') affectedHit = affectedHit?.fixedIn ? affectedHit : fixedIn ? { fixedIn } : {};
    }
  }
  if (unaffectedHit) return { status: 'not-affected', reason: 'CVE record lists your version as unaffected' };
  if (affectedHit) {
    return {
      status: 'affected',
      reason: affectedHit.fixedIn ? `CVE record: affected before ${affectedHit.fixedIn}` : `CVE record lists ${version} as affected`,
      ...affectedHit,
    };
  }
  if (defaultStatus === 'affected') return { status: 'affected', reason: 'CVE record: affected unless listed otherwise' };
  if (defaultStatus === 'unaffected' && !unknownAffected) return { status: 'not-affected', reason: 'CVE record does not list your version' };
  const hasVersions = entries.some((entry) => (entry.versions ?? []).some((range) => !PLACEHOLDER.has(norm(range.version)) || range.lessThan));
  if (hasVersions && !unknownAffected) return { status: 'not-affected', reason: 'CVE record does not list your version' };
  return { status: 'unconfirmed', reason: `CVE record names ${label} but not the affected versions` };
}
