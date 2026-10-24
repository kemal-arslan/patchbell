import { compareVersions, describeRange, hasPrefix, inRange, tokenize, type Range } from './versions.js';

export interface Cpe {
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  targetSw: string;
}

/** A vulnerable-software entry from an NVD configuration. */
export interface CpeMatch extends Range {
  criteria: string;
  vulnerable: boolean;
  /** Part of an AND configuration ("X running on Y"), so only some setups are affected. */
  conditional?: boolean;
}

const unescape = (value: string) => value.replace(/\\(.)/g, '$1');

/** Parses a CPE 2.3 formatted string such as cpe:2.3:a:php:php:8.3.0:*:*:*:*:*:*:*. */
export function parseCpe(value: string): Cpe | null {
  const fields = value.split(/(?<!\\):/).map(unescape);
  if (fields[0] !== 'cpe' || fields[1] !== '2.3' || fields.length < 5) return null;
  const field = (index: number) => (fields[index] ?? '*').toLowerCase();
  return {
    part: field(2),
    vendor: field(3),
    product: field(4),
    version: field(5),
    update: field(6),
    targetSw: field(10),
  };
}

export interface Product {
  vendor: string;
  product: string;
}

const hasRange = (match: CpeMatch) =>
  match.startIncluding !== undefined || match.startExcluding !== undefined || match.endIncluding !== undefined || match.endExcluding !== undefined;

const isAny = (value: string) => value === '*' || value === '';

/** Whether an exact CPE version (with its update field, e.g. 10.2.7 + h3) is the user's version. */
function sameVersion(version: string, cpe: Cpe): boolean {
  if (cpe.update !== '-' && !isAny(cpe.update)) return compareVersions(version, `${cpe.version}-${cpe.update}`) === 0;
  if (compareVersions(version, cpe.version) === 0) return true;
  if (!isAny(cpe.update)) return false;
  // Any update of this version: 10.2.7-h3 counts for 10.2.7:*.
  const rest = tokenize(version).slice(tokenize(cpe.version).length);
  return hasPrefix(version, cpe.version) && typeof rest[0] === 'string';
}

export type CpeVerdict =
  | { status: 'no-match' }
  | { status: 'not-affected'; reason: string }
  | { status: 'affected' | 'unconfirmed' | 'product'; reason: string; fixedIn?: string; conditional: boolean };

/**
 * Decides whether a product version is affected, from a CVE's vulnerable CPE entries.
 * Version ranges and exact versions are trusted over entries without version information.
 */
export function matchCpe(matches: readonly CpeMatch[], target: Product, version?: string): CpeVerdict {
  const relevant = matches.flatMap((match) => {
    const cpe = match.vulnerable ? parseCpe(match.criteria) : null;
    return cpe && cpe.vendor === target.vendor && cpe.product === target.product ? [{ match, cpe }] : [];
  });
  if (relevant.length === 0) return { status: 'no-match' };
  const conditional = relevant.some(({ match }) => match.conditional);
  const versioned = relevant.filter(({ match, cpe }) => hasRange(match) || !(isAny(cpe.version) || cpe.version === '-'));

  if (!version) {
    const ranges = versioned.filter(({ match }) => hasRange(match)).map(({ match }) => describeRange(match));
    return { status: 'product', reason: ranges.length ? `NVD: ${ranges.slice(0, 3).join('; ')}` : 'NVD lists the product as affected', conditional };
  }

  const hits = versioned.filter(({ match, cpe }) => (hasRange(match) ? inRange(version, match) : sameVersion(version, cpe)));
  if (hits.length > 0) {
    // Overlapping ranges for one version are a data error; the later fix is the safe advice.
    const fixes = hits
      .map(({ match }) => match.endExcluding)
      .filter((fix): fix is string => !!fix && compareVersions(fix, version) > 0)
      .sort((a, b) => compareVersions(b, a));
    const ranged = hits.find(({ match }) => hasRange(match));
    const reason = ranged ? `NVD: ${describeRange(ranged.match)}` : `NVD lists ${version} as affected`;
    return { status: 'affected', reason, conditional, ...(fixes[0] ? { fixedIn: fixes[0] } : {}) };
  }
  if (versioned.length > 0) return { status: 'not-affected', reason: 'NVD version ranges do not include your version' };
  if (relevant.some(({ cpe }) => isAny(cpe.version))) return { status: 'affected', reason: 'NVD: all versions', conditional };
  return { status: 'unconfirmed', reason: 'NVD names the product but not the affected versions', conditional };
}
