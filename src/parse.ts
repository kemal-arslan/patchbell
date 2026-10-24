import { parseCpe } from './cpe.js';
import { looksLikeVersion } from './versions.js';

/** Friendly prefixes for OSV ecosystems: npm:express@4.19.2, pypi:django@4.2.1. */
export const ECOSYSTEMS: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  pip: 'PyPI',
  go: 'Go',
  cargo: 'crates.io',
  crates: 'crates.io',
  maven: 'Maven',
  gem: 'RubyGems',
  rubygems: 'RubyGems',
  composer: 'Packagist',
  packagist: 'Packagist',
  nuget: 'NuGet',
  hex: 'Hex',
  pub: 'Pub',
};

export interface PackageSpec {
  ecosystem: string;
  name: string;
  version?: string;
}

function splitVersion(rest: string): { name: string; version?: string } {
  const at = rest.lastIndexOf('@');
  if (at <= 0) return { name: rest };
  const version = rest.slice(at + 1);
  return version ? { name: rest.slice(0, at), version } : { name: rest.slice(0, at) };
}

/**
 * npm:express@4.19.2, npm:@scope/pkg, maven:org.apache.logging.log4j:log4j-core@2.14.1,
 * or any OSV ecosystem as osv:Debian:12/openssl@3.0.15-1~deb12u1.
 */
export function parsePackage(spec: string): PackageSpec | null {
  const colon = spec.indexOf(':');
  if (colon <= 0) return null;
  const prefix = spec.slice(0, colon).toLowerCase();
  const rest = spec.slice(colon + 1).trim();
  if (prefix === 'osv') {
    const slash = rest.indexOf('/');
    if (slash <= 0) return null;
    const { name, version } = splitVersion(rest.slice(slash + 1));
    return name ? { ecosystem: rest.slice(0, slash), name, ...(version ? { version } : {}) } : null;
  }
  const ecosystem = ECOSYSTEMS[prefix];
  if (!ecosystem || !rest) return null;
  const { name, version } = splitVersion(rest);
  // PyPI names are case-insensitive; OSV stores them normalized.
  const normalized = ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
  return normalized ? { ecosystem, name: normalized, ...(version ? { version } : {}) } : null;
}

export interface CpeSpec {
  part: 'a' | 'o' | 'h';
  vendor: string;
  product: string;
  version?: string;
}

/** cpe:2.3:a:plex:media_server[:1.41.2…] or the short cpe:plex:media_server. */
export function parseCpeSpec(spec: string): CpeSpec | null {
  if (!/^cpe:/i.test(spec)) return null;
  if (/^cpe:2\.3:/i.test(spec)) {
    const cpe = parseCpe(`${spec}${':*'.repeat(Math.max(0, 13 - spec.split(/(?<!\\):/).length))}`);
    if (!cpe || !['a', 'o', 'h'].includes(cpe.part) || cpe.vendor === '*' || cpe.product === '*') return null;
    const version = cpe.version !== '*' && cpe.version !== '-' ? cpe.version : undefined;
    return { part: cpe.part as CpeSpec['part'], vendor: cpe.vendor, product: cpe.product, ...(version ? { version } : {}) };
  }
  const [, vendor, product] = spec.toLowerCase().split(':');
  return vendor && product ? { part: 'a', vendor, product } : null;
}

/** "plex media server 1.41.2" → name "plex media server", version "1.41.2". */
export function splitNameVersion(text: string): { name: string; version?: string } {
  const words = text.trim().split(/\s+/);
  const last = words.at(-1) ?? '';
  if (words.length > 1 && looksLikeVersion(last)) return { name: words.slice(0, -1).join(' '), version: last.replace(/^v(?=\d)/i, '') };
  const at = text.lastIndexOf('@');
  if (at > 0 && looksLikeVersion(text.slice(at + 1))) return { name: text.slice(0, at).trim(), version: text.slice(at + 1) };
  return { name: text.trim() };
}

export const slugify = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'item';
