import { findByCpe, findInCatalog, type CatalogEntry } from './catalog.js';
import { ALSO } from './catalog-extra.js';
import { parseCpeSpec, parsePackage, slugify, splitNameVersion } from './parse.js';
import { nvdGet } from './sources/nvd.js';
import type { Level, WatchItem } from './types.js';

/** A product NVD knows, offered when a name could mean several things. */
export interface Candidate {
  cpe: string;
  title: string;
  /** How many CPE entries NVD has for it, a rough measure of how common it is. */
  entries: number;
}

export type NewItem = Omit<WatchItem, 'id' | 'addedAt'>;

export type Resolution =
  | { kind: 'resolved'; item: NewItem; how: 'package' | 'cpe' | 'catalog' | 'search'; idHint?: string }
  | { kind: 'ambiguous'; query: string; candidates: Candidate[] }
  | { kind: 'not-found'; query: string };

export interface ResolveOptions {
  version?: string;
  level?: Level;
  updates?: boolean;
  note?: string;
  /** Pick this candidate (1-based) when the name is ambiguous. */
  pick?: number;
}

const norm = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

const titleCase = (product: string) => product.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

function fromCatalog(entry: CatalogEntry): Pick<NewItem, 'name' | 'source' | 'eol' | 'keyword'> {
  const also = ALSO[entry.slug];
  return {
    name: entry.label,
    source: { kind: 'cpe', part: entry.part, vendor: entry.vendor, product: entry.product, ...(also ? { also } : {}) },
    ...(entry.eol ? { eol: entry.eol } : {}),
    keyword: entry.label,
  };
}

interface CpeSearchPage {
  products: { cpe: { cpeName: string; deprecated: boolean; titles?: { title: string; lang: string }[] } }[];
}

/** Titles without the version at the end: "Plex Media Server 1.13.2.5154" → "Plex Media Server". */
const baseTitle = (title: string) => title.replace(/(\s+(v?\d[\w.\-()]*|update\s+\d+|sp\d+|r\d+))+\s*$/i, '').trim();

/** Products in NVD's CPE dictionary that match a name, most likely first. */
export async function searchProducts(query: string): Promise<Candidate[]> {
  const page = await nvdGet<CpeSearchPage>(`cpes/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=1000`);
  const groups = new Map<string, { title: string; entries: number; deprecated: number }>();
  for (const { cpe } of page.products) {
    const [, , part, vendor, product] = cpe.cpeName.split(':');
    if (!part || !vendor || !product) continue;
    const key = `cpe:2.3:${part}:${vendor}:${product}`;
    const title = baseTitle(cpe.titles?.find((t) => t.lang === 'en')?.title ?? titleCase(product));
    const group = groups.get(key) ?? { title, entries: 0, deprecated: 0 };
    group.entries += 1;
    if (cpe.deprecated) group.deprecated += 1;
    groups.set(key, group);
  }
  const wanted = norm(query);
  const score = (cpe: string, title: string, entries: number) => {
    const product = cpe.split(':')[4] ?? '';
    let value = Math.log10(entries + 1);
    if (norm(title) === wanted || norm(product) === wanted) value += 10;
    else if (norm(title).startsWith(wanted)) value += 3;
    return value;
  };
  return [...groups.entries()]
    // Only-deprecated names have been renamed; NVD lists the new name too.
    .filter(([, group]) => group.deprecated < group.entries)
    .map(([cpe, group]) => ({ cpe, title: group.title, entries: group.entries }))
    .sort((a, b) => score(b.cpe, b.title, b.entries) - score(a.cpe, a.title, a.entries));
}

function withOptions(base: Pick<NewItem, 'name' | 'source'> & Partial<NewItem>, options: ResolveOptions, version?: string): NewItem {
  const finalVersion = options.version ?? version;
  return {
    ...base,
    ...(finalVersion ? { version: finalVersion } : {}),
    ...(options.level ? { level: options.level } : {}),
    ...(options.updates ? { updates: true } : {}),
    ...(options.note ? { note: options.note } : {}),
  };
}

/**
 * Turns what the user typed into a watch item:
 *   "plex 1.41.2"                → catalog
 *   "npm:express@4.19.2"         → OSV package
 *   "cpe:2.3:a:nginx:nginx 1.26" → NVD product
 *   "tp-link archer ax55"        → NVD CPE search (may need a pick)
 */
export async function resolve(input: string, options: ResolveOptions = {}): Promise<Resolution> {
  const text = input.trim();
  const pkg = parsePackage(text.split(/\s+/)[0] ?? '');
  if (pkg && !/^cpe:/i.test(text)) {
    const extraVersion = text.split(/\s+/)[1];
    const label = pkg.ecosystem === 'npm' || pkg.ecosystem === 'PyPI' ? pkg.name : `${pkg.name} (${pkg.ecosystem})`;
    return {
      kind: 'resolved',
      how: 'package',
      item: withOptions({ name: label, source: { kind: 'package', ecosystem: pkg.ecosystem, name: pkg.name } }, options, pkg.version ?? extraVersion),
    };
  }

  const [first, second] = text.split(/\s+/);
  const cpe = first ? parseCpeSpec(first) : null;
  if (cpe) {
    const known = findByCpe(cpe.vendor, cpe.product);
    const base = known
      ? fromCatalog(known)
      : { name: titleCase(cpe.product), source: { kind: 'cpe' as const, part: cpe.part, vendor: cpe.vendor, product: cpe.product }, keyword: titleCase(cpe.product) };
    return { kind: 'resolved', how: 'cpe', item: withOptions(base, options, cpe.version ?? second), ...(known ? { idHint: known.slug } : {}) };
  }

  const { name, version } = splitNameVersion(text);
  const entry = findInCatalog(name);
  if (entry) return { kind: 'resolved', how: 'catalog', item: withOptions(fromCatalog(entry), options, version), idHint: entry.slug };

  const candidates = await searchProducts(name);
  if (candidates.length === 0) return { kind: 'not-found', query: name };
  const chosen = options.pick ? candidates[options.pick - 1] : undefined;
  const top = candidates[0]!;
  const obvious = candidates.length === 1 || norm(top.title) === norm(name) || norm(top.cpe.split(':')[4] ?? '') === norm(name);
  const pick = chosen ?? (obvious ? top : undefined);
  if (!pick) return { kind: 'ambiguous', query: name, candidates: candidates.slice(0, 8) };
  const spec = parseCpeSpec(pick.cpe)!;
  return {
    kind: 'resolved',
    how: 'search',
    item: withOptions({ name: pick.title, source: { kind: 'cpe', part: spec.part, vendor: spec.vendor, product: spec.product }, keyword: pick.title }, options, version),
  };
}

/** A unique, readable ID: "php", then "php-2" for a second PHP. */
export function newId(item: NewItem, taken: readonly string[], hint?: string): string {
  const { source } = item;
  const base = hint ?? slugify(source.kind === 'package' && source.ecosystem !== 'npm' ? `${source.ecosystem}-${source.name}` : item.name);
  if (!taken.includes(base)) return base;
  for (let n = 2; ; n += 1) if (!taken.includes(`${base}-${n}`)) return `${base}-${n}`;
}

export function describeSource(item: Pick<WatchItem, 'source'>): string {
  const { source } = item;
  return source.kind === 'package' ? `${source.ecosystem} package ${source.name}` : `cpe:2.3:${source.part}:${source.vendor}:${source.product}`;
}
