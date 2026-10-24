import { EOL_PRODUCTS } from './catalog-data.js';
import { EXTRA, EXTRA_ALIASES } from './catalog-extra.js';

export interface CatalogEntry {
  slug: string;
  label: string;
  aliases: string[];
  part: 'a' | 'o' | 'h';
  vendor: string;
  product: string;
  /** endoflife.date product, when it tracks this one. */
  eol?: string;
}

const norm = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

function toEntry(slug: string, label: string, aliases: string[], cpe: string, eol?: string): CatalogEntry {
  const [part, vendor, product] = cpe.split(':') as [CatalogEntry['part'], string, string];
  return { slug, label, aliases, part, vendor, product, ...(eol ? { eol } : {}) };
}

let entries: CatalogEntry[] | undefined;
let index: Map<string, CatalogEntry> | undefined;

export function catalog(): CatalogEntry[] {
  entries ??= [
    ...EOL_PRODUCTS.map(([slug, label, aliases, cpe]) => toEntry(slug, label, [...aliases, ...(EXTRA_ALIASES[slug] ?? [])], cpe, slug)),
    ...EXTRA.filter((extra) => !EOL_PRODUCTS.some(([slug]) => slug === extra.slug)).map((extra) => toEntry(extra.slug, extra.label, extra.aliases, extra.cpe)),
  ];
  return entries;
}

/** Looks a product up by its slug, label or an alias: "plex", "Plex Media Server", "node". */
export function findInCatalog(name: string): CatalogEntry | undefined {
  if (!index) {
    index = new Map();
    // Labels and slugs win over aliases when two products share a word.
    for (const pass of ['primary', 'alias'] as const) {
      for (const entry of catalog()) {
        const keys = pass === 'primary' ? [entry.slug, entry.label] : [...entry.aliases, `${entry.vendor} ${entry.product}`];
        for (const key of keys) if (!index.has(norm(key))) index.set(norm(key), entry);
      }
    }
  }
  return index.get(norm(name));
}

/** The catalog entry for a CPE product, to fill in end-of-life data for cpe: items. */
export function findByCpe(vendor: string, product: string): CatalogEntry | undefined {
  return catalog().find((entry) => entry.vendor === vendor && entry.product === product);
}
