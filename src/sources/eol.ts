import { cached, DAY } from '../cache.js';
import { endpoints, getJsonOrUndefined } from '../http.js';
import type { EolInfo } from '../types.js';
import { hasPrefix, tokenize } from '../versions.js';

export interface EolRelease {
  name: string;
  isEol: boolean;
  eolFrom?: string | null;
  latest?: { name: string; date?: string } | null;
}

export interface EolProduct {
  name: string;
  label: string;
  releases: EolRelease[];
}

/** A product's release lines from endoflife.date: which still get fixes, and their latest versions. */
export async function eolProduct(slug: string): Promise<EolProduct | undefined> {
  return cached(`eol/${slug}`, DAY, async () => {
    const response = await getJsonOrUndefined<{ result: EolProduct }>(`${endpoints().eol}/products/${encodeURIComponent(slug)}`);
    if (!response) return undefined;
    const { name, label, releases } = response.result;
    return {
      name,
      label,
      releases: releases.map(({ name: cycle, isEol, eolFrom, latest }) => ({
        name: cycle,
        isEol,
        eolFrom: eolFrom ?? null,
        latest: latest ? { name: latest.name, ...(latest.date ? { date: latest.date } : {}) } : null,
      })),
    };
  });
}

/** The release line a version belongs to (the longest matching prefix: 8.3 for 8.3.10). */
export function eolFor(product: EolProduct, version: string): EolInfo | undefined {
  const cycle = product.releases
    .filter((release) => hasPrefix(version, release.name))
    .sort((a, b) => tokenize(b.name).length - tokenize(a.name).length)[0];
  if (!cycle) return undefined;
  const latest = product.releases.find((release) => release.latest)?.latest?.name;
  return {
    cycle: cycle.name,
    isEol: cycle.isEol,
    ...(cycle.eolFrom ? { eolFrom: cycle.eolFrom } : {}),
    ...(cycle.latest ? { latestInCycle: cycle.latest.name } : {}),
    ...(latest ? { latest } : {}),
    url: `https://endoflife.date/${product.name}`,
  };
}
