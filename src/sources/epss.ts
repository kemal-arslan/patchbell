import { DAY, readCache, writeCache } from '../cache.js';
import { endpoints, getJson } from '../http.js';

interface EpssResponse {
  data: { cve: string; epss: string; percentile: string }[];
}

export interface Epss {
  score: number;
  percentile: number;
}

type Store = Record<string, Epss & { at: number }>;

/** FIRST's EPSS: the estimated chance a CVE is exploited in the next 30 days. Best effort. */
export async function loadEpss(cves: readonly string[]): Promise<Map<string, Epss>> {
  const store = (await readCache<Store>('epss'))?.data ?? {};
  const now = Date.now();
  const wanted = [...new Set(cves.filter((cve) => /^CVE-\d{4}-\d+$/.test(cve)))];
  const stale = wanted.filter((cve) => !store[cve] || now - store[cve].at > DAY);
  try {
    for (let index = 0; index < stale.length; index += 50) {
      const chunk = stale.slice(index, index + 50);
      const response = await getJson<EpssResponse>(`${endpoints().epss}?cve=${chunk.join(',')}`, { retries: 1 });
      for (const row of response.data) store[row.cve] = { score: Number(row.epss), percentile: Number(row.percentile), at: now };
      // CVEs EPSS hasn't scored yet: remember that, so they aren't asked for again today.
      for (const cve of chunk) store[cve] ??= { score: 0, percentile: 0, at: now };
    }
    if (stale.length > 0) await writeCache('epss', store);
  } catch {
    // EPSS only adds context; checks work without it.
  }
  const result = new Map<string, Epss>();
  for (const cve of wanted) {
    const entry = store[cve];
    if (entry && entry.score > 0) result.set(cve, { score: entry.score, percentile: entry.percentile });
  }
  return result;
}
