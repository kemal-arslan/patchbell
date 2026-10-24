import { HOUR, readCache, writeCache } from '../cache.js';
import type { CpeMatch, Product } from '../cpe.js';
import { parseCpe } from '../cpe.js';
import { endpoints, getJson, sleep } from '../http.js';
import type { Cvss } from '../types.js';

/** The parts of an NVD CVE record Patchbell uses. */
export interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  status: string;
  description: string;
  cvss?: Cvss;
  cwes: string[];
  matches: CpeMatch[];
}

interface RawMetric {
  type?: string;
  cvssData: { baseScore: number; version: string; vectorString?: string };
}

interface RawCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: { lang: string; value: string }[];
  metrics?: Record<string, RawMetric[] | undefined>;
  weaknesses?: { description: { value: string }[] }[];
  configurations?: {
    operator?: string;
    nodes: {
      negate?: boolean;
      cpeMatch: {
        vulnerable: boolean;
        criteria: string;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }[];
    }[];
  }[];
}

interface RawPage {
  totalResults: number;
  resultsPerPage: number;
  startIndex: number;
  vulnerabilities: { cve: RawCve }[];
}

/** NVD's own score first, then the reporter's; newer CVSS versions before older ones. */
function bestCvss(metrics: RawCve['metrics'] = {}): Cvss | undefined {
  const order = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'];
  const pick = (primary: boolean) => {
    for (const key of order) {
      const metric = metrics[key]?.find((candidate) => (candidate.type === 'Primary') === primary);
      if (metric) return metric;
    }
    return undefined;
  };
  const metric = pick(true) ?? pick(false) ?? metrics.cvssMetricV2?.[0];
  if (!metric) return undefined;
  const { baseScore, version, vectorString } = metric.cvssData;
  return { score: baseScore, version, ...(vectorString ? { vector: vectorString } : {}) };
}

export function trimCve(raw: RawCve): NvdCve {
  const matches: CpeMatch[] = [];
  for (const configuration of raw.configurations ?? []) {
    const conditional = configuration.operator === 'AND';
    for (const node of configuration.nodes) {
      if (node.negate) continue;
      for (const match of node.cpeMatch) {
        matches.push({
          criteria: match.criteria,
          vulnerable: match.vulnerable,
          ...(match.versionStartIncluding ? { startIncluding: match.versionStartIncluding } : {}),
          ...(match.versionStartExcluding ? { startExcluding: match.versionStartExcluding } : {}),
          ...(match.versionEndIncluding ? { endIncluding: match.versionEndIncluding } : {}),
          ...(match.versionEndExcluding ? { endExcluding: match.versionEndExcluding } : {}),
          ...(conditional ? { conditional } : {}),
        });
      }
    }
  }
  const cvss = bestCvss(raw.metrics);
  return {
    id: raw.id,
    published: raw.published,
    lastModified: raw.lastModified,
    status: raw.vulnStatus,
    description: raw.descriptions.find((description) => description.lang === 'en')?.value ?? '',
    ...(cvss ? { cvss } : {}),
    cwes: [...new Set((raw.weaknesses ?? []).flatMap((weakness) => weakness.description.map((d) => d.value)).filter((value) => /^CWE-\d+$/.test(value)))],
    matches,
  };
}

/** NVD allows 5 requests per 30 seconds without an API key and 50 with one. */
let nextSlot = 0;
async function slot(): Promise<void> {
  const delay = Number(process.env.PATCHBELL_NVD_DELAY_MS ?? (process.env.NVD_API_KEY ? 700 : 6500));
  const now = Date.now();
  const at = Math.max(now, nextSlot);
  nextSlot = at + delay;
  if (at > now) await sleep(at - now);
}

/** NVD dates: UTC without the trailing Z. */
export const nvdDate = (date: Date) => date.toISOString().replace('Z', '');

/** A rate-limited GET against the NVD API, e.g. nvdGet('cves/2.0?cveId=…'). */
export async function nvdGet<T>(path: string): Promise<T> {
  await slot();
  return getJson<T>(`${endpoints().nvd}/${path}`, {
    headers: process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {},
    timeoutMs: 120_000,
  });
}

async function query(params: string): Promise<NvdCve[]> {
  const cves: NvdCve[] = [];
  for (let start = 0; ; ) {
    const page = await nvdGet<RawPage>(`cves/2.0?${params}&resultsPerPage=2000&startIndex=${start}`);
    cves.push(...page.vulnerabilities.map((entry) => trimCve(entry.cve)));
    start += page.vulnerabilities.length;
    if (page.vulnerabilities.length === 0 || start >= page.totalResults) return cves;
  }
}

const forProduct = (cve: NvdCve, target: Product): NvdCve => ({
  ...cve,
  matches: cve.matches.filter((match) => {
    const cpe = parseCpe(match.criteria);
    return cpe?.vendor === target.vendor && cpe.product === target.product;
  }),
});

/** CPE names escape punctuation: archer_c7_(2.0) is archer_c7_\\(2.0\\). */
const escapeCpe = (value: string) => value.replace(/[^a-z0-9_\-.]/gi, (char) => `\\${char}`);

interface ProductCache {
  fetchedAt: number;
  cves: NvdCve[];
}

/**
 * Every CVE NVD has mapped to a product. The first call downloads them all; later calls
 * only ask for records changed since, which NVD allows for up to 120 days.
 */
export async function productCves(target: Product): Promise<NvdCve[]> {
  const name = `nvd/${target.vendor}__${target.product}`;
  const entry = (await readCache<ProductCache>(name))?.data;
  const now = Date.now();
  if (entry && now - entry.fetchedAt < 2 * HOUR) return entry.cves;
  // Any part: NVD files some products both as applications and as operating systems.
  const match = encodeURIComponent(`cpe:2.3:*:${escapeCpe(target.vendor)}:${escapeCpe(target.product)}`);
  let cves: NvdCve[];
  if (entry && now - entry.fetchedAt < 110 * 24 * HOUR) {
    const since = nvdDate(new Date(entry.fetchedAt - HOUR));
    const changed = await query(`virtualMatchString=${match}&lastModStartDate=${since}&lastModEndDate=${nvdDate(new Date(now))}`);
    const byId = new Map(entry.cves.map((cve) => [cve.id, cve]));
    for (const cve of changed) byId.set(cve.id, forProduct(cve, target));
    cves = [...byId.values()];
  } else {
    cves = (await query(`virtualMatchString=${match}`)).map((cve) => forProduct(cve, target));
  }
  await writeCache(name, { fetchedAt: now, cves } satisfies ProductCache);
  return cves;
}

/** Recently published CVEs that mention a phrase, to catch ones NVD hasn't mapped to products yet. */
export async function recentCves(keyword: string, since: Date): Promise<NvdCve[]> {
  const params = `keywordSearch=${encodeURIComponent(keyword)}&keywordExactMatch&noRejected&pubStartDate=${nvdDate(since)}&pubEndDate=${nvdDate(new Date())}`;
  return query(params);
}

export async function cveById(id: string): Promise<NvdCve | undefined> {
  const [cve] = await query(`cveId=${encodeURIComponent(id)}`);
  return cve;
}
