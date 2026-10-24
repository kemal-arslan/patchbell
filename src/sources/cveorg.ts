import { cached, HOUR } from '../cache.js';
import type { Cve5Affected } from '../cve5.js';
import { cvss3Score } from '../cvss.js';
import { endpoints, getJsonOrUndefined } from '../http.js';
import type { Cvss } from '../types.js';

interface RawMetric {
  cvssV4_0?: { baseScore: number; vectorString: string };
  cvssV3_1?: { baseScore: number; vectorString: string };
  cvssV3_0?: { baseScore: number; vectorString: string };
}

interface RawContainer {
  title?: string;
  affected?: Cve5Affected[];
  metrics?: RawMetric[];
  problemTypes?: { descriptions?: { cweId?: string }[] }[];
  descriptions?: { lang: string; value: string }[];
}

interface RawRecord {
  cveMetadata?: { state?: string; datePublished?: string };
  containers?: { cna?: RawContainer; adp?: RawContainer[] };
}

export interface CveRecord {
  title?: string;
  description?: string;
  published?: string;
  affected: Cve5Affected[];
  cvss?: Cvss;
  cwes: string[];
}

function pickCvss(containers: RawContainer[]): Cvss | undefined {
  for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0'] as const) {
    for (const container of containers) {
      const metric = container.metrics?.find((candidate) => candidate[key])?.[key];
      if (metric) {
        const score = metric.baseScore ?? cvss3Score(metric.vectorString);
        if (score !== undefined) return { score, version: metric.vectorString.split('/')[0]!.replace('CVSS:', ''), vector: metric.vectorString };
      }
    }
  }
  return undefined;
}

/** The CVE record as published on cve.org, which carries the reporter's affected-version data. */
export async function cveRecord(id: string): Promise<CveRecord | undefined> {
  return cached(`cve5/${id}`, 12 * HOUR, async () => {
    const raw = await getJsonOrUndefined<RawRecord>(`${endpoints().cve}/${encodeURIComponent(id)}`);
    if (!raw?.containers?.cna || raw.cveMetadata?.state === 'REJECTED') return undefined;
    const containers = [raw.containers.cna, ...(raw.containers.adp ?? [])];
    const cvss = pickCvss(containers);
    return {
      ...(raw.containers.cna.title ? { title: raw.containers.cna.title } : {}),
      ...(raw.containers.cna.descriptions?.[0] ? { description: raw.containers.cna.descriptions.find((d) => d.lang.startsWith('en'))?.value ?? raw.containers.cna.descriptions[0].value } : {}),
      ...(raw.cveMetadata?.datePublished ? { published: raw.cveMetadata.datePublished } : {}),
      affected: containers.flatMap((container) => container.affected ?? []),
      ...(cvss ? { cvss } : {}),
      cwes: [
        ...new Set(
          containers.flatMap((container) => (container.problemTypes ?? []).flatMap((type) => (type.descriptions ?? []).map((d) => d.cweId ?? ''))).filter(Boolean),
        ),
      ],
    };
  });
}
