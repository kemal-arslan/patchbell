import { cached, HOUR } from '../cache.js';
import { endpoints, getJson } from '../http.js';
import type { KevEntry } from '../types.js';

interface KevFeed {
  vulnerabilities: {
    cveID: string;
    vulnerabilityName: string;
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse?: string;
    requiredAction: string;
  }[];
}

/** CISA's Known Exploited Vulnerabilities catalog: CVEs attackers are using. */
export async function loadKev(): Promise<Map<string, KevEntry>> {
  const entries = await cached('kev', 6 * HOUR, async () => {
    const feed = await getJson<KevFeed>(endpoints().kev);
    return feed.vulnerabilities.map(
      (entry): KevEntry => ({
        cve: entry.cveID,
        name: entry.vulnerabilityName,
        dateAdded: entry.dateAdded,
        dueDate: entry.dueDate,
        ransomware: entry.knownRansomwareCampaignUse === 'Known',
        action: entry.requiredAction,
      }),
    );
  });
  return new Map(entries.map((entry) => [entry.cve, entry]));
}
