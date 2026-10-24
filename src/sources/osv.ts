import { cached, HOUR } from '../cache.js';
import { endpoints, request } from '../http.js';
import { compareVersions } from '../versions.js';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    package?: { ecosystem: string; name: string };
    ranges?: { type: string; events: OsvEvent[] }[];
    versions?: string[];
  }[];
}

interface QueryResponse {
  vulns?: OsvVuln[];
  next_page_token?: string;
}

/**
 * Vulnerabilities affecting a package version, decided by OSV itself (including distro
 * backports for Debian, Ubuntu and Alpine). Without a version: all of the package's.
 */
export async function osvQuery(ecosystem: string, name: string, version?: string): Promise<OsvVuln[]> {
  return cached(`osv/${ecosystem}/${name}@${version ?? 'any'}`, 2 * HOUR, async () => {
    const vulns: OsvVuln[] = [];
    let pageToken: string | undefined;
    do {
      const body = { package: { ecosystem, name }, ...(version ? { version } : {}), ...(pageToken ? { page_token: pageToken } : {}) };
      const page = (await (await request(`${endpoints().osv}/query`, { body })).json()) as QueryResponse;
      vulns.push(...(page.vulns ?? []));
      pageToken = page.next_page_token;
    } while (pageToken);
    return vulns;
  });
}

const samePackage = (ecosystem: string, name: string) => (pkg?: { ecosystem: string; name: string }) =>
  !!pkg && pkg.ecosystem.toLowerCase() === ecosystem.toLowerCase() && pkg.name.toLowerCase() === name.toLowerCase();

/** The first fixed version after the range that contains `version`. */
export function osvFixedIn(vuln: OsvVuln, ecosystem: string, name: string, version: string): string | undefined {
  const fixes: string[] = [];
  for (const affected of (vuln.affected ?? []).filter((entry) => samePackage(ecosystem, name)(entry.package))) {
    for (const range of affected.ranges ?? []) {
      if (range.type === 'GIT') continue;
      let introduced: string | undefined;
      for (const event of range.events) {
        if (event.introduced !== undefined) introduced = event.introduced;
        const fixed = event.fixed;
        if (fixed && (introduced === undefined || introduced === '0' || compareVersions(version, introduced) >= 0) && compareVersions(version, fixed) < 0) {
          fixes.push(fixed);
        }
      }
    }
  }
  return fixes.sort(compareVersions)[0];
}

/** Every package an advisory names, for answering "which of my packages does this hit?". */
export async function osvVuln(id: string): Promise<OsvVuln | undefined> {
  return cached(`osv-vuln/${id}`, 6 * HOUR, async () => {
    try {
      return (await (await request(`${endpoints().osv}/vulns/${encodeURIComponent(id)}`, { retries: 1 })).json()) as OsvVuln;
    } catch {
      return undefined;
    }
  });
}
