import { matchCpe, type Product } from './cpe.js';
import { matchCve5 } from './cve5.js';
import { cvss3Score } from './cvss.js';
import { byUrgency, meetsLevel } from './filter.js';
import { cveRecord } from './sources/cveorg.js';
import { eolFor, eolProduct } from './sources/eol.js';
import { loadEpss } from './sources/epss.js';
import { loadKev } from './sources/kev.js';
import { latestVersion } from './sources/latest.js';
import { productCves, recentCves, type NvdCve } from './sources/nvd.js';
import { osvFixedIn, osvQuery, type OsvVuln } from './sources/osv.js';
import type { Finding, ItemResult, KevEntry, Level, Status, WatchItem } from './types.js';
import { mapLimit, shortTitle } from './util.js';

/** How far back to look for brand-new CVEs, and for product-wide alerts on items without a version. */
export const FRESH_DAYS = 30;
/** CVE records fetched per item per check, to stay polite to cve.org. */
const MAX_UNMAPPED = 40;

const DAY_MS = 86_400_000;

function nvdFinding(cve: NvdCve, status: Status, reason: string, fixedIn?: string, extra: Partial<Finding> = {}): Finding {
  return {
    id: cve.id,
    aliases: [],
    title: shortTitle(cve.description || cve.id),
    status,
    ...(cve.cvss ? { cvss: cve.cvss } : {}),
    cwes: cve.cwes,
    ...(fixedIn ? { fixedIn } : {}),
    published: cve.published,
    reason,
    url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    ...extra,
  };
}

/** NVD for enriched CVEs, plus cve.org records for new CVEs NVD hasn't mapped to products yet. */
async function cpeFindings(item: WatchItem, since: Date): Promise<Finding[]> {
  if (item.source.kind !== 'cpe') return [];
  const source = item.source;
  const targets: Product[] = [{ vendor: source.vendor, product: source.product }, ...(source.also ?? [])];
  const found = new Map<string, Finding>();
  for (const target of targets) {
    for (const cve of await productCves(target)) {
      if (cve.status === 'Rejected' || found.has(cve.id)) continue;
      const verdict = matchCpe(cve.matches, target, item.version);
      if (verdict.status === 'no-match' || verdict.status === 'not-affected') continue;
      const reason = verdict.conditional ? `${verdict.reason} (only in some setups)` : verdict.reason;
      found.set(cve.id, nvdFinding(cve, verdict.status, reason, verdict.fixedIn));
    }
  }

  if (item.keyword) {
    const unmapped = (await recentCves(item.keyword, since))
      .filter((cve) => cve.matches.length === 0 && cve.status !== 'Rejected' && !found.has(cve.id))
      .sort((a, b) => b.published.localeCompare(a.published))
      .slice(0, MAX_UNMAPPED);
    const names = [item.name, item.keyword];
    await mapLimit(unmapped, 4, async (cve) => {
      const record = await cveRecord(cve.id).catch(() => undefined);
      if (!record) return;
      const verdict = matchCve5(record.affected, targets[0]!, names, item.version);
      if (verdict.status === 'no-match' || verdict.status === 'not-affected') return;
      found.set(
        cve.id,
        nvdFinding(cve, verdict.status, verdict.reason, verdict.fixedIn, {
          ...(record.title ? { title: shortTitle(record.title) } : {}),
          ...(!cve.cvss && record.cvss ? { cvss: record.cvss } : {}),
          ...(cve.cwes.length === 0 ? { cwes: record.cwes } : {}),
        }),
      );
    });
  }
  return [...found.values()];
}

function osvFinding(vuln: OsvVuln, item: WatchItem, ecosystem: string, name: string): Finding {
  const cve = [vuln.id, ...(vuln.aliases ?? [])].find((id) => id.startsWith('CVE-'));
  const id = cve ?? vuln.id;
  const v3 = vuln.severity?.find((entry) => entry.type === 'CVSS_V3');
  const v4 = vuln.severity?.find((entry) => entry.type === 'CVSS_V4');
  const score = v3 ? cvss3Score(v3.score) : undefined;
  const fixedIn = item.version ? osvFixedIn(vuln, ecosystem, name, item.version) : undefined;
  return {
    id,
    aliases: [vuln.id, ...(vuln.aliases ?? [])].filter((alias) => alias !== id),
    title: shortTitle(vuln.summary || vuln.details || id),
    status: item.version ? 'affected' : 'product',
    ...(score !== undefined ? { cvss: { score, version: v3!.score.slice(5, 8), vector: v3!.score } } : {}),
    ...(score === undefined && v4 ? { vector: v4.score } : {}),
    ...(vuln.database_specific?.severity ? { severity: vuln.database_specific.severity.toLowerCase() } : {}),
    cwes: vuln.database_specific?.cwe_ids ?? [],
    ...(fixedIn ? { fixedIn } : {}),
    ...(vuln.published ? { published: vuln.published } : {}),
    reason: item.version ? `OSV: ${vuln.id} affects ${name} ${item.version}` : `OSV: ${vuln.id}`,
    url: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}

async function packageFindings(item: WatchItem): Promise<Finding[]> {
  if (item.source.kind !== 'package') return [];
  const { ecosystem, name } = item.source;
  const vulns = await osvQuery(ecosystem, name, item.version);
  return vulns.filter((vuln) => !(vuln as { withdrawn?: string }).withdrawn).map((vuln) => osvFinding(vuln, item, ecosystem, name));
}

const cveIds = (finding: Finding) => [finding.id, ...finding.aliases].filter((id) => id.startsWith('CVE-'));

function isRecent(finding: Finding, since: Date): boolean {
  return (!!finding.published && new Date(finding.published) >= since) || (!!finding.kev && new Date(finding.kev.dateAdded) >= since);
}

export interface CheckOptions {
  /** The level for items that don't set their own. */
  level: Level;
  /** When each item was last checked, to look for new CVEs since then. */
  lastChecks?: Record<string, string | undefined>;
  onItem?: (item: WatchItem) => void;
  now?: Date;
}

/** Checks every item. One item failing (a source down) doesn't stop the others. */
export async function runCheck(items: readonly WatchItem[], options: CheckOptions): Promise<ItemResult[]> {
  const now = options.now ?? new Date();
  const window = new Date(now.getTime() - FRESH_DAYS * DAY_MS);
  const kev: Map<string, KevEntry> = await loadKev().catch(() => new Map());

  const results = await mapLimit(items, 3, async (item): Promise<ItemResult> => {
    options.onItem?.(item);
    const last = options.lastChecks?.[item.id];
    const since = last ? new Date(Math.max(new Date(last).getTime() - DAY_MS, window.getTime())) : window;
    try {
      let findings = item.source.kind === 'package' ? await packageFindings(item) : await cpeFindings(item, since);
      for (const finding of findings) {
        const exploited = cveIds(finding).map((id) => kev.get(id)).find(Boolean);
        if (exploited) finding.kev = exploited;
      }
      // Without a version every CVE in history would match; only new ones are news.
      findings = findings.filter((finding) => finding.status !== 'product' || isRecent(finding, window));
      const result: ItemResult = { item, findings, alerts: [] };
      if (item.eol) {
        const product = await eolProduct(item.eol).catch(() => undefined);
        const eol = product && item.version ? eolFor(product, item.version) : undefined;
        if (eol) result.eol = eol;
      }
      if (item.updates) {
        const latest = await latestVersion(item).catch(() => undefined);
        if (latest) result.latest = latest;
      }
      return result;
    } catch (error) {
      return { item, findings: [], alerts: [], error: error instanceof Error ? error.message : String(error) };
    }
  });

  const epss = await loadEpss(results.flatMap((result) => result.findings.flatMap(cveIds)));
  for (const result of results) {
    for (const finding of result.findings) {
      const score = cveIds(finding).map((id) => epss.get(id)).find(Boolean);
      if (score) finding.epss = score;
    }
    result.findings.sort(byUrgency);
    result.alerts = result.findings.filter((finding) => meetsLevel(finding, result.item.level ?? options.level));
  }
  return results;
}

export interface Verdict {
  item: WatchItem;
  status: 'affected' | 'not-affected' | 'unknown';
  reason: string;
  fixedIn?: string;
}

/** "Am I affected by CVE-X?" for every item, from NVD, the CVE record and OSV. */
export async function checkCve(
  id: string,
  items: readonly WatchItem[],
  lookups: {
    nvd: NvdCve | undefined;
    record: Awaited<ReturnType<typeof cveRecord>>;
  },
): Promise<Verdict[]> {
  return mapLimit(items, 3, async (item): Promise<Verdict> => {
    if (item.source.kind === 'package') {
      if (!item.version) return { item, status: 'unknown', reason: 'No version set' };
      const findings = await packageFindings(item);
      const hit = findings.find((finding) => finding.id === id || finding.aliases.includes(id));
      return hit
        ? { item, status: 'affected', reason: hit.reason, ...(hit.fixedIn ? { fixedIn: hit.fixedIn } : {}) }
        : { item, status: 'not-affected', reason: `OSV doesn't list ${id} for ${item.source.name} ${item.version}` };
    }
    const source = item.source;
    const targets: Product[] = [{ vendor: source.vendor, product: source.product }, ...(source.also ?? [])];
    for (const target of targets) {
      const verdict = matchCpe(lookups.nvd?.matches ?? [], target, item.version);
      if (verdict.status === 'no-match') continue;
      if (verdict.status === 'not-affected') return { item, status: 'not-affected', reason: verdict.reason };
      if (verdict.status === 'affected') return { item, status: 'affected', reason: verdict.reason, ...(verdict.fixedIn ? { fixedIn: verdict.fixedIn } : {}) };
      return { item, status: 'unknown', reason: verdict.status === 'product' ? 'No version set' : verdict.reason };
    }
    const fromRecord = lookups.record ? matchCve5(lookups.record.affected, targets[0]!, [item.name, item.keyword ?? item.name], item.version) : undefined;
    if (fromRecord && fromRecord.status !== 'no-match') {
      if (fromRecord.status === 'affected') return { item, status: 'affected', reason: fromRecord.reason, ...(fromRecord.fixedIn ? { fixedIn: fromRecord.fixedIn } : {}) };
      if (fromRecord.status === 'not-affected') return { item, status: 'not-affected', reason: fromRecord.reason };
      return { item, status: 'unknown', reason: fromRecord.status === 'product' ? 'No version set' : fromRecord.reason };
    }
    return { item, status: 'not-affected', reason: `${id} doesn't name ${item.name}` };
  });
}
