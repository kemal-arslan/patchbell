import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * Stand-ins for NVD, OSV, CISA KEV, EPSS, cve.org, endoflife.date, npm, ntfy, Telegram,
 * a webhook and the GitHub issues API, shaped like the real responses (trimmed).
 */
const DAY = 86_400_000;
const daysAgo = (days: number) => new Date(Date.now() - days * DAY).toISOString().replace('Z', '');

const range = (vendor: string, product: string, bounds: Record<string, string>) => ({
  vulnerable: true,
  criteria: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
  ...bounds,
});

const cve = (id: string, description: string, score: number, vector: string, matches: object[], extra: Record<string, unknown> = {}) => ({
  cve: {
    id,
    published: extra.published ?? daysAgo(3),
    lastModified: daysAgo(1),
    vulnStatus: matches.length ? 'Analyzed' : 'Awaiting Analysis',
    descriptions: [{ lang: 'en', value: description }],
    metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { version: '3.1', baseScore: score, vectorString: vector } }] },
    weaknesses: [{ description: [{ value: (extra.cwe as string) ?? 'CWE-416' }] }],
    configurations: matches.length ? [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: matches }] }] : [],
  },
});

const PRODUCT_CVES: Record<string, ReturnType<typeof cve>[]> = {
  'php:php': [
    cve(
      'CVE-2026-109618',
      'PHP uses longjmp() for out-of-memory errors. Remote attackers can corrupt memory.',
      9.8,
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      [range('php', 'php', { versionStartIncluding: '7.3.0', versionEndExcluding: '8.2.35' }), range('php', 'php', { versionStartIncluding: '8.3.0', versionEndExcluding: '8.3.36' })],
    ),
    cve('CVE-2024-11111', 'A medium PHP issue.', 5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', [range('php', 'php', { versionStartIncluding: '8.3.0', versionEndExcluding: '8.3.14' })], {
      published: daysAgo(600),
      cwe: 'CWE-200',
    }),
  ],
  'plex:media_server': [
    cve('CVE-2026-96656', 'Plex Media Server before 1.43.3.10861 allows an admin user to write arbitrary files.', 8.6, 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', [
      range('plex', 'media_server', { versionEndExcluding: '1.43.3.10861' }),
    ], { cwe: 'CWE-22' }),
    cve('CVE-2026-96655', 'Plex Media Server before 1.43.3.10861 allows SSRF.', 5.3, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', [range('plex', 'media_server', { versionEndExcluding: '1.43.3.10861' })], {
      cwe: 'CWE-918',
    }),
  ],
};

/** New CVEs NVD hasn't mapped yet, found by keyword: one about Plex, one noise. */
const UNMAPPED = [
  cve('CVE-2026-999001', 'A remote code execution flaw in Plex Media Server lets attackers run code.', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', [], { cwe: 'CWE-94' }),
  cve('CVE-2026-999002', 'Some Plugin for Plex Media Server has XSS.', 6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', [], { cwe: 'CWE-79' }),
];

const CVE_RECORDS: Record<string, object> = {
  'CVE-2026-999001': {
    cveMetadata: { state: 'PUBLISHED', datePublished: daysAgo(2) },
    containers: {
      cna: {
        title: 'Plex Media Server RCE in transcoder',
        affected: [{ vendor: 'Plex', product: 'Plex Media Server', versions: [{ version: '0', lessThan: '1.44.0', status: 'affected' }], defaultStatus: 'unaffected' }],
        metrics: [{ cvssV3_1: { baseScore: 9.1, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' } }],
        problemTypes: [{ descriptions: [{ cweId: 'CWE-94' }] }],
      },
    },
  },
  'CVE-2026-999002': {
    cveMetadata: { state: 'PUBLISHED' },
    containers: { cna: { affected: [{ vendor: 'Someone', product: 'Some Plugin', versions: [{ version: '1.0', status: 'affected' }] }] } },
  },
  'CVE-2026-109618': {
    cveMetadata: { state: 'PUBLISHED' },
    containers: {
      cna: {
        title: 'RCE via OOM corruption',
        affected: [{ vendor: 'PHP Group', product: 'PHP', versions: [{ version: '8.3.*', lessThan: '8.3.36', status: 'affected' }], defaultStatus: 'unaffected' }],
      },
    },
  },
};

const OSV: Record<string, object[]> = {
  'npm/express@4.17.1': [
    {
      id: 'GHSA-qw6h-vgh9-j6wx',
      aliases: ['CVE-2024-43796'],
      summary: 'express vulnerable to XSS via response.redirect()',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L' }],
      database_specific: { severity: 'LOW', cwe_ids: ['CWE-79'] },
      affected: [{ package: { ecosystem: 'npm', name: 'express' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.20.0' }] }] }],
    },
    {
      id: 'GHSA-crit-test',
      aliases: ['CVE-2026-50000'],
      summary: 'express prototype pollution leads to RCE',
      severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }],
      database_specific: { severity: 'CRITICAL', cwe_ids: ['CWE-1321'] },
      affected: [{ package: { ecosystem: 'npm', name: 'express' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.21.2' }] }] }],
    },
  ],
};

const CPES = {
  'acme widget': [
    { cpe: { cpeName: 'cpe:2.3:a:acme:widget_pro:1.0:*:*:*:*:*:*:*', deprecated: false, titles: [{ lang: 'en', title: 'Acme Widget Pro 1.0' }] } },
    { cpe: { cpeName: 'cpe:2.3:a:acme:widget_pro:1.1:*:*:*:*:*:*:*', deprecated: false, titles: [{ lang: 'en', title: 'Acme Widget Pro 1.1' }] } },
    { cpe: { cpeName: 'cpe:2.3:a:acme:widget_lite:2.0:*:*:*:*:*:*:*', deprecated: false, titles: [{ lang: 'en', title: 'Acme Widget Lite 2.0' }] } },
  ],
};

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: string[];
}

export interface FakeApis {
  url: string;
  env: Record<string, string>;
  kev: { cveID: string; vulnerabilityName: string; dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string; requiredAction: string }[];
  ntfy: Record<string, unknown>[];
  telegram: Record<string, unknown>[];
  webhook: Record<string, unknown>[];
  issues: Issue[];
  requests: string[];
  close(): Promise<void>;
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

export async function startFakeApis(): Promise<FakeApis> {
  const state: Omit<FakeApis, 'url' | 'env' | 'close'> = {
    kev: [
      { cveID: 'CVE-2026-96656', vulnerabilityName: 'Plex Media Server Path Traversal', dateAdded: '2026-10-20', dueDate: '2026-10-23', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Apply mitigations per vendor instructions.' },
      { cveID: 'CVE-2026-96655', vulnerabilityName: 'Plex Media Server SSRF', dateAdded: '2026-10-20', dueDate: '2026-11-03', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Apply mitigations per vendor instructions.' },
    ],
    ntfy: [],
    telegram: [],
    webhook: [],
    issues: [],
    requests: [],
  };

  const json = (response: ServerResponse, status: number, body: unknown) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(JSON.stringify(body));
  };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    const path = url.pathname;
    state.requests.push(`${request.method} ${path}${url.search}`);
    const body = request.method === 'GET' ? '' : await readBody(request);

    if (path === '/nvd/cves/2.0') {
      const match = url.searchParams.get('virtualMatchString');
      const keyword = url.searchParams.get('keywordSearch');
      const id = url.searchParams.get('cveId');
      let list: ReturnType<typeof cve>[] = [];
      if (match) list = PRODUCT_CVES[match.split(':').slice(3, 5).join(':')] ?? [];
      else if (keyword) list = UNMAPPED.filter((entry) => entry.cve.descriptions[0]!.value.toLowerCase().includes(keyword.toLowerCase()));
      else if (id) list = [...Object.values(PRODUCT_CVES).flat(), ...UNMAPPED].filter((entry) => entry.cve.id === id);
      return json(response, 200, { totalResults: list.length, resultsPerPage: list.length, startIndex: 0, vulnerabilities: list });
    }
    if (path === '/nvd/cpes/2.0') {
      const products = CPES[(url.searchParams.get('keywordSearch') ?? '').toLowerCase() as keyof typeof CPES] ?? [];
      return json(response, 200, { totalResults: products.length, products });
    }
    if (path === '/osv/query') {
      const query = JSON.parse(body) as { package: { ecosystem: string; name: string }; version?: string };
      return json(response, 200, { vulns: OSV[`${query.package.ecosystem}/${query.package.name}@${query.version}`] ?? [] });
    }
    if (path === '/kev.json') return json(response, 200, { vulnerabilities: state.kev });
    if (path === '/epss') {
      const scores: Record<string, string> = { 'CVE-2026-109618': '0.118', 'CVE-2026-96656': '0.31' };
      const cves = (url.searchParams.get('cve') ?? '').split(',');
      return json(response, 200, { data: cves.filter((id) => scores[id]).map((id) => ({ cve: id, epss: scores[id], percentile: '0.96' })) });
    }
    if (path.startsWith('/cve/')) {
      const record = CVE_RECORDS[decodeURIComponent(path.slice(5))];
      return record ? json(response, 200, record) : json(response, 404, { error: 'not found' });
    }
    if (path === '/eol/products/php') {
      return json(response, 200, {
        result: {
          name: 'php',
          label: 'PHP',
          releases: [
            { name: '8.5', isEol: false, eolFrom: '2029-12-31', latest: { name: '8.5.12', date: '2026-10-21' } },
            { name: '8.3', isEol: false, eolFrom: '2027-12-31', latest: { name: '8.3.36', date: '2026-10-21' } },
            { name: '8.1', isEol: true, eolFrom: '2025-12-31', latest: { name: '8.1.34', date: '2025-12-18' } },
          ],
        },
      });
    }
    if (path.startsWith('/eol/')) return json(response, 404, {});
    if (path === '/npm/express/latest') return json(response, 200, { version: '5.2.1' });
    if (path === '/ntfy' && request.method === 'POST') {
      state.ntfy.push(JSON.parse(body) as Record<string, unknown>);
      return json(response, 200, { id: String(state.ntfy.length) });
    }
    if (path.startsWith('/telegram/bot')) {
      state.telegram.push({ path, ...(JSON.parse(body) as Record<string, unknown>) });
      return json(response, 200, { ok: true });
    }
    if (path === '/hook') {
      state.webhook.push(JSON.parse(body) as Record<string, unknown>);
      return json(response, 200, {});
    }

    const gh = /^\/gh\/repos\/me\/infra(\/.*)$/.exec(path)?.[1];
    if (gh !== undefined) {
      if (request.headers.authorization !== 'Bearer test-token') return json(response, 401, { message: 'Bad credentials' });
      if (gh === '/labels/patchbell') return json(response, 404, { message: 'Not Found' });
      if (gh === '/labels') return json(response, 201, JSON.parse(body));
      if (gh === '/issues' && request.method === 'GET') {
        const page = Number(url.searchParams.get('page') ?? '1');
        return json(response, 200, page === 1 ? state.issues.map(({ comments: _, ...issue }) => issue) : []);
      }
      if (gh === '/issues' && request.method === 'POST') {
        const input = JSON.parse(body) as { title: string; body: string; labels: string[] };
        const issue: Issue = { number: state.issues.length + 1, state: 'open', comments: [], ...input };
        state.issues.push(issue);
        return json(response, 201, issue);
      }
      const issueMatch = /^\/issues\/(\d+)(\/comments)?$/.exec(gh);
      const issue = issueMatch ? state.issues.find((candidate) => candidate.number === Number(issueMatch[1])) : undefined;
      if (issue && issueMatch?.[2]) {
        issue.comments.push((JSON.parse(body) as { body: string }).body);
        return json(response, 201, {});
      }
      if (issue && request.method === 'PATCH') {
        Object.assign(issue, JSON.parse(body));
        return json(response, 200, issue);
      }
    }
    json(response, 404, { message: `no fake for ${request.method} ${path}` });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    ...state,
    url,
    env: {
      PATCHBELL_NVD_URL: `${url}/nvd`,
      PATCHBELL_OSV_URL: `${url}/osv`,
      PATCHBELL_KEV_URL: `${url}/kev.json`,
      PATCHBELL_EPSS_URL: `${url}/epss`,
      PATCHBELL_CVE_URL: `${url}/cve`,
      PATCHBELL_EOL_URL: `${url}/eol`,
      PATCHBELL_NPM_URL: `${url}/npm`,
      PATCHBELL_PYPI_URL: `${url}/pypi`,
      PATCHBELL_TELEGRAM_URL: `${url}/telegram`,
      GITHUB_API_URL: `${url}/gh`,
      PATCHBELL_NVD_DELAY_MS: '0',
      PATCHBELL_RETRY_MS: '10',
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
