import { VERSION } from './meta.js';

/** Data sources. Each can be pointed elsewhere, which the tests use. */
export const endpoints = () => ({
  nvd: process.env.PATCHBELL_NVD_URL ?? 'https://services.nvd.nist.gov/rest/json',
  osv: process.env.PATCHBELL_OSV_URL ?? 'https://api.osv.dev/v1',
  kev: process.env.PATCHBELL_KEV_URL ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  epss: process.env.PATCHBELL_EPSS_URL ?? 'https://api.first.org/data/v1/epss',
  cve: process.env.PATCHBELL_CVE_URL ?? 'https://cveawg.mitre.org/api/cve',
  eol: process.env.PATCHBELL_EOL_URL ?? 'https://endoflife.date/api/v1',
  npm: process.env.PATCHBELL_NPM_URL ?? 'https://registry.npmjs.org',
  pypi: process.env.PATCHBELL_PYPI_URL ?? 'https://pypi.org/pypi',
  github: process.env.GITHUB_API_URL ?? 'https://api.github.com',
  telegram: process.env.PATCHBELL_TELEGRAM_URL ?? 'https://api.telegram.org',
});

export const USER_AGENT = `patchbell/${VERSION} (+https://github.com/kemal-arslan/patchbell)`;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    body: string,
  ) {
    super(`HTTP ${status} from ${new URL(url).host}${body ? `: ${body.slice(0, 200)}` : ''}`);
  }
}

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
  retries?: number;
}

const RETRY_STATUS = new Set([403, 429, 500, 502, 503, 504]);

/** fetch with a timeout, JSON bodies and retries for rate limits and flaky servers. */
export async function request(url: string, options: RequestOptions = {}): Promise<Response> {
  const retries = options.retries ?? 3;
  const backoff = Number(process.env.PATCHBELL_RETRY_MS ?? 3000);
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(url, {
        method: options.method ?? (options.body === undefined ? 'GET' : 'POST'),
        headers: {
          'user-agent': USER_AGENT,
          accept: 'application/json',
          ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
          ...options.headers,
        },
        ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        signal: AbortSignal.timeout(options.timeoutMs ?? 60_000),
      });
      if (response.ok) return response;
      const body = await response.text().catch(() => '');
      if (attempt < retries && RETRY_STATUS.has(response.status)) {
        const wait = Number(response.headers.get('retry-after')) * 1000 || backoff * 2 ** attempt;
        await sleep(Math.min(wait, 60_000));
        continue;
      }
      throw new HttpError(response.status, url, body);
    } catch (error) {
      if (error instanceof HttpError || attempt >= retries) throw error;
      await sleep(backoff * 2 ** attempt);
    }
  }
}

export async function getJson<T>(url: string, options: RequestOptions = {}): Promise<T> {
  return (await (await request(url, options)).json()) as T;
}

/** Returns undefined for 404 instead of throwing. */
export async function getJsonOrUndefined<T>(url: string, options: RequestOptions = {}): Promise<T | undefined> {
  try {
    return await getJson<T>(url, { retries: 2, ...options });
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return undefined;
    throw error;
  }
}
