import { fixAdvice, severityWord, whyItMatters } from '../explain.js';
import { endpoints, request } from '../http.js';
import { REPO_URL, SUPPORT_URL } from '../meta.js';
import type { Finding, ItemResult, WatchItem } from '../types.js';

/**
 * GitHub Actions mode: one issue per vulnerability, deduplicated by a hidden marker, so the
 * issues themselves are the state. Closing an issue dismisses it; it's reopened only if the
 * vulnerability starts being exploited.
 */
interface Issue {
  number: number;
  state: 'open' | 'closed';
  body?: string | null;
  pull_request?: unknown;
}

export const LABEL = 'patchbell';
const marker = (item: WatchItem, finding: Finding) => `<!-- patchbell:${item.id}:${finding.id} -->`;
const kevMarker = (exploited: boolean) => `<!-- patchbell-kev:${exploited ? 1 : 0} -->`;

export function issueTitle(item: WatchItem, finding: Finding): string {
  const label = `${item.name}${item.version ? ` ${item.version}` : ''}`;
  return `${label}: ${finding.id}${finding.kev ? ' is actively exploited' : ` (${severityWord(finding)})`}`;
}

export function issueBody(item: WatchItem, finding: Finding): string {
  const facts = [
    `- **Severity:** ${severityWord(finding)}${finding.cvss?.vector ? ` (\`${finding.cvss.vector}\`)` : ''}`,
    finding.kev ? `- **Exploited:** yes, in CISA's KEV catalog since ${finding.kev.dateAdded}${finding.kev.ransomware ? ' (used by ransomware)' : ''}` : '- **Exploited:** not known',
    finding.epss ? `- **EPSS:** ${(finding.epss.score * 100).toFixed(1)}% chance of exploitation in 30 days` : '',
    `- **Why Patchbell thinks you're affected:** ${finding.reason}`,
    finding.aliases.length ? `- **Also known as:** ${finding.aliases.join(', ')}` : '',
  ].filter(Boolean);
  return [
    marker(item, finding),
    kevMarker(!!finding.kev),
    `**${finding.title}**`,
    '',
    whyItMatters(finding).join(' '),
    '',
    ...facts,
    '',
    `**Fix:** ${fixAdvice(finding, item.version)}`,
    '',
    `Details: ${finding.url}`,
    '',
    '---',
    `<sub>Opened by [Patchbell](${REPO_URL}) for \`${item.id}\` in your watchlist. Close this issue to dismiss it. · [Support Patchbell](${SUPPORT_URL})</sub>`,
  ].join('\n');
}

export interface GitHubTarget {
  repository: string;
  token: string;
}

async function api<T>(target: GitHubTarget, path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const response = await request(`${endpoints().github}/repos/${target.repository}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${target.token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    retries: 2,
  });
  return (response.status === 204 ? undefined : await response.json()) as T;
}

async function existingIssues(target: GitHubTarget): Promise<Map<string, Issue>> {
  const found = new Map<string, Issue>();
  for (let page = 1; page <= 20; page += 1) {
    const issues = await api<Issue[]>(target, `/issues?labels=${LABEL}&state=all&per_page=100&page=${page}`);
    for (const issue of issues) {
      const key = issue.body?.match(/<!-- patchbell:([^ ]+) -->/)?.[1];
      if (key && !issue.pull_request) found.set(key, issue);
    }
    if (issues.length < 100) break;
  }
  return found;
}

async function ensureLabel(target: GitHubTarget): Promise<void> {
  try {
    await api(target, `/labels/${LABEL}`);
  } catch {
    await api(target, '/labels', { method: 'POST', body: { name: LABEL, color: 'd93f0b', description: 'Vulnerability alerts from Patchbell' } }).catch(() => undefined);
  }
}

export interface IssueSummary {
  opened: number;
  escalated: number;
  unchanged: number;
}

export async function syncIssues(results: readonly ItemResult[], target: GitHubTarget): Promise<IssueSummary> {
  const summary: IssueSummary = { opened: 0, escalated: 0, unchanged: 0 };
  const alerts = results.flatMap((result) => result.alerts.map((finding) => ({ item: result.item, finding })));
  if (alerts.length === 0) return summary;
  await ensureLabel(target);
  const issues = await existingIssues(target);
  for (const { item, finding } of alerts) {
    const issue = issues.get(`${item.id}:${finding.id}`);
    if (!issue) {
      await api(target, '/issues', { method: 'POST', body: { title: issueTitle(item, finding), body: issueBody(item, finding), labels: [LABEL] } });
      summary.opened += 1;
      continue;
    }
    const wasExploited = issue.body?.includes(kevMarker(true)) ?? false;
    if (finding.kev && !wasExploited) {
      await api(target, `/issues/${issue.number}`, { method: 'PATCH', body: { title: issueTitle(item, finding), body: issueBody(item, finding), state: 'open' } });
      await api(target, `/issues/${issue.number}/comments`, {
        method: 'POST',
        body: { body: `⚠️ ${finding.id} is now being exploited (CISA KEV, added ${finding.kev.dateAdded}). ${fixAdvice(finding, item.version)}` },
      });
      summary.escalated += 1;
    } else {
      summary.unchanged += 1;
    }
  }
  return summary;
}
