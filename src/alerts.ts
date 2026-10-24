import { fixAdvice, severityWord, whyItMatters } from './explain.js';
import { scoreOf } from './filter.js';
import type { ItemState, State } from './store.js';
import type { Finding, ItemResult, WatchItem } from './types.js';
import { plural } from './util.js';
import { compareVersions } from './versions.js';

export interface Alert {
  item: WatchItem;
  finding: Finding;
  /** Seen before, but it got worse: now exploited, or now confirmed for your version. */
  escalated: boolean;
}

export interface Notice {
  item: WatchItem;
  kind: 'eol' | 'update';
  title: string;
  body: string;
  url?: string;
}

/** What's new since the last check, and the state to save afterwards. */
export function diffResults(results: readonly ItemResult[], state: State, now = new Date()): { alerts: Alert[]; notices: Notice[]; state: State } {
  const next: State = { items: { ...state.items } };
  const alerts: Alert[] = [];
  const notices: Notice[] = [];
  const at = now.toISOString();
  for (const result of results) {
    if (result.error) continue;
    const { item } = result;
    const previous = next.items[item.id];
    const current: ItemState =
      previous && previous.version === item.version ? { ...previous, notified: { ...previous.notified } } : { notified: {}, ...(item.version ? { version: item.version } : {}) };
    for (const finding of result.alerts) {
      const seen = current.notified[finding.id];
      const escalated = !!seen && ((!!finding.kev && !seen.kev) || (finding.status === 'affected' && seen.status !== 'affected'));
      if (!seen || escalated) alerts.push({ item, finding, escalated });
      current.notified[finding.id] = { at: seen?.at ?? at, kev: !!finding.kev, status: finding.status };
    }
    if (result.eol?.isEol && current.eolNotified !== result.eol.cycle) {
      notices.push({
        item,
        kind: 'eol',
        title: `${item.name} ${result.eol.cycle} no longer gets security fixes`,
        body: [
          result.eol.eolFrom ? `Support ended on ${result.eol.eolFrom}.` : 'Support has ended.',
          result.eol.latest ? `The newest release is ${result.eol.latest}.` : '',
        ]
          .filter(Boolean)
          .join(' '),
        url: result.eol.url,
      });
      current.eolNotified = result.eol.cycle;
    }
    if (result.latest && current.latestNotified !== result.latest && (!item.version || compareVersions(result.latest, item.version) > 0)) {
      notices.push({
        item,
        kind: 'update',
        title: `${item.name} ${result.latest} is out`,
        body: item.version ? `You have ${item.version}.` : 'A new release is available.',
      });
      current.latestNotified = result.latest;
    }
    current.lastCheck = at;
    next.items[item.id] = current;
  }
  return { alerts, notices, state: next };
}

export interface Message {
  title: string;
  body: string;
  url?: string;
  priority: 'urgent' | 'high' | 'default';
  itemId: string;
}

const MAX_PER_MESSAGE = 3;

function findingLines(finding: Finding, item: WatchItem, escalated: boolean): string[] {
  const label = [severityWord(finding), finding.kev ? 'exploited' : ''].filter(Boolean).join(', ');
  const prefix = escalated ? (finding.kev ? 'Now exploited: ' : 'Now confirmed: ') : '';
  return [`${prefix}${finding.id} (${label}): ${finding.title}`, ...whyItMatters(finding).slice(0, 2), `Fix: ${fixAdvice(finding, item.version)}`];
}

/** One message per item, so ten CVEs in one product are one notification, not ten. */
export function buildMessages(alerts: readonly Alert[], notices: readonly Notice[]): Message[] {
  const messages: Message[] = [];
  const byItem = new Map<string, Alert[]>();
  for (const alert of alerts) byItem.set(alert.item.id, [...(byItem.get(alert.item.id) ?? []), alert]);
  for (const group of byItem.values()) {
    const { item } = group[0]!;
    const exploited = group.filter((alert) => alert.finding.kev).length;
    const critical = group.filter((alert) => scoreOf(alert.finding) >= 9).length;
    const label = `${item.name}${item.version ? ` ${item.version}` : ''}`;
    const title = exploited
      ? `${label}: ${exploited === 1 ? 'actively exploited vulnerability' : `${exploited} actively exploited vulnerabilities`}`
      : critical
        ? `${label}: ${plural(critical, 'critical vulnerability', 'critical vulnerabilities')}`
        : `${label}: ${plural(group.length, 'serious vulnerability', 'serious vulnerabilities')}`;
    const shown = group.slice(0, MAX_PER_MESSAGE);
    const body = [
      ...shown.map((alert) => findingLines(alert.finding, item, alert.escalated).join('\n')),
      ...(group.length > shown.length ? [`…and ${group.length - shown.length} more. Run: patchbell check`] : []),
    ].join('\n\n');
    messages.push({
      title,
      body,
      url: shown[0]!.finding.url,
      priority: exploited ? 'urgent' : critical ? 'high' : 'default',
      itemId: item.id,
    });
  }
  for (const notice of notices) {
    messages.push({ title: notice.title, body: notice.body, ...(notice.url ? { url: notice.url } : {}), priority: 'default', itemId: notice.item.id });
  }
  return messages;
}
