import { fixAdvice, severityWord, whyItMatters } from './explain.js';
import { scoreOf } from './filter.js';
import { describeSource } from './resolve.js';
import type { Finding, ItemResult, WatchItem } from './types.js';
import { plural } from './util.js';

const useColor = () => !!process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (text: string) => (useColor() ? `\u001b[${code}m${text}\u001b[0m` : text);
export const bold = paint(1);
export const dim = paint(2);
export const red = paint(31);
export const green = paint(32);
export const yellow = paint(33);

export const itemLabel = (item: WatchItem) => `${item.name}${item.version ? ` ${item.version}` : dim(' (no version)')}`;

function findingBlock(finding: Finding, item: WatchItem): string[] {
  const tags = [
    scoreOf(finding) >= 9 ? red(severityWord(finding)) : severityWord(finding),
    finding.kev ? red('exploited') : '',
    finding.epss && finding.epss.score >= 0.01 ? `EPSS ${Math.round(finding.epss.score * 100)}%` : '',
    finding.status === 'unconfirmed' ? yellow('versions unconfirmed') : '',
  ].filter(Boolean);
  return [
    `    ${bold(finding.id)}  ${tags.join(' · ')}`,
    `      ${finding.title}`,
    ...whyItMatters(finding).map((line) => `      ${dim(line)}`),
    `      Fix: ${fixAdvice(finding, item.version)}`,
    `      ${dim(finding.url)}`,
  ];
}

export interface FormatOptions {
  /** Show every finding, not only those at the alert level. */
  all?: boolean;
  /** Findings to show per item. */
  limit?: number;
}

export function formatResults(results: readonly ItemResult[], options: FormatOptions = {}): string {
  const lines: string[] = [];
  const limit = options.limit ?? 5;
  for (const result of results) {
    const { item } = result;
    if (result.error) {
      lines.push(`${red('✗')} ${itemLabel(item)}  ${red(`check failed: ${result.error}`)}`);
      continue;
    }
    const shown = options.all ? result.findings : result.alerts;
    const hidden = result.findings.length - result.alerts.length;
    if (shown.length === 0) {
      const extra = hidden > 0 && !options.all ? dim(` (${plural(hidden, 'lower-severity issue')}: patchbell check --all)`) : '';
      lines.push(`${green('✓')} ${itemLabel(item)}  nothing at your alert level${extra}`);
    } else {
      const exploited = shown.filter((finding) => finding.kev).length;
      const summary = `${plural(shown.length, options.all ? 'vulnerability' : 'alert', options.all ? 'vulnerabilities' : 'alerts')}${exploited ? `, ${red(`${exploited} exploited`)}` : ''}`;
      lines.push(`${exploited ? red('●') : yellow('●')} ${bold(itemLabel(item))}  ${summary}`);
      for (const finding of shown.slice(0, limit)) lines.push(...findingBlock(finding, item));
      if (shown.length > limit) lines.push(dim(`    …and ${shown.length - limit} more (patchbell check ${item.id} --json for all)`));
    }
    if (result.eol?.isEol) {
      lines.push(`  ${yellow('!')} ${item.name} ${result.eol.cycle} no longer gets security fixes${result.eol.eolFrom ? ` (since ${result.eol.eolFrom})` : ''}.${result.eol.latest ? ` Newest: ${result.eol.latest}.` : ''}`);
    } else if (result.eol?.latestInCycle && item.version && result.eol.latestInCycle !== item.version) {
      lines.push(dim(`  Latest ${result.eol.cycle} release: ${result.eol.latestInCycle}`));
    }
    if (result.latest && item.updates) lines.push(dim(`  Newest release: ${result.latest}`));
    if (!item.version) lines.push(dim(`  Set a version for precise answers: patchbell set ${item.id} <version>`));
  }
  return lines.join('\n');
}

export function formatItems(items: readonly WatchItem[]): string {
  if (items.length === 0) return 'Your watchlist is empty. Add something: patchbell add "php 8.3.10"';
  return items
    .map((item) => {
      const extras = [item.level ? `level ${item.level}` : '', item.updates ? 'updates' : '', item.note ?? ''].filter(Boolean).join(', ');
      return `${bold(item.id.padEnd(22))} ${itemLabel(item)}${extras ? dim(`  [${extras}]`) : ''}\n${' '.repeat(23)}${dim(describeSource(item))}`;
    })
    .join('\n');
}
