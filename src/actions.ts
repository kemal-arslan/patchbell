import { buildMessages, diffResults, type Message } from './alerts.js';
import { checkCve, runCheck, type Verdict } from './check.js';
import { deliver } from './notify/channels.js';
import { newId, resolve, type ResolveOptions, type Resolution } from './resolve.js';
import { cveRecord } from './sources/cveorg.js';
import { loadEpss } from './sources/epss.js';
import { loadKev } from './sources/kev.js';
import { cveById } from './sources/nvd.js';
import { loadConfig, loadState, loadWatchlist, saveState, saveWatchlist } from './store.js';
import type { Config, Cvss, ItemResult, KevEntry, Level, WatchItem } from './types.js';

/** The operations the CLI and the MCP server share. */

export async function addItem(input: string, options: ResolveOptions & { id?: string } = {}): Promise<{ resolution: Resolution; item?: WatchItem }> {
  const resolution = await resolve(input, options);
  if (resolution.kind !== 'resolved') return { resolution };
  const list = await loadWatchlist();
  const ids = list.items.map((item) => item.id);
  if (options.id && ids.includes(options.id)) throw new Error(`There is already an item called "${options.id}".`);
  const item: WatchItem = { ...resolution.item, id: options.id ?? newId(resolution.item, ids, resolution.idHint), addedAt: new Date().toISOString() };
  list.items.push(item);
  await saveWatchlist(list);
  return { resolution, item };
}

export async function findItem(id: string): Promise<WatchItem> {
  const list = await loadWatchlist();
  const item = list.items.find((candidate) => candidate.id === id);
  if (!item) {
    const ids = list.items.map((candidate) => candidate.id);
    throw new Error(`No item "${id}" in your watchlist.${ids.length ? ` Items: ${ids.join(', ')}` : ''}`);
  }
  return item;
}

export async function updateItem(id: string, change: Partial<Pick<WatchItem, 'version' | 'level' | 'updates' | 'note'>>): Promise<WatchItem> {
  const list = await loadWatchlist();
  const index = list.items.findIndex((item) => item.id === id);
  if (index < 0) await findItem(id);
  const updated = { ...list.items[index]!, ...change };
  for (const key of Object.keys(change) as (keyof typeof change)[]) if (change[key] === undefined) delete updated[key];
  list.items[index] = updated;
  await saveWatchlist(list);
  return updated;
}

export async function removeItem(id: string): Promise<WatchItem> {
  const list = await loadWatchlist();
  const item = await findItem(id);
  list.items = list.items.filter((candidate) => candidate.id !== id);
  await saveWatchlist(list);
  const state = await loadState();
  delete state.items[id];
  await saveState(state);
  return item;
}

export interface CheckRun {
  results: ItemResult[];
  messages: Message[];
  failures: { channel: string; error: string }[];
}

/**
 * Checks the watchlist, notifies about what's new (unless notify is false) and remembers it.
 * `items` checks a subset; `config` overrides the saved one.
 */
export async function checkAndNotify(options: { ids?: string[]; notify?: boolean; level?: Level; config?: Config; onItem?: (item: WatchItem) => void } = {}): Promise<CheckRun> {
  const config = options.config ?? (await loadConfig());
  const list = await loadWatchlist();
  const items = options.ids?.length ? list.items.filter((item) => options.ids!.includes(item.id)) : list.items;
  if (options.ids?.length && items.length !== options.ids.length) {
    const missing = options.ids.filter((id) => !items.some((item) => item.id === id));
    throw new Error(`Not in your watchlist: ${missing.join(', ')}`);
  }
  const state = await loadState();
  const lastChecks = Object.fromEntries(items.map((item) => [item.id, state.items[item.id]?.lastCheck]));
  const results = await runCheck(items, { level: options.level ?? config.level, lastChecks, ...(options.onItem ? { onItem: options.onItem } : {}) });
  const { alerts, notices, state: next } = diffResults(results, state);
  const messages = buildMessages(alerts, notices);
  const failures: CheckRun['failures'] = [];
  if (options.notify !== false) {
    for (const message of messages) failures.push(...(await deliver(message, config.channels)));
  }
  // Remember what was reported only once it was sent (or the user saw it in the terminal).
  await saveState(next);
  return { results, messages, failures };
}

export interface CveAnswer {
  id: string;
  found: boolean;
  title?: string;
  description?: string;
  cvss?: Cvss;
  kev?: KevEntry;
  epss?: { score: number; percentile: number };
  verdicts: Verdict[];
}

export async function answerCve(rawId: string): Promise<CveAnswer> {
  const id = rawId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new Error(`"${rawId}" doesn't look like a CVE ID (CVE-2026-12345).`);
  const [nvd, record, kev, epss, list] = await Promise.all([
    cveById(id).catch(() => undefined),
    cveRecord(id).catch(() => undefined),
    loadKev().catch(() => new Map<string, KevEntry>()),
    loadEpss([id]),
    loadWatchlist(),
  ]);
  const verdicts = await checkCve(id, list.items, { nvd, record });
  const cvss = nvd?.cvss ?? record?.cvss;
  const description = nvd?.description || record?.description;
  const kevEntry = kev.get(id);
  const score = epss.get(id);
  return {
    id,
    found: !!(nvd || record),
    ...(record?.title ? { title: record.title } : {}),
    ...(description ? { description } : {}),
    ...(cvss ? { cvss } : {}),
    ...(kevEntry ? { kev: kevEntry } : {}),
    ...(score ? { epss: score } : {}),
    verdicts,
  };
}
