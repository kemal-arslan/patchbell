import { readFile } from 'node:fs/promises';
import YAML from 'yaml';
import { newId, resolve, type NewItem } from './resolve.js';
import { validateLevel } from './store.js';
import type { Level, WatchItem } from './types.js';

/**
 * A watchlist file kept in a repository for the GitHub Action (YAML or JSON):
 *
 *   level: critical
 *   items:
 *     - php 8.3.10
 *     - name: Plex Media Server
 *       version: 1.41.2
 *       level: exploited
 *     - package: npm:express@4.19.2
 *     - cpe: cpe:2.3:a:f5:nginx
 *       version: 1.26.2
 */
interface ItemSpec {
  id?: string;
  name?: string;
  version?: string | number;
  cpe?: string;
  package?: string;
  eol?: string;
  keyword?: string;
  level?: string;
  updates?: boolean;
  note?: string;
}

interface FileSpec {
  level?: string;
  items?: (string | ItemSpec)[];
}

export interface WatchFile {
  level?: Level;
  items: WatchItem[];
}

function specToInput(spec: string | ItemSpec): { input: string; spec: ItemSpec } {
  if (typeof spec === 'string') return { input: spec, spec: {} };
  const input = spec.package ?? spec.cpe ?? spec.name;
  if (!input) throw new Error(`Watchlist item needs a name, package or cpe: ${JSON.stringify(spec)}`);
  return { input, spec };
}

export function parseWatchFile(text: string): FileSpec {
  const parsed = YAML.parse(text) as FileSpec | (string | ItemSpec)[] | null;
  if (Array.isArray(parsed)) return { items: parsed };
  return parsed ?? {};
}

/** Reads and resolves a watchlist file. Names that could mean several products are an error. */
export async function loadWatchFile(path: string): Promise<WatchFile> {
  const file = parseWatchFile(await readFile(path, 'utf8'));
  const items: WatchItem[] = [];
  const now = new Date().toISOString();
  for (const entry of file.items ?? []) {
    const { input, spec } = specToInput(entry);
    const resolution = await resolve(input, {
      ...(spec.version !== undefined ? { version: String(spec.version) } : {}),
      ...(spec.level ? { level: validateLevel(spec.level) } : {}),
      ...(spec.updates ? { updates: true } : {}),
      ...(spec.note ? { note: spec.note } : {}),
    });
    if (resolution.kind === 'not-found') throw new Error(`${path}: nothing found for "${input}". Use a cpe: or package: entry.`);
    if (resolution.kind === 'ambiguous') {
      const options = resolution.candidates.slice(0, 5).map((candidate) => `  cpe: ${candidate.cpe}   # ${candidate.title}`);
      throw new Error(`${path}: "${input}" could be several products. Replace it with one of:\n${options.join('\n')}`);
    }
    const item: NewItem = {
      ...resolution.item,
      ...(spec.name && (spec.cpe || spec.package) ? { name: spec.name } : {}),
      ...(spec.eol ? { eol: spec.eol } : {}),
      ...(spec.keyword ? { keyword: spec.keyword } : {}),
    };
    items.push({ ...item, id: spec.id ?? newId(item, items.map((existing) => existing.id), resolution.idHint), addedAt: now });
  }
  return { ...(file.level ? { level: validateLevel(file.level) } : {}), items };
}

/** The local watchlist as a file for the GitHub Action, with every item already resolved. */
export function exportWatchFile(items: readonly WatchItem[], level: Level): string {
  const specs = items.map((item) => {
    const { source } = item;
    const where = source.kind === 'package' ? { package: `osv:${source.ecosystem}/${source.name}` } : { cpe: `cpe:2.3:${source.part}:${source.vendor}:${source.product}` };
    return {
      id: item.id,
      name: item.name,
      ...where,
      ...(item.version ? { version: item.version } : {}),
      ...(item.eol ? { eol: item.eol } : {}),
      ...(item.keyword ? { keyword: item.keyword } : {}),
      ...(item.level ? { level: item.level } : {}),
      ...(item.updates ? { updates: true } : {}),
      ...(item.note ? { note: item.note } : {}),
    };
  });
  return `# Patchbell watchlist: https://github.com/kemal-arslan/patchbell\n${YAML.stringify({ level, items: specs })}`;
}
