import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { configPath, statePath, watchlistPath } from './paths.js';
import type { Config, Level, Status, Watchlist } from './types.js';

export const LEVELS: readonly Level[] = ['exploited', 'critical', 'high', 'all'];

export function validateLevel(value: string): Level {
  if (!LEVELS.includes(value as Level)) throw new Error(`Unknown level "${value}". Use one of: ${LEVELS.join(', ')}.`);
  return value as Level;
}

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new Error(`Could not read ${path}: ${(error as Error).message}`);
  }
}

async function writeJson(path: string, value: unknown, secret = false): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: secret ? 0o600 : 0o644 });
  await rename(temp, path);
  if (secret) await chmod(path, 0o600);
}

export async function loadWatchlist(): Promise<Watchlist> {
  return (await readJson<Watchlist>(watchlistPath())) ?? { items: [] };
}
export const saveWatchlist = (list: Watchlist) => writeJson(watchlistPath(), list);

export const defaultConfig = (): Config => ({ level: 'critical', channels: { desktop: process.platform === 'darwin' || process.platform === 'linux' } });

export async function loadConfig(): Promise<Config> {
  const config = await readJson<Partial<Config>>(configPath());
  const defaults = defaultConfig();
  return { level: config?.level ?? defaults.level, channels: config?.channels ?? defaults.channels };
}
/** Mode 600: channels can hold tokens and webhook URLs. */
export const saveConfig = (config: Config) => writeJson(configPath(), config, true);

export interface Notified {
  at: string;
  kev: boolean;
  status: Status;
}

export interface ItemState {
  /** The version the notifications were for; changing it starts over. */
  version?: string;
  notified: Record<string, Notified>;
  lastCheck?: string;
  eolNotified?: string;
  latestNotified?: string;
}

export interface State {
  items: Record<string, ItemState>;
}

export async function loadState(): Promise<State> {
  return (await readJson<State>(statePath())) ?? { items: {} };
}
export const saveState = (state: State) => writeJson(statePath(), state);
