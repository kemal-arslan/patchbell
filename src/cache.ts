import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { cacheDir } from './paths.js';

interface Entry<T> {
  savedAt: number;
  data: T;
}

const fileFor = (name: string) => join(cacheDir(), `${name.replace(/[^a-zA-Z0-9@._/-]/g, '_')}.json`);

export async function readCache<T>(name: string): Promise<Entry<T> | undefined> {
  try {
    return JSON.parse(await readFile(fileFor(name), 'utf8')) as Entry<T>;
  } catch {
    return undefined;
  }
}

export async function writeCache(name: string, data: unknown): Promise<void> {
  const file = fileFor(name);
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.tmp`;
  await writeFile(temp, JSON.stringify({ savedAt: Date.now(), data }));
  await rename(temp, file);
}

/** Cached for maxAgeMs. If refreshing fails, stale data is better than none. */
export async function cached<T>(name: string, maxAgeMs: number, load: () => Promise<T>): Promise<T> {
  const entry = await readCache<T>(name);
  if (entry && Date.now() - entry.savedAt < maxAgeMs) return entry.data;
  try {
    const data = await load();
    await writeCache(name, data);
    return data;
  } catch (error) {
    if (entry) return entry.data;
    throw error;
  }
}

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
