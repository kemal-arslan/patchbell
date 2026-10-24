import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Everything lives under ~/.patchbell (or $PATCHBELL_HOME):
 *   watchlist.json  what you follow
 *   config.json     alert level and notification channels (mode 600: may hold tokens)
 *   state.json      what you were already told about
 *   cache/          downloaded vulnerability data
 */
export function homeDir(): string {
  return process.env.PATCHBELL_HOME ?? join(homedir(), '.patchbell');
}

export const watchlistPath = () => join(homeDir(), 'watchlist.json');
export const configPath = () => join(homeDir(), 'config.json');
export const statePath = () => join(homeDir(), 'state.json');
export const cacheDir = () => join(homeDir(), 'cache');
export const logDir = () => join(homeDir(), 'logs');
