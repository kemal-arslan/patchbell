import { createRequire } from 'node:module';

// Resolves to the package root both from src/ (tsx) and from dist/ (built).
const pkg = createRequire(import.meta.url)('../package.json') as { version: string };

export const VERSION = pkg.version;
export const REPO_URL = 'https://github.com/kemal-arslan/patchbell';
export const SUPPORT_URL = 'https://buymeacoffee.com/kemalarslan';
