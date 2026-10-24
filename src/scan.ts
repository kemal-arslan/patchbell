import { execFile } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { findInCatalog } from './catalog.js';

const run = promisify(execFile);

/**
 * Opt-in only: looks at what's installed and suggests watchlist items. Nothing is added
 * unless the user picks it, and nothing leaves the machine.
 */
export interface Found {
  /** What `patchbell add` accepts for it. */
  input: string;
  label: string;
  version: string;
  where: string;
  /** Catalog entry or package, to avoid listing the same thing twice. */
  key: string;
}

interface Tool {
  cmd: string;
  args: string[];
  pattern: RegExp;
  product: string;
}

/** Version commands for common tools; the output may come on stdout or stderr. */
export const TOOLS: Tool[] = [
  { cmd: 'node', args: ['--version'], pattern: /v(\d+\.\d+\.\d+)/, product: 'nodejs' },
  { cmd: 'php', args: ['--version'], pattern: /^PHP (\d+\.\d+\.\d+)/m, product: 'php' },
  { cmd: 'python3', args: ['--version'], pattern: /Python (\d+\.\d+\.\d+)/, product: 'python' },
  { cmd: 'git', args: ['--version'], pattern: /git version (\d+\.\d+\.\d+)/, product: 'git' },
  { cmd: 'openssl', args: ['version'], pattern: /^OpenSSL (\d+\.\d+\.\d+[a-z]?)/, product: 'openssl' },
  { cmd: 'ssh', args: ['-V'], pattern: /OpenSSH_(\d+\.\d+(?:p\d+)?)/, product: 'openssh' },
  { cmd: 'curl', args: ['--version'], pattern: /^curl (\d+\.\d+\.\d+)/, product: 'curl' },
  { cmd: 'nginx', args: ['-v'], pattern: /nginx\/(\d+\.\d+\.\d+)/, product: 'nginx' },
  { cmd: 'httpd', args: ['-v'], pattern: /Apache\/(\d+\.\d+\.\d+)/, product: 'apache-http-server' },
  { cmd: 'apache2', args: ['-v'], pattern: /Apache\/(\d+\.\d+\.\d+)/, product: 'apache-http-server' },
  { cmd: 'docker', args: ['--version'], pattern: /Docker version (\d+\.\d+\.\d+)/, product: 'docker-engine' },
  { cmd: 'psql', args: ['--version'], pattern: /(\d+\.\d+)/, product: 'postgresql' },
  { cmd: 'redis-server', args: ['--version'], pattern: /v=(\d+\.\d+\.\d+)/, product: 'redis' },
  { cmd: 'java', args: ['-version'], pattern: /version "(\d+(?:\.\d+)*)/, product: 'openjdk' },
  { cmd: 'go', args: ['version'], pattern: /go(\d+\.\d+(?:\.\d+)?)/, product: 'go' },
  { cmd: 'ruby', args: ['--version'], pattern: /ruby (\d+\.\d+\.\d+)/, product: 'ruby' },
  { cmd: 'sudo', args: ['--version'], pattern: /Sudo version (\d+\.\d+\.\d+(?:p\d+)?)/, product: 'sudo' },
];

async function output(cmd: string, args: string[], timeout = 5000): Promise<string | undefined> {
  try {
    const { stdout, stderr } = await run(cmd, args, { timeout, maxBuffer: 32 * 1024 * 1024 });
    return `${stdout}\n${stderr}`;
  } catch (error) {
    // Some tools print their version and exit non-zero; keep what they printed.
    const { stdout, stderr } = error as { stdout?: string; stderr?: string };
    return stdout || stderr ? `${stdout ?? ''}\n${stderr ?? ''}` : undefined;
  }
}

async function stdoutOf(cmd: string, args: string[], timeout: number): Promise<string | undefined> {
  try {
    return (await run(cmd, args, { timeout, maxBuffer: 64 * 1024 * 1024 })).stdout;
  } catch (error) {
    // npm ls exits non-zero for missing peer dependencies but still prints the tree.
    return (error as { stdout?: string }).stdout || undefined;
  }
}

function fromCatalog(name: string, version: string, where: string): Found | undefined {
  const entry = findInCatalog(name);
  if (!entry || !/\d/.test(version)) return undefined;
  return { input: `${entry.slug} ${version}`, label: entry.label, version, where, key: entry.slug };
}

export function parseTool(tool: Tool, text: string): Found | undefined {
  const version = tool.pattern.exec(text)?.[1];
  return version ? fromCatalog(tool.product, version, `${tool.cmd} ${tool.args.join(' ')}`) : undefined;
}

interface BrewInfo {
  formulae?: { name: string; installed?: { version: string }[] }[];
  casks?: { token: string; installed?: string | null }[];
}

/** Casks whose names would match the wrong product. */
const CASK_PRODUCTS: Record<string, string> = { docker: 'docker-desktop', 'docker-desktop': 'docker-desktop', 'visual-studio-code': 'vscode' };

export function parseBrew(info: BrewInfo): Found[] {
  const found: Found[] = [];
  for (const formula of info.formulae ?? []) {
    const version = formula.installed?.[0]?.version.replace(/_\d+$/, '');
    const entry = version ? fromCatalog(formula.name.replace(/@[\d.]+$/, ''), version, `brew formula ${formula.name}`) : undefined;
    if (entry) found.push(entry);
  }
  for (const cask of info.casks ?? []) {
    const version = cask.installed?.split(',')[0];
    const entry = version ? fromCatalog(CASK_PRODUCTS[cask.token] ?? cask.token, version, `brew cask ${cask.token}`) : undefined;
    if (entry) found.push(entry);
  }
  return found;
}

/** App bundle names whose catalog name differs. */
const APP_PRODUCTS: Record<string, string> = { Docker: 'docker-desktop', Code: 'vscode', VLC: 'vlc' };

async function macApps(): Promise<Found[]> {
  const found: Found[] = [];
  const apps = await readdir('/Applications').catch(() => [] as string[]);
  for (const app of apps.filter((name) => name.endsWith('.app'))) {
    const text = await stdoutOf('plutil', ['-convert', 'json', '-o', '-', join('/Applications', app, 'Contents', 'Info.plist')], 3000);
    if (!text) continue;
    try {
      const plist = JSON.parse(text.trim()) as Record<string, string>;
      const name = plist.CFBundleDisplayName ?? plist.CFBundleName ?? app.replace(/\.app$/, '');
      const version = plist.CFBundleShortVersionString;
      const entry = version ? fromCatalog(APP_PRODUCTS[name] ?? name, version, `/Applications/${app}`) : undefined;
      if (entry) found.push(entry);
    } catch {
      // Not JSON: an unreadable plist.
    }
  }
  const macos = (await output('sw_vers', ['-productVersion']))?.trim();
  const entry = macos ? fromCatalog('macos', macos, 'sw_vers') : undefined;
  if (entry) found.push(entry);
  return found;
}

export function parseNpmGlobal(text: string): Found[] {
  const tree = JSON.parse(text) as { dependencies?: Record<string, { version?: string }> };
  return Object.entries(tree.dependencies ?? {}).flatMap(([name, info]) =>
    info.version ? [{ input: `npm:${name}@${info.version}`, label: name, version: info.version, where: 'npm global package', key: `npm:${name}` }] : [],
  );
}

/** Debian/Ubuntu source packages worth watching, checked through OSV so distro backports count. */
const INTERESTING_DEB = /^(openssl|openssh|nginx|apache2|php\d+(\.\d+)?|curl|sudo|glibc|bash|systemd|linux|openjdk-\d+|nodejs|python3\.\d+|postgresql-\d+|mariadb(-\d+(\.\d+)?)?|mysql-\d+\.\d+|redis|docker\.io|containerd|runc|git|samba|bind9|exim4|postfix|xz-utils|policykit-1|polkit|libssh|dnsmasq|haproxy|squid|unbound|dovecot|tomcat\d+|cups|rsync|vim|wget)$/;

export function osvDistro(osRelease: string): string | undefined {
  const field = (key: string) => osRelease.match(new RegExp(`^${key}="?([^"\\n]*)"?`, 'm'))?.[1];
  const id = field('ID');
  const versionId = field('VERSION_ID');
  if (!versionId) return undefined;
  if (id === 'debian') return `Debian:${versionId.split('.')[0]}`;
  if (id === 'ubuntu') return `Ubuntu:${versionId}${/LTS/.test(field('VERSION') ?? '') ? ':LTS' : ''}`;
  return undefined;
}

export function parseDpkg(text: string, ecosystem: string): Found[] {
  const seen = new Set<string>();
  const found: Found[] = [];
  for (const line of text.split('\n')) {
    const [name, version] = line.trim().split('\t');
    if (!name || !version || seen.has(name) || !INTERESTING_DEB.test(name)) continue;
    seen.add(name);
    found.push({ input: `osv:${ecosystem}/${name}@${version}`, label: `${name} (${ecosystem})`, version, where: 'dpkg', key: `${ecosystem}:${name}` });
  }
  return found;
}

async function linuxPackages(): Promise<Found[]> {
  const ecosystem = osvDistro(await readFile('/etc/os-release', 'utf8').catch(() => ''));
  if (!ecosystem) return [];
  const text = await stdoutOf('dpkg-query', ['-W', '-f', '${source:Package}\t${source:Version}\n'], 15_000);
  return text ? parseDpkg(text, ecosystem) : [];
}

export async function scanComputer(): Promise<Found[]> {
  const groups = await Promise.all([
    Promise.all(TOOLS.map(async (tool) => {
      const text = await output(tool.cmd, tool.args);
      return text ? parseTool(tool, text) : undefined;
    })).then((list) => list.filter((entry): entry is Found => !!entry)),
    process.platform === 'darwin' ? macApps() : Promise.resolve([]),
    stdoutOf('brew', ['info', '--json=v2', '--installed'], 60_000).then((text) => {
      try {
        return text ? parseBrew(JSON.parse(text) as BrewInfo) : [];
      } catch {
        return [];
      }
    }),
    stdoutOf('npm', ['ls', '-g', '--depth=0', '--json'], 30_000).then((text) => {
      try {
        return text ? parseNpmGlobal(text) : [];
      } catch {
        return [];
      }
    }),
    process.platform === 'linux' ? linuxPackages() : Promise.resolve([]),
  ]);
  // Apps and tools report the real version; keep the first source for each product.
  const byKey = new Map<string, Found>();
  for (const entry of groups.flat()) if (!byKey.has(entry.key)) byKey.set(entry.key, entry);
  return [...byKey.values()].sort((a, b) => a.label.localeCompare(b.label));
}
