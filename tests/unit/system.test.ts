import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { osvDistro, parseBrew, parseDpkg, parseNpmGlobal, parseTool, TOOLS } from '../../src/scan.js';
import { cronLine, launchdPlist, parseTime, systemdUnits } from '../../src/schedule.js';
import { exportWatchFile, loadWatchFile, parseWatchFile } from '../../src/watchfile.js';

const tool = (cmd: string) => TOOLS.find((candidate) => candidate.cmd === cmd)!;

describe('scan parsers', () => {
  it('reads version output from common tools', () => {
    expect(parseTool(tool('php'), 'PHP 8.3.10 (cli) (built: Aug 1 2026)\nCopyright (c) The PHP Group')).toMatchObject({ input: 'php 8.3.10', label: 'PHP' });
    expect(parseTool(tool('ssh'), 'OpenSSH_9.8p1, LibreSSL 3.3.6')).toMatchObject({ input: 'openssh 9.8p1' });
    expect(parseTool(tool('node'), 'v24.10.0\n')).toMatchObject({ input: 'nodejs 24.10.0' });
    expect(parseTool(tool('openssl'), 'LibreSSL 3.3.6')).toBeUndefined();
    expect(parseTool(tool('nginx'), 'nginx version: nginx/1.26.2')).toMatchObject({ input: 'nginx 1.26.2' });
  });

  it('maps Homebrew formulae and casks to catalog products', () => {
    const found = parseBrew({
      formulae: [
        { name: 'php@8.3', installed: [{ version: '8.3.10_1' }] },
        { name: 'openssl@3', installed: [{ version: '3.5.4' }] },
        { name: 'some-obscure-tool', installed: [{ version: '1.0' }] },
      ],
      casks: [
        { token: 'google-chrome', installed: '131.0.6778.86' },
        { token: 'plex-media-server', installed: '1.41.2.9200,c26e2b1b8' },
        { token: 'docker', installed: '4.40.0,187762' },
        { token: 'not-installed', installed: null },
      ],
    });
    expect(found.map((entry) => entry.input)).toEqual(['php 8.3.10', 'openssl 3.5.4', 'chrome 131.0.6778.86', 'plex 1.41.2.9200', 'docker-desktop 4.40.0']);
  });

  it('reads global npm packages and Debian packages', () => {
    expect(parseNpmGlobal(JSON.stringify({ dependencies: { typescript: { version: '5.9.3' }, broken: {} } }))).toEqual([
      { input: 'npm:typescript@5.9.3', label: 'typescript', version: '5.9.3', where: 'npm global package', key: 'npm:typescript' },
    ]);
    expect(osvDistro('ID=debian\nVERSION_ID="12"\n')).toBe('Debian:12');
    expect(osvDistro('ID=ubuntu\nVERSION="24.04.1 LTS (Noble Numbat)"\nVERSION_ID="24.04"\n')).toBe('Ubuntu:24.04:LTS');
    expect(osvDistro('ID=fedora\nVERSION_ID=41\n')).toBeUndefined();
    const deb = parseDpkg('openssl\t3.0.15-1~deb12u1\nopenssl\t3.0.15-1~deb12u1\nlibfoo\t1.0\nphp8.2\t8.2.29-1~deb12u1\n', 'Debian:12');
    expect(deb.map((entry) => entry.input)).toEqual(['osv:Debian:12/openssl@3.0.15-1~deb12u1', 'osv:Debian:12/php8.2@8.2.29-1~deb12u1']);
  });
});

describe('schedule files', () => {
  const command = { command: '/usr/local/bin/node', args: ['/opt/patchbell/dist/cli.js'] };

  it('writes a valid launchd agent', () => {
    const plist = launchdPlist(command, parseTime('07:30'), { PATH: '/usr/bin:/bin', NOTE: 'a & b' });
    expect(plist).toContain('<string>check</string>');
    expect(plist).toContain('<integer>7</integer>');
    expect(plist).toContain('a &amp; b');
    if (process.platform === 'darwin') {
      const file = join(mkdtempSync(join(tmpdir(), 'patchbell-plist-')), 'agent.plist');
      writeFileSync(file, plist);
      expect(execFileSync('plutil', ['-lint', file]).toString()).toContain('OK');
    }
  });

  it('writes systemd units and cron lines', () => {
    const units = systemdUnits({ command: '/usr/bin/npx', args: ['-y', 'patchbell'] }, parseTime('9:05'), { PATH: '/usr/bin' });
    expect(units.service).toContain('ExecStart=/usr/bin/npx -y patchbell check --quiet');
    expect(units.timer).toContain('OnCalendar=*-*-* 09:05:00');
    expect(cronLine({ command: '/my node/node', args: ['cli.js'] }, parseTime('23:59'))).toBe("59 23 * * * '/my node/node' cli.js check --quiet");
    expect(() => parseTime('25:00')).toThrow(/like 09:00/);
  });
});

describe('watchlist files', () => {
  it('accepts strings, objects and a bare list', () => {
    expect(parseWatchFile('level: high\nitems:\n  - php 8.3.10\n  - name: Plex Media Server\n    version: 1.41.2\n')).toEqual({
      level: 'high',
      items: ['php 8.3.10', { name: 'Plex Media Server', version: '1.41.2' }],
    });
    expect(parseWatchFile('- npm:express@4.19.2\n')).toEqual({ items: ['npm:express@4.19.2'] });
  });

  it('round-trips an exported watchlist', async () => {
    const items = [
      { id: 'php', name: 'PHP', version: '8.3.10', source: { kind: 'cpe' as const, part: 'a' as const, vendor: 'php', product: 'php' }, eol: 'php', keyword: 'PHP', addedAt: 'x' },
      { id: 'express', name: 'express', version: '4.17.1', level: 'all' as const, source: { kind: 'package' as const, ecosystem: 'npm', name: 'express' }, addedAt: 'x' },
    ];
    const file = join(mkdtempSync(join(tmpdir(), 'patchbell-watch-')), 'patchbell.yml');
    writeFileSync(file, exportWatchFile(items, 'critical'));
    const loaded = await loadWatchFile(file);
    expect(loaded.level).toBe('critical');
    expect(loaded.items.map(({ addedAt: _, ...item }) => item)).toEqual(items.map(({ addedAt: _, ...item }) => item));
  });

  it('resolves the example file without network access', async () => {
    const loaded = await loadWatchFile(new URL('../../examples/patchbell.yml', import.meta.url).pathname);
    expect(loaded.level).toBe('critical');
    expect(loaded.items.map((item) => item.id)).toEqual(['php', 'plex', 'express', 'pypi-django', 'debian-12-openssl', 'nginx']);
    expect(loaded.items.find((item) => item.id === 'plex')).toMatchObject({ level: 'exploited', note: 'home server', version: '1.41.2' });
  });

  it('explains which field is missing', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'patchbell-watch-')), 'bad.yml');
    writeFileSync(file, 'items:\n  - version: 1.0\n');
    await expect(loadWatchFile(file)).rejects.toThrow(/needs a name, package or cpe/);
  });
});
