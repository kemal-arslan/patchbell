import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { homedir, userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { homeDir, logDir } from './paths.js';

const run = promisify(execFile);

export interface Command {
  command: string;
  args: string[];
}

/** How to run this Patchbell later: via npx when started from npx's temporary cache. */
export async function launchCommand(): Promise<Command> {
  const script = await realpath(process.argv[1]!);
  if (/[/\\]_npx[/\\]/.test(script)) {
    const npx = join(dirname(process.execPath), 'npx');
    return { command: existsSync(npx) ? npx : 'npx', args: ['-y', 'patchbell'] };
  }
  return { command: process.execPath, args: [script] };
}

export interface Time {
  hour: number;
  minute: number;
}

export function parseTime(value: string): Time {
  const match = /^(\d{1,2}):(\d{2})$/.exec(value.trim());
  const hour = Number(match?.[1]);
  const minute = Number(match?.[2]);
  if (!match || hour > 23 || minute > 59) throw new Error(`Use a time like 09:00, not "${value}".`);
  return { hour, minute };
}

const xml = (text: string) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const pad = (n: number) => String(n).padStart(2, '0');

export const LABEL = 'dev.patchbell.check';

export function launchdPlist(command: Command, at: Time, env: Record<string, string>): string {
  const args = [command.command, ...command.args, 'check', '--quiet'];
  const log = join(logDir(), 'check.log');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args.map((arg) => `    <string>${xml(arg)}</string>`).join('\n')}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>${at.hour}</integer>
    <key>Minute</key>
    <integer>${at.minute}</integer>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
${Object.entries(env)
  .map(([key, value]) => `    <key>${xml(key)}</key>\n    <string>${xml(value)}</string>`)
  .join('\n')}
  </dict>
  <key>StandardOutPath</key>
  <string>${xml(log)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(log)}</string>
</dict>
</plist>
`;
}

/** systemd quoting: arguments with spaces or quotes in double quotes. */
const systemdArg = (arg: string) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : `"${arg.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);

export function systemdUnits(command: Command, at: Time, env: Record<string, string>): { service: string; timer: string } {
  const exec = [command.command, ...command.args, 'check', '--quiet'].map(systemdArg).join(' ');
  return {
    service: `[Unit]
Description=Patchbell vulnerability check

[Service]
Type=oneshot
ExecStart=${exec}
${Object.entries(env)
  .map(([key, value]) => `Environment=${systemdArg(`${key}=${value}`)}`)
  .join('\n')}
`,
    timer: `[Unit]
Description=Daily Patchbell vulnerability check

[Timer]
OnCalendar=*-*-* ${pad(at.hour)}:${pad(at.minute)}:00
Persistent=true

[Install]
WantedBy=timers.target
`,
  };
}

export function cronLine(command: Command, at: Time): string {
  const quote = (arg: string) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`);
  return `${at.minute} ${at.hour} * * * ${[command.command, ...command.args, 'check', '--quiet'].map(quote).join(' ')}`;
}

/** The environment a scheduled check needs: PATH for npx, and where the watchlist lives. */
function scheduleEnv(): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    ...(process.env.PATCHBELL_HOME ? { PATCHBELL_HOME: homeDir() } : {}),
    ...(process.env.NVD_API_KEY ? { NVD_API_KEY: process.env.NVD_API_KEY } : {}),
  };
}

const plistPath = () => join(homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
const systemdDir = () => join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'systemd', 'user');

/** Installs a daily check. Returns a sentence saying what was set up. */
export async function installSchedule(at: Time): Promise<string> {
  const command = await launchCommand();
  const env = scheduleEnv();
  await mkdir(logDir(), { recursive: true, mode: 0o700 });
  if (process.platform === 'darwin') {
    const path = plistPath();
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, launchdPlist(command, at, env));
    const domain = `gui/${userInfo().uid}`;
    await run('launchctl', ['bootout', `${domain}/${LABEL}`]).catch(() => undefined);
    await run('launchctl', ['bootstrap', domain, path]);
    return `Patchbell will check every day at ${pad(at.hour)}:${pad(at.minute)} (launchd agent ${path}).`;
  }
  if (process.platform === 'linux') {
    const units = systemdUnits(command, at, env);
    try {
      await mkdir(systemdDir(), { recursive: true });
      await writeFile(join(systemdDir(), 'patchbell.service'), units.service);
      await writeFile(join(systemdDir(), 'patchbell.timer'), units.timer);
      await run('systemctl', ['--user', 'daemon-reload']);
      await run('systemctl', ['--user', 'enable', '--now', 'patchbell.timer']);
      return `Patchbell will check every day at ${pad(at.hour)}:${pad(at.minute)} (systemd user timer patchbell.timer).`;
    } catch {
      return `Couldn't use systemd here. Add this line with "crontab -e" instead:\n  ${cronLine(command, at)}`;
    }
  }
  return `Automatic scheduling isn't supported on ${process.platform}. Run "patchbell check" from Task Scheduler, or use the GitHub Action.`;
}

export async function removeSchedule(): Promise<string> {
  if (process.platform === 'darwin') {
    await run('launchctl', ['bootout', `gui/${userInfo().uid}/${LABEL}`]).catch(() => undefined);
    await rm(plistPath(), { force: true });
    return 'Daily checks are off.';
  }
  if (process.platform === 'linux') {
    await run('systemctl', ['--user', 'disable', '--now', 'patchbell.timer']).catch(() => undefined);
    await rm(join(systemdDir(), 'patchbell.timer'), { force: true });
    await rm(join(systemdDir(), 'patchbell.service'), { force: true });
    return 'Daily checks are off. (If you used cron, remove the line with "crontab -e".)';
  }
  return 'Nothing to remove on this platform.';
}

export async function scheduleStatus(): Promise<string> {
  if (process.platform === 'darwin') {
    if (!existsSync(plistPath())) return 'No daily check. Turn it on with: patchbell schedule daily';
    const loaded = await run('launchctl', ['print', `gui/${userInfo().uid}/${LABEL}`]).then(() => true, () => false);
    return loaded ? `Daily check is on (${plistPath()}). Log: ${join(logDir(), 'check.log')}` : `The agent file exists but isn't loaded. Run: patchbell schedule daily`;
  }
  if (process.platform === 'linux') {
    const enabled = await run('systemctl', ['--user', 'is-enabled', 'patchbell.timer']).then(() => true, () => false);
    return enabled ? 'Daily check is on (systemd user timer patchbell.timer).' : 'No daily check found in systemd. Turn it on with: patchbell schedule daily';
  }
  return `Scheduling isn't managed by Patchbell on ${process.platform}.`;
}
