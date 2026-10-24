#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { addItem, answerCve, checkAndNotify, findItem, removeItem, updateItem } from './actions.js';
import { buildMessages, type Message } from './alerts.js';
import { runCheck } from './check.js';
import { formatCveAnswer } from './cve-format.js';
import { bold, dim, formatItems, formatResults, green, red, yellow } from './format.js';
import { REPO_URL, SUPPORT_URL, VERSION } from './meta.js';
import { deliver, enabledChannels } from './notify/channels.js';
import { syncIssues } from './notify/github.js';
import { homeDir } from './paths.js';
import { describeSource, type Resolution } from './resolve.js';
import { scanComputer, type Found } from './scan.js';
import { installSchedule, launchCommand, parseTime, removeSchedule, scheduleStatus } from './schedule.js';
import { loadConfig, loadWatchlist, saveConfig, validateLevel } from './store.js';
import type { Config, ItemResult } from './types.js';
import { parseSelection, plural } from './util.js';
import { exportWatchFile, loadWatchFile } from './watchfile.js';

/** Human output goes to stderr, so `mcp` keeps stdout clean and --json stays parseable. */
const say = (...lines: string[]) => console.error(lines.join('\n'));

const HELP = `${bold('patchbell')} ${VERSION} — get told when software you run has a serious vulnerability, and only then.

${bold('Watchlist')}
  patchbell add <what> [--level L] [--updates] [--note text]
      "php 8.3.10"  "plex 1.41.2"  "npm:express@4.19.2"  "pypi:django@4.2.1"
      "cpe:2.3:a:f5:nginx 1.26.2"  "osv:Debian:12/openssl@3.0.15-1~deb12u1"
  patchbell list
  patchbell set <id> <version>          after you upgrade (also: --level L, --updates, --no-updates)
  patchbell remove <id>
  patchbell scan                        optional: suggest items from this computer; you pick

${bold('Checking')}
  patchbell check [ids…] [--all] [--json] [--quiet] [--no-notify]
  patchbell cve <CVE-ID>                am I affected?
  patchbell level <exploited|critical|high|all>
                                        default alert level (now: see "patchbell notify")

${bold('Notifications')}
  patchbell notify                      show channels
  patchbell notify desktop on|off
  patchbell notify ntfy <topic> [--server URL] [--token T] | off
  patchbell notify telegram <bot-token> <chat-id> | off
  patchbell notify slack|discord|webhook <url> | off
  patchbell notify test
  patchbell schedule daily [--at 09:00] | off | status

${bold('Agents and CI')}
  patchbell mcp [--allow-scan]          MCP server for Claude, Codex, Cursor…
  patchbell setup                       how to add the MCP server to your agent
  patchbell export [--out patchbell.yml]
  patchbell check --watchlist patchbell.yml [--github-issues] [--fail-on-alerts]

Levels: exploited (attackers use it) · critical (exploited, CVSS 9+, EPSS 10%+; default) · high (…CVSS 7+, EPSS 5%+) · all
Data: NVD, OSV, CISA KEV, FIRST EPSS, cve.org, endoflife.date. Set NVD_API_KEY for faster checks.
Your data: ${homeDir()} (override with PATCHBELL_HOME)

${dim(`Patchbell is free and open source: ${REPO_URL}`)}
${dim(`If it helps you, you can buy me a coffee: ${SUPPORT_URL}`)}
`;

async function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

function printAmbiguous(resolution: Extract<Resolution, { kind: 'ambiguous' }>): void {
  say(`"${resolution.query}" could be several products:`);
  resolution.candidates.forEach((candidate, index) => say(`  ${String(index + 1).padStart(2)}. ${candidate.title.padEnd(40)} ${dim(candidate.cpe)}`));
}

async function add(text: string, values: Values, check: boolean): Promise<void> {
  const options = {
    ...(values.level ? { level: validateLevel(values.level) } : {}),
    ...(values.updates ? { updates: true } : {}),
    ...(values.note ? { note: values.note } : {}),
    ...(values.id ? { id: values.id } : {}),
    ...(values.pick ? { pick: Number(values.pick) } : {}),
  };
  let { resolution, item } = await addItem(text, options);
  if (resolution.kind === 'ambiguous') {
    printAmbiguous(resolution);
    if (!process.stdin.isTTY) {
      say('', `Add it again with --pick <number>, or use the cpe: name, e.g. patchbell add "${resolution.candidates[0]!.cpe} <version>"`);
      process.exitCode = 1;
      return;
    }
    const answer = await ask(`Which one? [1-${resolution.candidates.length}, Enter to cancel] `);
    if (!answer) return say('Nothing added.');
    ({ resolution, item } = await addItem(text, { ...options, pick: parseSelection(answer, resolution.candidates.length)[0]! + 1 }));
  }
  if (resolution.kind === 'not-found') {
    say(`${yellow('Not found:')} nothing in NVD matches "${resolution.query}".`, 'Try the product’s official name, or a package such as npm:name@version.');
    process.exitCode = 1;
    return;
  }
  if (!item) return;
  say(`${green('Added')} ${bold(item.id)}: ${item.name}${item.version ? ` ${item.version}` : ''}  ${dim(describeSource(item))}`);
  if (!item.version) say(dim(`No version: you'll only hear about new product-wide issues. Set one with: patchbell set ${item.id} <version>`));
  if (!check) return;
  say(dim('Checking it now…'));
  const run = await checkAndNotify({ ids: [item.id], notify: false });
  say(formatResults(run.results));
}

function printNotifySummary(messages: readonly Message[], failures: { channel: string; error: string }[], config: Config, quiet: boolean): void {
  if (messages.length === 0) return;
  const channels = enabledChannels(config.channels);
  if (channels.length === 0 && !quiet) say(dim('No notification channels set up. See: patchbell notify'));
  else if (!quiet) say(dim(`Sent ${plural(messages.length, 'notification')} to ${channels.join(', ')}.`));
  for (const failure of failures) say(`${yellow('Notification failed')} (${failure.channel}): ${failure.error}`);
}

async function check(ids: string[], values: Values): Promise<void> {
  const level = values.level ? validateLevel(values.level) : undefined;
  let results: ItemResult[];
  if (values.watchlist) {
    // A watchlist file (GitHub Action): no local state; issues or the exit code carry the result.
    const file = await loadWatchFile(values.watchlist);
    results = await runCheck(file.items, { level: level ?? file.level ?? 'critical', onItem: (item) => values.quiet || say(dim(`Checking ${item.name}…`)) });
    if (values['github-issues']) {
      const token = process.env.GITHUB_TOKEN;
      const repository = process.env.GITHUB_REPOSITORY;
      if (!token || !repository) throw new Error('--github-issues needs GITHUB_TOKEN and GITHUB_REPOSITORY (both are set inside GitHub Actions).');
      const summary = await syncIssues(results, { token, repository });
      say(`GitHub issues: ${summary.opened} opened, ${summary.escalated} updated because they're now exploited, ${summary.unchanged} already open or dismissed.`);
    } else if (values.notify !== false && !values.json) {
      const config = await loadConfig();
      const messages = buildMessages(results.flatMap((result) => result.alerts.map((finding) => ({ item: result.item, finding, escalated: false }))), []);
      const failures = [];
      for (const message of messages) failures.push(...(await deliver(message, config.channels)));
      printNotifySummary(messages, failures, config, !!values.quiet);
    }
  } else {
    const list = await loadWatchlist();
    if (list.items.length === 0) {
      say('Your watchlist is empty. Add what you run, for example:', '  patchbell add "php 8.3.10"', '  patchbell add "plex 1.41.2"', '  patchbell add npm:express@4.19.2');
      return;
    }
    const config = await loadConfig();
    const run = await checkAndNotify({
      ids,
      notify: values.notify !== false,
      ...(level ? { level } : {}),
      config,
      onItem: (item) => values.quiet || values.json || say(dim(`Checking ${item.name}…`)),
    });
    results = run.results;
    printNotifySummary(run.messages, run.failures, config, !!values.quiet);
  }

  if (values.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    const alerts = results.reduce((sum, result) => sum + result.alerts.length, 0);
    const failed = results.filter((result) => result.error).length;
    // Quiet (scheduled) runs only print when there is something to say.
    if (!values.quiet || alerts > 0 || failed > 0) {
      say(formatResults(results, { all: !!values.all }));
      say('', alerts ? `${red(plural(alerts, 'alert'))} across ${plural(results.length, 'item')}.` : `${green('No alerts')} for ${plural(results.length, 'item')}.`);
    }
  }
  if (values['fail-on-alerts'] && results.some((result) => result.alerts.length > 0)) process.exitCode = 2;
  if (results.length > 0 && results.every((result) => result.error)) process.exitCode = 1;
}

async function scan(values: Values): Promise<void> {
  say(dim('Looking at installed apps, Homebrew, runtimes and packages. Nothing is sent anywhere.'));
  const found = await scanComputer();
  const list = await loadWatchlist();
  const followed = new Set(list.items.map((item) => `${item.name}`.toLowerCase()));
  const fresh = found.filter((entry) => !followed.has(entry.label.toLowerCase()));
  if (values.json) return void console.log(JSON.stringify(fresh, null, 2));
  if (fresh.length === 0) return say('Found nothing new that Patchbell recognizes. You can still add anything by name.');
  fresh.forEach((entry: Found, index) => say(`  ${String(index + 1).padStart(3)}. ${entry.label.padEnd(30)} ${entry.version.padEnd(18)} ${dim(entry.where)}`));
  if (!process.stdin.isTTY) return say('', 'Add the ones you want with: patchbell add "<name> <version>"');
  const picked = parseSelection(await ask(`\nWhich should Patchbell follow? (e.g. 1,3,5-7, all, Enter for none) `), fresh.length);
  for (const index of picked) await add(fresh[index]!.input, {}, false);
  if (picked.length) say('', `Run ${bold('patchbell check')} to see current alerts.`);
}

async function notify(args: string[], values: Values): Promise<void> {
  const config = await loadConfig();
  const [channel, value, extra] = args;
  const off = value === 'off';
  switch (channel) {
    case undefined: {
      const enabled = enabledChannels(config.channels);
      say(`Alert level: ${bold(config.level)}`, `Channels: ${enabled.length ? enabled.join(', ') : 'none'}`);
      return;
    }
    case 'test': {
      const message: Message = { title: 'Patchbell test', body: 'Notifications work. You’ll hear from Patchbell only when something you run is at risk.', url: REPO_URL, priority: 'default', itemId: 'test' };
      const failures = await deliver(message, config.channels);
      const enabled = enabledChannels(config.channels);
      if (enabled.length === 0) return say('No channels set up yet.');
      for (const name of enabled) {
        const failure = failures.find((candidate) => candidate.channel === name);
        say(failure ? `${red('✗')} ${name}: ${failure.error}` : `${green('✓')} ${name}`);
      }
      if (failures.length) process.exitCode = 1;
      return;
    }
    case 'desktop':
      if (value !== 'on' && value !== 'off') throw new Error('Use: patchbell notify desktop on|off');
      config.channels.desktop = value === 'on';
      break;
    case 'ntfy':
      if (off) delete config.channels.ntfy;
      else if (value) config.channels.ntfy = { server: values.server ?? 'https://ntfy.sh', topic: value, ...(values.token ? { token: values.token } : {}) };
      else throw new Error('Use: patchbell notify ntfy <topic> [--server URL] [--token T]');
      break;
    case 'telegram':
      if (off) delete config.channels.telegram;
      else if (value && extra) config.channels.telegram = { token: value, chatId: extra };
      else throw new Error('Use: patchbell notify telegram <bot-token> <chat-id>');
      break;
    case 'slack':
    case 'discord':
    case 'webhook':
      if (off) delete config.channels[channel];
      else if (value && /^https?:\/\//.test(value)) config.channels[channel] = { url: value };
      else throw new Error(`Use: patchbell notify ${channel} <url>`);
      break;
    default:
      throw new Error(`Unknown channel "${channel}". Channels: desktop, ntfy, telegram, slack, discord, webhook.`);
  }
  await saveConfig(config);
  say(`${green('Saved.')} Channels: ${enabledChannels(config.channels).join(', ') || 'none'}. Try: patchbell notify test`);
  if (channel === 'ntfy' && !off) say(dim(`Subscribe to "${value}" in the ntfy app. Anyone who knows the topic name can read it, so pick something hard to guess.`));
}

async function setup(): Promise<void> {
  const { command, args } = await launchCommand();
  const serveArgs = [...args, 'mcp'];
  const quote = (value: string) => (/^[\w@%+=:,./-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`);
  say(
    bold('Claude Code'),
    `  claude mcp add patchbell -- ${[command, ...serveArgs].map(quote).join(' ')}`,
    '',
    bold('Codex') + dim(' (~/.codex/config.toml)'),
    '  [mcp_servers.patchbell]',
    `  command = ${JSON.stringify(command)}`,
    `  args = ${JSON.stringify(serveArgs)}`,
    '',
    bold('Cursor, Claude Desktop and other MCP clients'),
    JSON.stringify({ mcpServers: { patchbell: { command, args: serveArgs } } }, null, 2)
      .split('\n')
      .map((line) => `  ${line}`)
      .join('\n'),
    '',
    dim('Add --allow-scan to the args to let the agent suggest items from installed software.'),
  );
}

const OPTIONS = {
  level: { type: 'string' },
  updates: { type: 'boolean' },
  'no-updates': { type: 'boolean' },
  note: { type: 'string' },
  id: { type: 'string' },
  pick: { type: 'string' },
  check: { type: 'boolean', default: true },
  'no-check': { type: 'boolean' },
  all: { type: 'boolean' },
  json: { type: 'boolean' },
  quiet: { type: 'boolean', short: 'q' },
  notify: { type: 'boolean', default: true },
  'no-notify': { type: 'boolean' },
  watchlist: { type: 'string' },
  'github-issues': { type: 'boolean' },
  'fail-on-alerts': { type: 'boolean' },
  server: { type: 'string' },
  token: { type: 'string' },
  at: { type: 'string' },
  out: { type: 'string' },
  'allow-scan': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
} as const;

type Values = Partial<{ [K in keyof typeof OPTIONS]: (typeof OPTIONS)[K]['type'] extends 'string' ? string : boolean }>;

async function main(): Promise<void> {
  const { values: parsed, positionals } = parseArgs({ allowPositionals: true, options: OPTIONS });
  const values: Values = { ...parsed, notify: parsed.notify && !parsed['no-notify'], check: parsed.check && !parsed['no-check'] };
  const [command, ...rest] = positionals;
  if (values.version) return void console.log(VERSION);
  if (values.help || !command) return void say(HELP);
  const need = (what: string) => {
    if (!rest[0]) throw new Error(`Missing ${what}. See: patchbell --help`);
    return rest[0];
  };

  switch (command) {
    case 'add':
      if (rest.length === 0) throw new Error('What should Patchbell follow? e.g. patchbell add "php 8.3.10"');
      return add(rest.join(' '), values, values.check !== false);
    case 'list':
    case 'ls': {
      const [list, config] = await Promise.all([loadWatchlist(), loadConfig()]);
      if (values.json) return void console.log(JSON.stringify(list.items, null, 2));
      say(formatItems(list.items));
      if (list.items.length) say('', dim(`Default level: ${config.level}`));
      return;
    }
    case 'set': {
      const id = need('<id>');
      const version = rest[1];
      const change = {
        ...(version ? { version: version.replace(/^v(?=\d)/i, '') } : {}),
        ...(values.level ? { level: validateLevel(values.level) } : {}),
        ...(values.updates ? { updates: true } : values['no-updates'] ? { updates: false } : {}),
        ...(values.note ? { note: values.note } : {}),
      };
      if (Object.keys(change).length === 0) throw new Error('Nothing to change. e.g. patchbell set php 8.3.36');
      const item = await updateItem(id, change);
      return say(`${green('Updated')} ${bold(item.id)}: ${item.name}${item.version ? ` ${item.version}` : ''}${item.level ? dim(` [level ${item.level}]`) : ''}`);
    }
    case 'remove':
    case 'rm': {
      const item = await removeItem(need('<id>'));
      return say(`Removed ${item.id} (${item.name}).`);
    }
    case 'check':
      return check(rest, values);
    case 'cve': {
      const answer = await answerCve(need('<CVE-ID>'));
      if (values.json) return void console.log(JSON.stringify(answer, null, 2));
      say(formatCveAnswer(answer));
      if (answer.verdicts.some((verdict) => verdict.status === 'affected') && values['fail-on-alerts']) process.exitCode = 2;
      return;
    }
    case 'scan':
      return scan(values);
    case 'level': {
      const config = await loadConfig();
      if (!rest[0]) return say(`Default alert level: ${bold(config.level)}`);
      config.level = validateLevel(rest[0]);
      await saveConfig(config);
      return say(`${green('Saved.')} Default alert level: ${config.level}`);
    }
    case 'notify':
      return notify(rest, values);
    case 'schedule': {
      const mode = rest[0] ?? 'status';
      if (mode === 'daily') return say(await installSchedule(parseTime(values.at ?? '09:00')));
      if (mode === 'off') return say(await removeSchedule());
      if (mode === 'status') return say(await scheduleStatus());
      throw new Error('Use: patchbell schedule daily [--at 09:00] | off | status');
    }
    case 'export': {
      const [list, config] = await Promise.all([loadWatchlist(), loadConfig()]);
      const text = exportWatchFile(list.items, config.level);
      if (values.out) {
        await writeFile(values.out, text);
        return say(`Wrote ${values.out} with ${plural(list.items.length, 'item')}. Commit it next to the workflow from the README.`);
      }
      return void process.stdout.write(text);
    }
    case 'mcp': {
      const { serveMcp } = await import('./mcp.js');
      return serveMcp({ allowScan: !!values['allow-scan'] });
    }
    case 'setup':
      return setup();
    case 'show': {
      const item = await findItem(need('<id>'));
      return void console.log(JSON.stringify(item, null, 2));
    }
    default:
      throw new Error(`Unknown command "${command}". See: patchbell --help`);
  }
}

main().catch((error: unknown) => {
  say(`${red('error')} ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});

