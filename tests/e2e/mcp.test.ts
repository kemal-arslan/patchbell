import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startFakeApis, type FakeApis } from './fake-apis.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

let apis: FakeApis;
let home: string;
let client: Client;

/** The real CLI's MCP server over stdio, with a real MCP client. */
async function connect(...flags: string[]): Promise<Client> {
  const { NVD_API_KEY: _, ...base } = process.env as Record<string, string>;
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--import', 'tsx', 'src/cli.ts', 'mcp', ...flags],
    cwd: ROOT,
    env: { ...base, ...apis.env, PATCHBELL_HOME: home },
    stderr: 'pipe',
  });
  const connected = new Client({ name: 'patchbell-test', version: '0.0.0' });
  await connected.connect(transport);
  return connected;
}

const text = (result: Awaited<ReturnType<Client['callTool']>>) => (result.content as { text: string }[]).map((item) => item.text).join('\n');

beforeAll(async () => {
  apis = await startFakeApis();
  home = await mkdtemp(join(tmpdir(), 'patchbell-mcp-'));
  client = await connect();
});

afterAll(async () => {
  await client?.close();
  await apis?.close();
  await rm(home, { recursive: true, force: true });
});

describe('MCP server', () => {
  it('lists its tools, without computer scanning unless allowed', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name)).toEqual(['list_watchlist', 'add_to_watchlist', 'update_watchlist_item', 'remove_from_watchlist', 'check_now', 'whats_new', 'am_i_affected']);
    expect(tools.find((tool) => tool.name === 'check_now')?.annotations).toMatchObject({ readOnlyHint: true });
    expect(tools.find((tool) => tool.name === 'remove_from_watchlist')?.annotations).toMatchObject({ destructiveHint: true });

    const scanning = await connect('--allow-scan');
    expect((await scanning.listTools()).tools.map((tool) => tool.name)).toContain('suggest_from_computer');
    await scanning.close();
  });

  it('adds items, and returns candidates for ambiguous names', async () => {
    expect(text(await client.callTool({ name: 'add_to_watchlist', arguments: { item: 'plex 1.41.2', note: 'home server' } }))).toContain('Added "plex": Plex Media Server 1.41.2');
    const ambiguous = text(await client.callTool({ name: 'add_to_watchlist', arguments: { item: 'acme widget', version: '1.0' } }));
    expect(ambiguous).toContain('cpe:2.3:a:acme:widget_pro');
    expect(ambiguous).toContain('Ask the user which one');
    expect(text(await client.callTool({ name: 'add_to_watchlist', arguments: { item: 'cpe:2.3:a:php:php', version: '8.3.10' } }))).toContain('Added "php": PHP 8.3.10');
    expect(text(await client.callTool({ name: 'list_watchlist', arguments: {} }))).toContain('home server');
  });

  it('checks without notifying', async () => {
    const result = text(await client.callTool({ name: 'check_now', arguments: {} }));
    expect(result).toContain('CVE-2026-96656');
    expect(result).toContain('Attackers are already using it');
    expect(result).toContain('CVE-2026-109618');
    expect(apis.ntfy).toHaveLength(0);
    const recent = text(await client.callTool({ name: 'whats_new', arguments: { days: 7 } }));
    expect(recent).toContain('CVE-2026-999001');
  });

  it('answers per CVE and updates versions', async () => {
    expect(text(await client.callTool({ name: 'am_i_affected', arguments: { cve: 'CVE-2026-109618' } }))).toMatch(/affected\s+PHP 8\.3\.10/);
    expect(text(await client.callTool({ name: 'update_watchlist_item', arguments: { id: 'php', version: '8.3.36' } }))).toContain('PHP 8.3.36');
    expect(text(await client.callTool({ name: 'am_i_affected', arguments: { cve: 'CVE-2026-109618' } }))).toMatch(/not affected\s+PHP 8\.3\.36/);
    const missing = await client.callTool({ name: 'remove_from_watchlist', arguments: { id: 'nope' } });
    expect(missing.isError).toBe(true);
    expect(text(await client.callTool({ name: 'remove_from_watchlist', arguments: { id: 'php' } }))).toContain('Removed "php"');
  });
});
