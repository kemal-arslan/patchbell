import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Message } from '../alerts.js';
import { endpoints, request } from '../http.js';
import type { Channels } from '../types.js';

const run = promisify(execFile);

const NTFY_PRIORITY = { urgent: 5, high: 4, default: 3 } as const;
const truncate = (text: string, max: number) => (text.length <= max ? text : `${text.slice(0, max - 1)}…`);

/** AppleScript string literal. */
const appleString = (text: string) => `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

export async function sendDesktop(message: Message): Promise<void> {
  // Desktop notifications show a line or two; the first finding is enough.
  const firstLine = message.body.split('\n')[0] ?? '';
  if (process.platform === 'darwin') {
    const script = `display notification ${appleString(truncate(firstLine, 220))} with title "Patchbell" subtitle ${appleString(truncate(message.title, 120))}`;
    await run('osascript', ['-e', script], { timeout: 10_000 });
  } else if (process.platform === 'linux') {
    const urgency = message.priority === 'urgent' ? 'critical' : message.priority === 'high' ? 'normal' : 'low';
    await run('notify-send', ['--app-name=Patchbell', `--urgency=${urgency}`, message.title, truncate(message.body, 1000)], { timeout: 10_000 });
  } else {
    throw new Error('Desktop notifications are supported on macOS and Linux. Use ntfy, Telegram or a webhook instead.');
  }
}

export async function sendNtfy(message: Message, config: NonNullable<Channels['ntfy']>): Promise<void> {
  // JSON publishing keeps non-ASCII titles intact (headers can't carry them).
  await request(config.server.replace(/\/+$/, ''), {
    body: {
      topic: config.topic,
      title: message.title,
      message: truncate(message.body, 3500),
      priority: NTFY_PRIORITY[message.priority],
      tags: message.priority === 'urgent' ? ['rotating_light'] : ['warning'],
      ...(message.url ? { click: message.url } : {}),
    },
    headers: config.token ? { authorization: `Bearer ${config.token}` } : {},
    retries: 1,
  });
}

export async function sendTelegram(message: Message, config: NonNullable<Channels['telegram']>): Promise<void> {
  await request(`${endpoints().telegram}/bot${config.token}/sendMessage`, {
    body: {
      chat_id: config.chatId,
      text: truncate(`${message.title}\n\n${message.body}${message.url ? `\n\n${message.url}` : ''}`, 4000),
      disable_web_page_preview: true,
    },
    retries: 1,
  });
}

export async function sendSlack(message: Message, url: string): Promise<void> {
  await request(url, { body: { text: truncate(`*${message.title}*\n${message.body}${message.url ? `\n${message.url}` : ''}`, 3900) }, retries: 1 });
}

export async function sendDiscord(message: Message, url: string): Promise<void> {
  await request(url, { body: { content: truncate(`**${message.title}**\n${message.body}${message.url ? `\n<${message.url}>` : ''}`, 2000) }, retries: 1 });
}

export async function sendWebhook(message: Message, url: string): Promise<void> {
  await request(url, { body: { source: 'patchbell', ...message }, retries: 1 });
}

export type ChannelName = keyof Channels;

export function enabledChannels(channels: Channels): ChannelName[] {
  return (Object.keys(channels) as ChannelName[]).filter((name) => (name === 'desktop' ? channels.desktop === true : !!channels[name]));
}

/** Sends to every configured channel. Returns the channels that failed, with why. */
export async function deliver(message: Message, channels: Channels): Promise<{ channel: ChannelName; error: string }[]> {
  const failures: { channel: ChannelName; error: string }[] = [];
  const attempt = async (channel: ChannelName, send: () => Promise<void>) => {
    try {
      await send();
    } catch (error) {
      failures.push({ channel, error: error instanceof Error ? error.message : String(error) });
    }
  };
  await Promise.all([
    channels.desktop ? attempt('desktop', () => sendDesktop(message)) : undefined,
    channels.ntfy ? attempt('ntfy', () => sendNtfy(message, channels.ntfy!)) : undefined,
    channels.telegram ? attempt('telegram', () => sendTelegram(message, channels.telegram!)) : undefined,
    channels.slack ? attempt('slack', () => sendSlack(message, channels.slack!.url)) : undefined,
    channels.discord ? attempt('discord', () => sendDiscord(message, channels.discord!.url)) : undefined,
    channels.webhook ? attempt('webhook', () => sendWebhook(message, channels.webhook!.url)) : undefined,
  ]);
  return failures;
}
