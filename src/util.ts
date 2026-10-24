/** Runs fn over items with at most `limit` in flight, keeping the order of results. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/** The first sentence of a description, short enough for a notification. */
export function shortTitle(text: string, max = 140): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  const sentence = clean.match(/^(.+?[.!?])(\s|$)/)?.[1] ?? clean;
  return sentence.length <= max ? sentence : `${sentence.slice(0, max - 1).trimEnd()}…`;
}

export const plural = (count: number, word: string, many = `${word}s`) => `${count} ${count === 1 ? word : many}`;

/** "1,3,5-7", "all" or "none" → zero-based indexes. */
export function parseSelection(answer: string, count: number): number[] {
  const text = answer.trim().toLowerCase();
  if (!text || text === 'none' || text === 'n') return [];
  if (text === 'all' || text === 'a') return Array.from({ length: count }, (_, index) => index);
  const picked = new Set<number>();
  for (const part of text.split(/[\s,]+/).filter(Boolean)) {
    const range = /^(\d+)-(\d+)$/.exec(part);
    const [from, to] = range ? [Number(range[1]), Number(range[2])] : [Number(part), Number(part)];
    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 1 || to > count || from > to) throw new Error(`"${part}" isn't between 1 and ${count}.`);
    for (let n = from; n <= to; n += 1) picked.add(n - 1);
  }
  return [...picked].sort((a, b) => a - b);
}
