import { cached, HOUR } from '../cache.js';
import { endpoints, getJsonOrUndefined } from '../http.js';
import type { WatchItem } from '../types.js';
import { eolProduct } from './eol.js';

/** The newest release of an item: from npm or PyPI for packages, endoflife.date for products. */
export async function latestVersion(item: WatchItem): Promise<string | undefined> {
  const { source } = item;
  if (source.kind === 'package' && source.ecosystem === 'npm') {
    return cached(`latest/npm/${source.name}`, 12 * HOUR, async () => {
      const name = source.name.startsWith('@') ? `@${encodeURIComponent(source.name.slice(1))}` : encodeURIComponent(source.name);
      return (await getJsonOrUndefined<{ version: string }>(`${endpoints().npm}/${name}/latest`))?.version;
    });
  }
  if (source.kind === 'package' && source.ecosystem === 'PyPI') {
    return cached(`latest/pypi/${source.name}`, 12 * HOUR, async () => {
      return (await getJsonOrUndefined<{ info: { version: string } }>(`${endpoints().pypi}/${encodeURIComponent(source.name)}/json`))?.info.version;
    });
  }
  if (item.eol) {
    const product = await eolProduct(item.eol);
    return product?.releases.find((release) => release.latest)?.latest?.name;
  }
  return undefined;
}
