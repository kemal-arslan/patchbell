/** Where an item's vulnerabilities come from. */
export type Source =
  /** A package in an OSV ecosystem (npm, PyPI, Go, Maven, Debian:12, ...). */
  | { kind: 'package'; ecosystem: string; name: string }
  /** A product in NVD, identified by its CPE vendor and product (and older names it had). */
  | { kind: 'cpe'; part: 'a' | 'o' | 'h'; vendor: string; product: string; also?: { vendor: string; product: string }[] };

/** How serious something must be before you hear about it. */
export type Level = 'exploited' | 'critical' | 'high' | 'all';

export interface WatchItem {
  id: string;
  /** Display name, e.g. "Plex Media Server". */
  name: string;
  /** The version you run. Without one, only new product-wide alerts are reported. */
  version?: string;
  source: Source;
  /** endoflife.date product, for end-of-life and new-release information. */
  eol?: string;
  /** Phrase used to find brand-new CVEs that NVD has not mapped to products yet. */
  keyword?: string;
  /** Overrides the default level for this item. */
  level?: Level;
  /** Also report new releases, not only vulnerabilities. */
  updates?: boolean;
  note?: string;
  addedAt: string;
}

export interface Watchlist {
  items: WatchItem[];
}

/**
 * affected: your version is in a vulnerable range.
 * unconfirmed: the product is affected but the records don't say which versions.
 * product: the item has no version, so this affects some versions of the product.
 */
export type Status = 'affected' | 'unconfirmed' | 'product';

export interface Cvss {
  score: number;
  version: string;
  vector?: string;
}

export interface KevEntry {
  cve: string;
  name: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  action: string;
}

export interface Finding {
  /** CVE ID when there is one, otherwise the advisory ID (GHSA-…, PYSEC-…). */
  id: string;
  aliases: string[];
  title: string;
  status: Status;
  cvss?: Cvss;
  /** CVSS vector without a computed score (CVSS 4.0 from OSV), used to explain the attack. */
  vector?: string;
  /** Severity word from the advisory, used when there is no CVSS score. */
  severity?: string;
  cwes: string[];
  kev?: KevEntry;
  epss?: { score: number; percentile: number };
  /** First version without the problem, when known. */
  fixedIn?: string;
  published?: string;
  /** Which records said this version is affected. */
  reason: string;
  url: string;
}

export interface EolInfo {
  cycle: string;
  isEol: boolean;
  eolFrom?: string;
  latestInCycle?: string;
  latest?: string;
  url: string;
}

export interface ItemResult {
  item: WatchItem;
  /** Everything that affects the item. */
  findings: Finding[];
  /** Findings at or above the item's level. */
  alerts: Finding[];
  eol?: EolInfo;
  /** Newest release, when the item asks for updates. */
  latest?: string;
  error?: string;
}

export interface Channels {
  desktop?: boolean;
  ntfy?: { server: string; topic: string; token?: string };
  telegram?: { token: string; chatId: string };
  slack?: { url: string };
  discord?: { url: string };
  webhook?: { url: string };
}

export interface Config {
  level: Level;
  channels: Channels;
}
