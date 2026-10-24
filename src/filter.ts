import type { Finding, Level } from './types.js';

const LABEL_SCORE: Record<string, number> = { critical: 9, high: 7, moderate: 5, medium: 5, low: 2 };

/** A finding's CVSS score, or one implied by its advisory's severity word. */
export const scoreOf = (finding: Finding) => finding.cvss?.score ?? LABEL_SCORE[finding.severity ?? ''] ?? 0;

/**
 * Whether a finding is serious enough to tell you about:
 *   exploited  attackers are using it (CISA KEV)
 *   critical   exploited, CVSS 9+, or EPSS 10%+   (default)
 *   high       exploited, CVSS 7+, or EPSS 5%+
 *   all        everything that affects your version
 */
export function meetsLevel(finding: Finding, level: Level): boolean {
  if (level === 'all' || finding.kev) return true;
  if (level === 'exploited') return false;
  const epss = finding.epss?.score ?? 0;
  if (level === 'critical') return scoreOf(finding) >= 9 || epss >= 0.1;
  return scoreOf(finding) >= 7 || epss >= 0.05;
}

/** Most urgent first: exploited, then confirmed for your version, then by score. */
export function byUrgency(a: Finding, b: Finding): number {
  return (
    Number(!!b.kev) - Number(!!a.kev) ||
    Number(b.status === 'affected') - Number(a.status === 'affected') ||
    scoreOf(b) - scoreOf(a) ||
    (b.epss?.score ?? 0) - (a.epss?.score ?? 0) ||
    (b.published ?? '').localeCompare(a.published ?? '')
  );
}
