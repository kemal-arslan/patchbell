import { parseVector } from './cvss.js';
import type { Finding } from './types.js';

/** What an attacker gets, by CWE. */
const IMPACT_BY_CWE: Record<string, string> = {
  'CWE-77': 'run commands on it',
  'CWE-78': 'run commands on it',
  'CWE-94': 'run code on it',
  'CWE-95': 'run code on it',
  'CWE-502': 'run code on it',
  'CWE-434': 'upload files that run code on it',
  'CWE-416': 'crash it or possibly run code on it',
  'CWE-787': 'crash it or possibly run code on it',
  'CWE-120': 'crash it or possibly run code on it',
  'CWE-121': 'crash it or possibly run code on it',
  'CWE-122': 'crash it or possibly run code on it',
  'CWE-89': 'read or change its database',
  'CWE-22': 'read or write files it shouldn’t',
  'CWE-23': 'read or write files it shouldn’t',
  'CWE-73': 'read or write files it shouldn’t',
  'CWE-79': 'run scripts in its pages',
  'CWE-352': 'make a logged-in user do things unknowingly',
  'CWE-287': 'get in without valid credentials',
  'CWE-288': 'get in without valid credentials',
  'CWE-290': 'get in without valid credentials',
  'CWE-306': 'use features that should need a login',
  'CWE-862': 'do things they aren’t allowed to',
  'CWE-863': 'do things they aren’t allowed to',
  'CWE-269': 'gain higher privileges',
  'CWE-918': 'make it send requests to internal systems',
  'CWE-611': 'read files through crafted XML',
  'CWE-798': 'log in with a built-in password',
  'CWE-200': 'read information they shouldn’t',
  'CWE-400': 'slow it down or crash it',
  'CWE-770': 'slow it down or crash it',
  'CWE-601': 'redirect users to a malicious site',
};

function impactFromVector(metrics: Record<string, string>): string | undefined {
  const c = metrics.C ?? metrics.VC;
  const i = metrics.I ?? metrics.VI;
  const a = metrics.A ?? metrics.VA;
  if (c === 'H' && i === 'H') return 'take control of it';
  if (i === 'H') return 'change its data';
  if (c === 'H') return 'read sensitive data';
  if (a === 'H') return 'crash it';
  return undefined;
}

/** One plain sentence: "An attacker can run code on it over the network without logging in." */
export function describeAttack(finding: Pick<Finding, 'cvss' | 'vector' | 'cwes'>): string | undefined {
  const vector = finding.cvss?.vector ?? finding.vector;
  const metrics = vector ? parseVector(vector) : {};
  const impact = finding.cwes.map((cwe) => IMPACT_BY_CWE[cwe]).find(Boolean) ?? impactFromVector(metrics);
  if (!impact) return undefined;
  const where = { N: ' over the network', A: ' from the same local network', L: ' with access to the machine', P: ' with physical access' }[
    metrics.AV ?? ''
  ];
  const who = { N: ' without logging in', L: ' with a normal account', H: ' with an admin account' }[metrics.PR ?? ''] ?? '';
  const click = ['R', 'P', 'A'].includes(metrics.UI ?? '') ? ', if someone opens a link or file' : '';
  return `An attacker can ${impact}${where ?? ''}${who}${click}.`;
}

const month = (date: string) => new Date(`${date}T00:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });

/** Short sentences on why this one matters, most important first. */
export function whyItMatters(finding: Finding): string[] {
  const lines: string[] = [];
  if (finding.kev) {
    lines.push(`Attackers are already using it (CISA, since ${month(finding.kev.dateAdded)}${finding.kev.ransomware ? ', including ransomware' : ''}).`);
  }
  const attack = describeAttack(finding);
  if (attack) lines.push(attack);
  if (finding.epss && finding.epss.score >= 0.01) {
    lines.push(`Estimated ${Math.round(finding.epss.score * 100)}% chance of attacks in the next 30 days (EPSS).`);
  }
  if (finding.status === 'unconfirmed') lines.push('The records don’t say which versions are affected yet, so check the advisory.');
  if (finding.status === 'product') lines.push('Some versions are affected. Set your version for a precise answer.');
  return lines;
}

export function severityWord(finding: Finding): string {
  if (finding.cvss) {
    const score = finding.cvss.score;
    const word = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
    return `${word} ${score.toFixed(1)}`;
  }
  return (finding.severity ?? 'unknown').toLowerCase();
}

export function fixAdvice(finding: Finding, currentVersion?: string): string {
  if (finding.fixedIn) return `Update to ${finding.fixedIn} or later.`;
  if (finding.kev?.action) return finding.kev.action;
  return currentVersion ? 'No fixed version is listed yet; see the advisory.' : 'See the advisory for fixed versions.';
}
