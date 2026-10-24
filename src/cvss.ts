/** Parses "CVSS:3.1/AV:N/AC:L/..." into { AV: 'N', AC: 'L', ... }. */
export function parseVector(vector: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  for (const part of vector.split('/')) {
    const [key, value] = part.split(':');
    if (key && value && key !== 'CVSS') metrics[key] = value;
  }
  return metrics;
}

const roundUp = (value: number) => {
  const scaled = Math.round(value * 100_000);
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10;
};

/** CVSS v3.x base score from a vector string, or undefined when the vector is incomplete. */
export function cvss3Score(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = parseVector(vector);
  const changed = m.S === 'C';
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV ?? ''];
  const ac = { L: 0.77, H: 0.44 }[m.AC ?? ''];
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR ?? ''];
  const ui = { N: 0.85, R: 0.62 }[m.UI ?? ''];
  const cia = (key: string) => ({ H: 0.56, L: 0.22, N: 0 })[m[key] ?? ''];
  const [c, i, a] = [cia('C'), cia('I'), cia('A')];
  if ([av, ac, pr, ui, c, i, a].some((value) => value === undefined) || !['U', 'C'].includes(m.S ?? '')) return undefined;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  return roundUp(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

export function severityOf(score: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}
