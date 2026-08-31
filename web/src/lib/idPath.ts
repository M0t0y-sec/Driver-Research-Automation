// ============================================================================
// ID path resolution. Mirrors `server/dra/models/common.py:IDPrefix`.
// When a new prefix is added to the backend, add it here too — every
// breadcrumb / cross-link in the UI depends on this map.
// ============================================================================

const prefixToPath: Record<string, string> = {
  PRJ: '/projects',
  TGT: '/targets',
  RES: '/research/runs',
  OBS: '/hypotheses', // observations don't have a dedicated page; closest cross-link
  ASF: '/projects',  // attack surface items live inside target pages
  HYP: '/hypotheses',
  EXP: '/experiments',
  EXE: '/experiments',
  CRS: '/findings',  // crashes are surfaced under findings
  TLM: '/findings',
  EVD: '/evidence',
  RCN: '/findings',
  IMP: '/findings',
  XPL: '/findings',
  FND: '/findings',
  APR: '/approvals',
  TRN: '/tool-runs',
  ARN: '/agents',
  VIS: '/detection',
  DET: '/detection',
  RBT: '/detection',
  QAR: '/qa',
  ART: '/tool-runs',
}

export function idPath(id: string): string {
  const prefix = id.split('-')[0]
  const route = prefixToPath[prefix]
  if (!route) return '#'
  // For 'research/runs' we expose the run detail at /research/runs/{id}
  // but our route is /research/{id} (Research Run). Normalize:
  if (route === '/research/runs') return `/research/runs/${id}`
  return `${route}/${id}`
}

export function idShort(id: string): string {
  // Display the short tail of long ids (e.g. "FND-…-AB12CD34")
  const parts = id.split('-')
  if (parts.length <= 2) return id
  return `${parts[0]}-…-${parts[parts.length - 1]}`
}
