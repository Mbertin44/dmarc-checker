import { parseDmarcRecord } from './parse.js'
import { recommend } from './recommend.js'
import type { DmarcIssue, DmarcResult, DmarcSeverity } from './types.js'

const SEVERITY_ORDER: DmarcSeverity[] = ['error', 'warning', 'info']

/** Validates a DMARC record and explains how to improve it. */
export function analyzeDmarcRecord(record: string): DmarcResult {
  const { tags, issues } = parseDmarcRecord(record)

  if (tags === null) {
    return { record, tags, valid: false, issues: sortBySeverity(issues) }
  }

  return { record, tags, valid: true, issues: sortBySeverity([...issues, ...recommend(tags)]) }
}

function sortBySeverity(issues: DmarcIssue[]): DmarcIssue[] {
  return issues.toSorted((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
}
