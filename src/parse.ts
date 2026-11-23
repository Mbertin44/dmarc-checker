import type { DmarcAlignment, DmarcIssue, DmarcPolicy, DmarcTags } from './types.js'

const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri'])

const POLICIES = new Map<string, DmarcPolicy>([
  ['none', 'none'],
  ['quarantine', 'quarantine'],
  ['reject', 'reject'],
])

const ALIGNMENTS = new Map<string, DmarcAlignment>([
  ['r', 'relaxed'],
  ['s', 'strict'],
])

/** A mailto: address, optionally followed by a size limit such as `!10m` (RFC 7489 §6.2). */
const REPORT_URI = /^mailto:[^\s@]+@[^\s@!]+(?:!\d+[kmgt]?)?$/i

export interface ParsedRecord {
  /** The tags with defaults applied, or `null` when the record has any error. */
  tags: DmarcTags | null
  issues: DmarcIssue[]
}

/** Checks the syntax and tag values of a DMARC record (RFC 7489 §6.3 and §6.4). */
export function parseDmarcRecord(record: string): ParsedRecord {
  const { values, issues } = splitTags(record)

  const [firstTag] = values.keys()
  if (firstTag !== 'v' || values.get('v') !== 'DMARC1') {
    issues.push({
      severity: 'error',
      code: 'invalid-version',
      message: 'The record does not start with "v=DMARC1", so receivers ignore it.',
      recommendation: 'Start the record with "v=DMARC1", written exactly like this.',
    })
  }

  if (!values.has('p')) {
    issues.push({
      severity: 'error',
      code: 'missing-policy',
      message: 'The record has no policy ("p" tag), so receivers ignore it.',
      recommendation: 'Add a policy right after the version, e.g. "v=DMARC1; p=none".',
    })
  }

  for (const name of values.keys()) {
    if (!KNOWN_TAGS.has(name)) {
      issues.push({
        severity: 'warning',
        code: 'unknown-tag',
        message: `"${name}" is not a known DMARC tag, so receivers ignore it.`,
        recommendation: 'Check its spelling, or remove it.',
      })
    }
  }

  /** Parses a tag's value, reporting it when it is invalid. Returns `undefined` when the tag is absent or invalid. */
  const readTag = <T>(name: string, parse: (value: string) => T | undefined, expected: string): T | undefined => {
    const value = values.get(name)
    if (value === undefined) return undefined

    const parsed = parse(value)
    if (parsed === undefined) {
      issues.push({
        severity: 'error',
        code: 'invalid-value',
        message: `"${name}=${value}" is not a valid value.`,
        recommendation: `Set "${name}" to ${expected}.`,
      })
    }
    return parsed
  }

  const policy = readTag('p', parsePolicy, 'none, quarantine or reject')
  const subdomainPolicy = readTag('sp', parsePolicy, 'none, quarantine or reject')
  const percentage = readTag('pct', parsePercentage, 'a whole number from 0 to 100')
  const aggregateReportUris = readTag('rua', parseReportUris, 'mailto: addresses separated by commas, e.g. mailto:dmarc@example.com')
  const failureReportUris = readTag('ruf', parseReportUris, 'mailto: addresses separated by commas, e.g. mailto:dmarc@example.com')
  const dkimAlignment = readTag('adkim', parseAlignment, 'r (relaxed) or s (strict)')
  const spfAlignment = readTag('aspf', parseAlignment, 'r (relaxed) or s (strict)')
  const failureReportingOptions = readTag('fo', parseFailureReportingOptions, '0, 1, d or s, separated by colons')
  const reportFormats = readTag('rf', parseReportFormats, 'afrf')
  const reportInterval = readTag('ri', parseWholeNumber, 'a number of seconds, e.g. 86400')

  if (policy === undefined || issues.some(issue => issue.severity === 'error')) {
    return { tags: null, issues }
  }

  return {
    tags: {
      policy,
      subdomainPolicy: subdomainPolicy ?? policy,
      percentage: percentage ?? 100,
      aggregateReportUris: aggregateReportUris ?? [],
      failureReportUris: failureReportUris ?? [],
      dkimAlignment: dkimAlignment ?? 'relaxed',
      spfAlignment: spfAlignment ?? 'relaxed',
      failureReportingOptions: failureReportingOptions ?? ['0'],
      reportFormats: reportFormats ?? ['afrf'],
      reportInterval: reportInterval ?? 86_400,
    },
    issues,
  }
}

/** Splits a record into `name=value` tags separated by semicolons, reporting malformed and repeated ones. */
function splitTags(record: string): { values: Map<string, string>; issues: DmarcIssue[] } {
  const values = new Map<string, string>()
  const issues: DmarcIssue[] = []

  for (const part of record.split(';')) {
    const tag = part.trim()
    if (tag === '') continue

    const separator = tag.indexOf('=')
    if (separator < 1) {
      issues.push({
        severity: 'error',
        code: 'invalid-syntax',
        message: `"${tag}" is not a valid tag.`,
        recommendation: 'Write each tag as name=value and separate tags with semicolons, e.g. "v=DMARC1; p=none".',
      })
      continue
    }

    const name = tag.slice(0, separator).trim().toLowerCase()
    if (values.has(name)) {
      issues.push({
        severity: 'error',
        code: 'duplicate-tag',
        message: `The "${name}" tag appears more than once, which makes the record invalid.`,
        recommendation: `Keep a single "${name}" tag.`,
      })
      continue
    }

    values.set(name, tag.slice(separator + 1).trim())
  }

  return { values, issues }
}

function parsePolicy(value: string): DmarcPolicy | undefined {
  return POLICIES.get(value.toLowerCase())
}

function parseAlignment(value: string): DmarcAlignment | undefined {
  return ALIGNMENTS.get(value.toLowerCase())
}

function parseWholeNumber(value: string): number | undefined {
  if (!/^\d+$/.test(value)) return undefined
  return Number(value)
}

function parsePercentage(value: string): number | undefined {
  const percentage = parseWholeNumber(value)
  if (percentage === undefined || percentage > 100) return undefined
  return percentage
}

function parseReportUris(value: string): string[] | undefined {
  const uris = value.split(',').map(uri => uri.trim())
  if (!uris.every(uri => REPORT_URI.test(uri))) return undefined
  return uris
}

function parseFailureReportingOptions(value: string): string[] | undefined {
  return parseKeywords(value, ['0', '1', 'd', 's'])
}

function parseReportFormats(value: string): string[] | undefined {
  return parseKeywords(value, ['afrf'])
}

function parseKeywords(value: string, allowed: string[]): string[] | undefined {
  const keywords = value.split(':').map(keyword => keyword.trim().toLowerCase())
  if (!keywords.every(keyword => allowed.includes(keyword))) return undefined
  return keywords
}
