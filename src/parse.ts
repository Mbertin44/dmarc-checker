import type { DmarcAlignment, DmarcIssue, DmarcPolicy, DmarcPublicSuffixDomain, DmarcTags } from './types.js'

const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'np', 't', 'psd', 'rua', 'ruf', 'adkim', 'aspf', 'fo'])

/** Tags that RFC 9989 removed from DMARC, with what to do instead. */
const OBSOLETE_TAGS = new Map([
  ['pct', 'Remove it. To try out a policy before fully applying it, use "t=y" instead.'],
  ['rf', 'Remove it.'],
  ['ri', 'Remove it.'],
])

const POLICIES = new Map<string, DmarcPolicy>([
  ['none', 'none'],
  ['quarantine', 'quarantine'],
  ['reject', 'reject'],
])

const ALIGNMENTS = new Map<string, DmarcAlignment>([
  ['r', 'relaxed'],
  ['s', 'strict'],
])

const TEST_MODES = new Map<string, boolean>([
  ['y', true],
  ['n', false],
])

const PUBLIC_SUFFIX_DOMAINS = new Map<string, DmarcPublicSuffixDomain>([
  ['y', 'yes'],
  ['n', 'no'],
  ['u', 'unspecified'],
])

const FAILURE_REPORTING_OPTIONS = ['0', '1', 'd', 's']

/** A URI with its commas and "!" encoded, optionally followed by an obsolete size limit such as `!10m` (RFC 9989 §4.8). */
const REPORT_URI = /^[a-z][a-z\d+.-]*:[^\s,!]+(?:!\d+[kmgt]?)?$/i

export interface ParsedRecord {
  /** The tags with defaults applied, or `null` when the record has any error. */
  tags: DmarcTags | null
  issues: DmarcIssue[]
}

/** Checks the syntax and tag values of a DMARC record (RFC 9989 §4.7 and §4.8). */
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
      severity: 'warning',
      code: 'missing-policy',
      message: 'The record has no policy ("p" tag), so receivers treat it as "p=none".',
      recommendation: 'Write the policy explicitly, e.g. "v=DMARC1; p=none".',
    })
  }

  for (const name of values.keys()) {
    const obsoleteTagAdvice = OBSOLETE_TAGS.get(name)
    if (obsoleteTagAdvice !== undefined) {
      issues.push({
        severity: 'warning',
        code: 'obsolete-tag',
        message: `"${name}" was removed from DMARC by RFC 9989, so receivers may ignore it.`,
        recommendation: obsoleteTagAdvice,
      })
    } else if (!KNOWN_TAGS.has(name)) {
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

  const policy = readTag('p', parsePolicy, 'none, quarantine or reject') ?? 'none'
  const subdomainPolicy = readTag('sp', parsePolicy, 'none, quarantine or reject') ?? policy
  const nonExistentSubdomainPolicy = readTag('np', parsePolicy, 'none, quarantine or reject') ?? subdomainPolicy
  const testMode = readTag('t', parseTestMode, 'y or n') ?? false
  const aggregateReportUris = readTag('rua', parseReportUris, 'URIs separated by commas, e.g. mailto:dmarc@example.com') ?? []
  const failureReportUris = readTag('ruf', parseReportUris, 'URIs separated by commas, e.g. mailto:dmarc@example.com') ?? []
  const dkimAlignment = readTag('adkim', parseAlignment, 'r (relaxed) or s (strict)') ?? 'relaxed'
  const spfAlignment = readTag('aspf', parseAlignment, 'r (relaxed) or s (strict)') ?? 'relaxed'
  const failureReportingOptions = readTag('fo', parseFailureReportingOptions, '0 or 1, optionally with d and s, separated by colons') ?? ['0']
  const publicSuffixDomain = readTag('psd', parsePublicSuffixDomain, 'y, n or u') ?? 'unspecified'

  if (issues.some(issue => issue.severity === 'error')) {
    return { tags: null, issues }
  }

  return {
    tags: {
      policy,
      subdomainPolicy,
      nonExistentSubdomainPolicy,
      testMode,
      aggregateReportUris,
      failureReportUris,
      dkimAlignment,
      spfAlignment,
      failureReportingOptions,
      publicSuffixDomain,
    },
    issues,
  }
}

/** Reads the `psd` tag of a record. Errors in other tags do not matter, as receivers replace them with defaults (RFC 9989 §4.8). */
export function readPublicSuffixDomain(record: string): DmarcPublicSuffixDomain {
  const value = splitTags(record).values.get('psd')
  if (value === undefined) return 'unspecified'
  return parsePublicSuffixDomain(value) ?? 'unspecified'
}

/** Splits a record into `name=value` tags separated by semicolons, reporting malformed and repeated ones. */
function splitTags(record: string): { values: Map<string, string>; issues: DmarcIssue[] } {
  const values = new Map<string, string>()
  const issues: DmarcIssue[] = []

  for (const part of record.split(';')) {
    const tag = part.trim()
    if (tag === '') continue

    const separator = tag.indexOf('=')
    const name = separator === -1 ? '' : tag.slice(0, separator).trim().toLowerCase()
    if (!/^[a-z]+$/.test(name)) {
      issues.push({
        severity: 'error',
        code: 'invalid-syntax',
        message: `"${tag}" is not a valid tag.`,
        recommendation: 'Write each tag as name=value, with a name made of letters only, and separate tags with semicolons, e.g. "v=DMARC1; p=none".',
      })
      continue
    }

    if (values.has(name)) {
      issues.push({
        severity: 'error',
        code: 'duplicate-tag',
        message: `The "${name}" tag appears more than once, so receivers may ignore the whole record.`,
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

function parseTestMode(value: string): boolean | undefined {
  return TEST_MODES.get(value.toLowerCase())
}

function parsePublicSuffixDomain(value: string): DmarcPublicSuffixDomain | undefined {
  return PUBLIC_SUFFIX_DOMAINS.get(value.toLowerCase())
}

function parseReportUris(value: string): string[] | undefined {
  const uris = value.split(',').map(uri => uri.trim())
  if (!uris.every(uri => REPORT_URI.test(uri))) return undefined
  return uris
}

/** `0` and `1` exclude each other, and each option appears at most once (RFC 9989 §4.8). */
function parseFailureReportingOptions(value: string): string[] | undefined {
  const options = value.split(':').map(option => option.trim().toLowerCase())
  if (!options.every(option => FAILURE_REPORTING_OPTIONS.includes(option))) return undefined
  if (new Set(options).size !== options.length) return undefined
  if (options.includes('0') && options.includes('1')) return undefined
  return options
}
