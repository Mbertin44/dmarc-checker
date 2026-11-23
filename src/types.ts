/** What receivers should do with mail that fails DMARC (`p` and `sp` tags). */
export type DmarcPolicy = 'none' | 'quarantine' | 'reject'

/** How closely the visible From domain must match the SPF or DKIM domain (`aspf` and `adkim` tags). */
export type DmarcAlignment = 'relaxed' | 'strict'

/** The tags of a valid DMARC record, with the RFC 7489 defaults applied to the optional ones. */
export interface DmarcTags {
  /** `p`: policy for the domain itself. */
  policy: DmarcPolicy
  /** `sp`: policy for subdomains. Defaults to `policy`. */
  subdomainPolicy: DmarcPolicy
  /** `pct`: percentage of failing mail the policy applies to. Defaults to `100`. */
  percentage: number
  /** `rua`: where aggregate reports are sent. */
  aggregateReportUris: string[]
  /** `ruf`: where failure reports are sent. */
  failureReportUris: string[]
  /** `adkim`: DKIM alignment mode. Defaults to `'relaxed'`. */
  dkimAlignment: DmarcAlignment
  /** `aspf`: SPF alignment mode. Defaults to `'relaxed'`. */
  spfAlignment: DmarcAlignment
  /** `fo`: when failure reports are generated. Defaults to `['0']`. */
  failureReportingOptions: string[]
  /** `rf`: failure report formats. Defaults to `['afrf']`. */
  reportFormats: string[]
  /** `ri`: requested interval between aggregate reports, in seconds. Defaults to `86400`. */
  reportInterval: number
}

/**
 * - `error`: the record is missing or breaks RFC 7489, so receivers may ignore it.
 * - `warning`: the record works but leaves a gap in protection or visibility.
 * - `info`: a possible improvement.
 */
export type DmarcSeverity = 'error' | 'warning' | 'info'

export type DmarcIssueCode =
  | 'no-record'
  | 'multiple-records'
  | 'invalid-syntax'
  | 'duplicate-tag'
  | 'invalid-version'
  | 'missing-policy'
  | 'invalid-value'
  | 'unknown-tag'
  | 'policy-none'
  | 'policy-quarantine'
  | 'partial-percentage'
  | 'subdomain-policy-none'
  | 'no-aggregate-reports'

export interface DmarcIssue {
  severity: DmarcSeverity
  /** Stable identifier, safe to rely on in code. */
  code: DmarcIssueCode
  /** What is wrong, in plain language. */
  message: string
  /** What to do about it, in plain language. */
  recommendation: string
}

export interface DmarcResult {
  /** The raw DMARC record, or `null` when none was found. */
  record: string | null
  /** The parsed tags, or `null` when the record is missing or invalid. */
  tags: DmarcTags | null
  /** `true` when the record exists and has no errors. */
  valid: boolean
  /** Errors first, then warnings, then suggestions. */
  issues: DmarcIssue[]
}
