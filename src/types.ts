/** What receivers should do with mail that fails DMARC (`p`, `sp` and `np` tags). */
export type DmarcPolicy = 'none' | 'quarantine' | 'reject'

/** How closely the visible From domain must match the SPF or DKIM domain (`aspf` and `adkim` tags). */
export type DmarcAlignment = 'relaxed' | 'strict'

/**
 * Whether the record is published by a public suffix domain such as a TLD (`psd` tag).
 * `'no'` also marks the domain as the Organizational Domain of its subdomains.
 */
export type DmarcPublicSuffixDomain = 'yes' | 'no' | 'unspecified'

/** The tags of a valid DMARC record, with the RFC 9989 defaults applied to the absent ones. */
export interface DmarcTags {
  /** `p`: policy for the domain itself. Defaults to `'none'`. */
  policy: DmarcPolicy
  /** `sp`: policy for existing subdomains. Defaults to `policy`. */
  subdomainPolicy: DmarcPolicy
  /** `np`: policy for subdomains that do not exist. Defaults to `subdomainPolicy`. */
  nonExistentSubdomainPolicy: DmarcPolicy
  /** `t`: when `true`, receivers apply the policy one level below the one requested. Defaults to `false`. */
  testMode: boolean
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
  /** `psd`: whether the record is published by a public suffix domain. Defaults to `'unspecified'`. */
  publicSuffixDomain: DmarcPublicSuffixDomain
}

/**
 * - `error`: the record is missing or breaks the DMARC syntax, so receivers may ignore all or part of it.
 * - `warning`: the record works but leaves a gap in protection or visibility.
 * - `info`: something worth knowing, or a possible improvement.
 */
export type DmarcSeverity = 'error' | 'warning' | 'info'

export type DmarcIssueCode =
  | 'no-record'
  | 'multiple-records'
  | 'invalid-syntax'
  | 'duplicate-tag'
  | 'invalid-version'
  | 'invalid-value'
  | 'missing-policy'
  | 'unknown-tag'
  | 'obsolete-tag'
  | 'policy-none'
  | 'test-mode'
  | 'subdomain-policy-none'
  | 'no-aggregate-reports'
  | 'policy-quarantine'
  | 'inherited-record'

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
  /** The parsed tags, or `null` when the record is missing or has errors. */
  tags: DmarcTags | null
  /** `true` when the record exists and has no errors. */
  valid: boolean
  /** Errors first, then warnings, then information. */
  issues: DmarcIssue[]
}
