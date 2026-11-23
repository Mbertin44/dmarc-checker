import { resolveTxt } from 'node:dns/promises'
import { analyzeDmarcRecord } from './analyze.js'
import { readPublicSuffixDomain } from './parse.js'
import type { DmarcIssue, DmarcResult } from './types.js'

type ResolveTxt = (hostname: string) => Promise<string[][]>

export interface CheckDmarcOptions {
  /** Returns the TXT records of a hostname. Defaults to the system resolver; pass your own to query a specific DNS server. */
  resolveTxt?: ResolveTxt
}

interface FoundRecord {
  domain: string
  record: string
}

/** Receivers discard TXT records that do not start with the version tag, whose value is case-sensitive (RFC 9989 §4.7). */
const DMARC_RECORD = /^[Vv]\s*=\s*DMARC1\s*(?:;|$)/

/** A DNS tree walk makes at most 8 queries, so the walk up the parent domains starts from at most 7 labels (RFC 9989 §4.10). */
const MAX_PARENT_LABELS = 7

/** DNS error codes meaning that the name has no TXT record, as opposed to a failed query. */
const NOT_FOUND_CODES = ['ENOTFOUND', 'ENODATA']

/**
 * Finds the DMARC record that applies to a domain, validates it and explains how to improve it.
 * The record is looked up at `_dmarc.<domain>`, then on the parent domains (RFC 9989 §4.10.1).
 * Rejects when a DNS query itself fails (timeout, unreachable server…).
 */
export async function checkDmarc(domain: string, options: CheckDmarcOptions = {}): Promise<DmarcResult> {
  const resolve = options.resolveTxt ?? resolveTxt
  const domainName = domain.trim().toLowerCase().replace(/\.$/, '')
  const records = await lookupDmarcRecords(domainName, resolve)
  const [record] = records

  if (records.length > 1) {
    return failedLookup({
      severity: 'error',
      code: 'multiple-records',
      message: `Found ${records.length} DMARC records at _dmarc.${domainName}: receivers ignore them all.`,
      recommendation: 'Merge them into a single TXT record.',
    })
  }

  if (record !== undefined) {
    return analyzeDmarcRecord(record)
  }

  const inherited = await findInheritedRecord(domainName, resolve)
  if (inherited === undefined) {
    return failedLookup({
      severity: 'error',
      code: 'no-record',
      message: `No DMARC record found for ${domainName} or its parent domains, so it has no DMARC protection.`,
      recommendation: `Publish a TXT record at _dmarc.${domainName} such as "v=DMARC1; p=none; rua=mailto:dmarc@${domainName}" to start seeing who sends email using your domain.`,
    })
  }

  const result = analyzeDmarcRecord(inherited.record)
  const inheritedRecordIssue: DmarcIssue = {
    severity: 'info',
    code: 'inherited-record',
    message: `${domainName} has no DMARC record of its own, so receivers apply the subdomain policy of the record published by ${inherited.domain}.`,
    recommendation: `Publish a record at _dmarc.${domainName} only if this domain needs different settings.`,
  }
  return { ...result, issues: [...result.issues, inheritedRecordIssue] }
}

/**
 * Walks up the parent domains to find the record of the Organizational Domain, or failing that,
 * of the public suffix domain (RFC 9989 §4.10 and §4.10.1). The walk stops at a record with `psd=n` or `psd=y`.
 */
async function findInheritedRecord(domain: string, resolve: ResolveTxt): Promise<FoundRecord | undefined> {
  const found: FoundRecord[] = []

  for (const parent of parentDomains(domain)) {
    const records = await lookupDmarcRecords(parent, resolve)
    const [record] = records
    if (record === undefined || records.length > 1) continue

    const publicSuffixDomain = readPublicSuffixDomain(record)
    if (publicSuffixDomain === 'no') {
      return { domain: parent, record }
    }
    if (publicSuffixDomain === 'yes') {
      // The Organizational Domain is the one just below the public suffix domain: its record wins if it has one.
      const organizationalDomain = domainBelow(parent, domain)
      return found.find(foundRecord => foundRecord.domain === organizationalDomain) ?? { domain: parent, record }
    }

    found.push({ domain: parent, record })
  }

  return found.at(-1)
}

/** The parent domains of a domain, longest first, starting from at most `MAX_PARENT_LABELS` labels. */
function parentDomains(domain: string): string[] {
  const labels = domain.split('.')
  const parents: string[] = []
  for (let count = Math.min(labels.length - 1, MAX_PARENT_LABELS); count > 0; count--) {
    parents.push(labels.slice(-count).join('.'))
  }
  return parents
}

/** The domain one label below `parent` on the way down to `domain`, e.g. `example.com` for `com` and `mail.example.com`. */
function domainBelow(parent: string, domain: string): string {
  const labelCount = parent.split('.').length + 1
  return domain.split('.').slice(-labelCount).join('.')
}

/** Returns the DMARC records published at `_dmarc.<domain>`, each one joined back from its 255-character chunks. */
async function lookupDmarcRecords(domain: string, resolve: ResolveTxt): Promise<string[]> {
  try {
    const txtRecords = await resolve(`_dmarc.${domain}`)
    return txtRecords.map(chunks => chunks.join('')).filter(txtRecord => DMARC_RECORD.test(txtRecord))
  } catch (error) {
    if (isNotFound(error)) return []
    throw error
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && typeof error.code === 'string' && NOT_FOUND_CODES.includes(error.code)
}

function failedLookup(issue: DmarcIssue): DmarcResult {
  return { record: null, tags: null, valid: false, issues: [issue] }
}
