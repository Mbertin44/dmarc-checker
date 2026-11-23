import { resolveTxt } from 'node:dns/promises'
import { analyzeDmarcRecord } from './analyze.js'
import type { DmarcIssue, DmarcResult } from './types.js'

type ResolveTxt = (hostname: string) => Promise<string[][]>

export interface CheckDmarcOptions {
  /** Returns the TXT records of a hostname. Defaults to the system resolver; pass your own to query a specific DNS server. */
  resolveTxt?: ResolveTxt
}

/** Receivers only consider TXT records that start with the DMARC version tag (RFC 7489 §6.6.3). */
const DMARC_RECORD = /^v\s*=\s*DMARC1\s*(?:;|$)/i

/** DNS error codes meaning that the name has no TXT record, as opposed to a failed query. */
const NOT_FOUND_CODES = ['ENOTFOUND', 'ENODATA']

/**
 * Looks up the DMARC record published at `_dmarc.<domain>`, validates it and explains how to improve it.
 * Rejects when the DNS query itself fails (timeout, unreachable server…).
 */
export async function checkDmarc(domain: string, options: CheckDmarcOptions = {}): Promise<DmarcResult> {
  const domainName = domain.trim().toLowerCase().replace(/\.$/, '')
  const hostname = `_dmarc.${domainName}`
  const txtRecords = await lookupTxt(hostname, options.resolveTxt ?? resolveTxt)
  const records = txtRecords.filter(txtRecord => DMARC_RECORD.test(txtRecord))
  const [record] = records

  if (record === undefined) {
    return failedLookup({
      severity: 'error',
      code: 'no-record',
      message: `No DMARC record found at ${hostname}, so your domain has no DMARC protection.`,
      recommendation: `Publish a TXT record at ${hostname} such as "v=DMARC1; p=none; rua=mailto:dmarc@${domainName}" to start seeing who sends email using your domain.`,
    })
  }

  if (records.length > 1) {
    return failedLookup({
      severity: 'error',
      code: 'multiple-records',
      message: `Found ${records.length} DMARC records at ${hostname}: receivers ignore DMARC when there is more than one.`,
      recommendation: 'Merge them into a single TXT record.',
    })
  }

  return analyzeDmarcRecord(record)
}

/** Returns the TXT records of a hostname, each one joined back from its 255-character chunks. */
async function lookupTxt(hostname: string, resolve: ResolveTxt): Promise<string[]> {
  try {
    const txtRecords = await resolve(hostname)
    return txtRecords.map(chunks => chunks.join(''))
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
