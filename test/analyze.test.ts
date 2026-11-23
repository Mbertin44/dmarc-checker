import { describe, expect, it } from 'vitest'
import { analyzeDmarcRecord } from '../src/index.js'

function issueCodes(record: string) {
  return analyzeDmarcRecord(record).issues.map(issue => issue.code)
}

describe('analyzeDmarcRecord', () => {
  it('accepts a strong record and applies the RFC 9989 defaults', () => {
    expect(analyzeDmarcRecord('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')).toEqual({
      record: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
      valid: true,
      issues: [],
      tags: {
        policy: 'reject',
        subdomainPolicy: 'reject',
        nonExistentSubdomainPolicy: 'reject',
        testMode: false,
        aggregateReportUris: ['mailto:dmarc@example.com'],
        failureReportUris: [],
        dkimAlignment: 'relaxed',
        spfAlignment: 'relaxed',
        failureReportingOptions: ['0'],
        publicSuffixDomain: 'unspecified',
      },
    })
  })

  it('reads every tag, whatever the case and spacing', () => {
    const { tags } = analyzeDmarcRecord(
      'v=DMARC1;p=Reject ; sp = quarantine; np=reject; t=n; psd=n; rua=mailto:a@example.com, https://reports.example.net/dmarc; ruf=mailto:f@example.com!10m; adkim=s; aspf=R; fo=1:d;',
    )

    expect(tags).toEqual({
      policy: 'reject',
      subdomainPolicy: 'quarantine',
      nonExistentSubdomainPolicy: 'reject',
      testMode: false,
      aggregateReportUris: ['mailto:a@example.com', 'https://reports.example.net/dmarc'],
      failureReportUris: ['mailto:f@example.com!10m'],
      dkimAlignment: 'strict',
      spfAlignment: 'relaxed',
      failureReportingOptions: ['1', 'd'],
      publicSuffixDomain: 'no',
    })
  })

  it('rejects a record that does not start with v=DMARC1, in uppercase', () => {
    expect(issueCodes('p=reject; v=DMARC1; rua=mailto:dmarc@example.com')).toEqual(['invalid-version'])
    expect(issueCodes('v=dmarc1; p=reject; rua=mailto:dmarc@example.com')).toEqual(['invalid-version'])
  })

  it('treats a record without a policy as p=none', () => {
    const result = analyzeDmarcRecord('v=DMARC1; rua=mailto:dmarc@example.com')

    expect(result.valid).toBe(true)
    expect(result.tags?.policy).toBe('none')
    expect(result.issues.map(issue => issue.code)).toEqual(['missing-policy', 'policy-none'])
  })

  it('reports malformed, repeated and invalid tags', () => {
    const result = analyzeDmarcRecord('v=DMARC1; p=reject; p=none; adkim; x1=y; fo=0:1; rua=dmarc@example.com')

    expect(result.valid).toBe(false)
    expect(result.tags).toBeNull()
    expect(result.issues.map(issue => issue.code)).toEqual([
      'duplicate-tag',
      'invalid-syntax',
      'invalid-syntax',
      'invalid-value',
      'invalid-value',
    ])
    expect(result.issues[3]?.recommendation).toBe('Set "rua" to URIs separated by commas, e.g. mailto:dmarc@example.com.')
  })

  it('warns about obsolete and unknown tags without invalidating the record', () => {
    const result = analyzeDmarcRecord('v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50; rau=mailto:dmarc@example.com')

    expect(result.valid).toBe(true)
    expect(result.issues.map(issue => issue.code)).toEqual(['obsolete-tag', 'unknown-tag'])
    expect(result.issues[0]?.recommendation).toContain('"t=y"')
  })

  it('recommends enforcing a monitoring-only record and collecting reports', () => {
    expect(issueCodes('v=DMARC1; p=none')).toEqual(['policy-none', 'no-aggregate-reports'])
  })

  it('flags test mode and unprotected subdomains, before suggestions', () => {
    expect(issueCodes('v=DMARC1; p=quarantine; sp=none; t=y; rua=mailto:dmarc@example.com')).toEqual([
      'test-mode',
      'subdomain-policy-none',
      'policy-quarantine',
    ])
  })
})
