import { describe, expect, it } from 'vitest'
import { analyzeDmarcRecord } from '../src/index.js'

function issueCodes(record: string) {
  return analyzeDmarcRecord(record).issues.map(issue => issue.code)
}

describe('analyzeDmarcRecord', () => {
  it('accepts a strong record and applies the RFC 7489 defaults', () => {
    expect(analyzeDmarcRecord('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')).toEqual({
      record: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
      valid: true,
      issues: [],
      tags: {
        policy: 'reject',
        subdomainPolicy: 'reject',
        percentage: 100,
        aggregateReportUris: ['mailto:dmarc@example.com'],
        failureReportUris: [],
        dkimAlignment: 'relaxed',
        spfAlignment: 'relaxed',
        failureReportingOptions: ['0'],
        reportFormats: ['afrf'],
        reportInterval: 86_400,
      },
    })
  })

  it('reads every tag, whatever the case and spacing', () => {
    const { tags } = analyzeDmarcRecord(
      'v=DMARC1;p=Reject ; sp = quarantine; pct=100; rua=mailto:a@example.com, mailto:b@example.net!10m; ruf=mailto:f@example.com; adkim=s; aspf=R; fo=1:d; rf=afrf; ri=3600;',
    )

    expect(tags).toEqual({
      policy: 'reject',
      subdomainPolicy: 'quarantine',
      percentage: 100,
      aggregateReportUris: ['mailto:a@example.com', 'mailto:b@example.net!10m'],
      failureReportUris: ['mailto:f@example.com'],
      dkimAlignment: 'strict',
      spfAlignment: 'relaxed',
      failureReportingOptions: ['1', 'd'],
      reportFormats: ['afrf'],
      reportInterval: 3600,
    })
  })

  it('rejects a record that does not start with v=DMARC1', () => {
    expect(issueCodes('p=reject; v=DMARC1; rua=mailto:dmarc@example.com')).toEqual(['invalid-version'])
  })

  it('rejects a record without a policy', () => {
    expect(issueCodes('v=DMARC1; rua=mailto:dmarc@example.com')).toEqual(['missing-policy'])
  })

  it('reports malformed, repeated and invalid tags', () => {
    const result = analyzeDmarcRecord('v=DMARC1; p=reject; p=none; adkim; pct=150; rua=dmarc@example.com')

    expect(result.valid).toBe(false)
    expect(result.tags).toBeNull()
    expect(result.issues.map(issue => issue.code)).toEqual(['duplicate-tag', 'invalid-syntax', 'invalid-value', 'invalid-value'])
    expect(result.issues[3]?.recommendation).toBe('Set "rua" to mailto: addresses separated by commas, e.g. mailto:dmarc@example.com.')
  })

  it('warns about unknown tags without invalidating the record', () => {
    const result = analyzeDmarcRecord('v=DMARC1; p=reject; rua=mailto:dmarc@example.com; rau=mailto:dmarc@example.com')

    expect(result.valid).toBe(true)
    expect(result.issues.map(issue => issue.code)).toEqual(['unknown-tag'])
  })

  it('recommends enforcing a monitoring-only record and collecting reports', () => {
    expect(issueCodes('v=DMARC1; p=none')).toEqual(['policy-none', 'no-aggregate-reports'])
  })

  it('flags a partial rollout and unprotected subdomains, before suggestions', () => {
    expect(issueCodes('v=DMARC1; p=quarantine; sp=none; pct=25; rua=mailto:dmarc@example.com')).toEqual([
      'partial-percentage',
      'subdomain-policy-none',
      'policy-quarantine',
    ])
  })
})
