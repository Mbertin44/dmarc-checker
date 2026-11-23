import { describe, expect, it } from 'vitest'
import { checkDmarc } from '../src/index.js'

/** A fake DNS resolver serving the given TXT records, "not found" for any other hostname, and remembering what was queried. */
function fakeDns(recordsByHostname: Record<string, string[][]>) {
  const queried: string[] = []

  async function resolveTxt(hostname: string) {
    queried.push(hostname)
    const txtRecords = recordsByHostname[hostname]
    if (txtRecords === undefined) throw Object.assign(new Error(`queryTxt ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' })
    return txtRecords
  }

  return { resolveTxt, queried }
}

describe('checkDmarc', () => {
  it('finds the DMARC record among the TXT records of _dmarc.<domain>', async () => {
    const dns = fakeDns({
      '_dmarc.example.com': [
        ['google-site-verification=abc'],
        ['v=dmarc1; p=none'], // ignored: the version is case-sensitive
        ['v=DMARC1; p=reject; ', 'rua=mailto:dmarc@example.com'], // split into chunks, like long TXT records
      ],
    })

    const result = await checkDmarc(' Example.com. ', { resolveTxt: dns.resolveTxt })

    expect(result.record).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
    expect(result.valid).toBe(true)
    expect(dns.queried).toEqual(['_dmarc.example.com'])
  })

  it('reports a missing record after looking at the parent domains', async () => {
    const dns = fakeDns({})

    const result = await checkDmarc('mail.example.com', { resolveTxt: dns.resolveTxt })

    expect(result).toMatchObject({ record: null, tags: null, valid: false, issues: [{ code: 'no-record' }] })
    expect(dns.queried).toEqual(['_dmarc.mail.example.com', '_dmarc.example.com', '_dmarc.com'])
  })

  it('reports several records, which makes receivers ignore them all', async () => {
    const dns = fakeDns({ '_dmarc.example.com': [['v=DMARC1; p=none'], ['v=DMARC1; p=reject']] })

    const result = await checkDmarc('example.com', { resolveTxt: dns.resolveTxt })

    expect(result).toMatchObject({ record: null, tags: null, valid: false, issues: [{ code: 'multiple-records' }] })
  })

  it('applies the record of the highest parent domain that has one', async () => {
    const dns = fakeDns({
      '_dmarc.mail.example.com': [['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']],
      '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
    })

    const result = await checkDmarc('a.mail.example.com', { resolveTxt: dns.resolveTxt })

    expect(result.record).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
    expect(result.issues.map(issue => issue.code)).toEqual(['inherited-record'])
  })

  it('stops at a record flagged psd=n, which marks the Organizational Domain', async () => {
    const dns = fakeDns({
      '_dmarc.mail.example.com': [['v=DMARC1; p=quarantine; psd=n; rua=mailto:dmarc@example.com']],
      '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
    })

    const result = await checkDmarc('a.mail.example.com', { resolveTxt: dns.resolveTxt })

    expect(result.record).toBe('v=DMARC1; p=quarantine; psd=n; rua=mailto:dmarc@example.com')
  })

  it('stops at a public suffix domain flagged psd=y and applies the record just below it, or its own', async () => {
    const dns = fakeDns({
      '_dmarc.giant.bank.example': [['v=DMARC1; p=reject; rua=mailto:dmarc@giant.bank.example']],
      '_dmarc.bank.example': [['v=DMARC1; p=quarantine; psd=y']],
    })

    const giant = await checkDmarc('mail.giant.bank.example', { resolveTxt: dns.resolveTxt })
    const tiny = await checkDmarc('mail.tiny.bank.example', { resolveTxt: dns.resolveTxt })

    expect(giant.record).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@giant.bank.example')
    expect(tiny.record).toBe('v=DMARC1; p=quarantine; psd=y')
  })

  it('makes at most 8 queries for a deep domain, as in RFC 9989 §4.10', async () => {
    const dns = fakeDns({})

    await checkDmarc('a.b.c.d.e.f.g.h.i.j.mail.example.com', { resolveTxt: dns.resolveTxt })

    expect(dns.queried).toEqual([
      '_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com',
      '_dmarc.g.h.i.j.mail.example.com',
      '_dmarc.h.i.j.mail.example.com',
      '_dmarc.i.j.mail.example.com',
      '_dmarc.j.mail.example.com',
      '_dmarc.mail.example.com',
      '_dmarc.example.com',
      '_dmarc.com',
    ])
  })

  it('rejects when a DNS query fails, rather than reporting a missing record', async () => {
    async function resolveTxt(): Promise<string[][]> {
      throw Object.assign(new Error('queryTxt ETIMEOUT _dmarc.example.com'), { code: 'ETIMEOUT' })
    }

    await expect(checkDmarc('example.com', { resolveTxt })).rejects.toThrow('ETIMEOUT')
  })
})
