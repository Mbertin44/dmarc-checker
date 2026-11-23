import { describe, expect, it } from 'vitest'
import { checkDmarc } from '../src/index.js'

/** A fake DNS resolver serving the given TXT records, and "not found" for any other hostname. */
function fakeResolver(recordsByHostname: Record<string, string[][]>) {
  return async (hostname: string) => {
    const txtRecords = recordsByHostname[hostname]
    if (txtRecords === undefined) throw Object.assign(new Error(`queryTxt ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' })
    return txtRecords
  }
}

describe('checkDmarc', () => {
  it('finds the DMARC record among the TXT records of _dmarc.<domain>', async () => {
    const resolveTxt = fakeResolver({
      '_dmarc.example.com': [['google-site-verification=abc'], ['v=DMARC1; p=reject; ', 'rua=mailto:dmarc@example.com']],
    })

    const result = await checkDmarc(' Example.com. ', { resolveTxt })

    expect(result.record).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
    expect(result.valid).toBe(true)
  })

  it('reports a missing record', async () => {
    const result = await checkDmarc('example.com', { resolveTxt: fakeResolver({}) })

    expect(result).toMatchObject({ record: null, tags: null, valid: false, issues: [{ code: 'no-record' }] })
  })

  it('reports several records, which makes receivers ignore DMARC', async () => {
    const resolveTxt = fakeResolver({ '_dmarc.example.com': [['v=DMARC1; p=none'], ['v=DMARC1; p=reject']] })

    const result = await checkDmarc('example.com', { resolveTxt })

    expect(result).toMatchObject({ record: null, tags: null, valid: false, issues: [{ code: 'multiple-records' }] })
  })

  it('rejects when the DNS query fails, rather than reporting a missing record', async () => {
    const resolveTxt = async () => {
      throw Object.assign(new Error('queryTxt ETIMEOUT _dmarc.example.com'), { code: 'ETIMEOUT' })
    }

    await expect(checkDmarc('example.com', { resolveTxt })).rejects.toThrow('ETIMEOUT')
  })
})
