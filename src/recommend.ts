import type { DmarcIssue, DmarcTags } from './types.js'

/** Explains, in plain language, what a valid record still leaves unprotected or unseen. */
export function recommend(tags: DmarcTags): DmarcIssue[] {
  const issues: DmarcIssue[] = []

  if (tags.policy === 'none') {
    issues.push({
      severity: 'warning',
      code: 'policy-none',
      message: 'The policy is "none": mail that fails DMARC is delivered as usual, so anyone can still send email pretending to be your domain.',
      recommendation: 'Once your reports show that all your legitimate senders pass DMARC, move to p=quarantine, then p=reject.',
    })
  }

  if (tags.policy === 'quarantine') {
    issues.push({
      severity: 'info',
      code: 'policy-quarantine',
      message: 'The policy is "quarantine": mail that fails DMARC goes to spam instead of being blocked.',
      recommendation: 'When you are confident that no legitimate mail fails DMARC, move to p=reject for full protection.',
    })
  }

  if (tags.policy !== 'none' && tags.percentage < 100) {
    issues.push({
      severity: 'warning',
      code: 'partial-percentage',
      message: `The policy only applies to ${tags.percentage}% of the mail that fails DMARC.`,
      recommendation: 'Raise pct step by step up to 100, or remove the tag: 100 is the default.',
    })
  }

  if (tags.policy !== 'none' && tags.subdomainPolicy === 'none') {
    issues.push({
      severity: 'warning',
      code: 'subdomain-policy-none',
      message: 'Subdomains are not protected (sp=none): anyone can send email pretending to be one of them.',
      recommendation: 'Remove the sp tag so subdomains follow the main policy, or set it to quarantine or reject.',
    })
  }

  if (tags.aggregateReportUris.length === 0) {
    issues.push({
      severity: 'warning',
      code: 'no-aggregate-reports',
      message: 'No address receives aggregate reports (rua), so you cannot see who sends email using your domain.',
      recommendation: 'Add an address you read, e.g. rua=mailto:dmarc@example.com, to get a daily summary from each mailbox provider.',
    })
  }

  return issues
}
