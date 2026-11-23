# dmarc-checker

[![npm version](https://img.shields.io/npm/v/dmarc-checker)](https://www.npmjs.com/package/dmarc-checker)
[![CI](https://github.com/Mbertin44/dmarc-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Mbertin44/dmarc-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Look up, validate and explain a domain's DMARC record, following [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), with recommendations in plain language.

- Finds the record that applies to a domain, including one inherited from a parent domain.
- Checks every tag against RFC 9989, the DMARC standard that replaced RFC 7489 in 2026.
- Says what is wrong and what to do next, in words a non-expert understands.
- Returns typed results with stable issue codes.
- Has no dependencies.

## Install

```sh
npm install dmarc-checker
```

Requires Node.js 22 or later. The package is ESM-only.

## Usage

```ts
import { checkDmarc } from 'dmarc-checker'

const result = await checkDmarc('example.com')

if (result.tags) {
  console.log(`Policy: ${result.tags.policy}`)
}

for (const issue of result.issues) {
  console.log(`[${issue.severity}] ${issue.message}\n  → ${issue.recommendation}`)
}
```

For a domain publishing `v=DMARC1; p=none`, this prints:

```
Policy: none
[warning] The policy is "none": mail that fails DMARC is delivered as usual, so anyone can still send email pretending to be your domain.
  → Once your reports show that all your legitimate senders pass DMARC, move to p=quarantine.
[warning] No address receives aggregate reports (rua), so you cannot see who sends email using your domain.
  → Add an address you read, e.g. rua=mailto:dmarc@example.com, to get a daily summary from each mailbox provider.
```

To check a record before publishing it, analyze the text directly, without any DNS query:

```ts
import { analyzeDmarcRecord } from 'dmarc-checker'

analyzeDmarcRecord('v=DMARC1; p=rejet').issues
// [{
//   severity: 'error',
//   code: 'invalid-value',
//   message: '"p=rejet" is not a valid value.',
//   recommendation: 'Set "p" to none, quarantine or reject.'
// }]
```

## API

### `checkDmarc(domain, options?)`

Looks up the TXT records at `_dmarc.<domain>` and keeps the one starting with `v=DMARC1`. When the domain has none, walks up its parent domains as receivers do ([RFC 9989 §4.10](https://www.rfc-editor.org/rfc/rfc9989#section-4.10)) and uses the record of its Organizational Domain. Returns a `Promise<DmarcResult>`.

A missing record is not an exception: it is reported as a `no-record` issue. The promise only rejects when a DNS query itself fails (timeout, unreachable server…).

| Option       | Type                                        | Description                                                             |
| ------------ | ------------------------------------------- | ----------------------------------------------------------------------- |
| `resolveTxt` | `(hostname: string) => Promise<string[][]>` | Returns the TXT records of a hostname. Defaults to the system resolver. |

For example, to query a specific DNS server:

```ts
import { Resolver } from 'node:dns/promises'

const resolver = new Resolver()
resolver.setServers(['1.1.1.1'])

await checkDmarc('example.com', { resolveTxt: hostname => resolver.resolveTxt(hostname) })
```

### `analyzeDmarcRecord(record)`

Validates a DMARC record given as text. Returns a `DmarcResult`.

### `DmarcResult`

| Field    | Type                | Description                                                                              |
| -------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `record` | `string \| null`    | The raw record, or `null` when none was found.                                           |
| `tags`   | `DmarcTags \| null` | The parsed tags, or `null` when the record is missing or has errors.                     |
| `valid`  | `boolean`           | `true` when the record exists and has no errors.                                         |
| `issues` | `DmarcIssue[]`      | Each issue has a `severity`, a `code`, a `message` and a `recommendation`, errors first. |

### `DmarcTags`

Absent tags are filled in with their RFC 9989 default.

| Field                        | Tag     | Default                   |
| ---------------------------- | ------- | ------------------------- |
| `policy`                     | `p`     | `'none'`                  |
| `subdomainPolicy`            | `sp`    | same as `policy`          |
| `nonExistentSubdomainPolicy` | `np`    | same as `subdomainPolicy` |
| `testMode`                   | `t`     | `false`                   |
| `aggregateReportUris`        | `rua`   | `[]`                      |
| `failureReportUris`          | `ruf`   | `[]`                      |
| `dkimAlignment`              | `adkim` | `'relaxed'`               |
| `spfAlignment`               | `aspf`  | `'relaxed'`               |
| `failureReportingOptions`    | `fo`    | `['0']`                   |
| `publicSuffixDomain`         | `psd`   | `'unspecified'`           |

### Issue codes

| Code                    | Severity | Meaning                                                   |
| ----------------------- | -------- | --------------------------------------------------------- |
| `no-record`             | error    | No DMARC record for the domain or its parent domains.     |
| `multiple-records`      | error    | More than one DMARC record, so receivers ignore them all. |
| `invalid-syntax`        | error    | Part of the record is not written as `name=value`.        |
| `duplicate-tag`         | error    | A tag appears more than once.                             |
| `invalid-version`       | error    | The record does not start with `v=DMARC1`.                |
| `invalid-value`         | error    | A tag has a value RFC 9989 does not allow.                |
| `missing-policy`        | warning  | No `p` tag, so receivers treat the record as `p=none`.    |
| `unknown-tag`           | warning  | A tag RFC 9989 does not define, often a typo.             |
| `obsolete-tag`          | warning  | `pct`, `rf` or `ri`, which RFC 9989 removed.              |
| `policy-none`           | warning  | `p=none` monitors mail but does not protect the domain.   |
| `test-mode`             | warning  | `t=y` makes receivers apply a policy one level below.     |
| `subdomain-policy-none` | warning  | `sp=none` leaves subdomains unprotected.                  |
| `no-aggregate-reports`  | warning  | No `rua` address, so no visibility on who sends mail.     |
| `policy-quarantine`     | info     | `p=quarantine` might be tightened to `p=reject`.          |
| `inherited-record`      | info     | The domain has no record of its own and uses a parent's.  |

## Limitations

- For a domain that inherits its parent's record, receivers apply `sp` if the domain exists and `np` if it does not. This package does not check whether the domain exists.
- Report addresses on another domain are not checked for the authorization record that domain must publish ([RFC 9990 §4](https://www.rfc-editor.org/rfc/rfc9990#section-4)).

## License

[MIT](LICENSE) © Morgan Bertin
