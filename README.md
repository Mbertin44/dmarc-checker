# dmarc-inspector

[![npm version](https://img.shields.io/npm/v/dmarc-inspector)](https://www.npmjs.com/package/dmarc-inspector)
[![CI](https://github.com/Mbertin44/dmarc-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/Mbertin44/dmarc-inspector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Look up, validate and explain a domain's DMARC record ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)), with recommendations in plain language.

- Fetches the record from DNS and checks every tag against RFC 7489.
- Says what is wrong and what to do next, in words a non-expert understands.
- Returns typed results with stable issue codes.
- Has no dependencies.

## Install

```sh
npm install dmarc-inspector
```

Requires Node.js 22 or later. The package is ESM-only.

## Usage

```ts
import { checkDmarc } from "dmarc-inspector";

const result = await checkDmarc("example.com");

if (result.tags) {
  console.log(`Policy: ${result.tags.policy}`);
}

for (const issue of result.issues) {
  console.log(
    `[${issue.severity}] ${issue.message}\n  → ${issue.recommendation}`,
  );
}
```

For a domain publishing `v=DMARC1; p=none`, this prints:

```
Policy: none
[warning] The policy is "none": mail that fails DMARC is delivered as usual, so anyone can still send email pretending to be your domain.
  → Once your reports show that all your legitimate senders pass DMARC, move to p=quarantine, then p=reject.
[warning] No address receives aggregate reports (rua), so you cannot see who sends email using your domain.
  → Add an address you read, e.g. rua=mailto:dmarc@example.com, to get a daily summary from each mailbox provider.
```

To check a record before publishing it, analyze the text directly, without any DNS query:

```ts
import { analyzeDmarcRecord } from "dmarc-inspector";

analyzeDmarcRecord("v=DMARC1; p=reject; pct=150").issues;
// [{
//   severity: 'error',
//   code: 'invalid-value',
//   message: '"pct=150" is not a valid value.',
//   recommendation: 'Set "pct" to a whole number from 0 to 100.'
// }]
```

## API

### `checkDmarc(domain, options?)`

Looks up the TXT records at `_dmarc.<domain>`, keeps the one starting with `v=DMARC1` and analyzes it. Returns a `Promise<DmarcResult>`.

A missing record is not an exception: it is reported as a `no-record` issue. The promise only rejects when the DNS query itself fails (timeout, unreachable server…).

| Option       | Type                                        | Description                                                             |
| ------------ | ------------------------------------------- | ----------------------------------------------------------------------- |
| `resolveTxt` | `(hostname: string) => Promise<string[][]>` | Returns the TXT records of a hostname. Defaults to the system resolver. |

For example, to query a specific DNS server:

```ts
import { Resolver } from "node:dns/promises";

const resolver = new Resolver();
resolver.setServers(["1.1.1.1"]);

await checkDmarc("example.com", {
  resolveTxt: (hostname) => resolver.resolveTxt(hostname),
});
```

### `analyzeDmarcRecord(record)`

Validates a DMARC record given as text. Returns a `DmarcResult`.

### `DmarcResult`

| Field    | Type                | Description                                                                              |
| -------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `record` | `string \| null`    | The raw record, or `null` when none was found.                                           |
| `tags`   | `DmarcTags \| null` | The parsed tags, or `null` when the record is missing or invalid.                        |
| `valid`  | `boolean`           | `true` when the record exists and has no errors.                                         |
| `issues` | `DmarcIssue[]`      | Each issue has a `severity`, a `code`, a `message` and a `recommendation`, errors first. |

### `DmarcTags`

Optional tags are filled in with their RFC 7489 default.

| Field                     | Tag     | Default          |
| ------------------------- | ------- | ---------------- |
| `policy`                  | `p`     | (required)       |
| `subdomainPolicy`         | `sp`    | same as `policy` |
| `percentage`              | `pct`   | `100`            |
| `aggregateReportUris`     | `rua`   | `[]`             |
| `failureReportUris`       | `ruf`   | `[]`             |
| `dkimAlignment`           | `adkim` | `'relaxed'`      |
| `spfAlignment`            | `aspf`  | `'relaxed'`      |
| `failureReportingOptions` | `fo`    | `['0']`          |
| `reportFormats`           | `rf`    | `['afrf']`       |
| `reportInterval`          | `ri`    | `86400` seconds  |

### Issue codes

| Code                    | Severity | Meaning                                                    |
| ----------------------- | -------- | ---------------------------------------------------------- |
| `no-record`             | error    | No DMARC record at `_dmarc.<domain>`.                      |
| `multiple-records`      | error    | More than one DMARC record, so receivers ignore them all.  |
| `invalid-syntax`        | error    | Part of the record is not written as `name=value`.         |
| `duplicate-tag`         | error    | A tag appears more than once.                              |
| `invalid-version`       | error    | The record does not start with `v=DMARC1`.                 |
| `missing-policy`        | error    | The record has no `p` tag.                                 |
| `invalid-value`         | error    | A tag has a value RFC 7489 does not allow.                 |
| `unknown-tag`           | warning  | A tag RFC 7489 does not define, often a typo.              |
| `policy-none`           | warning  | `p=none` monitors mail but does not protect the domain.    |
| `partial-percentage`    | warning  | `pct` below 100 leaves part of the failing mail untouched. |
| `subdomain-policy-none` | warning  | `sp=none` leaves subdomains unprotected.                   |
| `no-aggregate-reports`  | warning  | No `rua` address, so no visibility on who sends mail.      |
| `policy-quarantine`     | info     | `p=quarantine` could be tightened to `p=reject`.           |

## Limitations

- Only `_dmarc.<domain>` is queried. Receivers fall back to the organizational domain's record for subdomains without one (RFC 7489 §6.6.3), which this package does not do.
- Report addresses on another domain are not checked for the authorization record that domain must publish (RFC 7489 §7.1).

## License

[MIT](LICENSE) © Morgan Bertin
