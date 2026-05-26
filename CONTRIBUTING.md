# Contributing to wisp

Thanks for the interest. A few things to know up front.

## Before you start

Read [`docs/design.md`](docs/design.md). It explains why things are
shaped the way they are. If you find yourself disagreeing with the
design — especially the threat model in §2 — open a discussion before
writing a PR. Most disagreements turn out to be about scope, not code.

## Style

- `gofmt`-clean. CI rejects unformatted files.
- `go vet`-clean. No exceptions.
- Public identifiers carry a doc comment.
- No external dependencies without prior discussion. The goal of a
  small, audit-friendly binary is more important than convenience.

## Tests

Everything below the CLI layer should have unit tests. `make test`
runs the suite with the race detector. Network-heavy integration
tests, when we have them, will live under `test/integration/` behind
a build tag.

## Out of scope (PRs will be politely declined)

These have been considered and explicitly deferred:

- A long-lived, multi-tenant, configured deployment mode. Use frp.
- Domain fronting (see design.md §15).
- Built-in obfuscation that goes beyond "plausible HTTPS." For
  nation-state-grade evasion, use xray or sing-box.
- Configuration files. Flags and environment variables only.

If you want one of these anyway, open a discussion first.

## Security

Email <wenleigood@gmail.com> rather than opening a public issue.
