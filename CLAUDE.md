# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repo.

## Project at a glance

**wisp** is an ephemeral, TLS-tunneled reverse TCP relay. The
end-to-end story is: a public-facing **server** runs on a host you
control; a **client** behind NAT connects out to it and tells it
"please forward whatever lands on your port N back to my local
`host:port`." All transport is TLS-on-443 dressed up like an ordinary
HTTPS site (uTLS browser ClientHello, decoy nginx welcome page,
indistinguishable 404s).

The design goals — ephemeral by default (TTL-bound), zero-config,
single static binary, indistinguishable from corporate HTTPS — are
**load-bearing**. Touch them with care. Full rationale and protocol
spec live in [`docs/design.md`](docs/design.md); read its §2 (threat
model) and §3 (wire protocol) before designing anything new.

## Status

Alpha. v0.1.0 tag was cut after real public-internet e2e on
`wisp.shiyuehehu.com` (aliyun ECS). What works, what's deferred to
v0.2, and how to deploy are in [`README.md`](README.md).

## Develop / test / run

```bash
# unit tests with race detector — must stay green
go test -race -count=1 ./...

# vet + format — CI rejects unformatted files
go vet ./... && gofmt -l .

# host build
make build                 # → bin/wisp

# cross-compile a release set
make release               # → dist/wisp-{linux,darwin,windows}-{amd64,arm64}

# static linux build (for older glibc hosts; see Pitfalls)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags='-s -w -buildid= -X github.com/jasonwwl/wisp/internal/version.Tag=vX.Y.Z' \
  -o dist/wisp-linux-amd64-static ./cmd/wisp
```

Run a local dev pair (one terminal each):

```bash
# server (loopback, self-signed):
./bin/wisp serve --listen 127.0.0.1:8443 --domain localhost \
  --tls-self-signed --token devtoken --port-range auto \
  --tunnel-bind-host 127.0.0.1

# client, pointed at the endpoint the server printed at startup:
./bin/wisp expose --server localhost:8443 --endpoint <printed> \
  --token devtoken --to 127.0.0.1:22 --insecure-dev
```

## Package layout

```
cmd/wisp/                  CLI (stdlib flag, no cobra)
  main.go                  dispatch
  serve.go                 wisp serve flags + boot
  expose.go                wisp expose flags + Dial/Forward
  daemon{,_unix,_windows}.go    --detach via re-exec + setsid
  sigpipe_{unix,windows}.go     ignore SIGPIPE on Unix only
internal/
  frame/                   wisp.Frame envelope codec (random padding)
  protocol/                HELLO / HELLO_ACK / BYE binary encodings
  wsraw/                   hand-rolled RFC 6455 + uTLS-on-TLS dial
  mux/                     wsraw.Conn → net.Conn for yamux
  server/                  HTTPS server, decoy, tunnel handler,
                           port allocator, ACME (autocert), TLS resolve
  client/                  Dial + Session.Forward
  version/                 ld-flagged build version
  shape/                   placeholder; padding-only is in frame today
```

Wire stack, top → bottom inside each WS message:

```
yamux frame → wisp.Frame{Type=Yamux} → wsraw binary msg → TLS-1.3
```

Control messages (HELLO, HELLO_ACK, BYE) ride the same wsraw stream
in wisp.Frame envelopes with their own `Type`.

## Conventions

- **`gofmt`-clean, `go vet`-clean.** No linter beyond that. Public
  identifiers carry doc comments.
- **External dependencies are deliberate.** Current ones are yamux,
  uTLS, and (via uTLS) x/crypto+x/net. Anything new needs a written
  reason — the single-binary, audit-friendly story is part of the
  pitch.
- **Tests are the contract.** Every internal package has table /
  integration tests; the most important one is `internal/client`'s
  `TestForward_*` — real wisp server + real client + real TLS,
  end-to-end. If you change protocol or transport, that test must
  still pass with the race detector on.
- **Commits**: `feat(scope): subject`, `fix(scope): subject`,
  `docs(scope): subject`, etc. Bodies are wrapped at ~72 chars and
  explain *why*, not just *what*. Tags are `vX.Y.Z`.
- **CLAUDE.md / docs stay lean.** Don't bloat this file with content
  that belongs in `docs/design.md` or in commit messages; cross-link
  instead.

## Things that have bitten us

- **gopls reports `BrokenImport` / "not in workspace" warnings**
  inside this module because the parent workspace is the HMS repo.
  Ignore them — `go vet ./...` and `go test ./...` are the ground
  truth.
- **`pkill -f "<pattern>"` self-kills.** If your shell command line
  contains the literal pattern, pgrep matches the very shell running
  it and kill nukes it. Use an awk-regex trick (`[w]isp` instead of
  `wisp`) or kill by PID. We hit this multiple times during
  deployment work.
- **`CGO_ENABLED=1` (the default) links glibc**, which means the
  binary refuses to run on hosts with an older glibc than the build
  machine ("GLIBC_2.34 not found"). For release / for shipping to
  Ubuntu 18/20 servers, build with `CGO_ENABLED=0`. The static
  binaries we publish use this.
- **Aliyun ECS port mapping is two-layered.** Security group rules
  are *not* enough on their own when the public IP is fronted by a
  NAT gateway or SLB: the outer layer needs a DNAT / listener entry
  too. Symptom of missing DNAT is "nc/telnet succeeded" but tcpdump
  on the box shows 0 packets — the outer layer is spoofing SYN-ACK.
- **WebSocket-over-HTTP/2 is not implemented (RFC 8441).** Both the
  uTLS client and the http.Server force ALPN to `http/1.1` for the
  tunnel path. The decoy `/` site is also h1 by consequence; this is
  fine for low-traffic personal sites. Don't try to enable h2 on the
  same listener until RFC 8441 is wired in.
- **`net.Pipe()` is strictly synchronous.** It's used in `mux`
  in-memory tests; payloads bigger than ~4 KiB will deadlock against
  yamux flow control. Real TCP transports buffer past this — the
  client/server e2e tests pass 1 MB without issue.

## What's deferred and why

These are intentionally not in v0.1, and not all are done yet in v0.2:

- **HELLO nonce verification.** The server reads it but doesn't yet
  bind subsequent frames to it.
- **`--shape burst` / `--shape chaff`.** Padding is on by default;
  burst-smoothing and chaff frames need an interactive workload (SSH)
  to validate against.
- **Windows `--detach`.** Re-exec with `DETACHED_PROCESS` works but
  needs `golang.org/x/sys/windows`; not yet worth adding.
- **HTTP/2 RFC 8441 transport.** See pitfall above.

## Pointers

- Wire protocol + threat model — [`docs/design.md`](docs/design.md)
- User-facing quick start — [`README.md`](README.md)
- Contributor expectations — [`CONTRIBUTING.md`](CONTRIBUTING.md)
- License (MIT) — [`LICENSE`](LICENSE)
