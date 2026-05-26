# wisp — Design Notes

> Status: working draft. Subject to change until `v0.1.0`.

This document explains how wisp works on the wire and inside each
binary. It is written for contributors and security reviewers, not end
users; for the latter see [`README.md`](../README.md).

---

## 1. Goals

In rough order of priority:

1. **Ephemeral.** Every tunnel has a TTL. The default is one hour, the
   maximum is configurable. The server is authoritative; the client
   cannot extend its own lifetime past what the server allows.
2. **Zero-config.** All knobs are flags or environment variables. There
   is no on-disk config file the user is expected to write.
3. **Indistinguishable from an ordinary HTTPS service** to network
   middleboxes performing passive observation and standard active
   probes. (See §2 for what this does and does not mean.)
4. **Single static binary.** No dependencies on system libraries, no
   sidecars (`stunnel`, `nginx`, `cloudflared`). Cross-compiles for
   linux/amd64, linux/arm64, darwin, and windows.
5. **Survives a hostile TTY.** The client daemonizes itself so that
   closing the parent shell, web terminal, or PTY does not bring the
   tunnel down before its TTL.
6. **Recoverable.** A short resume window lets the client re-attach to
   the same public port after a transient network drop.

## 2. Threat model

wisp is built for one specific kind of environment: a host sitting
behind a corporate or institutional network where outbound HTTPS to
arbitrary destinations is permitted, but inbound connectivity is not
available and TCP tunneling is discouraged by policy. Typical examples:

- A workstation behind a corporate NAT and a next-generation firewall
  (NGFW) that does TLS-handshake inspection and JA3/JA4 fingerprinting.
- A jump host reached through a vendor-supplied web terminal whose
  outbound traffic is reverse-proxied through an application-layer
  gateway.
- A home or small-office router with carrier-grade NAT (CGNAT).

### 2.1 What "indistinguishable from HTTPS" means here

We assume an adversary who is doing **passive observation** of TLS
metadata (SNI, ALPN, JA3/JA4) and **standard active probing**
(connecting to the server's `443/tcp` and seeing whether it serves a
plausible web response). Under that model, wisp aims to be
**statistically indistinguishable from an ordinary low-traffic
self-hosted HTTPS service** — say, a personal blog or a Nextcloud
instance.

Specifically:

- A passive observer sees a real TLS 1.3 handshake with a
  browser-issued `ClientHello` (cipher suite list, extension order,
  GREASE values, signature algorithms, etc., all sourced from a
  current Chrome or Firefox release via `uTLS`).
- The observer sees a normal SNI matching the server's certificate and
  ALPN negotiating `h2` or `http/1.1`.
- Any active probe to `https://<domain>/` returns a real HTTP response
  served by the wisp server itself — a static landing page chosen at
  deploy time, by default a generic "It works!" page that looks like
  a default web server install.
- The tunnel endpoint lives at an unguessable URL path
  (`/<random-32-byte-base64url>/ws`), reachable only with a valid
  bearer token. Probes to `/`, `/.well-known/`, `/robots.txt`,
  `/favicon.ico` get plausible 200/404 responses; probes to
  guessed paths get 404 with timing equivalent to the landing page.

### 2.2 What this model does **not** cover

- **Nation-state DPI** with traffic-correlation capability, ML-based
  flow classification, or active probes that include lattice-style
  enumeration of port and timing patterns. These adversaries have
  defeated TLS-based obfuscation tools before (`shadowsocks`,
  early `v2ray`); they will likely defeat this one too. If that is
  your threat model, use [`xray`](https://github.com/XTLS/Xray-core)
  or [`sing-box`](https://github.com/SagerNet/sing-box) — they have
  a research community behind them. wisp does not.
- **TLS-MITM environments** where the firewall presents its own
  certificate and the host trusts it. No application-layer obfuscation
  helps here; the firewall sees plaintext. We document the mitigation
  in §10 but it is not a primary objective.
- **Endpoint compromise.** wisp cannot protect against an adversary
  who controls the client or server host.
- **Long-term traffic-volume analysis.** A box that suddenly originates
  many gigabytes of outbound TLS to a previously-unseen domain is
  conspicuous regardless of fingerprint. wisp does not try to hide that
  fact.

## 3. Wire protocol

Layering, top to bottom:

```
┌──────────────────────────────────────────────────────────┐
│  application TCP (ssh, postgres, http, ...)              │
├──────────────────────────────────────────────────────────┤
│  yamux stream (one stream per inbound TCP connection)    │
├──────────────────────────────────────────────────────────┤
│  yamux session (multiplexer)                             │
├──────────────────────────────────────────────────────────┤
│  WebSocket binary frames (RFC 6455)                      │
├──────────────────────────────────────────────────────────┤
│  HTTP/1.1 upgrade  -or-  HTTP/2 stream (rfc8441)         │
├──────────────────────────────────────────────────────────┤
│  TLS 1.3 (browser-fingerprinted via uTLS)                │
├──────────────────────────────────────────────────────────┤
│  TCP/443                                                 │
└──────────────────────────────────────────────────────────┘
```

### 3.1 TLS layer

- TLS 1.3 only. No 1.2 fallback on the client side.
- ALPN: client offers `h2`, `http/1.1` in that order. Server picks
  based on its own preference (default: prefer `h2`).
- SNI: required, matches the server's certificate CN/SAN.
- **Client `ClientHello` is generated by [`uTLS`](https://github.com/refraction-networking/utls)**
  using a rotating set of recent browser profiles (Chrome 120, Firefox
  121, Safari 17). The active profile is chosen pseudorandomly per
  session, seeded by the server domain so that a given client to a
  given server is consistent across reconnects (avoids flagging a
  single client as fingerprint-hopping).
- Certificate: real, public-CA-issued (Let's Encrypt or equivalent).
  Self-signed is supported in `--insecure-dev` mode for local testing,
  not for production.

### 3.2 HTTP layer

Two transports are supported. The client negotiates which to use based
on ALPN.

**HTTP/1.1 + WebSocket (`/<endpoint>/ws`):**

```http
GET /<endpoint>/ws HTTP/1.1
Host: wisp.example.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <16 random bytes, base64>
Authorization: Bearer <token>
User-Agent: <a current real browser UA string>
```

Server responds with `101 Switching Protocols`. Header order, casing,
and the `User-Agent` are chosen to match a real browser's request.

**HTTP/2 extended CONNECT (`:method = CONNECT`, `:protocol = websocket`,
RFC 8441):**

The same logical WebSocket session is opened as an HTTP/2 stream. This
is useful where intermediaries strip `Upgrade:` headers.

### 3.3 wisp framing inside the WebSocket

Once the WebSocket is open, every WS binary message carries one or
more **wisp frames**. (Text frames are reserved and not used.)

```
struct Frame {
  uint8   type;     // 0x01 HELLO, 0x02 HELLO_ACK, 0x03 PING,
                    // 0x04 PONG,  0x05 YAMUX,    0x06 BYE
  uint16  length;   // payload length in bytes
  uint8   padding;  // length of trailing random padding (0..255)
  bytes   payload;  // 'length' bytes
  bytes   pad;      // 'padding' bytes of randomness
}
```

- `HELLO` (client → server): contains the session id (32-byte
  base64url), requested TTL, requested target description (just
  free-form metadata; the actual `--to` is client-local and the server
  never sees it), client version, and a 16-byte nonce.
- `HELLO_ACK` (server → client): assigned public port, granted TTL
  (may be less than requested), a server nonce.
- `PING`/`PONG`: liveness, see §6. Payload is timestamp + random
  padding.
- `YAMUX`: opaque carrier for a single yamux frame. wisp does not
  parse yamux internals.
- `BYE`: orderly shutdown. Payload contains a reason code.

`padding` length is drawn from a distribution that approximates
real-world WebSocket message size statistics (see §7). Receivers
discard the pad bytes and never echo them.

### 3.4 yamux

[`yamux`](https://github.com/hashicorp/yamux) provides bidirectional
multiplexing. Each new TCP connection on the server's public port
opens a new yamux stream from server to client. yamux's own
heartbeats are disabled (we use WS-level PINGs instead) to avoid
introducing a second periodic signal on the wire.

## 4. Authentication

A wisp server has a single shared **token**, a high-entropy secret set
at startup via `--token` or `$WISP_TOKEN`. There are no user accounts,
no per-tunnel auth, no PKI.

### 4.1 Token transmission

The token rides in `Authorization: Bearer <token>` on the WebSocket
upgrade request. This is the standard OAuth 2.0 bearer pattern and is
indistinguishable on the wire from any API request.

### 4.2 Token validation

- Compared in constant time (`subtle.ConstantTimeCompare`).
- Invalid tokens get a `401 Unauthorized` with the
  `WWW-Authenticate: Bearer` header, then the connection is closed.
  Crucially, the **timing** of this response is matched to a successful
  upgrade response by inserting a calibrated delay — a passive observer
  cannot distinguish auth success from failure by latency alone.
- A client IP that fails auth 5 times in 60 seconds enters a 10-minute
  cooldown during which all `/<endpoint>/ws` requests get an
  indistinguishable `404 Not Found`. Other paths (the decoy site) are
  unaffected.

### 4.3 Endpoint path obscurity

The `<endpoint>` path segment is configured server-side. It defaults
to a fresh random 32-byte base64url string generated at server first
startup and persisted to `--state-dir`. The client must know it (it is
embedded in the `wisp` binary at build time, via `wisp serve --build-client`).

Reasoning: even with a valid token, an attacker who has not
seen a client binary cannot enumerate the tunnel endpoint by URL.
Probes to the wrong path get a plain 404 from the decoy site.

## 5. Session lifecycle

```
                    HELLO ─────────────────────────►
client                                                   server
                ◄───────────────────── HELLO_ACK (port assigned)

                       … data flows over yamux …

                ◄──── PING ────►   (every 15-45s, jittered)

                    BYE  ─────────────────────────►
                ◄───────────────────────────── BYE
                                                 (or TTL expiry — server
                                                  closes WS with code 1001)
```

### 5.1 Identifiers

A **session id** is a 32-byte base64url string generated by the client
on first HELLO. It is the only identifier needed for resume. Server
state for a session: `{session_id → (public_port, allocated_at, ttl,
remote_addr_hash, ws_conn?)}`.

### 5.2 TTL

The server enforces TTL authoritatively. When `allocated_at + ttl`
passes:

1. Server sends `BYE` with reason `ttl_expired` on the wisp framing
   channel.
2. Server closes the WebSocket with code 1001 (going away).
3. Server's public port stops accepting new TCP connections.
4. Server lets existing TCP connections drain for `--drain` (default
   10s) then force-closes them.
5. Server's record of the session enters the resume window (§5.3).

The client mirrors this on its end: when its WS closes with 1001 it
prints a final line and exits with status 0.

### 5.3 Resume

For 5 minutes after a session's WS connection drops (whether by TTL,
network drop, or explicit BYE), the server retains the
`{session_id → (public_port, …)}` mapping. A new client connection
presenting the same session id (`--resume <id>`) gets the same public
port back, provided:

- TTL has not yet expired, and
- No other live WS is currently bound to that session id.

Resumes do not extend TTL.

## 6. Liveness

The WS is kept warm with **wisp `PING`s** (not WS-level pings, to keep
WebSocket framing patterns plausible):

- Interval is drawn uniformly from `[15s, 45s]` per ping. Average
  ≈30s, matching common application keepalive ranges.
- Payload size is jittered: 8-byte timestamp + random pad of
  `0..256` bytes.
- Three consecutive missed PONGs → client tears down the session
  client-side and tries one resume attempt.

There is no application-layer keepalive on the per-stream yamux level
(yamux internal keepalive is off, see §3.4). Idle streams cost
nothing.

## 7. Traffic shaping

To reduce the statistical fingerprint of SSH and other interactive
protocols (small, latency-sensitive packets at irregular intervals
characteristic of human typing), wisp does limited shaping at the
wisp-frame layer:

- **Padding.** Every wisp frame carries a random pad of 0..255 bytes.
  The pad length is drawn from a piecewise distribution chosen to
  shift the per-frame size histogram toward the modes typical of
  HTTPS-over-WebSocket web apps (e.g. heartbeats, periodic position
  updates). This is not perfect cover but raises the cost of trivial
  size-histogram classifiers.
- **Burst smoothing (optional, off by default).** When enabled with
  `--shape burst`, the client coalesces frames produced within a 10ms
  window into a single WebSocket message. This trades a tiny latency
  hit for hiding the keystroke cadence of interactive SSH.
- **Chaff (optional, off by default).** With `--shape chaff`, the
  client emits zero-application-payload wisp frames at low rate
  (~1/s, jittered) during idle periods, so a long-lived tunnel does
  not show a conspicuous silent interval followed by a burst.

All shaping options are off in the default `wisp expose` invocation.
The defaults are tuned to be plausible without paying latency.

## 8. Daemonization

The client must outlive the shell that started it. This is harder than
it sounds on the kinds of constrained PTYs we target (vendor web
terminals, captive sessions over a bastion).

### 8.1 Unix

The wisp client, when invoked from a terminal, performs the standard
double-fork:

1. `fork()` once. Parent exits, printing the child's PID.
2. Child calls `setsid()` to detach from the controlling TTY.
3. Child `fork()`s again. Intermediate exits.
4. Final grandchild `chdir("/")`, closes stdin/stdout/stderr (or
   redirects them to `--log-file`, default `~/.wisp/<session>.log`),
   and writes `~/.wisp/<session>.pid`.

The parent of the original invocation prints:

```
wisp expose: session=abc... public=wisp.example.com:22017 ttl=1h00m
            pid=12345 log=~/.wisp/abc.log
            stop: kill 12345  |  or wait 1h00m for auto-shutdown
```

`--foreground` disables daemonization for systemd-style supervision.

### 8.2 Windows

Daemonization on Windows uses `CreateProcessW` with `DETACHED_PROCESS
| CREATE_NEW_PROCESS_GROUP` and an explicit redirect of standard
handles. The behavior of `~/.wisp/...` paths is the same; the log
file location uses `%LOCALAPPDATA%\wisp\`.

### 8.3 Macros for hostile terminals

Some web terminals send `SIGHUP` to the foreground process group on
disconnect *before* `setsid` can be observed by the parent process
(this is a race window when the PTY is closed within milliseconds of
process start). The client mitigates by:

- Ignoring `SIGHUP` until daemonization completes.
- Falling back to `nohup`-equivalent `signal(SIGHUP, SIG_IGN)` if
  the fork dance is interrupted.

## 9. Port allocation

Server-side port assignment is from a configurable range
(`--port-range 22000-22099`).

- **First allocation:** Pick the lowest free port in the range.
- **Resume:** If the session id is in the resume window and its port
  is still free, return that port. Otherwise treat as a fresh
  allocation.
- **Exhaustion:** Server returns `HELLO_ACK` with `port=0` and
  closes; client prints an actionable error.

Ports are released to the pool 30 seconds after the last connection
drains (longer than typical TIME_WAIT) to avoid handing the same port
to a different user too quickly.

## 10. TLS MITM behavior

Some corporate networks intercept TLS by installing a CA on the host.
There is no protocol-level defense against this; if the host trusts
the firewall, the firewall sees plaintext.

Two practical considerations:

- The client logs (in `--verbose` mode) the SHA256 of the certificate
  it received. If this differs from the server-pinned hash provided
  at build time (via `wisp serve --build-client --pin`), the client
  refuses to start. This is opt-in; the default is permissive because
  it is easier for a non-technical user to recover from "certificate
  rotated" than from "tunnel won't start".
- The decoy landing page is the same content over MITM and direct
  connection. The fingerprint of the wisp client (UA, header order,
  ALPN list) was chosen to match a real browser, so a MITM box that
  classifies by client behavior will see "ordinary browser".

## 11. Server-side decoy site

A wisp server, on `GET /` and any path other than the configured
endpoint, serves a static decoy site.

- Default: a minimal "It works!" page that looks like a default
  installation of a small Go HTTP server, with `Server: nginx/1.24.0`
  header. (Yes, the lie is in the header — but `nginx` is the modal
  default and matches what most fresh VPSs show.)
- Custom: `--decoy-dir /path/to/static/` serves any directory of
  HTML. A real personal-site mirror is recommended for production.
- All routes return responses within the same latency envelope as
  the tunnel handshake, so timing oracles are not informative.

## 12. Distribution endpoint

The server hosts the wisp client binary itself at a configurable path,
default `/w`. This is so the user behind the firewall can do:

```bash
curl -sSL https://wisp.example.com/w | sh
```

The hosted artifact is a small shell script that detects OS/arch,
fetches the right binary from `/w/<os>/<arch>`, verifies a sha256
embedded in the script against the binary, and execs it with the
remaining arguments.

The script and binaries are served only over the same TLS endpoint as
the tunnel; they share a cert and a fingerprint. They have their own
opaque path component (default `/w`) just like the tunnel endpoint
does, to avoid `/w` showing up as an obvious "download my reverse
shell" URL in passive scans of the domain.

## 13. Logging

- **Server, default level:** warn. Server logs: bind events, session
  creation/expiry, auth failures (counted, not per-IP), errors.
- **Client, default level:** quiet after daemonization. The PID file
  and log file are the only persistent artifacts.
- **No client IPs in logs by default.** `--log-remote-ip` opts in.
- All logs are line-formatted, suitable for `journalctl` and friends.

## 14. Distribution security

- Server binary is built with `-trimpath -ldflags="-s -w -buildid="`
  and reproducibly. Build provenance is published via GitHub release
  attestations.
- The hosted client artifact at `/w/<os>/<arch>` is the same binary
  that was published; the install script verifies a sha256 from the
  same release.

## 15. Open questions / future work

- **Domain fronting.** Not in v1. Useful where the adversary cannot
  block the front-end CDN. Cloudflare deprecated it; Fastly still
  works in some forms.
- **QUIC.** A QUIC transport would help in networks that prefer UDP
  or where HTTP/3 is common. Adds complexity; deferred to v2.
- **Per-tunnel auth.** Currently a single shared token serves the
  whole server. A short-lived per-tunnel token, signed by the server,
  could replace this and would scale to multi-user.
- **Pluggable transports.** Carve the WebSocket-over-TLS step into an
  interface so that gRPC, HTTP/3, or a raw TLS transport can be
  swapped in without touching the framing or yamux layers.
