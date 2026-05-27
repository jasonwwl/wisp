# wisp

English · [中文](README_zh.md)

> Ephemeral reverse TCP tunnels. One line. TLS by default. TTL-bound. No config files.

```bash
# On a public host you control (one-time):
$ wisp serve --listen :443 --domain wisp.example.com \
    --acme --acme-email you@example.com --token $WISP_TOKEN

# On the machine behind NAT, when you need help for an hour:
$ wisp expose -s wisp.example.com -t $WISP_TOKEN \
    -e <endpoint-from-server> --to 127.0.0.1:22 --ttl 1h --detach
# → wisp: tunnel started in background
#   public:  wisp.example.com:22017
```

That's it. When the timer is up, the tunnel evaporates.

---

## Why wisp exists

You're on call. A friend's NAS won't boot. They're behind double NAT, in a
different country, with a CGNAT router they don't have the password to.
You need shell access for thirty minutes.

You don't want them to install ngrok and hand you an auth token. You don't
want to walk them through a frp config file. You don't want a permanent
service quietly listening on their box six months from now.

You want them to paste **one line** into a terminal, get a short-lived
endpoint, hand it to you, and have everything melt away when they close
the laptop.

That's wisp.

## What it is

A self-hostable, single-binary, TLS-tunneled reverse TCP relay with
**time-bounded sessions** as a first-class concept.

- **Ephemeral by default.** Every tunnel has a TTL. The default is one
  hour. The maximum is whatever you configure on your server. There is no
  "forever" mode.
- **Zero configuration.** No `wisp.toml`, no `[proxies]` block, no
  registry. Everything is command-line flags or environment variables.
- **TLS on 443, real certificate.** Built-in ACME / Let's Encrypt
  issuance and renewal — `--acme` on the server, nothing else. Looks
  and behaves like an HTTPS endpoint. No stunnel, no nginx in front,
  no `-k` to swallow self-signed warnings.
- **Foreground by default; `--detach` when you need it.** Run wisp in
  the foreground and stop it with `Ctrl-C`; or add `--detach` to fork
  it into a real daemon that survives the parent terminal — useful in
  vendor web terminals or captive bastion sessions where closing the
  browser tab would otherwise kill the process.
- **Not just SSH.** The client forwards any local TCP target. Postgres,
  Redis, an HTTP dev server — `--to` takes a `host:port`.

## What it isn't

- Not a replacement for **frp** or **rathole**. Those are built for
  long-lived, multi-tenant, configured deployments. wisp is the opposite.
- Not a SaaS. There is no `wisp.io`. You run your own server on a $5 VPS.
- Not a nation-state DPI evasion tool. wisp blends with ordinary HTTPS in
  the corporate-NGFW threat class — JA3/JA4 fingerprint matching, real
  certificates, decoy landing page, traffic shaping — but it does not try
  to defeat traffic-correlation adversaries with research budgets. For
  that, use [xray](https://github.com/XTLS/Xray-core),
  [sing-box](https://github.com/SagerNet/sing-box), or
  [naive](https://github.com/klzgrad/naiveproxy), not this. See
  [`docs/design.md`](docs/design.md) §2 for the threat model.
- Not a VPN. One TCP target per tunnel. By design.

## Quick start

### Build

```bash
git clone https://github.com/jasonwwl/wisp && cd wisp
make build
# → ./bin/wisp
```

Or cross-compile a release set: `make release` (linux/darwin/windows
amd64 + arm64, ~9 MB each).

### Deploy the server (public host)

A. **Production — Let's Encrypt, zero-maintenance certs:**

```bash
# DNS: A record for wisp.example.com → server IP
# Open inbound TCP 80 (HTTP-01 challenge) and 443 (TLS).
$ sudo setcap CAP_NET_BIND_SERVICE=+eip ./wisp   # let it bind 80 + 443
$ export WISP_TOKEN=$(openssl rand -base64 32)
$ ./wisp serve \
    --listen :443 \
    --domain wisp.example.com \
    --acme --acme-email you@example.com \
    --token $WISP_TOKEN
wisp server listening on :443 (domain wisp.example.com)
  endpoint: ULsykonosAZGj5ZpyoSDDmfE_sXZpY--wXNPoFdfLyw
  client:   wisp expose --server wisp.example.com --endpoint ... --token $WISP_TOKEN ...
```

The first hit to `https://wisp.example.com/` will take ~10s while
ACME issues the cert; after that it's instant. Renewals happen
automatically about 30 days before expiry.

B. **Self-managed cert (corporate CA, Caddy reverse-proxy, etc.):**

```bash
$ ./wisp serve --listen :443 --domain wisp.example.com \
    --cert /etc/wisp/cert.pem --key /etc/wisp/key.pem --token $WISP_TOKEN
```

C. **Local development:**

```bash
$ ./wisp serve --listen 127.0.0.1:8443 --domain localhost \
    --tls-self-signed --token dev
# client must pass --insecure-dev
```

### Use it from the inside

Foreground (your terminal stays attached, `Ctrl-C` to stop):

```bash
$ ./wisp expose -s wisp.example.com -t $WISP_TOKEN \
    -e ULsykonos... --to 127.0.0.1:22 --ttl 1h
wisp: tunnel up
  public:  wisp.example.com:22017
  session: a28iBDFg7kbXiTqndfaIPdmAiq_Xg3lcnwj8_P-811E
  ttl:     1h0m0s
Ctrl-C to stop.
```

Detached (the only sane mode inside a vendor web terminal where
closing the tab would otherwise kill the process):

```bash
$ ./wisp expose ... --detach
wisp: tunnel started in background
  pid:     2972313
  public:  wisp.example.com:22017
  log:     ~/.wisp/wisp-20260527-120031.log
  stop:    kill 2972313
```

### Optional: systemd unit for the server

```ini
# /etc/systemd/system/wisp.service
[Unit]
Description=wisp tunnel server
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wisp serve \
  --listen :443 --domain wisp.example.com \
  --acme --acme-email you@example.com
EnvironmentFile=/etc/wisp/env       # contains WISP_TOKEN=...
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
StateDirectory=wisp                  # /var/lib/wisp/ for acme-cache
Environment=HOME=/var/lib/wisp
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
$ sudo systemctl enable --now wisp
```

## Design

See [`docs/design.md`](docs/design.md) for the wire protocol, threat
model, traffic-shaping strategy, daemonization, and resume semantics.
Read it before opening a PR that touches anything below the CLI.

## Status

**Alpha.** Real deployments work end-to-end on Linux (server +
client). Public API will not break gratuitously but may move before
`v1.0`.

Working:

- TLS-1.3-on-443 with ACME-issued certificates that auto-renew
- uTLS browser ClientHello (Chrome / Firefox / Safari / Edge)
- Decoy nginx-style site at `/`, indistinguishable 404 on the
  tunnel endpoint without a valid token
- HELLO / HELLO_ACK over wisp.Frame envelopes
- yamux-multiplexed many-streams-per-tunnel forwarding
- Server-side port allocator (fixed range or kernel-ephemeral)
- TTL enforcement with orderly BYE
- Unix `--detach` daemonization that survives PTY close

Landed since `v0.1` on `main` (will ship as `v0.2`):

- 5-minute session resume window: a transient WS drop is transparent;
  the client redials with the same session id and gets the same public
  port back. `--no-resume` returns to v0.1 single-shot behaviour.

Still deferred to a future release:

- HELLO nonce verification
- Traffic-shape `--shape burst` and `--shape chaff`
- Windows `--detach`
- HTTP/2 RFC 8441 WebSocket transport (current is HTTP/1.1 only)

## License

[MIT](LICENSE) © wenlei <wenleigood@gmail.com>
