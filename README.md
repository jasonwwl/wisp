# wisp

> Ephemeral reverse TCP tunnels. One line. TLS by default. TTL-bound. No config files.

```bash
# On a public host you control:
wisp serve --domain wisp.example.com --token $TOKEN

# On the machine behind NAT, when you need help for an hour:
curl -sSL https://wisp.example.com/w | sh -s -- --to 127.0.0.1:22 --ttl 1h
# → exposed at wisp.example.com:22017
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
- **TLS on 443, real certificate.** Looks and behaves like an HTTPS
  endpoint. No stunnel, no nginx in front, no `-k` to swallow self-signed
  warnings.
- **Foreground by default; `--detach` when you need it.** Run wisp in
  the foreground and stop it with `Ctrl-C`; or add `--detach` to fork
  it into a real daemon that survives the parent terminal — useful in
  vendor web terminals or captive bastion sessions where closing the
  browser tab would otherwise kill the process.
- **Session resume.** Lost your SSH? Re-run the same command with
  `--resume <id>` within five minutes and you get the same public port
  back.
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

> Coming soon — pinned in the next release.

## Design

See [`docs/design.md`](docs/design.md) for the wire protocol, threat
model, traffic-shaping strategy, daemonization, and session-resume
semantics. Read it before opening a PR that touches anything below
the CLI.

## Status

Pre-alpha. Design is being prototyped in public; expect breaking changes
until `v0.1.0`.

## License

[MIT](LICENSE) © wenlei <wenleigood@gmail.com>
