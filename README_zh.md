# wisp

[English](README.md) · 中文

> 临时反向 TCP 隧道。一行命令。默认 TLS。到点自动消失。无需配置文件。

```bash
# 在你能控制的公网机器上跑一次：
$ wisp serve --listen :443 --domain wisp.example.com \
    --acme --acme-email you@example.com --token $WISP_TOKEN

# 在 NAT 后那台机器上，需要临时让别人接进来一小时：
$ wisp expose -s wisp.example.com -t $WISP_TOKEN \
    -e <服务器启动时打印的 endpoint> --to 127.0.0.1:22 --ttl 1h --detach
# → wisp: tunnel started in background
#   public:  wisp.example.com:22017
```

时间一到，隧道自动消失。

---

## wisp 解决什么问题

你 on-call。朋友家的 NAS 起不来了。他在双层 NAT 后面，在另一个国家，
家里那台运营商 CGNAT 路由器的管理密码他根本不知道。你需要 shell 进去
半小时。

你不想让他装 ngrok 然后把 auth token 念给你听。你不想远程指导他写
frp 配置。你也不想留一个常驻服务在他机器上半年不下线。

你只想让他粘贴**一行命令**到终端、拿到一个短期 endpoint、转给你、
然后他合上电脑，所有东西自动消失。

那就是 wisp。

## 它是什么

一个可自托管的、单文件二进制的、TLS 隧道反向 TCP 中继。把
**有时限的会话**当成一等概念。

- **默认临时。** 每条隧道都有 TTL。默认一小时，最大值由服务端配置。
  没有"永久"模式。
- **零配置。** 没有 `wisp.toml`，没有 `[proxies]` 段，没有任何注册表。
  全是命令行 flag 或环境变量。
- **TLS on 443，真证书。** 内置 ACME / Let's Encrypt 签发和续期 —
  服务端加 `--acme` 就够了。看起来、用起来都是一个 HTTPS 端点。
  不需要 stunnel，不需要前置 nginx，不需要 `-k` 吞自签警告。
- **默认前台运行，需要时 `--detach`。** 前台跑 `Ctrl-C` 停掉；
  加 `--detach` 会把自己 fork 成真守护进程，关掉父终端不影响它 —
  在云厂商网页终端、跳板机会话这种"关窗口就杀进程"的场景下很有用。
- **断网自动重连（v0.2）。** 网络抖一下不会让隧道死掉：客户端会
  用同一个 session id 重连，服务端在 5 分钟的恢复窗口内把同一个
  公网端口给回来。用 `--no-resume` 可以退回到 v0.1 的"一次性"行为。
- **不限于 SSH。** 客户端转发任何本地 TCP target。Postgres、Redis、
  一个 HTTP 开发服务器都行 — `--to` 接 `host:port`。

## 它不是什么

- **不是 frp / rathole 的替代品。** 那两个是为长期、多租户、有配置的
  部署做的；wisp 走相反路线。
- **不是 SaaS。** 没有 `wisp.io`。你在自己的 5 美元 VPS 上跑。
- **不是国家级 DPI 对抗工具。** 在企业 NGFW 这一档威胁模型下 wisp
  能融入普通 HTTPS（JA3/JA4 指纹、真实证书、伪装落地页、流量整形），
  但它不试图对抗有研究预算的流量关联分析。如果那是你的威胁模型，
  请用 [xray](https://github.com/XTLS/Xray-core)、
  [sing-box](https://github.com/SagerNet/sing-box) 或
  [naive](https://github.com/klzgrad/naiveproxy)，别用 wisp。详见
  [`docs/design.md`](docs/design.md) §2。
- **不是 VPN。** 一条隧道一个 TCP target。这是设计如此。

## 快速上手

### 构建

```bash
git clone https://github.com/jasonwwl/wisp && cd wisp
make build
# → ./bin/wisp
```

需要发布套件可以交叉编译：`make release`（linux / darwin / windows
× amd64 / arm64,每个约 9 MB)。

### 部署服务端(公网机器)

**A. 生产环境 — Let's Encrypt,免维护证书:**

```bash
# DNS: wisp.example.com 的 A 记录指向服务器 IP
# 防火墙放通 TCP 80（HTTP-01 challenge）和 443（TLS）
$ sudo setcap CAP_NET_BIND_SERVICE=+eip ./wisp   # 允许它绑定 80 + 443
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

第一次访问 `https://wisp.example.com/` 会卡 ~10 秒等 ACME 出证书,
之后就是瞬时响应。到期前 30 天自动续期。

**B. 自管证书(企业 CA、Caddy 前置反代等):**

```bash
$ ./wisp serve --listen :443 --domain wisp.example.com \
    --cert /etc/wisp/cert.pem --key /etc/wisp/key.pem --token $WISP_TOKEN
```

**C. 本地开发:**

```bash
$ ./wisp serve --listen 127.0.0.1:8443 --domain localhost \
    --tls-self-signed --token dev
# 客户端必须加 --insecure-dev
```

### 从内网这一侧用起来

前台模式(终端保持连接,`Ctrl-C` 停止):

```bash
$ ./wisp expose -s wisp.example.com -t $WISP_TOKEN \
    -e ULsykonos... --to 127.0.0.1:22 --ttl 1h
wisp: tunnel up
  public:  wisp.example.com:22017
  session: a28iBDFg7kbXiTqndfaIPdmAiq_Xg3lcnwj8_P-811E
  ttl:     1h0m0s
Ctrl-C to stop.
```

Detach 模式(在云厂商网页终端这种"关 tab 就杀进程"的场景下唯一靠谱选择):

```bash
$ ./wisp expose ... --detach
wisp: tunnel started in background
  pid:     2972313
  public:  wisp.example.com:22017
  log:     ~/.wisp/wisp-20260527-120031.log
  stop:    kill 2972313
```

接上之前的 session(daemon 重启后用同一个公网端口继续):

```bash
$ ./wisp expose ... --resume a28iBDFg7kbXiTqndfaIPdmAiq_Xg3lcnwj8_P-811E
```

只要在服务端 5 分钟恢复窗口内、TTL 还没过,服务器就会把同一个端口给回来。

### 可选:服务端的 systemd 单元

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
EnvironmentFile=/etc/wisp/env       # 内容是 WISP_TOKEN=...
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
StateDirectory=wisp                  # /var/lib/wisp/,用于 acme-cache
Environment=HOME=/var/lib/wisp
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
$ sudo systemctl enable --now wisp
```

## 设计文档

详见 [`docs/design.md`](docs/design.md):wire 协议、威胁模型、流量整形
策略、守护进程化、恢复语义。改协议或传输层之前请先读它。

## 项目状态

**Alpha。** Linux 上服务端 + 客户端的真实部署能跑通。公开 API 不会
无谓地破坏向后兼容,但 `v1.0` 之前可能调整。

已就绪:

- TLS 1.3 on 443, ACME 签发的证书自动续期
- uTLS 浏览器 ClientHello(Chrome / Firefox / Safari / Edge)
- nginx 风格的伪装落地页,无效 token 路径返回的 404 跟落地页 404
  字节级一致
- 包在 wisp.Frame 信封里的 HELLO / HELLO_ACK
- yamux 多路复用,一条隧道多个 stream
- 服务端公网端口分配器(固定段或内核临时端口)
- TTL 强制 + 优雅 BYE
- Unix 下 `--detach` 守护进程化,关 PTY 不掉
- **从 v0.1 起在 `main` 上落地(将作为 v0.2 发布):**
  - 5 分钟会话恢复窗口:网络抖动不掉隧道,重连后是同一个公网端口。
    `--no-resume` 可退回 v0.1 行为

仍然推迟的:

- HELLO nonce 验证
- 流量整形 `--shape burst` 和 `--shape chaff`
- Windows 下 `--detach`
- HTTP/2 RFC 8441 WebSocket 传输(当前只有 HTTP/1.1)

## 许可证

[MIT](LICENSE) © wenlei <wenleigood@gmail.com>
