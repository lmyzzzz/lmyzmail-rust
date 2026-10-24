# lmyzmail

[中文](README.md) · [English](README.en.md) · [日本語](README.ja.md)

lmyzmail 是面向 Linux x86_64 的单进程邮件服务器：SMTP 收发、Webmail、管理 API、邮件安全与报告、Minecraft 邮箱世界，以及完整的 Skibidi / brainrot 互动功能共用一个模块化 Rust 运行时。PostgreSQL、Redis 和 Maildir 保存持久状态。安装后的服务不需要 Java、JVM、Python 或 Rust 工具链。

当前发布形态为 **0.1.0 候选版**。已有可复现构建、安装、差分和半小时多模块稳定性证据；高邮件量正式验收和原生 AVX-512 验收仍开放。可用功能不等于全部生产验收已完成；准确状态见[剩余工作清单](docs/goal-remaining.zh-CN.md)和[验收记录](docs/acceptance-status.md)。

## 手册导航

- [功能与使用](#功能与使用)
- [安装与首次启动](#安装与首次启动)
- [配置加载规则](#配置加载规则)
- [完整配置参考](#完整配置参考)
- [HTTP 接口](#http-接口)
- [运维与故障处理](#运维与故障处理)
- [兼容数据接管与回滚](#兼容数据接管与回滚)
- [构建与验证](#构建与验证)

## 功能与使用

### 邮件与 Webmail

在 HTTP 根路径 `/` 打开 Webmail。支持邮箱登录、按配置开放注册、收件箱/已发送/垃圾邮件等文件夹、分页、HTML/纯文本邮件、原始邮件与头查看、附件下载、JSON 或 multipart 附件发送、发送状态、配额、星标、标签、联系人和用户偏好。`/cringe.html` 支持连接、风险统计、列表排序、搜索、翻页，以及单 IP 详情和活动记录。邮件详情、附件和用户数据都绑定当前邮箱会话。

入站 SMTP 支持 EHLO、MAIL/RCPT、DATA、BDAT、PIPELINING、STARTTLS、SMTPUTF8、MIME、收件域和邮箱检查。DATA 客户端必须先等 `354` 再传正文。这个监听器**不是 SMTP AUTH submission 服务**：AUTH 返回 `502`；认证发信走 Webmail 或 HTTP API。不要把账户密码交给该端口的 AUTH 命令。

出站经过持久队列、租约续期、有界并发和连接池，执行 MX 选路、STARTTLS、DKIM 签名、临时失败退避、终态归档和 DSN 退信。Sent 文件、数据库索引、队列和文件暂存的所有权及恢复有单独校验；进程重启恢复未完成工作。HTTP 发送默认异步，`async=false` 不受支持。

### 安全、报告与诱捕

具备 SPF / DKIM / DMARC 校验，MTA-STS 出站策略与 TLS-RPT、DMARC 聚合报告；报告支持手动触发及每日 UTC 调度，目标地址受 DNS/HTTP 安全边界约束。需要管理员配置域名 DNS、DKIM 密钥、SMTP 证书和报告发送邮箱，软件不会替你发布 DNS。

内容过滤覆盖 RBL、域名 SOA 启发式、缺失头、Subject 编码、过量收件人、垃圾/钓鱼词、可疑 URL、危险/双扩展名及 MIME 不匹配。连接级 Spamhaus DNSBL/DBL 与内容评分层 RBL 分开配置。

包含 104 类 HTTP 扫描诱饵与 TCP `NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC` 诱捕，记录来源 IP、活动和当前/历史 cringe 分数，支持搜索、导出、衰减及阈值封禁。所有内嵌诱饵和路径的目录见[HTTP 诱饵处理](crates/lmyzmail/src/honeypot.rs)与[协议资源清单](crates/lmyzmail/src/honeypot_assets.json)。这些协议用于诱捕，不提供真实 SSH、FTP、数据库或 VNC 服务。

SSH 日志监控读取首个可用日志并处理轮转、失败窗口、报告冷却和有界 IP 跟踪。可选 XDP 防火墙沿用固定 C/eBPF ABI，提供 IPv4/IPv6 封禁、白名单、统计、PPS/SYN 流量观察、分数同步和重启持久化。默认 systemd 单元只给低端口绑定能力，**不足以挂载 XDP**；按[XDP 部署与真实挂载验收](docs/xdp-privileged-gate.md)配置专门权限，不要简单把整个服务改成无限制 root。

HTTP 按来源策略处理代理 IP 与 CORS，认证、上传、路径、收件域、MIME、队列和缓存都有边界。代理必须删除外部伪造的转发头，只把实际代理地址放入 trusted-proxies。CORS 不是认证。

### Skibidi、问答、推理与视频

SMTP banner、随机文本、概率阈值、seed 与 batch 全部使用固定的 Skibidi C 1.8.0 库；不模拟旧 Java 快速路径。SIMD 选择检测 CPU 与 OS 状态，不能执行的指令不会被强行调用。[生成器 ABI/概率契约](docs/skibidi-banner-contract.md)保留来源和所有权说明。

`SKIBIDITOILET` 有 474 道题，三个难度分别为 BABYGRONK（15 题）、SKIBIDITOILET（30 题）、OHIOFINALBOSS（60 题）。连接 SMTP 后可逐行输入：

```text
SKIBIDITOILET HELP
SKIBIDITOILET START BABYGRONK
SKIBIDITOILET ANSWER A
SKIBIDITOILET QUIT
SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=160 FPS=12 CONTRAST=1.5
```

ASCII 播放还接受 `BRIGHTNESS`、`GAMMA`、`ASPECT`、`INVERT`，遵守配置尺寸和 FPS 上限。使用单色 ANSI、`250-` 行帧；全局同一时间只允许一个观看者，断开连接停止播放。

SkibidiInferX 以 Rust 实现 SafeTensors 只读 mmap、BPE、KV cache、采样、seed、取消和超时，默认安装 compact-20261022 模型（12,192,512 参数，48,779,520 字节，FFN 宽 512）。旧权重保留且可通过路径继续使用。模型和 tokenizer 应原子替换后重启，不能截断正在 mmap 的文件。忙、超时或模型不可用时返回固定 fallback。详见[模型契约与兼容参数](docs/skibidi-inferx-contract.md)。

ASCII、邮件 HTML、图片/视频、Minecraft block/map 调色、dither、resize、分页和逐帧处理由 Rust 管线管理，底层使用固定 FFmpeg、litehtml/Cairo，**不依赖旧 libasciiart**。Scalar、AVX2+FMA、AVX-512 均有安全 runtime dispatch；本机已验证 Scalar/AVX2 像素/帧和协议 golden，原生 AVX-512 性能与全路径执行仍待有相应硬件后验收。

### Minecraft 与 HTCPCP

Minecraft 客户端版本为 **1.8.9**。支持状态查询、online/offline 登录、游戏内邮箱认证、GUI 文件夹、邮件地图显示与分页、联系人相关交互、书本草稿/发信、世界模板、方块视频和地图墙视频。online-mode 的 Mojang 登录不替代邮箱密码。主要命令：

```text
/help
/stuck
/skibidi
/draft
/clear
/mail rendersize 256 256 16
/mail next
/mail prev
/mail close
/video play width=48 fps=6
/video play map width=5 fps=10 dither=1
/video pause
/video stop
```

邮箱输入由游戏内界面引导；`/mail rs` 是 rendersize 别名。配置中的默认尺寸与无参数命令的兼容默认可能不同；显式传参可避免歧义。视频停止、断连、超时后释放相应预算。

HTCPCP 在独立 TCP 端口提供咖啡/茶壶状态机，处理 `GET HEAD OPTIONS PROPFIND BREW POST WHEN`、添加物、茶种、冲泡时间和错误状态。随附样例包含八个不同能力的壶；省略 pots 时为单个 coffee 壶。可用 `curl -i http://127.0.0.1:8888/pot-0` 查看响应，原始客户端可发送 `HTCPCP/1.0` 请求。壶能力不匹配的饮料与添加物会按协议拒绝。

## 安装与首次启动

### 平台和依赖

仅支持 Linux x86_64；开发验收环境为 Ubuntu 24.04 / WSL2。PostgreSQL 16 和 Redis 是已验证的数据服务。运行包的 `RELEASE.json` 列出该 ELF 的准确动态库依赖，按清单安装 x86_64 系统库。构建工具和 Python 仅用于构建/验收/离线工具，不是邮件服务运行依赖。

[发布说明](docs/release.md)说明运行包、完整源码包、历史 bundle、模型和视频资源的组成。下载后在 Linux 中校验同批次提供的 `SHA256SUMS`，解包时保留 Unix 权限：

```bash
sha256sum -c SHA256SUMS
tar -xzf lmyzmail-0.1.0-rc.COMMIT-linux-x86_64.tar.gz
cd lmyzmail-0.1.0-rc.COMMIT
./bin/lmyzmail --version
sudo tools/install-lmyzmail.sh
```

命令中的 `COMMIT` 需替换为实际发布标识。

安装器验证 ELF 和资源 hash，安装完成**保持停止**。已有配置不覆盖。默认路径：

| 路径 | 用途 |
| --- | --- |
| /usr/bin/lmyzmail | 服务二进制 |
| /etc/lmyzmail/application.properties | 管理员配置 |
| /usr/share/lmyzmail/models/skibidi-inferx | 模型和 tokenizer |
| /var/lib/lmyzmail/data/mail | Maildir、默认 spool |
| /var/log/lmyzmail | 服务可写日志目录；标准输出/错误进 journal |
| /run/lmyzmail | 私有运行目录 |
| deploy/lmyzmail.service | 服务单元来源 |

`--binary PATH` 选择 ELF；`--destdir ABS` 暂存安装而不创建系统用户或操作 systemd；`--legacy-rw ABS` / `--legacy-ro ABS` 给已有数据或证书路径精确授权；`--enable` 可在已准备好配置的新安装中启用并启动。不要在未配置凭据前使用它。

### 新数据库与配置

程序启动只增加自己的恢复/协调结构，**不会创建全部基础业务表**。已有数据库直接接管；新空数据库可使用仓库内纯 DDL 的 [PostgreSQL schema](blackbox/fixtures/legacy/postgres-schema.sql)，不导入测试账号或 seed。在源码根目录，且确认目标是新建空库后：

```bash
sudo -u postgres createuser --pwprompt lmyzmail
sudo -u postgres createdb --owner=lmyzmail lmyzmail
set -o pipefail
sed 's/^CREATE SCHEMA "public";$/CREATE SCHEMA IF NOT EXISTS "public";/' \
  blackbox/fixtures/legacy/postgres-schema.sql |
  PGHOST=127.0.0.1 PGUSER=lmyzmail PGDATABASE=lmyzmail \
    psql -X -W --set=ON_ERROR_STOP=1
```

该 schema 已将不兼容 PostgreSQL 的 LONGTEXT 表达转换成 text。**不要对已有库执行初始化 DDL。** 配置独立数据库用户、Redis ACL/密码与所需目录权限。

编辑 `/etc/lmyzmail/application.properties`，至少设置数据库、Redis、域名、监听地址、Maildir、发送域、TLS 和管理 API key。密码和私钥放在受保护配置/文件中；不要把真实凭据提交到 Git。示例配置默认绑定 loopback，公开注册、Minecraft、XDP 和压测关闭，HTCPCP 与 IP DNSBL 显式开启。

HTTP listener 是明文，公网 Webmail 需要 HTTPS 反向代理；SMTP PKCS12 不会启用 HTTPS。PostgreSQL 当前使用 NoTls，应部署在可信本地链路或受保护隧道内。Redis 可单独开启 TLS。

```bash
sudo -u lmyzmail /usr/bin/lmyzmail \
  --config /etc/lmyzmail/application.properties --check-config
sudo systemctl enable --now lmyzmail
curl --fail http://127.0.0.1:8080/api/health
journalctl -u lmyzmail -n 100 --no-pager
```

`--check-config` 检查主配置解析并打印摘要，不连接数据库，也不替代各模块启动校验。启动后核对日志、邮箱 API、SMTP 和实际邮件落盘，不要仅凭 health 判定部署完整。

### 域名发布

为实际域配置 MX 与对应 A/AAAA、服务器反向 DNS、SPF、DKIM selector TXT、DMARC，并按需求部署 MTA-STS HTTPS 策略与 `_mta-sts` / `_smtp._tls` TXT。开启所需入站端口；确认公网出站 TCP 25 可用。只发布本机实际服务的记录，不把示例域名或凭据用于正式系统。

## 配置加载规则

主配置选择顺序为 `--config PATH`（也可 `--config=PATH`）、环境变量 `LMYZMAIL_CONFIG`、当前目录 `application.properties`、`/etc/lmyzmail/application.properties`。只选一个主文件。CLI 支持 `--check-config`、`--version/-V`、`--help/-h` 和 `--lmyzmail.key=value` 覆盖。

普通配置为 UTF-8 properties，支持续行和 properties 转义，同名键后者覆盖。`spring.profiles.include=a,b` 依次加载同目录 `application-a.properties`、`application-b.properties`；缺失普通 profile 被忽略，缺失 keywords 时用内嵌正式词表。先主文件、后 profile、最后同名 CLI 覆盖。

每个字段先找新 `lmyzmail.*`，再找支持的旧 `botmail.*` 别名；**旧命名空间的 CLI 值也不能覆盖已经存在的新键**。不是所有键都会自动读取环境变量。单文件最多 1 MiB、16384 个键，include 最多 32 个、总 4 MiB。

也接受首个非空白字符为 `{` 的 `schema_version=1` 语义 JSON，供外部测试/编排使用；它是分组的 snake_case schema，**不是任意 properties 的 JSON 字典**。顶层字段为 `schema_version, profile, listen, postgres, redis, maildir, storage, domain, domains, allowed_origins, trusted_proxies, api_keys, features, skibidi_inferx, fail2ban, smtp, content_filter, xdp, cringe, reporting, stress, htcpcp, minecraft, mail_render, tls, limits`；分组字段和验证由[强类型定义](crates/lmyzmail/src/config.rs)限定，未知字段拒绝。JSON 的显式默认不总等于 properties 缺省，例如域项 send_enabled 默认 false；日常部署建议使用以下 properties 参考。

## 完整配置参考

以下所有相对键均加 `lmyzmail.` 前缀，表中已展开为完整键。`/` 分隔同一行的多个独立键，默认值按相同次序对应；`""` 为空字符串，`[]` 为空列表。`<maildir>` 指 maildir.base。除另注外，是**省略该键时的 properties 默认值**，而非样例文件的显式取值。`[n]` 从 0 连续编号，`<name>` 与 `<RULE>` 为替换位置。配置变更需重启；没有通用热重载接口。

### 监听、HTTP 与消息大小

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.listen.host` | `127.0.0.1` | 所有监听服务的绑定地址。公网部署需显式更改。 |
| `lmyzmail.http.port` / `lmyzmail.smtp.port` / `lmyzmail.htcpcp.port` / `lmyzmail.minecraft.port` | `8080 / 25 / 8888 / 25565` | 各协议端口；可选服务还需要 enabled。 |
| `lmyzmail.profile` | `production` | 配置标签，不会自动加载同名 profile 文件。 |
| `lmyzmail.http.max-request-bytes` | `10485760` | 普通 HTTP 请求体上限；附件另受以下限制。 |
| `lmyzmail.http.max-multipart-bytes` | `209715200` | multipart 请求体上限，不代表可发送这么大的邮件。 |
| `lmyzmail.http.max-connections` / `lmyzmail.http.request-timeout-ms` | `256 / 10000` | HTTP 并发连接与请求超时。 |
| `lmyzmail.http.upload-temp-dir` | `<maildir>/.lmyzmail-upload` | 流式上传临时目录，服务用户须可写。 |
| `lmyzmail.http.trusted-proxies` | `[]` | 可信代理 IP/CIDR；仅信任这些来源的转发 IP。支持 CSV 或 [n]。 |
| `lmyzmail.allowed-origins[n]` | `[]` | 允许的 CORS origin，支持明确的 scheme://*.domain 模式。 |
| `lmyzmail.max-email-size-bytes` / `lmyzmail.max-attachment-size-bytes` / `lmyzmail.max-total-attachments-size-bytes` | `15728640 / 10485760 / 15728640` | 整封邮件、单附件、附件总量上限；包括 MIME 编码开销。 |

### 数据库、Redis 与持久化

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.postgres.host` / `lmyzmail.postgres.port` / `lmyzmail.postgres.database` | `localhost / 5432 / lmyzmail` | PostgreSQL 地址、端口和数据库。 |
| `lmyzmail.postgres.username` / `lmyzmail.postgres.password` | `lmyzmail / ""` | 数据库身份；生产环境设置独立凭据。 |
| `lmyzmail.postgres.url` | `""` | 可选 JDBC/PostgreSQL URL；仅解析 host/port/database，用户名密码仍单独配置。 |
| `lmyzmail.postgres.pool.max-size` | `32` | 有界 PostgreSQL 连接池。当前连接使用 NoTls。 |
| `lmyzmail.redis.host` / `lmyzmail.redis.port` / `lmyzmail.redis.database` | `localhost / 6379 / 0` | Redis endpoint 与逻辑数据库；沿用已有 key 和 TTL。 |
| `lmyzmail.redis.username` / `lmyzmail.redis.password` | `"" / ""` | Redis ACL 用户和密码；无认证时留空。 |
| `lmyzmail.redis.tls-enabled` | `false` | Redis TLS；同命名空间别名 redis.ssl.enabled。 |
| `lmyzmail.redis.pool.max-active` | `32` | 有界 Redis 连接池。 |
| `lmyzmail.maildir.base` | `/var/lib/lmyzmail/data/mail` | 邮件存储根目录；保留现有目录和权限。 |
| `lmyzmail.maildir.max-files-per-directory` | `10000` | 目录分片阈值。整个服务使用 1..1000000；不要用 -1。 |
| `lmyzmail.storage.fsync-enabled` | `true` | 文件和目录耐久屏障。false 保留原子发布，但故障时可能丢失已确认的数据；不改变 PostgreSQL WAL 或 Redis 持久化设置。 |

### 域名、身份与限流

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.domain` | `lmyz.net` | 主域名；domains.main.domain 优先。 |
| `lmyzmail.domains.<name>.domain` | `domain (main)` | 命名域配置，最多 256 项；main 可省略 domain 字段。 |
| `lmyzmail.domains.<name>.receive-enabled` / `lmyzmail.domains.<name>.send-enabled` / `lmyzmail.domains.<name>.require-existing-mailbox` | `true / true / true` | 允许收信、发信及要求收件箱已存在。后两者不会启用 SMTP AUTH。 |
| `lmyzmail.domains.<name>.dkim-selector` / `lmyzmail.domains.<name>.dkim-private-key-path` | `"" / ""` | DKIM selector 与私钥路径，成对配置并发布相应 DNS TXT。 |
| `lmyzmail.domains.<name>.list-unsubscribe-mailto` / `lmyzmail.domains.<name>.list-unsubscribe-url` | `"" / ""` | 出站 List-Unsubscribe 目的地址。 |
| `lmyzmail.api-keys[n].key` / `lmyzmail.api-keys[n].label` | `required / api` | 连续索引的 API key 项，最多 256；key 最长 4096 字节、不可重复。 |
| `lmyzmail.api-keys[n].read` / `lmyzmail.api-keys[n].write` | `true / false` | 独立的读写权限；别名 readEnabled/writeEnabled。 |
| `lmyzmail.public-registration-enabled` | `false` | 公开注册开关；管理 API 仍可创建邮箱。 |
| `lmyzmail.session.expiry-days` / `lmyzmail.session.max-per-user` / `lmyzmail.session.track-last-used` | `7 / 10 / true` | 登录会话有效期、每用户上限、最近使用时间记录。 |
| `lmyzmail.rate-limit.enabled` | `true` | 认证和注册限流总开关。 |
| `lmyzmail.rate-limit.max-failed-login-attempts` / `lmyzmail.rate-limit.failed-login-window-minutes` / `lmyzmail.rate-limit.ip-ban-duration-hours` | `10 / 5 / 3` | 登录失败窗口与 IP 封禁时长。 |
| `lmyzmail.rate-limit.max-registrations-per-ip` / `lmyzmail.rate-limit.registration-rate-window-hours` | `5 / 3` | 单 IP 注册窗口配额。 |
| `lmyzmail.rate-limit.max-emails-per-account` / `lmyzmail.rate-limit.email-rate-window-hours` | `100 / 3` | 每账号发送配额与窗口；调大并发不会解除配额。 |

### 出站、队列与 DNS

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.outbound.spool-dir` | `<maildir>/.lmyzmail-outbound` | 大邮件暂存至队列终态归档；旧别名 botmail.outbound.temp-dir。 |
| `lmyzmail.outbound.max-pending-tasks` / `lmyzmail.outbound.retry-count` | `10000 / 5` | 待处理任务硬上限与最大重试次数。 |
| `lmyzmail.outbound.helo-hostname` | `domain` | 出站 EHLO/HELO 主机名。 |
| `lmyzmail.outbound.connection-timeout-ms` / `lmyzmail.outbound.read-timeout-ms` | `30000 / 60000` | 连接及 SMTP 命令读取超时。 |
| `lmyzmail.outbound.pool-enabled` / `lmyzmail.outbound.max-connections-per-host` / `lmyzmail.outbound.max-messages-per-connection` | `true / 5 / 100` | 成功会话 RSET 后复用；失败和结果不明的连接关闭。 |
| `lmyzmail.outbound.max-idle-time-ms` / `lmyzmail.outbound.connection-life-time-ms` / `lmyzmail.outbound.pool-cleanup-interval-ms` | `60000 / 300000 / 30000` | 空闲、连接寿命和池清理间隔。 |
| `lmyzmail.queue.worker-id` | `lmyzmail-<pid>` | 队列租约持有者；示例固定为 lmyzmail-worker，勿跨实例重用。 |
| `lmyzmail.queue.max-concurrent-sends` / `lmyzmail.queue.batch-size` / `lmyzmail.queue.poll-interval-ms` | `100 / 50 / 1000` | 有界并发、每次调度领取数、轮询间隔。 |
| `lmyzmail.queue.migration-batch-size` | `1000` | 恢复既有队列时的扫描批大小。 |
| `lmyzmail.queue.lease-seconds` / `lmyzmail.queue.renew-seconds` / `lmyzmail.queue.processing-timeout-minutes` | `90 / 10 / 10` | 租约、续期和处理期限；续期间隔须满足校验约束。 |
| `lmyzmail.queue.retry-base-seconds` / `lmyzmail.queue.retry-max-seconds` | `30 / 3600` | 重试退避基础和上限。 |
| `lmyzmail.outbound.dns.mx.l1-max-entries` / `lmyzmail.outbound.dns.mx.l1-ttl-minutes` / `lmyzmail.outbound.dns.mx.l2-ttl-minutes` / `lmyzmail.outbound.dns.mx.negative-ttl-minutes` | `10000 / 15 / 30 / 5` | MX 本地缓存容量、本地/Redis TTL、负缓存 TTL。 |
| `lmyzmail.outbound.dns.query-timeout-seconds` / `lmyzmail.outbound.route-deadline-seconds` | `15 / 30` | DNS 查询超时和整条选路期限。 |
| `lmyzmail.smtp.mta-sts-enabled` / `lmyzmail.smtp.mta-sts-fetch-timeout-ms` | `true / 10000` | MTA-STS 策略发现、HTTPS 获取和出站 TLS 策略。 |
| `lmyzmail.ssl.use-custom-certificate` / `lmyzmail.ssl.keystore-path` / `lmyzmail.ssl.keystore-password` | `false / "" / ""` | SMTP STARTTLS 的 PKCS12 证书；不为 HTTP listener 开启 HTTPS。 |

### SMTP 安全与内容过滤

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.smtp-security.tarpit-enabled` | `true` | 启用恶意客户端延迟响应策略。 |
| `lmyzmail.smtp-security.dns-server` | `""` | 可选数字 IP:port DNS 覆盖；空值使用系统解析器。 |
| `lmyzmail.smtp-security.spamhaus-enabled` / `lmyzmail.smtp-security.spamhaus-zones` | `false / zen.spamhaus.org` | 入站 IP DNSBL。安装示例显式启用；须符合所用 DNSBL 服务政策。 |
| `lmyzmail.smtp-security.spamhaus-reject-on-listed` / `lmyzmail.smtp-security.spamhaus-timeout-ms` / `lmyzmail.smtp-security.spamhaus-cache-ttl-seconds` | `true / 3000 / 300` | 命中拒收、查询超时、缓存 TTL。 |
| `lmyzmail.smtp-security.spamhaus-ignored-codes` | `[]` | 忽略的响应码 CSV。 |
| `lmyzmail.smtp-security.spamhaus-dbl-enabled` / `lmyzmail.smtp-security.spamhaus-dbl-zone` | `false / dbl.spamhaus.org` | 域名 DBL 查询。 |
| `lmyzmail.contentfilter.enabled` / `lmyzmail.contentfilter.suspicious-threshold` / `lmyzmail.contentfilter.spam-threshold` | `true / 5.0 / 10.0` | 加权可疑/垃圾评分阈值与 Spam header/分类。 |
| `lmyzmail.contentfilter.stream-buffer-size` | `65536` | 流式扫描缓冲区，最大 1048576。 |
| `lmyzmail.contentfilter.rules.<RULE>.enabled` / `lmyzmail.contentfilter.rules.<RULE>.weight` | `true / 1.0` | 每条规则开关和权重；权重 0..100。下方列出完整规则集。 |
| `lmyzmail.contentfilter.rbl.enabled` / `lmyzmail.contentfilter.rbl.servers` | `true / zen.spamhaus.org,bl.spamcop.net` | 评分层 RBL，区别于连接层 DNSBL 拒收。 |
| `lmyzmail.contentfilter.rbl.timeout-ms` / `lmyzmail.contentfilter.rbl.score-per-hit` / `lmyzmail.contentfilter.rbl.max-score` | `3000 / 3.0 / 6.0` | RBL 查询期限、单命中分数和封顶。 |
| `lmyzmail.contentfilter.keywords.enabled` / `lmyzmail.contentfilter.keywords.density-threshold` / `lmyzmail.contentfilter.keywords.base-score` / `lmyzmail.contentfilter.keywords.max-score` | `true / 0.05 / 2.0 / 8.0` | 关键词和密度评分。 |
| `lmyzmail.contentfilter.keywords.spam-keywords` / `lmyzmail.contentfilter.keywords.phishing-keywords` | `[] (keywords profile)` | CSV/索引列表；keywords profile 提供正式词表。 |
| `lmyzmail.contentfilter.url.enabled` / `lmyzmail.contentfilter.url.shortener-domains` / `lmyzmail.contentfilter.url.suspicious-tlds` | `true / [] / []` | URL 扫描；keywords profile 提供短链接域名与可疑 TLD 列表。 |
| `lmyzmail.contentfilter.url.shortener-score` / `lmyzmail.contentfilter.url.suspicious-tld-score` / `lmyzmail.contentfilter.url.ip-url-score` / `lmyzmail.contentfilter.url.max-score` | `1.5 / 2.0 / 3.0 / 8.0` | 短链接、可疑 TLD、IP URL 的加分和总上限。 |
| `lmyzmail.contentfilter.attachment.enabled` / `lmyzmail.contentfilter.attachment.dangerous-extensions` | `true / exe,scr,bat,cmd,com,pif,vbs,vbe,js,jse,wsf,wsh,msi,msp,hta,cpl,reg,inf,scf,lnk,ps1,psm1,jar` | 附件扫描与危险扩展名列表，可自定义。 |
| `lmyzmail.contentfilter.attachment.dangerous-extension-score` / `lmyzmail.contentfilter.attachment.double-extension-score` / `lmyzmail.contentfilter.attachment.mime-type-mismatch-score` | `5.0 / 4.0 / 3.0` | 危险扩展名、双扩展名、MIME 不匹配评分。 |

规则名：`RBL_CHECK`、`NEW_DOMAIN`、`MISSING_HEADERS`、`SUBJECT_ENCODING_TRICK`、`EXCESSIVE_RECIPIENTS`、`SPAM_KEYWORDS`、`SUSPICIOUS_URL`、`DANGEROUS_EXTENSION`、`DOUBLE_EXTENSION`、`MIME_TYPE_MISMATCH`。这些规则均有实际处理路径；`NEW_DOMAIN` 使用 SOA serial 启发式，不是注册日期数据库。安装示例加载 `spring.profiles.include=keywords`；不加载该 profile 时列表可为空。

### Skibidi、InferX 与 ASCII 渲染

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.smtp.skibidi-generator-mode` | `AUTO_SAFE` | AUTO_SAFE/AUTO/NATIVE/SCALAR/AVX2/AVX512；JAVA 仅是 Scalar C 兼容别名。全部概率与 seed/batch 语义以固定 C 1.8.0 为准。 |
| `lmyzmail.smtp.skibidi-generator-enable-avx512` / `lmyzmail.smtp.skibidi-generator-enable-simd-rng` | `true / true` | 允许相应后端，仍受 CPU/OS 功能检测约束。 |
| `lmyzmail.smtp.skibidi-insults-enabled` / `lmyzmail.smtp.skibidi-toilet-quiz-enabled` | `true / true` | SMTP 互动文本与 474 题问答。 |
| `lmyzmail.smtp.asciiart.simd-mode` / `lmyzmail.mailrender.simd-mode` | `AUTO / AUTO` | AUTO/SCALAR/AVX2/AVX512，安全 runtime dispatch；后者用于邮件像素和 Minecraft 颜色管线。 |
| `lmyzmail.smtp.asciiart.max-width` / `lmyzmail.smtp.asciiart.max-fps` / `lmyzmail.smtp.asciiart.default-width` / `lmyzmail.smtp.asciiart.default-fps` | `450 / 20 / 120 / 10` | SMTP ASCII 视频尺寸和帧率上限/默认值。 |
| `lmyzmail.smtp.asciiart.default-contrast` / `lmyzmail.smtp.asciiart.char-aspect` | `1.2 / 2.0` | 对比度与字符宽高补偿。 |
| `lmyzmail.skibidi-inferx.enabled` | `true` | 启用 Rust SafeTensors/BPE 文本生成；不可用时返回固定 fallback。 |
| `lmyzmail.skibidi-inferx.model-path` | `/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors` | 只读 mmap 权重，安装包为 compact-20261022；旧权重另保留。 |
| `lmyzmail.skibidi-inferx.tokenizer-path` | `/usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json` | BPE tokenizer；必须与权重配套。 |
| `lmyzmail.skibidi-inferx.temperature` / `lmyzmail.skibidi-inferx.top-k` / `lmyzmail.skibidi-inferx.top-p` | `0.85 / 50 / 0.92` | 采样参数。 |
| `lmyzmail.skibidi-inferx.max-tokens` | `80 (effective 120)` | 兼容历史行为：配置值被校验/报告，但生成仍使用有效上限 120。 |
| `lmyzmail.skibidi-inferx.timeout-ms` / `lmyzmail.skibidi-inferx.max-concurrent-generations` | `500 / 1` | 每请求期限；有效引擎单 worker，忙时立即 fallback；配置大于 1 不增加并发推理。 |
| `lmyzmail.skibidi-inferx.fallback-on-error` | `true` | 兼容参数：即使 false，外层错误/超时处理也返回 fallback。 |
| `lmyzmail.skibidi-inferx.simd-level` | `auto` | auto/scalar/avx2/avx512；AVX2 需 FMA，AVX512 另需 AVX-512F；不支持时安全降级。 |

### HTCPCP

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.htcpcp.enabled` / `lmyzmail.htcpcp.default-brew-time-seconds` | `false / 30` | 示例显式启用；GET/HEAD/OPTIONS/PROPFIND/BREW/POST/WHEN 状态机。 |
| `lmyzmail.htcpcp.pots[n].id` / `lmyzmail.htcpcp.pots[n].type` | `pot-0 / coffee` | 未配置 pots 时一个默认壶；type=coffee/tea/both。最多 64、索引连续、ID 唯一。 |
| `lmyzmail.htcpcp.pots[n].tea-varieties` | `darjeeling,earl-grey,peppermint` | 允许的茶种 CSV。 |
| `lmyzmail.htcpcp.pots[n].supported-additions` | `Cream,…,Stevia` | 允许的添加物 CSV；完整默认项与八壶示例见配置样例。 |

### Minecraft 1.8.9

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.minecraft.enabled` / `lmyzmail.minecraft.online-mode` | `false / true` | 启用服务与 Mojang session 校验；游戏登录后仍需邮箱认证。 |
| `lmyzmail.minecraft.compression-threshold` / `lmyzmail.minecraft.max-players` | `256 / 20` | 协议压缩阈值与玩家上限。 |
| `lmyzmail.minecraft.motd` / `lmyzmail.minecraft.favicon` | `§6LMYZMAIL §7- Send emails in Minecraft / ""` | 服务器列表说明与 favicon 资源。 |
| `lmyzmail.minecraft.read-timeout-seconds` / `lmyzmail.minecraft.session-server-url` | `30 / https://sessionserver.mojang.com/session/minecraft/hasJoined` | 读取期限与认证服务 URL。 |
| `lmyzmail.minecraft.world-template` / `lmyzmail.minecraft.view-distance` / `lmyzmail.minecraft.max-concurrent-videos` | `worlds/mailroom / 32 / 2` | 世界模板、视距、全局视频并发预算。 |
| `lmyzmail.minecraft.spawn.x` / `lmyzmail.minecraft.spawn.y` / `lmyzmail.minecraft.spawn.z` / `lmyzmail.minecraft.spawn.yaw` / `lmyzmail.minecraft.spawn.pitch` | `0.5 / 160 / 0.5 / 0 / 0` | 出生点与朝向。 |
| `lmyzmail.minecraft.whitelist.enabled` / `lmyzmail.minecraft.whitelist.players` / `lmyzmail.minecraft.blacklist.players` | `false / [] / []` | 名称白/黑名单；列表支持 CSV/[n]。 |
| `lmyzmail.minecraft.auth.max-attempts` / `lmyzmail.minecraft.auth.lockout-seconds` / `lmyzmail.minecraft.auth.window-seconds` | `5 / 300 / 600` | 邮箱登录错误窗口与锁定。 |
| `lmyzmail.minecraft.video.center-x` / `lmyzmail.minecraft.video.center-y` / `lmyzmail.minecraft.video.wall-z` | `0 / 180 / -20` | 方块视频墙位置。 |
| `lmyzmail.minecraft.video.max-width` / `lmyzmail.minecraft.video.max-fps` / `lmyzmail.minecraft.video.default-width` / `lmyzmail.minecraft.video.default-fps` / `lmyzmail.minecraft.video.default-contrast` | `64 / 20 / 32 / 10 / 1.2` | 方块视频上限与默认值。 |
| `lmyzmail.minecraft.video.spawn-protect-radius` / `lmyzmail.minecraft.video.clear-margin` | `8 / 2` | 出生区保护半径、停止后清除边距。 |
| `lmyzmail.minecraft.map-video.center-x` / `lmyzmail.minecraft.map-video.center-y` / `lmyzmail.minecraft.map-video.center-z` / `lmyzmail.minecraft.map-video.facing` | `0 / 180 / -20 / SOUTH` | 地图墙位置与方向（SOUTH/WEST/NORTH/EAST）。 |
| `lmyzmail.minecraft.map-video.max-maps-x` / `lmyzmail.minecraft.map-video.max-maps-y` / `lmyzmail.minecraft.map-video.max-fps` | `10 / 10 / 20` | 地图墙横纵图块数与帧率上限。 |
| `lmyzmail.minecraft.map-video.default-maps-x` / `lmyzmail.minecraft.map-video.default-fps` / `lmyzmail.minecraft.map-video.default-contrast` | `5 / 10 / 1.2` | 地图视频默认宽度、帧率与对比度。 |
| `lmyzmail.minecraft.map-video.base-map-id` / `lmyzmail.minecraft.map-video.base-entity-id` | `10000 / 100000` | 地图和展示实体 ID 起点，避免与自定义世界冲突。 |

### 诱捕、风险分数与 SSH 监控

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.honeypot.enabled` / `lmyzmail.honeypot.initial-delay-ms` / `lmyzmail.honeypot.post-banner-timeout-ms` | `false / 1500 / 10000` | TCP 诱捕总开关、banner 前延迟、banner 后读取期限。 |
| `lmyzmail.honeypot.max-connections-per-trap` / `lmyzmail.honeypot.max-read-bytes` | `100 / 1024` | 每诱捕连接上限和读取预算。 |
| `lmyzmail.honeypot.traps[n].port` / `lmyzmail.honeypot.traps[n].protocol` / `lmyzmail.honeypot.traps[n].label` / `lmyzmail.honeypot.traps[n].bind-address` | `required / NONE / trap / listen.host` | 最多 256；协议 NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC；server-protocol 为 protocol 别名。 |
| `lmyzmail.cringe.decay.interval` / `lmyzmail.cringe.decay.amount` | `24h / 10` | 风险分数按时间衰减，保留当前/历史统计。 |
| `lmyzmail.cringe.decay.check-interval` | `auto` | 默认 interval/4，夹在 1m..1h；别名 `lmyzmail.cringe.decay.checkInterval`。 |
| `lmyzmail.cringe.decay.activity-retention-days` | `360` | 活动记录保留天数。 |
| `lmyzmail.fail2ban.enabled` / `lmyzmail.fail2ban.ssh-log-paths` | `false / /var/log/auth.log,/var/log/secure,/var/log/messages` | 从首个可读 SSH 日志 EOF 开始监控，不重放全部旧日志。 |
| `lmyzmail.fail2ban.scan-interval` / `lmyzmail.fail2ban.max-retries` / `lmyzmail.fail2ban.find-time` | `10s / 5 / 10m` | 扫描间隔、失败阈值与统计窗口。 |
| `lmyzmail.fail2ban.report-cooldown` / `lmyzmail.fail2ban.max-tracked-ips` / `lmyzmail.fail2ban.cleanup-interval` | `5m / 10000 / 5m` | 重复报告冷却、跟踪 IP 硬上限与清理间隔。 |

### XDP 防火墙与 PPS

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.xdp.enabled` / `lmyzmail.xdp.interface-name` / `lmyzmail.xdp.bpf-object-path` / `lmyzmail.xdp.pin-path` | `false / eth0 / "" / /sys/fs/bpf/lmyzmail` | 空 object 路径使用内嵌固定 BPF；需专门配置内核权限和 bpffs。 |
| `lmyzmail.xdp.ban-threshold` / `lmyzmail.xdp.unban-threshold` | `50 / -1` | 分数封禁/解封；-1 表示 ban-threshold/2。 |
| `lmyzmail.xdp.force-generic-mode` / `lmyzmail.xdp.verbose` / `lmyzmail.xdp.sync-on-startup` | `false / false / true` | 通用 XDP 模式、详细日志、启动同步分数。 |
| `lmyzmail.xdp.whitelist` | `127.0.0.1,::1` | IP 白名单，CSV 或连续 [n]。 |
| `lmyzmail.xdp.reason-code-default` / `lmyzmail.xdp.reason-code-pps-overlimit` / `lmyzmail.xdp.reason-code-syn-flood` | `0 / 5 / 6` | 默认、PPS 和 SYN 事件原因码。 |
| `lmyzmail.xdp.pps-monitor.enabled` / `lmyzmail.xdp.pps-monitor.poll-interval-ms` | `true / 1000` | XDP 开启后轮询流量统计。 |
| `lmyzmail.xdp.pps-monitor.pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.pps-critical-threshold` | `100000 / 200000` | 总 PPS 警告/严重阈值。 |
| `lmyzmail.xdp.pps-monitor.syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.syn-pps-critical-threshold` | `10000 / 20000` | 总 SYN PPS 阈值。 |
| `lmyzmail.xdp.pps-monitor.per-ip-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-pps-critical-threshold` | `1000 / 5000` | 单 IP PPS 阈值。 |
| `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold` | `100 / 500` | 单 IP SYN PPS 阈值。 |
| `lmyzmail.xdp.pps-monitor.consecutive-exceed-count` / `lmyzmail.xdp.pps-monitor.record-to-cringe` | `3 / true` | 连续超限轮数、是否记录到分数系统。 |
| `lmyzmail.xdp.pps-monitor.max-ips-per-poll` / `lmyzmail.xdp.pps-monitor.ring-buffer-size` | `10000 / 1024` | 每轮 IP 处理上限与有界事件环。 |

### DMARC / TLS-RPT 报告

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.reporting.enabled` / `lmyzmail.reporting.auto-send-enabled` | `false / false` | 报告收集/生成和每日 01:00 UTC 自动发送。 |
| `lmyzmail.reporting.batch-size` / `lmyzmail.reporting.flush-interval-ms` / `lmyzmail.reporting.retention-days` | `500 / 2000 / 90` | 读取的兼容参数；当前有界写入使用内部预算，不能据此假设定时自动删除历史。 |
| `lmyzmail.reporting.min-volume-for-report` | `10` | 按日期枚举报告域名的最小消息量。 |
| `lmyzmail.reporting.dmarc-report-sender-address` / `lmyzmail.reporting.dmarc-report-sender-password` / `lmyzmail.reporting.tls-report-sender-address` / `lmyzmail.reporting.tls-report-sender-password` | `"" / "" / "" / ""` | 报告发送邮箱凭据；启用实际投递前配置。 |
| `lmyzmail.reporting.organization-name` / `lmyzmail.reporting.organization-email` | `"" / ""` | 聚合报告中的组织标识。 |
| `lmyzmail.reporting.dns-server` | `""` | 报告 RUA 发现 DNS 覆盖；数字 IP:port。 |
| `lmyzmail.reporting.http-delivery-enabled` / `lmyzmail.reporting.http-delivery-timeout-seconds` | `true / 30` | TLS-RPT HTTPS 投递；安装示例显式 false。HTTP 客户端执行目标地址安全约束。 |

### 内建压力测试与界面

| 配置键 | 缺省值 | 用途与行为 |
| --- | --- | --- |
| `lmyzmail.stress-test-enabled` | `false` | 仅隔离测试启用；管理 API 可触发大量真实 SMTP/磁盘/数据库操作。 |
| `lmyzmail.stress-test-sender-prefix` / `lmyzmail.stress-test-receiver-prefix` | `stresstest_send / stresstest_receive` | 测试邮箱前缀；避免与真实邮箱重合。 |
| `lmyzmail.stress-test-password` | `explicit secret` | 启用前必须显式设置受保护密码；不要依赖历史 fallback。 |
| `lmyzmail.stress-test-count` / `lmyzmail.stress-test-warmup-count` / `lmyzmail.stress-test-warmup-rounds` | `5000 / 1000 / 2` | 正式轮数量、预热数量、预热轮数；/start 每次推进一轮。 |
| `lmyzmail.stress-test-email-size-kb` | `100` | KiB，限制 1..10240；大档位需预先设磁盘硬预算。 |
| `lmyzmail.show-internet-nl-badge` | `false` | Web 界面徽章开关。 |

### 配置兼容别名

完整可编辑样例见 [lmyzmail.properties.example](config/lmyzmail.properties.example)。例如 `lmyzmail.domains.main.domain=example.com`；添加域使用独立的 `<name>`，不要只更改 UI 显示值。

常规配置支持相应旧命名空间别名；下表列出不只是替换前缀的映射。同命名空间内，推荐的新键优先。域项还接受 `receiveEnabled/sendEnabled/requireExistingMailbox/dkimSelector/dkimPrivateKeyPath/listUnsubscribeMailto/listUnsubscribeUrl`，API key 接受 `readEnabled/writeEnabled`，honeypot 接受 `server-protocol`。列表可用形式以各表说明为准。

| 推荐键 | 兼容别名 |
| --- | --- |
| `lmyzmail.http.port` | `lmyzmail.netty.http.port; botmail.netty.http.port` |
| `lmyzmail.http.max-request-bytes / lmyzmail.http.max-multipart-bytes` | `lmyzmail.netty.http.max-content-length / lmyzmail.netty.http.max-multipart-size; botmail.netty.http.*` |
| `lmyzmail.http.trusted-proxies` | `lmyzmail.netty.http.trusted-proxies; botmail.netty.http.trusted-proxies` |
| `lmyzmail.http.request-timeout-ms` | `botmail.netty.http.idle-timeout-seconds (seconds → ms)` |
| `lmyzmail.postgres.url / host / port / database / username / password` | `spring.datasource.url / host / port / database / username / password` |
| `lmyzmail.postgres.pool.max-size` | `spring.datasource.hikari.maximum-pool-size` |
| `lmyzmail.redis.host / port / database / username / password` | `spring.data.redis.host / port / database / username / password` |
| `lmyzmail.redis.username / password / tls-enabled` | `spring.redis.username / password / ssl; spring.data.redis.ssl.enabled; lmyzmail.redis.ssl.enabled` |
| `lmyzmail.redis.pool.max-active` | `spring.data.redis.lettuce.pool.max-active` |
| `lmyzmail.outbound.dns.mx.l1-max-entries / l1-ttl-minutes / l2-ttl-minutes / negative-ttl-minutes` | `dns.cache.mx.l1-max-size / l1-ttl-minutes / l2-ttl-minutes / negative-ttl-minutes` |
| `lmyzmail.outbound.dns.query-timeout-seconds` | `dns.cache.mx.query-timeout-seconds` |
| `lmyzmail.outbound.spool-dir` | `botmail.outbound.temp-dir` |


## HTTP 接口

下表列出全部正常业务路由；诱饵路径另由前述 104 类资源处理。`public` 不要求会话；`session` 使用 `X-Session-Token`；`read/write` 使用具有相应权限的 `X-API-Key`。API key 不替代邮箱密码，也不会授予 Web 会话路由访问权。路径参数须按 URI component 编码，文件标识使用列表返回值，不能拼接任意磁盘路径。

| 方法 | 路径 | 认证 | 用途 |
| --- | --- | --- | --- |
| GET | `/`<br>`/index.html`<br>`/cringe.html`<br>`/favicon.ico`<br>`/images/embed-badge-emailtest-internet.nl.svg` | `public` | Webmail、风险面板、静态资源 |
| GET | `/api/health`<br>`/api/skibidi`<br>`/web/domains`<br>`/web/config` | `public` | 健康、banner、可用域名与公开能力配置 |
| POST | `/web/login`<br>`/web/register` | `public` | JSON address/password；注册受开关和限流约束 |
| POST | `/web/logout` | `public` | 提供 X-Session-Token 时撤销该会话；无 token 也可调用 |
| POST | `/api/status` | `read` | 服务状态 |
| POST | `/api/mailboxes` | `write` | 创建邮箱；JSON address/password |
| GET | `/api/mailboxes/{address}/exists` | `read` | 邮箱是否存在 |
| POST | `/api/mail/send` | `write` | 邮箱凭据与邮件 JSON，异步排队 |
| POST | `/api/mail/poll`<br>`/api/mail/raw`<br>`/api/mail/rawDecoded` | `read` | 须额外提交邮箱凭据；见下方字段 |
| GET | `/api/mail/status/{queueId}`<br>`/api/mail/status/message/{messageId}`<br>`/api/mail/quota` | `read` | 队列/Message-ID 状态；quota?address= |
| GET | `/api/reports/status`<br>`/api/reports/domains`<br>`/api/reports/addresses/{domain}` | `read` | 报告配置、?date=YYYY-MM-DD、RUA 地址 |
| POST | `/api/reports/trigger`<br>`/api/reports/domain/{domain}` | `write` | 生成/投递报告，可带 ?date=YYYY-MM-DD |
| POST | `/api/stress/start`<br>`/api/stress/reset`<br>`/api/stress/cleanup` | `write` | 执行一轮、重置轮次、清理压力测试数据 |
| POST | `/api/stress/status` | `read` | 注意是 POST，不是 GET |
| GET | `/api/xdp-firewall/status`<br>`/api/xdp-firewall/stats`<br>`/api/xdp-firewall/check`<br>`/api/xdp-firewall/whitelist/check` | `read` | 状态/统计；check 使用 ?ip= |
| POST | `/api/xdp-firewall/ban`<br>`/api/xdp-firewall/unban`<br>`/api/xdp-firewall/sync` | `write` | ?ip=，ban 可带 &reason=；sync 重建分数映射 |
| DELETE | `/api/xdp-firewall/clear` | `write` | 清空封禁；谨慎使用 |
| GET | `/api/cringe-ips/insults`<br>`/api/cringe-ips/export`<br>`/api/cringe-ips/above-score/{score}` | `read` | 分页搜索、导出、阈值筛选 |
| GET | `/api/cringe-ips/{ip}/activities`<br>`/api/cringe-ips/{ip}/decay-estimate`<br>`/api/cringe-ips/decay-config` | `read` | 活动、衰减预测与配置 |
| GET | `/api/cringe-ips` | `read` | 风险 IP 分页列表；支持评分/计数/时间/IP 排序、搜索及 XDP 状态 |
| GET | `/api/cringe-ips/stats` | `read` | IP/活动总数、历史/实时风险统计与衰减配置；当前风险活动使用直接写入模式 |
| GET | `/api/cringe-ips/{ip}` | `read` | 单 IP 评分摘要、XDP 状态及完整活动历史；不存在返回 404，超出资源上限返回 500 |
| POST | `/api/cringe-ips/decay` | `write` | 触发分数衰减 |
| GET | `/web/mail/list`<br>`/web/mail/list/{folder}` | `session` | page=0&size=50&starredOnly=false |
| GET | `/web/mail/detail/{folder}/{file}`<br>`/web/mail/raw/{folder}/{file}`<br>`/web/mail/headers/{folder}/{file}`<br>`/web/mail/attachment/{folder}/{file}/{index}` | `session` | 详情、原文、头、单附件 |
| POST | `/web/mail/send`<br>`/web/mail/send/multipart` | `session` | JSON 或流式 multipart 发信 |
| GET | `/web/mail/send/status/{queueId}`<br>`/web/mail/send/status/file/{fileName}`<br>`/web/mail/quota` | `session` | 本邮箱任务状态与配额 |
| DELETE | `/web/mail/{folder}/{file}` | `session` | 删除邮件 |
| POST | `/web/mail/star/{folder}/{file}`<br>`/web/userdata/stars/{folder}/{fileName}` | `session` | 切换星标 |
| GET | `/web/userdata/stars/{folder}` | `session` | 该文件夹星标 |
| GET POST | `/web/userdata/preferences`<br>`/web/userdata/contacts`<br>`/web/userdata/labels` | `session` | 读/写偏好、联系人、标签 |
| PUT DELETE | `/web/userdata/contacts/{id}`<br>`/web/userdata/labels/{id}` | `session` | 更新/删除联系人或标签 |
| GET | `/web/userdata/labels/email/{folder}/{fileName}` | `session` | 邮件已分配标签 |
| POST DELETE | `/web/userdata/labels/email/{folder}/{fileName}/{labelId}` | `session` | 添加/移除邮件标签 |


风险 IP 列表使用 `page=0`、`size=50`、`sortBy=currentScore`、`sortDir=desc`、`search=` 作为默认值；`size` 上限为 500。排序字段使用白名单，无效字段回退到实时评分；只有 `asc`（不区分大小写）选择升序。搜索不区分大小写并保留 `%`、`_` 通配符，返回原始 `searchQuery`，响应包含每条 IP 的 `xdpBanned`、`whitelisted` 和总页数/总条数。畸形分页参数返回 400。

统计摘要返回 `totalIPs`、历史分数 `>=50`、实时分数 `>=50`、实时分数 `>0` 及活动表真实行数；`decayConfig` 包含 ISO 周期字符串、减分量和每小时速率。当前活动直接提交事务，因此 `batchStats.running=false`，不存在的队列、缓存及批处理计数均为零。旧实现默认的批量写入模式及其五项配置尚未移植，已单列 G20，不能把零计数当成批量模式已实现的证据。统计和真实面板验证见[统计记录](docs/cringe-stats-validation-20261024.md)，列表契约见[列表记录](docs/cringe-list-validation-20261024.md)。

单 IP 详情返回 `summary` 和按时间降序的 `activities`，不使用分页接口的 500 条上限。为兼容历史数据，先去掉地址中的控制字符、百分号编码残片及两端 ASCII 空白查询，未命中时回查原始值；活动始终按命中的存储原值查询。详情限制为 10000 条活动、8 MiB 活动 JSON、四个并发响应；超限在返回成功 header 前明确报错，不截断历史。更大的历史请使用分页活动接口。此资源保护与旧行为的差异及详情页面的真实验证见[详情记录](docs/cringe-detail-validation-20261024.md)。

已实现的 insults 列表支持 `page`、`size`、`search`；导出使用 `minScore`、`scoreType`。用户数据 JSON 字段见[用户数据类型](crates/lmyzmail/src/userdata.rs)，Web 界面使用同一接口。

### 请求示例

先在受保护配置中加入管理 key（下面仅为格式，必须替换），重启生效：

```properties
lmyzmail.api-keys[0].key=REPLACE_WITH_A_RANDOM_SECRET
lmyzmail.api-keys[0].label=operations
lmyzmail.api-keys[0].read=true
lmyzmail.api-keys[0].write=true
```

调用方从自己的秘密存储设置 `API_KEY`。创建邮箱；密码至少 8 个 UTF-16 code unit，示例不是正式凭据：

```bash
curl --fail-with-body http://127.0.0.1:8080/api/mailboxes \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data '{"address":"alice@example.com","password":"REPLACE_WITH_MAILBOX_PASSWORD"}'
```

向 `POST /api/mail/send` 提交以下 JSON（配合 API key）。`to/cc/bcc` 是地址数组，`inReplyTo/references` 可选；`attachments` 的内容为 Base64，MIME 编码会增加邮件总大小：

```json
{
  "from": "alice@example.com",
  "password": "REPLACE_WITH_MAILBOX_PASSWORD",
  "to": ["bob@example.net"],
  "cc": [],
  "bcc": [],
  "subject": "Hello",
  "text": "Hello from lmyzmail",
  "html": "<p>Hello from lmyzmail</p>",
  "attachments": [{
    "filename": "note.txt",
    "contentType": "text/plain",
    "contentBase64": "SGVsbG8K",
    "inline": false,
    "contentId": null
  }],
  "async": true
}
```

`POST /api/mail/poll` 接受 `address,password,sinceEpochMillis,limit`；`/api/mail/raw` 接受 `address,password,file`；`/api/mail/rawDecoded` 再接受 `html`。这些兼容 raw API 保留 32 KiB 原文上限，完整邮件和附件应使用会话下载接口，不要认为消息总大小设置会取消这个上限。

`POST /web/login` 提交 `{"address":"alice@example.com","password":"…"}`，返回的 `token` 放入 `X-Session-Token`。会话发信不需要再次传邮箱密码；服务从会话确定发件身份。大附件建议使用流式 multipart，`data` 是邮件 JSON，文件字段名必须为 `attachments`：

```bash
curl --fail-with-body http://127.0.0.1:8080/web/mail/send/multipart \
  -H "X-Session-Token: $SESSION_TOKEN" \
  -F 'data={"to":["bob@example.net"],"subject":"Report","text":"Attached"};type=application/json' \
  -F 'attachments=@report.pdf;type=application/pdf'
```

成功受理为 `202` 不表示已送达，应查询 queueId 或 messageId 的状态。错误沿用路由约定：`400` 无效输入、`401` 凭据/会话无效、`403` 权限/封禁、`404` 不存在、`413` 超限、`429` 限流、`500/503` 后端或容量问题；读取错误 JSON 的 `error`，不要把所有非 200 都当作可重试。

## 运维与故障处理

- **启动失败：**先查 journal、目录属主/权限、端口占用、数据库 schema 和 Redis ACL。主配置能通过解析不代表数据库可达。SMTP 25 需要低端口能力；XDP 需要单独权限。不得并行启动两个服务去“试试看”同一存储。
- **邮件排队：**按 queueId/Message-ID 查状态，再核对 MX/DNS、出站 TCP 25、TLS/MTA-STS、配额、租约和重试时间。保持 Sent/spool 与原队列记录，不要直接删除某一侧使“待处理数归零”。
- **容量和背压：**同时监控 RSS、FD、任务、队列深度/最老任务、延迟/错误、PostgreSQL 连接和锁、Redis 内存/延迟、Maildir/spool 字节与 inode。并发上限、配额、连接池、deadline 分别限制不同资源，单独调大一个参数不保证吞吐提升。PG/Redis/Maildir 均应部署在合适的持久存储上。
- **耐久性：**默认 fsync=true。false 面向明确接受丢失风险的部署或与无 fsync 行为对齐的 benchmark；它不是数据库“异步提交”开关。备份和稳定性验收不能只测关闭 fsync 的路径。
- **退出与恢复：**用 `systemctl stop lmyzmail` 或 SIGTERM，让有界 shutdown 完成；进程总退出 deadline 为 35 秒。强杀后重启会校验并恢复，但故障注入全部边界的验收仍见剩余清单。保留恢复/隔离诊断，不要手工清空 intent 或 quarantine 目录。
- **模型/视频失败：**查资源路径、权限、hash、模型 metadata、CPU backend 与期限。InferX fallback 不等于模型健康。配置文件、模型和证书改变后重启。
- **升级：**备份后重跑安装器，配置保留，资源原子替换；升级后检查保留的配置并显式启动。保护旧二进制和配置，未验证前不移除旧版本资产。
- **卸载：**`sudo tools/uninstall-lmyzmail.sh` 要求成功停止服务后才移除托管二进制/unit。保留配置、PG/Redis、Maildir/spool、日志、模型/视频、用户和 BPF pins。无法停止或 XDP detach 失败时拒绝继续；卸载不是数据清理。

没有承诺 Prometheus 指标或通用在线配置修改接口；目前通过 API、journal 与外部资源采集观察状态。高压基准与日常运行不要混用数据库或目录。内建 `/api/stress/start` 自发自收真实邮件，每次执行一轮；`reset` 重置轮次，`cleanup` 清理该压测拥有的数据。正式吞吐基准是一轮完整调用而不是 harness 分批；资源硬预算和完整审计由[外部测试器](blackbox/src/lmyzmail_blackbox)负责。

## 兼容数据接管与回滚

保留已有 PostgreSQL 表与事务语义、Redis key/TTL、Maildir 字节、证书、模型和受支持配置别名。新增 `lmyzmail_*` 恢复表不改变原业务列，回滚时保留它们。接管前一致备份 PG、Redis、完整 Maildir/spool、配置、证书和模型，停止旧服务并禁止 supervisor 自动重启。**两个出站 worker 不能同时使用同一队列。**

普通既有地址可直接接管；含下划线、连续点、字面 v1- 或 Unicode 等地址涉及历史路径别名，必须按[Maildir 所有权与接管说明](docs/maildir-takeover.md)处理。对多个真实邮箱发生冲突的有损旧别名，服务拒绝不安全的映射，不复制漏洞。若回滚到旧读取器，新编码邮件使用[只复制、带 fsync 的离线 exporter](docs/maildir-offline-rollback.md)导出到新目录，不覆盖源树；保留原绝对 spool 路径，PENDING 文件任务可能引用它。

特殊兼容行为还包括 InferX 的有效 120 token / 单 worker / 外层 fallback、SMTP `BDAT 0 LAST` 的历史确认与丢弃语义、raw API 的 32 KiB 限制。完整已批准差异见[兼容性记录](docs/compatibility.md)。概率生成器按 C 源码这一项是明确的行为选择。以上说明不宣称全部 in-flight 崩溃接管边界已通过。

## 构建与验证

源码包含固定 native 来源、第三方基础库、模型、资源、测试、golden 与证据。Rust toolchain 固定 **1.94.0 stable**，目标 `x86_64-unknown-linux-gnu`，依赖使用 `Cargo.lock`。C/C++、Clang **18.1.3**、pkg-config、libbpf/libelf、zlib/OpenSSL、Cairo/FreeType 开发包是构建依赖，FFmpeg 7.1 由仓库固定源码构建。生产运行不需要 oracle。

```bash
rustup show
LMYZMAIL_BPF_CLANG=clang-18 cargo build --release --locked \
  --target x86_64-unknown-linux-gnu -p lmyzmail
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
tools/test-installation.sh
tools/verify-release-reproducibility.sh /absolute/path/to/new-verification-output
```

测试器为 Python 3.12/pytest、raw sockets 和 Playwright，独立启动隔离端口、临时目录和 PG/Redis。`blackbox/bin/bootstrap-python.sh` 安装固定依赖，`provision-runtime.sh` / `provision-playwright.sh` 准备验收运行时；oracle 只用于开发差分。具体完整运行条件与证据见[本机验证记录](docs/local-validation-20261023.md)，不要对生产库运行测试。

已有证据覆盖 HTTP/UI/权限/附件、安全回归、SMTP 入站/出站/MIME/重试/报告、Redis/PG/Maildir、调度/重启、HTCPCP、Minecraft、诱捕、模型和渲染；长时负载、模糊/故障输入及全部要求按 feature→evidence 清单逐项核对，不能用单个 test 总数替代覆盖证明。历史 golden 不改写；只归一化真实非确定值，失败记录保留。

进一步参考：[队列](docs/outbound-queue-contract.md)、[选路](docs/outbound-route-contract.md)、[报告触发](docs/reporting-trigger-contract.md)、[HTTPS 报告](docs/reporting-https-contract.md)、[SSH 监控](docs/fail2ban-contract.md)、[发布](docs/release.md)、[验收状态](docs/acceptance-status.md)。旧证据中的 SHA 保留原值，身份统一后的对应关系见[历史映射](docs/git-identity-migration-20261023.md)。
