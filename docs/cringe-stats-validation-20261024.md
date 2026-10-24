# 风险 IP 统计与面板连接修复（2026-10-24）

本次补齐 G18 的 `GET /api/cringe-ips/stats` 成功处理器，解除 G17
面板连接/列表交互的阻塞。单 IP 详情 G19 仍未实现；默认批量写入模式
另列 G20，本次没有将直接模式的验证扩大为批量模式完成声明。

## 实现及已验证契约

- 与其他风险查询相同的 `read` 权限；缺失 key 返回 401、仅写 key
  返回 403，admin/read-only 可以查询。权限在获取 PG 连接前检查。
- 按冻结服务的顺序执行五次独立 READ COMMITTED 计数：IP 总数、
  累计分数 `>=50`、实时分数 `>=50`、实时分数 `>0`、活动表真实行数。
  不用汇总表的 `activity_count` 之和代替活动表计数，也不引入快照事务。
- 保留 `totalIPs` 的大小写、七个顶层字段及嵌套字段顺序和成功 JSON
  字节。`decayConfig` 返回 ISO 字符串（默认 `PT24H`），减分量和每小时率。
  与独立 decay-config API 的数值 duration 表示不同，不能混用 DTO。
- 数据库 admission 与五次查询共用 8 秒绝对 deadline，取消后沿用
  cancel/drain 或丢弃连接机制。每次只物化一个 count 行，没有逐 IP
  加载、内存缓存、无界任务、新 unsafe 或 schema 改动。

## 批量模式边界：G20 保持未完成

冻结 Java 的批量写入默认开启；现有黑盒启动器明确设置
`--botmail.cringe.batch.enabled=false`。候选的活动生产者目前直接等待
各自事务及 COMMIT reconciliation，没有批量 worker、待处理分数 map
或分数 cache。因此当前真实状态为 `running=false`，不存在的队列及
批量/缓存计数为零；这些计数并非活动数据库总量或即时写入总量。

本轮独立只读启动 Java 批量模式，实测 `running=true`，证据见
`mode-boundary-probe-v2.log`。此差异不是安全例外，也没有加入允许差异
白名单。G20 仍要求移植 enabled、size、flush-interval、max-queue-size、
shutdown-timeout 及其新键优先别名、真实有界批量事务/状态、即时 XDP、
故障和关机排空语义，并先建立 batch-enabled 黑盒 golden。直接模式
golden 不能关闭该项，整体 G18 兼容仍受其限制。

## 新增外部测试

[`test_candidate_cringe_stats_golden.py`](../blackbox/tests/test_candidate_cringe_stats_golden.py)
使用隔离 PG/Redis 和冻结 oracle JAR，自建运行环境，不依赖旧 smoke 实例。

- 默认与自定义衰减周期两组独立 golden，各自覆盖空库、六行双评分
  fixture、五条活动、四种权限。评分取 -1/0/1/49/50/51，累计与实时
  独立，故结果为 6/2/2/4/5；聚合活动计数故意与真实活动行数不同。
  自定义值为 `5400001ms`、7，candidate 同时提供冲突旧键验证新键优先。
- 单连接池并发 24 次统计查询；分别持 IP 表和活动表排他锁，验证
  403 无需等待数据库、约 8 秒后 500、解锁后恢复，最终无遗留 active 查询。
- Playwright 使用固定 Chromium、Vue CDN fixture、zh-CN/UTC 与
  1440×1100 viewport。应用请求全都发往实际进程，未 mock 统计、列表、
  XDP 或衰减 API。真实点击只读 key 连接，核验统计卡、21 行两页、排序、
  IPv6 搜索、空结果、断开和 localStorage 清理；比较 DOM 文本、请求
  序列与连接页面 PNG 字节。未调用缺失的详情接口或外部 IP 地理服务。

成功响应不做 JSON 字段/数值归一化；权限错误只沿用已举证的 JDK
Map.of 字段顺序归一化。UI 只固定端口、时区/语言/viewport 和动画。

## 冻结来源与可追溯证据

开发基点 `bd861a433941a24ad16331b61cfe9019c65ca605`。两个冻结旧仓库
保持只读。Java commit 为 `5dac2ab2922c30c726c4a83d7626c95ad4e231c8`，
JAR SHA-256 为
`fe2d8fcefad9a4127398eeb5d911805ea10a8dce75ec70912fd3be909c8fbdfc`。

原始 golden 是 `managed-cringe-stats-v2-{default,custom,dashboard}`，
全部由 Java 录制。v1 夹具错误地假设物理列顺序，三项失败记录和已创建
suite 均保留；修正为显式列名后用新 v2 路径录制，没有覆盖原件。

本轮日志保存在
[`evidence/compatibility/cringe-stats-20261024`](../evidence/compatibility/cringe-stats-20261024)。
`pre-fix-404.log` 保留旧 ELF 的失败；`mode-boundary-probe-v2.log`
记录旧 ELF 的实际 404 及 Java 批量状态。首次批量探针重复传入布尔
属性被 Spring 拒绝的日志也保留，修正启动参数后重新运行。

`oracle-campaign-v1.log`：7 项通过，28 个历史观察/资源相同，6910 个
原始 golden 文件不变（包括本次新建的 suite 和观察）。harness definition
SHA-256 为 `1ff47b6157eb2492aab3414937cdd5d2a28078341a8b0019cb00159411d36b14`。
新 campaign 只重新认证测试器定义；原 golden、断言及像素没有更改。

## 本机验证

- `product-tests.log`：881 项产品 Rust 测试通过，零失败/忽略。
- `clippy.log`：workspace/all-targets 严格 Clippy 通过。
- `release-build.log`：固定 Rust 1.94.0/Cargo.lock 的 Linux x86_64
  release 构建通过；本轮未重新封装已有发行包。
- `candidate-campaign-v2.log`：14 项全部通过，含新统计三组、统计并发/
  两表超时恢复、G17 列表、原风险 API/衰减/限额、XDP disabled 及旧
  Webmail UI golden。31 个历史观察/资源相同，6910 个原始 golden 文件
  不变。测试前后两个 ELF 的 SHA-256 均不变；本次通过不消除下述 G21。
- `readme-check.log`：三语言 README 的配置键/示例、路由、链接与
  代码围栏检查通过。
- 受测 ELF SHA-256：
  `0f65c82c2f0ffd2990fdec00a5f9baea6e8a381342ef9609750442794fb73302`。
  `.blackbox/cringe-stats-20261024-v1.elf` 是独立钉住副本，接受测试时
  同时校验默认 target 文件，防止构建过程替换被测二进制。

## 扩大回归中的失败记录

`candidate-campaign-v1.log` 为 12 通过、2 失败。新统计三组及统计并发/
锁恢复都通过；失败分别是旧 above-score 首次锁超时后的正常请求返回
500，以及未给 XDP disabled profile 补录本轮 campaign。随后
`oracle-xdp-campaign.log` 补录真实 Java，1 项通过，campaign 的历史
观察/资源累计 31 项一致，原始 6910 文件仍保持原字节。

连接池问题不能归结为漏录：`pool-recovery-repeat.log` 单项通过，但
`pool-recovery-diagnostic.log` 六轮首轮复现正常请求再等待约 8 秒后
500，后五轮正常；同时记录 SMTP projection audit / DSN 维护的池
超时。另一个保留 PG activity 的双轮探针通过，恢复后观察到连接 idle。
这些仅证明间歇性失败及后续可恢复，尚不能证明原因是取消竞态或维护
争用。新增独立 G21，未降低原断言、添加重试掩盖问题或宣称已经修复。

本轮不运行性能调优或正式 SMTP 重压，也不据此关闭 G01/G02、AVX-512、
大量邮件稳定性、最终封版或整体 goal。历史发行包及其验证结论保持原样。
