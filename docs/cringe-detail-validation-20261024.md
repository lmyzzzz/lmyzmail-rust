# 单 IP 详情与面板活动历史（2026-10-24）

本次处理 G19：`GET /api/cringe-ips/{ipAddress}`。开发基点为
`d5dc6ce44a70689c96d556ec2e75fbae5f0b6e5b`，两个冻结旧仓库保持只读。
默认批量活动写入 G20、此前记录的单连接池恢复问题 G21 仍是独立任务。

## 查询与响应契约

- 在数据库 admission 前检查 `read` 权限：无 key 为 401，仅写 key
  为 403，admin/read-only 可以查询；无匹配地址为 404 not_found。
- 路径先进行 URI 解码，`+` 保持加号；编码的斜杠仍是路由分隔符，
  无效 UTF-8 按冻结 Netty 的替换字符行为处理，不额外规范化 IPv6。
  不完整/非十六进制百分号返回 500 internal_error，发生于权限检查前。
  Java 会将编码代理区字符（包括两字节截断前缀）归为一个替换字符，
  与 Rust 标准 lossy 解码分组不同；窄兼容 helper 保留实测分组，
  不吞掉后续非 continuation 字节，不增加 unsafe。
- 先删除控制字符，再删除 `%` 后零到两个十六进制字符，最后去掉
  两端不大于 U+0020 的字符。两个删除步骤不能合并：`%<TAB>32`
  必须先成为 `%32` 再被删除。NBSP 等 Unicode 空白不因此被删除。
- 优先查询清洗值，未命中且值有变化才回查原值。两种身份同时存在
  时清洗值优先。活动查询使用最终命中的数据库原始身份，不能从
  清洗值拼接或混入另一身份的历史；只读请求不修改任何分数或活动。
- 保留独立 READ COMMITTED 查询；不新增快照事务或 schema。返回
  `summary`、`activities` 的顺序、摘要 DTO、可空字段省略、空字符串、
  微秒时间、活动按 timestamp 降序及 JSON 字节均由 oracle 约束。
  不增加同时间活动的额外排序键。摘要的两项 XDP 状态查询使用清洗
  后的存储地址，数据库连接在 XDP 查询与网络输出前已归还。

## 有证据的资源差异

冻结 Java controller 调用无分页的活动列表，再整体序列化。新增的
独立边界 golden 证明它返回 10001 条活动，以及 1600 条含转义 metadata
的 10051676 字节响应。来源为冻结 commit
`5dac2ab2922c30c726c4a83d7626c95ad4e231c8`；controller SHA-256
`59fa65284de9f2820956aed0bc5fe19b69114d21951962986b867822302ad621`，
service SHA-256
`392c021dcc834005d6e08188d1aed03ca68399ceb665755c4f445ddd19644675`。

候选详情允许最多 10000 条活动、8 MiB 编码活动 JSON。使用 RowStream
逐行编码，只持有一行临时 DTO/JSON 和有上限的响应 buffer；不再整体
复制活动集合。LIMIT 多读一行检测超限，字节检查为右方括号预留空间。
超限在任何成功 header 前返回 500 internal_error，绝不静默截断。
更大的历史通过原分页活动接口取得。容量失败会丢弃未完成 RowStream
所属的连接，避免将未完成查询交给下一借用者。

每个运行服务最多保留四个详情响应，permit 贯穿数据库读取、XDP 查询
及受背压的 socket 输出。admission、池等待和所有查询共用八秒绝对
deadline，之后沿用取消、最多两秒 drain 或丢弃连接；网络输出还受
既有 HTTP request deadline/断连取消约束。没有新增无界队列、后台任务
或 unsafe。差异白名单只覆盖资源溢出/饱和边界，不豁免正常响应兼容。

## 外部测试与 immutable golden

[`test_candidate_cringe_detail_golden.py`](../blackbox/tests/test_candidate_cringe_detail_golden.py)
自建隔离端口、PostgreSQL/Redis、Java oracle 或 Rust candidate。

- 43 个接口观察：IPv4/IPv6/大小写、缺失身份、空历史、null/空字符串/
  中文活动、控制/百分号清洗、原值回查、清洗身份优先、原值活动绑定、
  URI 中加号/空格/问号/井号/无效 UTF-8/斜杠、SQL 文本与权限。
  额外覆盖四种畸形百分号、无 key/仅写 key 的解码失败、代理区编码/
  截断/后接 ASCII/非法字节/两个代理区字符、多字节截断、overlong 和
  超过 Unicode 最大值的编码，区别一至四个替换字符的真实存储身份。
- 501 与 10000 条历史都必须完整返回，核验首尾、总数及全部响应的
  SHA-256 和长度；不是只验证前 500 条或几个实体字段。
- 只读 key 通过真实 API 连接面板，点击 IPv4 四条历史、关闭、点击
  IPv6 空历史、再关闭；核验文本、外链、请求及两幅 PNG 原始字节。
  固定 Chromium 1181、Vue/fonts fixture、zh-CN/UTC、1440×1100。
  仅阻止两个外部 geo 服务请求，应用 API 不 mock。
- Rust 独立安全测试涵盖行/字节超限及恢复、24 次并发、四个慢读
  响应占满名额后的第五个请求超时、断连释放、两表排他锁/超时/权限
  快速拒绝/恢复，以及已实际等待活动表锁的客户端断连后无遗留查询。

所有成功接口字节不归一化；沿用 HTTP Date、已举证的 JDK Map.of
权限错误字段顺序例外。大历史只存整段 wire 的长度/hash，未截断待比较
响应或修改 golden。最终原件为 `managed-cringe-detail-v5-{api,history,boundaries,ui}`。
v1 的非法 enum fixture、v2 的重复显示身份导致浏览器 locator 不唯一，
失败日志及已创建 suite/观察全部保留；修正夹具和 locator 后使用新目录。
v3/v4 的录制及 campaign 同样保留，追加 malformed URI 和 Java UTF-8
分组证据使用新 v4/v5 原件，没有覆盖或修改任何既有观察。

日志位于
[`evidence/compatibility/cringe-detail-20261024`](../evidence/compatibility/cringe-detail-20261024)。
`pre-fix-status.log` 独立记录旧 ELF 的实际 404；`pre-fix-404.log`
保留新契约在旧 ELF 上失败的结果。最终原件录制 v5 四项通过；随后
`oracle-campaign-v3.log` 重新运行 12 项全部通过，39 个历史观察/资源
相同，6945 个原始 golden 文件未变。harness definition SHA-256 为
`e796e65d8ba4d718084df1b2178f1bb1803e7064ef91465cca6194e428d0ae7e`。
Java JAR SHA-256 为
`fe2d8fcefad9a4127398eeb5d911805ea10a8dce75ec70912fd3be909c8fbdfc`。

`product-tests-v6.log`：lmyzmail crate 的 883 项 Rust 测试通过，零失败/
忽略，含新增路由/权限例及 1024 组随机 Unicode 路径/清洗属性测试。
早期类型参数/借用错误及属性断言宏编译错误的日志保留。strict workspace/
all-target Clippy 通过，六项存储 manifest 检查通过。

`uri-mutation-fuzz.log`：最终候选接受 4096 个固定 seed 的外部 raw-socket
URI 变异请求，含随机字节、百分号插入和边界碎片；200/404/500 分别为
13/2598/1485。66 次正常请求保持完整响应相同，数据库两表不变，二进制
hash 不变。工具为 `tools/fuzz-cringe-detail.py`。这是有界解析/隔离 smoke，
不替代正式多模块 soak 或吞吐基准。

受测 ELF 为 `.blackbox/cringe-detail-20261024-v3.elf`，SHA-256
`94bd9883d4e24ccd34583c37be1d701fc23220f3dcef94c9137ab12b84dd921c`。
固定 Rust 1.94.0/Cargo.lock release 构建见 `release-build-v3.log`，
本轮没有重新封装现有发行包或宣称全局 goal 完成。

`candidate-campaign-v3.log`：最终 18 项全部通过，包含详情三组差分/
安全边界、G18 三组及并发/锁恢复、G17 列表、原风险 API/衰减/导出/
取消、XDP disabled 与旧 Webmail UI。39 个历史观察/资源相同，6945 个
原始 golden 文件未变；钉住 ELF 与默认 target 的 SHA-256 在测试前后
均保持一致。`readme-final-check.log` 记录三语言配置键/示例、路由、
链接与围栏检查通过。两张 `oracle-detail-*.png` 是保留的浏览器观察
导出图；最终 Java/Rust 仍逐字节比较各自当场生成的截图。

## 扩大回归中的既有失败

`candidate-campaign-v1.log` 的初版候选为 17 通过、1 失败：新详情的
接口/历史/UI/限额与恢复四项全部通过；旧统计锁超时测试在读取 HTTP
响应时收到 EOF，而非预期的 500。这次失败与先前 G21 的超时后首个
健康请求失败是否同因尚无证据，故 G21 扩充记录该现象并保持未完成。
后续回归即使通过，也不能抹去该失败或据此宣称偶发问题已修复。

`uri-malformed-probe*.log` 与 `uri-utf8-probe.log` 保留新增解析修复前
Java/Rust 不同响应的独立证据。所有对应断言保持严格，没有放宽或跳过。
