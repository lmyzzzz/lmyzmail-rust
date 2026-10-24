# 风险 IP 分页列表修复验收（2026-10-24）

本次范围为 G17 的 `GET /api/cringe-ips` 数据接口。统计摘要 G18、IP 详情
G19 及完整面板连接流程仍是独立缺项，不据此宣称整体 goal 完成。

## 实现与兼容行为

- 接入实际 HTTP 路由和 `read` 权限校验；默认 page=0、size=50、
  sortBy=currentScore、sortDir=desc、search 为空，单页最多 500 条。
- 17 个排序字段映射到静态 SQL 标识符；搜索使用 PostgreSQL 参数，
  大小写不敏感，保留 `%`、`_` 通配符，反斜杠按普通字符处理。
  非法排序字段回退 currentScore，方向保持冻结实现的大小写折叠行为。
- 空参数采用默认值，重复参数采用第一个值；搜索遵守原有 isBlank/trim
  差别，同时原样返回 `searchQuery`。不额外添加改变并列项顺序的排序键。
- `content/page/size/totalElements/totalPages/searchQuery`、DTO 字段顺序、
  计数、时间精度及 null decay 字段省略均保留；不额外输出
  `protocolMismatchCount`。原始 IP 字段不改写，只清洗用于查询 XDP 的地址。
- 有效但偏移超过 signed-int 范围的分页请求保留冻结 ORM 的 500 响应，
  在获取数据库连接前处理。负页、非正 size、整数溢出及畸形整数返回
  400 `invalid_request`，对应已有的 `cringe-pagination-input-validation`
  安全差异白名单及新增的独立 Java 边界证据。
- PG 连接获取、分页与计数共用 8 秒 deadline，取消后执行取消/排空或
  丢弃连接。XDP 每页只进入一次原有有界专用池（1 worker、64 队列），
  批大小硬上限 500；未就绪时两项状态均 false，非法历史 IP 不使列表失败。
  没有新增 unsafe、原生库修改或数据库 schema 修改。

## 冻结来源与证据

开发基点为 `47f1c05ed6ef3dc2c0d68e93f7ff7f1c55b659df`。两个旧仓库
保持只读。oracle 来自已有冻结 manifest：commit
`5dac2ab2922c30c726c4a83d7626c95ad4e231c8`，JAR SHA-256
`fe2d8fcefad9a4127398eeb5d911805ea10a8dce75ec70912fd3be909c8fbdfc`。

专项黑盒测试是
[`test_candidate_cringe_list_golden.py`](../blackbox/tests/test_candidate_cringe_list_golden.py)。
它先录制新的
[`managed-cringe-list-v1`](../blackbox/golden/java/managed-cringe-list-v1/suite.json)
及[边界证据](../blackbox/golden/java/managed-cringe-list-v1-boundaries/suite.json)，
未覆盖任何旧 golden。主场景包含 57 组观察：默认、只读/仅写/缺失 key、
空集、首/尾/越界页、size 上限、17 种排序的两个方向、非法排序回退、
搜索大小写/通配符/SQL 文本/Unicode 空白、IPv6、历史控制字符/百分号 IP、
null decay。成功 JSON 的字节及数组顺序精确比较；只沿用已举证的 API-key
错误对象成员顺序归一化及 HTTP Date 处理。

额外的双端测试覆盖空值/重复参数、反斜杠搜索和 Unicode long-s 方向折叠。
candidate 独立测试在 505 行 fixture 上核验 500/5/0 三页、总条数/总页数，
在单连接池下并发 24 次读取，并强持表锁验证无效请求无需等待数据库、
约 8 秒取消、后续成功复用连接且没有遗留 active 查询。GET 前后对所有
fixture 行作完整比较，证明没有修改评分、计数或时间。

有界 XDP cache 单元测试覆盖 banned=true、IPv4/IPv6 CIDR whitelist=true、
重复项、非法项、500/501 边界、取消和未就绪状态；它不是新的内核挂载证据。
本次不改变原生 XDP 代码。

## 保留的失败与复验

所有本轮日志位于
[`evidence/compatibility/cringe-list-20261024`](../evidence/compatibility/cringe-list-20261024)。

- `pre-fix-404.log` 使用原 ELF
  `78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790`
  复现带有效读 key 的 404。
- `query-edges-before-like-fix.log` 保留早期构建对空参数错误返回 400 的失败。
- `candidate-campaign-v3.log` 保留 9 通过、1 失败：唯一差异是极大 page
  对应的 ORM 偏移范围限制；没有删除该断言或改写 golden，随后在产品中对齐。
- `rust-tests.log` 保留首次 workspace 测试中 benchmark 工具的 BDAT
  calibration smoke 偶发 ENOENT；`proxy-repeat.log` 的工具测试复验全过
  （67+5+13）。复验通过不宣称该偶发问题已消除，也不关闭 G01/G02。
- `oracle-campaign-v3.log`：5 通过，25 个历史观察/资源完全一致，6901 个
  原始 golden 文件保持原字节。该 6901 包括本轮新增的 4 个列表 golden；
  更早的 6897 个文件同样未改。v1/v2 campaign 与失败证据全部保留。

## 最终本机结果

- `product-tests-v4.log`：881 项产品 Rust 测试通过，零失败/忽略；包含
  属性测试、HTTP 解析、XDP batch、实际 PG/Redis/文件及协议回归。
- `clippy-v4.log`：workspace/all-targets 严格 Clippy 通过。
- `release-build-v4.log`：固定工具链与 lockfile 的 release 构建成功。
- `candidate-campaign-v4.log`：10 项通过，57 组列表观察与当前冻结 Java
  campaign 完全一致；同时通过原有 cringe API、衰减、错误/权限、查询取消、
  XDP disabled 与 Playwright UI golden 回归。原 golden 与像素资源未改。
- `hashes-v4.txt`：最终受测 ELF SHA-256 为
  `fe707de8fe38d61794a502f437372314c873721dc47a6c7b80f1c8ba43f7a860`；
  测试前后外部钉住副本与默认 target ELF 均保持该值。源文件摘要也一并记录。
- 三语言 README 的 273 项配置键/示例要求、路由、链接和代码围栏检查通过。

这些结果关闭本次列表数据接口缺口；不替代整体 goal 的正式压测、AVX-512、
最终覆盖矩阵、封版与交付验收，也不关闭下述完整面板集成限制。

## 验证命令

Rust 使用仓库固定的 stable 1.94.0、Cargo.lock 和 Linux x86_64 target。

```sh
cargo test -p lmyzmail --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p lmyzmail --bin lmyzmail
```

黑盒复验使用 `LMYZMAIL_GOLDEN_CAMPAIGN=cringe-list-20261024-v3`、
`PYTHONPATH=tools:blackbox/src` 和 `-p release_campaign`。先以冻结 Java
重新录制独立 campaign；再由 `tools/pytest-release.py` 钉住实际 ELF，
在相同 campaign 下验证列表、既有 cringe API、XDP disabled 及 UI golden。
插件仅改变新证据保存位置，原断言不变，另外核验历史观察、像素资源和
旧 golden 未被改写。

## 剩余限制

面板的 `fetchData` 先请求 `/api/cringe-ips/stats`，成功后才请求列表。
G18 尚未实现，因此本次不声称完整面板可登录或列表交互已验收；不通过 mock
统计响应隐藏这个缺口。UI golden 复验仅证明既有受测页面状态/像素没有回归。
G18 完成后还需真实连接、排序、搜索、翻页及详情交互验证。

本轮只产生局部修复和本机测试 ELF。原发布包及其校验和保持不变；完整封版、
全量验收和最终 Windows 工作目录交付仍按 G15/G16 执行。
