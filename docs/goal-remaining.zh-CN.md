# Goal 剩余工作清单

截至 2026-10-23。这是未关闭验收项的工作分解，不是完成声明。每个编号对应可单独领取、修复、验证的任务；依赖列决定执行顺序。重型 benchmark 在同机必须串行，避免相互干扰；源码/证据整理和异机 SIMD 验证可并行。

当前产品候选的 ELF SHA-256：`78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790`。历史证据里的提交 SHA 保留原值，统一作者后的 SHA 通过[映射表](../evidence/history/identity-20261023/commit-map.tsv)解析。

## 已有证据，不重复列为缺项

- 当前产品 961 项 Rust 测试和 strict Clippy 通过。
- fresh Java 107 项加独立 RBL，以及 candidate 126 项、188 项不重叠检查加独立 RBL 通过；6897 个历史 golden 不变，346 项新观察匹配。
- Scalar/AVX2 邮件与 Minecraft 的 wire/pixel/frame golden、实际分派和本机性能有证据；XDP 的实际 attach、IPv4/IPv6 封禁/放行、重启和清理已通过。
- 两个独立 target 的冻结构建生成相同 ELF，安装、升级、配置保留、卸载和版本化 Windows 包已验证。
- 真实 PG/Redis/Maildir 双向接管、四类特殊邮箱名、只复制的 fsynced 离线回滚导出，以及 PENDING memory/file 模式队列双向交接已有证据。
- 隔离的半小时、16 worker 多模块 soak 已通过：1800.152 秒、269344 次操作、零失败；RSS 峰值 412112 KiB、稳态增长 192 KiB，FD/任务稳态增长零，磁盘增长 5787648 字节，清理完成。它不能替代大量邮件落盘验收。

详见[本机验证](local-validation-20261023.md)、[发布验证](release-22dae7d0-validation.md)、[接管与回滚](maildir-takeover.md)和[完整历史验收记录](acceptance-status.md)。

## 独立工作项

| ID | 独立任务 | 依赖 | 关闭条件 |
| --- | --- | --- | --- |
| G01 | 使实际产品的 observer 校准可重复通过 | 无 | 保留当前 1% spread、因果开销、比例和快照一致性约束，定位环境/观测方差来源并取得全部实际校准通过证据。不能放宽阈值、选取最好轮次或把 gate off/on 当作 fsync off/on。 |
| G02 | 解释或修复校准收尾的 publication-intent / quarantine ENOENT | 无；可与 G01 的分析并行 | 定点复现并关联任务、文件/inode、事务和 shutdown 时间线；有证据证明预期状态转换，或修复真实恢复竞态后通过回归。不能仅凭消息计数全到齐认定无害。 |
| G03 | 完成 1 KiB、fsync-off 正式 SMTP 轮次 | G01；若 G02 涉及产品正确性则先关闭 G02 | 原 HTTP 压测端点单次 250000 封，无 harness 分批；合格后同进程、不重启再 100000 封，后轮吞吐至少首轮最初 100000 的 90%。全量身份、落盘、索引、重试/失败、资源和清理审计通过。 |
| G04 | 完成 10 KiB、fsync-off 正式 SMTP 轮次 | 同 G03；与其他重压轮次串行 | 与 G03 相同的 250000 + 100000 规则；按同机相同资源限制与 Java 稳定窗口比较。记录实际吞吐，不能用 9950X 的历史成绩替代本机基线。 |
| G05 | 完成 1 KiB、fsync-on 正式耐久轮次 | 同 G03；与其他重压轮次串行 | 同样 250000 + 同进程 100000；fsync 全程启用，证明无丢失、重复、泄漏、崩溃、OOM、死锁、遗留任务，并保留持久化屏障、重启恢复、最终残留及清理证据。 |
| G06 | 完成 10 KiB、fsync-on 正式耐久轮次 | 同 G05；与其他重压轮次串行 | 10 KiB 档满足 G05 的所有稳定性、后轮吞吐恢复及持久化要求。 |
| G07 | 完成 10 MiB、fsync-off 磁盘压力轮次 | G01；与其他重压轮次串行 | 按现有硬盘预算缩减数量（当前计划约 500），单次端点调用，证明 count、吞吐/延迟、峰值/最终磁盘、RSS/FD、失败/重试、残留、恢复与清理。此档不运行 Java 基线。 |
| G08 | 完成 10 MiB、fsync-on 磁盘耐久轮次 | 同 G07 | fsync 开启下独立取得 G07 的证据，并验证持久化/恢复。不能用关闭 fsync 的结果代替。 |
| G09 | 原生执行邮件渲染 AVX-512 验收 | 对应 Linux x86_64 硬件；可异机并行 | mail_render palette matching 与 resize/颜色热点实际进入 AVX-512；Scalar/AVX2+FMA/AVX-512 正确性、像素/分页 golden、runtime dispatch 和性能证据齐全。安全 fallback 或编译成功不能替代。 |
| G10 | 原生执行 Minecraft 视频 AVX-512 验收 | 对应硬件；可异机并行 | block/map palette matching、resize/颜色热点三后端正确性、帧/协议 golden、实际分派与性能证据齐全，不恢复 libasciiart。 |
| G11 | 原生执行 InferX AVX-512 验收 | 对应硬件；可异机并行 | 原/compact 权重的 scalar-vs-SIMD 数值、seed/采样输出、模型 golden、取消/超时与实际后端执行证据通过。 |
| G12 | 关闭 DNS query-order 的重复性问题 | 无；避免污染重压环境 | 针对保留的偶发 oracle 失败重复运行，区分实现/fixture 顺序竞态；必要时修复，保留原断言及 golden。一次 full replay 成功不能证明竞态消除。 |
| G13 | 补齐尚无交叉版本证据的 in-flight 崩溃接管边界 | 无；基于既有故障矩阵定点补齐 | 将已通过的 PENDING memory/file 交接与仍缺的 lease/PROCESSING、SMTP 结果不明、publish/index/intent 收尾等边界逐项对应，补齐所缺真实停机/恢复/回滚测试。已有单运行时故障回归无需冒充跨版本证据。 |
| G14 | 完成 feature → 测试/证据的最终覆盖矩阵 | 可先整理，最终依赖 G01–G13、G17–G19 | 每个原始功能、配置、安全边界、malformed/超限/超时/断连、属性/模糊/故障注入、背压、渲染/模型及持久化要求都有明确证据路径、运行 hash 和结论；缺证据单列补齐，不能用总测试数或 stub 代替。 |
| G15 | 对最终代码封版并更新 release/source/history | 产品修复结束，G14 对应结果齐全 | 对变更影响范围重跑 Rust/安全/差分和所需 golden；如产品改变，重做独立冻结可复现 release 和安装/升级/回滚验证。生成准确的源码包、历史、校验和、依赖与验收清单，保留旧发布和原证据。文档提交本身不要求无意义重编产品。 |
| G16 | 将完整最终工作目录交付到 Windows 路径 | 全部 goal 验收条件真实通过后 | 安全同步全部最终源码、Git 历史、golden、证据和必要未提交工作到 `D:\MiscProjects\lmyzmail-rust`，校验对象/关键文件/状态和交付包，保留 WSL 原件。未完成时只交付版本化候选 artifacts，不宣称已完成最终同步。 |
| G17 | 补齐 `GET /api/cringe-ips` 分页列表 | 无；可独立开发，不跑同机重压 | 恢复 page/size/sortBy/sortDir/search、分页元数据和 XDP enriched 字段。排序字段使用白名单，按冻结 oracle 对成功、空集、搜索、分页边界和权限做差分，并验证风险面板列表加载。 |
| G18 | 补齐 `GET /api/cringe-ips/stats` 统计摘要 | 无；可与 G17/G19 并行分工 | 历史/实时双评分和各统计字段与真实 PG fixture 的 oracle 响应一致；覆盖空库、已有数据、后端故障和权限，验证面板统计加载。 |
| G19 | 补齐 `GET /api/cringe-ips/{ipAddress}` 单 IP 详情 | 无；与其他路由有共享文件，集成时协调 | 恢复清洗/旧值回查、XDP banned/whitelisted 字段和活动明细；验证 URI 编码、特殊/缺失 IP、跨字段一致性、权限和有界资源，完成 oracle 差分与面板详情验证。 |

当前 275HX WSL 不暴露 AVX-512。用户确认暂无测试机并要求先完成本机可验收项；这授权继续本机工作，没有豁免 G09–G11。正式稳定性连续十轮仍不合格时应先推进其他独立项，而不是无限重跑或把失败标成通过。以上重压档位应收集 RSS、FD、任务、队列、延迟、错误和磁盘时间序列。

## 本次文档核对发现的三条功能缺口

冻结的 [72 路由清单](../blackbox/manifests/http-routes.json)声明了 G17–G19。
只读核对冻结 controller 的 `listCringeIPs/getStats/getIPDetail` 与候选
`http.rs` 的路由匹配、`ParsedRequest` 和处理分支后，确认候选没有这三个
成功处理器：带合法读 key 的请求会落入 `NotFound`。同文件
`parse_cringe_ip_route` 目前只处理 activities 与 decay-estimate。
`blackbox/tests/test_http_route_manifest.py` 只验证清单数量、唯一性和分类，
不是这三条路由成功行为的证明。因此既有 961 / 315 等通过数不能关闭
这些功能缺口。这里保留明确缺项，不修改 golden 或把 404 宣称为兼容成功。

## 最新校准终态

实际 run `af39ea25-5192-42db-bd69-385bced43de6` 已终止，不是正在执行的正式压测。10 KiB 的八轮各 8000 封完成后，observer off/on spread 分别为 `0.030884679683226064` / `0.029298289419937593`，超过不变的 `0.01` 上限，`qualification=false`。中位比例 `1.0095296262232085` 并不能覆盖 spread 失败；正式 250000 封阶段没有开始。

此处 off/on 指 observer gate，产品 fsync 全部为 off。受保护 checkpoint 位于 `/var/lib/lmyzmail-benchmark/artifacts/af39ea25-5192-42db-bd69-385bced43de6.checkpoint`，为 35 条 JSONL、279200934 字节，SHA-256 `228b0c159f2952996f21d082803bbf0581305b90126d84575b45d9662c8742eb`。终态 receipt 是 `request=ABORT, cleanup=passed, qualified_cleanup=0`。原件保留本地，不把超过 GitHub 单文件限制的 checkpoint 塞入 Git；其摘要和定位见[校准记录](proxy-runtime-isolation-20261023.md)。这不是合格吞吐成绩，也不关闭 G03–G08。
