# lmyzmail Linux x86_64 候选发布版

版本：`0.1.0-rc.22dae7d0`。
源码提交：`22dae7d0f8728f355fc6a31bdc65263bd21aa10d`。
运行时是一个 Rust 进程，不依赖 Java/JVM。
这是可安装、可运行的 release candidate；完整生产验收尚未结束。
具体通过项、负例及未完成项见同目录验证说明，不能将打包成功视为 goal 完成。

## 文件

- `lmyzmail-0.1.0-rc.22dae7d0-linux-x86_64.tar.gz`：可执行文件、模型、资源、
  默认配置、systemd unit、安装/卸载脚本和必要运行文档。
- `lmyzmail-0.1.0-rc.22dae7d0-source.tar.gz`：该提交全部 17,240 个已跟踪文件，
  包括 Cargo.lock、固定工具链、原生源码、测试、夹具、golden 和已有证据。
- `lmyzmail-0.1.0-rc.22dae7d0-history.bundle`：包含发布提交的完整 Git 历史。
- `RELEASE.json`、`SHA256SUMS`：版本、来源、模型和原始发布文件校验值。
- 后续验证补充文件单独记录验证源码提交和校验值，不改变上述发布文件。

最新完整源码及历史是 `lmyzmail-22dae7d0-validation-<commit>-source.tar.gz`
和对应的 `-history.bundle`，包含后续回滚工具、完整回放和 soak 证据。
`VALIDATION.json` 给出精确提交；检查 `VALIDATION-SHA256SUMS` 后可解压源码，
或用 `git clone <validation-history.bundle> lmyzmail-source` 恢复完整历史。
生产运行时代码与原始 `22dae7d0` 发布提交完全一致。

`updates/` 下保留后续版本化完整源码、Git 历史和验收补充。
每个子目录的 `VALIDATION.json` 给出精确源码提交，
`VALIDATION-SHA256SUMS` 校验其中全部交付文件；旧补充目录使用 `SHA256SUMS`。
最新补充包含外部 SMTP 观测器修正、85 项 Rust 观测器测试、221 项 Python
工具回归及完整失败证据。运行包及其模型和 ELF 未被这些工具变更替换。
最新 10 MiB 校准完成 8 轮、800/800 封，持久化核对全部通过，
但轮间波动未通过原有门槛，不能作为正式长压测验收结果。

## 安装

在 Linux x86_64 上先检查 `SHA256SUMS`。Windows 只能保存这些交付文件，
请在 WSL 或 Linux 中运行 ELF。需要系统共享库及 PostgreSQL、Redis；
详见运行包内 `docs/release.md`。安装器会检查 ELF 和资源校验值。

```bash
sha256sum -c SHA256SUMS
tar -xzf lmyzmail-0.1.0-rc.22dae7d0-linux-x86_64.tar.gz
cd lmyzmail-0.1.0-rc.22dae7d0
sudo tools/install-lmyzmail.sh --binary "$PWD/bin/lmyzmail"
sudoedit /etc/lmyzmail/application.properties
sudo -u lmyzmail /usr/bin/lmyzmail \
  --config /etc/lmyzmail/application.properties --check-config
sudo systemctl enable --now lmyzmail
```

安装器默认使用运行包内的可复现构建记录，不需要额外设置环境变量。
默认开启文件系统 fsync。`lmyzmail.storage.fsync-enabled=false` 可关闭文件及目录
同步以匹配 Java 的持久化行为；它降低断电/内核故障时的持久性保证。
Java 吞吐比较必须采用关闭 fsync 的结果，开启模式另做稳定性验收。
以配置示例中的实际配置键为准，修改前可查阅 `docs/release.md`。

升级/接管前停止旧服务并备份 PostgreSQL、Redis、完整 Maildir/spool、
证书、配置和模型。不要让 Java 与 Rust 的出站工作进程同时处理同一个队列。
旧 `botmail.*` 配置仍可读取，同名新 `lmyzmail.*` 键优先。
保留既有数据库、Redis key/TTL 和绝对 spool 路径。
含下划线、连续点、Unicode 或 `v1-` 的地址有额外的目录所有权约束；
回滚必须遵循验证补充源码中的 `docs/maildir-offline-rollback.md`，
不要手工合并目录。

```bash
# 保留配置、数据、模型及资源的卸载
sudo tools/uninstall-lmyzmail.sh
```

## 源码构建

```bash
git clone lmyzmail-0.1.0-rc.22dae7d0-history.bundle lmyzmail-rust
cd lmyzmail-rust
git checkout --detach 22dae7d0f8728f355fc6a31bdc65263bd21aa10d
cargo build --frozen --release -p lmyzmail
```

需要安装文档列出的 C/C++、FFmpeg、Cairo、libbpf 等构建/运行依赖；
`--frozen` 不会下载缺失的 Cargo 依赖，首次准备依赖时应先按文档执行
`cargo fetch --locked`。固定 stable 工具链为 Rust 1.94.0。
两次干净构建在相同源码路径、独立 target 目录下生成相同 ELF：
`78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790`。
不同源码绝对路径下的二进制字节一致性未作保证。

内嵌/随包模型已同步到指定模型优化线程的最新 FF512 checkpoint，
权重 SHA-256 为
`4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428`。
本机可运行 Scalar 与 AVX2+FMA；没有 AVX-512 硬件，
其原生执行/性能验收仍待补齐。正式 SMTP 长压力与同进程恢复要求也仍需合格证据。
当前完整 Java/candidate 矩阵、961 项 Rust 测试、真实 XDP 检查、
Scalar/AVX2 渲染以及独立 16 worker 半小时多模块 soak 已通过。
