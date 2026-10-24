# lmyzmail

[中文](README.md) · [English](README.en.md) · [日本語](README.ja.md)

lmyzmail は Linux x86_64 向けの単一プロセス型メールサーバーです。SMTP、Web メール、管理 API、メールの安全対策とレポート、Minecraft のメール空間、Skibidi / brainrot 機能を、モジュール化した Rust ランタイムで提供します。永続データは PostgreSQL、Redis、Maildir に保存します。インストール後のサービスに Java、JVM、Python、Rust ツールチェーンは不要です。

現在は **0.1.0 リリース候補版**です。再現可能ビルド、インストール、差分検証、複数モジュールの 30 分 soak には合格証拠があります。大量 SMTP 負荷試験と AVX-512 の実機検証は未完了です。機能の実装と、本番向けの全受入条件達成は区別してください。[残作業一覧](docs/goal-remaining.zh-CN.md)と[受入記録](docs/acceptance-status.md)を参照してください。

## 目次

- [機能と使い方](#機能と使い方)
- [インストールと初回起動](#インストールと初回起動)
- [設定の読み込み](#設定の読み込み)
- [全設定リファレンス](#全設定リファレンス)
- [HTTP インターフェース](#http-インターフェース)
- [運用と問題の切り分け](#運用と問題の切り分け)
- [既存データの引継ぎとロールバック](#既存データの引継ぎとロールバック)
- [ビルドと検証](#ビルドと検証)

## 機能と使い方

### メールと Web メール

`/` で Web メールを開きます。メールボックスへのログイン、設定に応じた公開登録、受信/送信済み/迷惑メール等のフォルダー、ページ表示、HTML/テキスト表示、原文・ヘッダー、添付取得、JSON/multipart 送信、配送状態、送信枠、スター、ラベル、連絡先、ユーザー設定に対応します。`/cringe.html` はリスク画面を提供しますが、一覧・統計・IP 詳細の成功応答は未実装です。下記の API 欠落を参照してください。メール・添付・ユーザーデータへのアクセスは認証されたメールボックスに限定されます。

受信 SMTP は EHLO、MAIL/RCPT、DATA、BDAT、PIPELINING、STARTTLS、SMTPUTF8、MIME、宛先ドメイン・メールボックス検証に対応します。DATA は `354` を受信してから本文を送ってください。この待受口は **SMTP AUTH による送信受付を提供しません**。AUTH は `502` を返します。認証付き送信には Web メールまたは HTTP API を使用し、このポートの AUTH にパスワードを送らないでください。

送信には永続キュー、更新可能なリース、同時実行上限、接続再利用を使用します。MX 検索、STARTTLS、DKIM 署名、一時失敗のバックオフ、終端結果の保存、DSN バウンスに対応します。Sent ファイル・DB 索引・キュー・spool の所有関係を確認し、再起動後に未完了処理を回復します。HTTP 送信は非同期で、`async=false` は未対応です。

### 安全対策・レポート・ハニーポット

SPF/DKIM/DMARC 検証、送信 MTA-STS、TLS-RPT、DMARC 集約レポートを備えます。レポートは手動実行と UTC の日次スケジュールに対応し、DNS/HTTP の宛先制約を適用します。DNS 公開、DKIM 鍵、SMTP 証明書、レポート送信用アカウントは管理者が設定します。

内容検査は RBL、SOA によるドメイン推定、ヘッダー欠落、Subject 符号化の偽装、宛先過多、迷惑/フィッシング語、疑わしい URL、危険/二重拡張子、MIME 不一致を対象にします。接続段階の Spamhaus DNSBL/DBL と、スコア用 RBL は独立設定です。

HTTP スキャナー向けの誘導応答は 104 分類あり、TCP は `NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC` に対応します。送信元 IP、活動、現在/履歴の cringe スコアを記録し、検索、出力、減衰、閾値による停止ができます。全体の一覧は[ハニーポット処理](crates/lmyzmail/src/honeypot.rs)と[プロトコル資産一覧](crates/lmyzmail/src/honeypot_assets.json)を参照してください。実際の SSH、FTP、DB、VNC サービスではありません。

SSH 監視は最初に読取可能なログを末尾から読み、ローテーション、失敗期間、報告間隔、追跡 IP 上限を処理します。任意の XDP 機能は固定の C/eBPF ABI を使用し、IPv4/IPv6 停止、許可リスト、統計、PPS/SYN 監視、スコア同期、再起動後の状態保持に対応します。既定の systemd unit は低ポートの bind 権限のみで、**XDP を attach できません**。[XDP の権限構成と実機受入](docs/xdp-privileged-gate.md)に従い、サービス全体を無制限 root にしないでください。

HTTP はプロキシ IP と CORS の規則を適用します。認証、アップロード、パス、宛先ドメイン、MIME、キュー、キャッシュには境界を設けています。プロキシで外部からの転送ヘッダー偽装を除去し、実際のプロキシだけを信頼してください。CORS は認証の代わりになりません。

### Skibidi・クイズ・推論・動画

SMTP banner、ランダム文、確率閾値、seed、batch はすべて固定 Skibidi C 1.8.0 を使用し、旧 Java の高速経路は模倣しません。SIMD は CPU と OS の実行可否を確認します。由来と所有権は[生成器 ABI・確率仕様](docs/skibidi-banner-contract.md)を参照してください。

`SKIBIDITOILET` の問題数は 474。モードは BABYGRONK（15 問）、SKIBIDITOILET（30 問）、OHIOFINALBOSS（60 問）です。SMTP 接続後に以下を入力できます。

```text
SKIBIDITOILET HELP
SKIBIDITOILET START BABYGRONK
SKIBIDITOILET ANSWER A
SKIBIDITOILET QUIT
SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=160 FPS=12 CONTRAST=1.5
```

ASCII 動画は `BRIGHTNESS`、`GAMMA`、`ASPECT`、`INVERT` にも対応し、設定された幅・FPS 上限を守ります。単色 ANSI と `250-` 行でフレームを送り、全体で同時視聴者は 1 人です。接続を切ると停止します。

SkibidiInferX は SafeTensors の読取専用 mmap、BPE、KV cache、サンプリング、seed、キャンセル、期限を Rust で処理します。同梱モデルは compact-20261022（12,192,512 パラメーター、48,779,520 バイト、FFN 幅 512）。旧重みは別パスで利用可能です。重みと tokenizer はアトミックに置換し再起動してください。mmap 中のファイルを切り詰めないでください。使用中・期限超過・利用不可時は固定フォールバック文を返します。[モデル契約と互換パラメーター](docs/skibidi-inferx-contract.md)を参照してください。

ASCII、メール HTML、画像/動画、Minecraft block/map のパレット、dither、resize、改ページ、逐次フレーム処理は Rust が管理し、固定 FFmpeg と litehtml/Cairo を土台にします。**旧 libasciiart は不要です。** Scalar、AVX2+FMA、AVX-512 は安全な実行時分岐を備えます。本機では Scalar/AVX2 の通信・画素・フレーム golden に合格しています。AVX-512 の実機実行・性能は対応機での検証が必要です。

### Minecraft と HTCPCP

対応 Minecraft クライアントは **1.8.9**。状態照会、online/offline ログイン、ゲーム内メールボックス認証、フォルダー GUI、地図上のメール描画・改ページ、連絡先関連操作、本による下書きと送信、ワールド、ブロック動画、地図壁動画に対応します。Mojang 認証だけではメールボックス認証は完了しません。

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

メールボックス入力はゲーム内 UI に従ってください。`/mail rs` は rendersize の別名です。設定の既定値と引数省略時の互換値は一致しない場合があるため、明示指定を推奨します。停止・切断・期限超過で動画リソースを解放します。

HTCPCP は独立 TCP ポートでコーヒー/茶ポットの状態機械を提供します。`GET HEAD OPTIONS PROPFIND BREW POST WHEN`、添加物、茶の種類、抽出時間、エラー状態に対応します。設定例は 8 ポット、pots 省略時は coffee ポット 1 個です。`curl -i http://127.0.0.1:8888/pot-0` で照会でき、raw クライアントは `HTCPCP/1.0` も使用できます。能力に合わない飲料・添加物は拒否されます。

## インストールと初回起動

### プラットフォームと依存関係

Linux x86_64 のみが対象です。検証環境は Ubuntu 24.04 / WSL2、データサービスは PostgreSQL 16 と Redis です。該当パッケージの `RELEASE.json` に記載された x86_64 共有ライブラリを導入してください。ビルドツールや Python はビルド・検証・オフラインツール用です。

[リリースガイド](docs/release.md)は実行パッケージ、全ソース、履歴 bundle、モデル、動画資産の構成を説明します。同じ配布物の `SHA256SUMS` を照合し、Linux で Unix 権限を維持して展開します。

```bash
sha256sum -c SHA256SUMS
tar -xzf lmyzmail-0.1.0-rc.COMMIT-linux-x86_64.tar.gz
cd lmyzmail-0.1.0-rc.COMMIT
./bin/lmyzmail --version
sudo tools/install-lmyzmail.sh
```

コマンド中の `COMMIT` を実際のリリース識別子に置換してください。

インストーラーは ELF・資産 hash を検証し、**停止状態のまま**設置します。既存の設定は上書きしません。

| パス | 用途 |
| --- | --- |
| /usr/bin/lmyzmail | サービス実行ファイル |
| /etc/lmyzmail/application.properties | 管理者設定 |
| /usr/share/lmyzmail/models/skibidi-inferx | モデル・tokenizer |
| /var/lib/lmyzmail/data/mail | Maildir・既定 spool |
| /var/log/lmyzmail | 書込可能ログ領域。標準出力/エラーは journal |
| /run/lmyzmail | 非公開の実行時ディレクトリ |
| deploy/lmyzmail.service | unit の元ファイル |

`--binary PATH` で ELF を選択します。`--destdir ABS` はユーザー作成・systemd 操作なしの配置用です。`--legacy-rw ABS` / `--legacy-ro ABS` は既存データ・証明書への限定的な許可です。`--enable` は設定済みの新規導入を有効化・起動します。認証情報の準備前には指定しないでください。

### データベースと設定

起動処理で追加するのは回復・調整用構造で、**基本業務テーブル全体は作成しません**。既存 DB は直接引き継ぎます。新しい空 DB には、テストアカウントを含まない [DDL のみの schema](blackbox/fixtures/legacy/postgres-schema.sql)を使用できます。ソースのルートで、対象が新規の空 DB であると確認してから実行します。

```bash
sudo -u postgres createuser --pwprompt lmyzmail
sudo -u postgres createdb --owner=lmyzmail lmyzmail
set -o pipefail
sed 's/^CREATE SCHEMA "public";$/CREATE SCHEMA IF NOT EXISTS "public";/' \
  blackbox/fixtures/legacy/postgres-schema.sql |
  PGHOST=127.0.0.1 PGUSER=lmyzmail PGDATABASE=lmyzmail \
    psql -X -W --set=ON_ERROR_STOP=1
```

PostgreSQL 非互換の LONGTEXT は text に変換済みです。**既存 DB に初期化 DDL を実行しないでください。** 専用 DB ユーザー、Redis ACL/パスワード、ディレクトリ権限を用意します。

`/etc/lmyzmail/application.properties` に DB、Redis、ドメイン、待受先、Maildir、送信ドメイン、TLS、管理 API キーを設定します。秘密情報は保護されたファイルで管理し、Git に登録しないでください。設定例は loopback に bind し、公開登録・Minecraft・XDP・負荷試験は無効、HTCPCP と IP DNSBL は明示的に有効です。

HTTP は平文です。公開 Web メールには HTTPS リバースプロキシが必要です。SMTP の PKCS12 は HTTPS を有効化しません。PostgreSQL は現在 NoTls のため、信頼できるローカル回線か保護されたトンネルを使用します。Redis は個別に TLS を有効化できます。

```bash
sudo -u lmyzmail /usr/bin/lmyzmail \
  --config /etc/lmyzmail/application.properties --check-config
sudo systemctl enable --now lmyzmail
curl --fail http://127.0.0.1:8080/api/health
journalctl -u lmyzmail -n 100 --no-pager
```

`--check-config` は主設定を解析し概要を出力します。DB には接続せず、モジュールの起動検証も代替しません。起動後はログ、メールボックス API、SMTP、実際の格納を確認してください。health だけでは導入完了を確認できません。

### DNS 公開

実ドメインに MX と対応 A/AAAA、逆引き、SPF、DKIM selector TXT、DMARC を設定します。必要に応じて MTA-STS の HTTPS ポリシーと `_mta-sts` / `_smtp._tls` TXT を公開します。必要な受信ポートを開き、外向き TCP 25 を確認してください。実際に提供するサービスだけを DNS に登録します。

## 設定の読み込み

主設定の選択順は `--config PATH`（または `--config=PATH`）、`LMYZMAIL_CONFIG`、`./application.properties`、`/etc/lmyzmail/application.properties` です。選ぶ主ファイルは 1 個です。CLI は `--check-config`、`--version/-V`、`--help/-h`、`--lmyzmail.key=value` に対応します。

通常は UTF-8 properties を使用し、継続行とエスケープ、同一キーの後勝ちに対応します。`spring.profiles.include=a,b` は同じディレクトリの `application-a.properties`、`application-b.properties` を順番に重ねます。通常 profile の欠落は無視し、keywords 欠落時は内蔵語彙を使います。主設定、profile、同名 CLI 上書きの順です。

各項目では対応する `lmyzmail.*` が `botmail.*` より優先です。**旧名前空間の CLI 値でも、存在する新キーは上書きできません。** 任意の環境変数から properties への自動変換はありません。上限は 1 MiB/ファイル、16384 キー、include 32 個、合計 4 MiB です。

空白を除いた先頭が `{` の場合は、試験・外部編成用の `schema_version=1` 意味設定 JSON を受理します。snake_case の階層 schema であり、**任意の properties 辞書ではありません**。最上位項目は `schema_version, profile, listen, postgres, redis, maildir, storage, domain, domains, allowed_origins, trusted_proxies, api_keys, features, skibidi_inferx, fail2ban, smtp, content_filter, xdp, cringe, reporting, stress, htcpcp, minecraft, mail_render, tls, limits` です。内部項目・検証条件は[型定義](crates/lmyzmail/src/config.rs)に従い、不明項目は拒否します。JSON には properties と異なる既定値もあり、ドメインの send_enabled は false です。通常導入には以下の properties を推奨します。

## 全設定リファレンス

表は `lmyzmail.` を含む完全なキーです。`/` は同じ行にまとめた独立キーの区切りで、既定値も同順です。`""` は空文字列、`[]` は空リスト、`<maildir>` は maildir.base。注記のない値は**properties の省略時既定値**で、設定例の明示値とは異なります。`[n]` は 0 始まりの連続添字、`<name>` と `<RULE>` は置換箇所です。変更後は再起動が必要で、汎用 hot-reload API はありません。

### 待ち受け・HTTP・メッセージサイズ

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.listen.host` | `127.0.0.1` | 各リスナーのバインド先。外部公開時は明示的に変更。 |
| `lmyzmail.http.port` / `lmyzmail.smtp.port` / `lmyzmail.htcpcp.port` / `lmyzmail.minecraft.port` | `8080 / 25 / 8888 / 25565` | 各プロトコルのポート。任意サービスには enabled も必要。 |
| `lmyzmail.profile` | `production` | 識別用ラベル。同名の設定ファイルは自動読込しない。 |
| `lmyzmail.http.max-request-bytes` | `10485760` | 通常の HTTP 本文の上限。添付には別の上限も適用。 |
| `lmyzmail.http.max-multipart-bytes` | `209715200` | multipart 本文の上限。送信可能なメールサイズとは異なる。 |
| `lmyzmail.http.max-connections` / `lmyzmail.http.request-timeout-ms` | `256 / 10000` | HTTP 同時接続数と要求タイムアウト。 |
| `lmyzmail.http.upload-temp-dir` | `<maildir>/.lmyzmail-upload` | ストリーミングアップロード用の書込可能な一時ディレクトリ。 |
| `lmyzmail.http.trusted-proxies` | `[]` | 転送元 IP を信頼するプロキシの IP/CIDR。CSV または [n]。 |
| `lmyzmail.allowed-origins[n]` | `[]` | 許可する CORS オリジン。scheme://*.domain 形式にも対応。 |
| `lmyzmail.max-email-size-bytes` / `lmyzmail.max-attachment-size-bytes` / `lmyzmail.max-total-attachments-size-bytes` | `15728640 / 10485760 / 15728640` | メール全体・添付単体・添付合計の上限。MIME 符号化の増分にも注意。 |

### PostgreSQL・Redis・永続化

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.postgres.host` / `lmyzmail.postgres.port` / `lmyzmail.postgres.database` | `localhost / 5432 / lmyzmail` | PostgreSQL の接続先・ポート・データベース。 |
| `lmyzmail.postgres.username` / `lmyzmail.postgres.password` | `lmyzmail / ""` | DB の認証情報。本番では専用の認証情報を設定。 |
| `lmyzmail.postgres.url` | `""` | 任意の JDBC/PostgreSQL URL。host/port/database のみ反映。認証情報は別途指定。 |
| `lmyzmail.postgres.pool.max-size` | `32` | 上限付き接続プール。現在の接続方式は NoTls。 |
| `lmyzmail.redis.host` / `lmyzmail.redis.port` / `lmyzmail.redis.database` | `localhost / 6379 / 0` | Redis の接続先と論理 DB。既存キーと TTL を維持。 |
| `lmyzmail.redis.username` / `lmyzmail.redis.password` | `"" / ""` | Redis ACL のユーザー名・パスワード。認証なしなら空。 |
| `lmyzmail.redis.tls-enabled` | `false` | Redis TLS。同一名前空間の別名は redis.ssl.enabled。 |
| `lmyzmail.redis.pool.max-active` | `32` | 上限付き Redis 接続プール。 |
| `lmyzmail.maildir.base` | `/var/lib/lmyzmail/data/mail` | メール格納ルート。既存の配置と権限を維持。 |
| `lmyzmail.maildir.max-files-per-directory` | `10000` | ディレクトリ分割の閾値。サービス全体では 1..1000000 を使用し、-1 は使用しない。 |
| `lmyzmail.storage.fsync-enabled` | `true` | ファイル・ディレクトリの耐久性バリア。false でも公開はアトミックだが、障害時に受付済みデータを失う可能性がある。PG WAL・Redis 永続化は変更しない。 |

### ドメイン・認証・レート制限

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.domain` | `lmyz.net` | 主ドメイン。domains.main.domain が優先。 |
| `lmyzmail.domains.<name>.domain` | `domain (main)` | 名前付きドメイン設定。最大 256 件。main は domain を継承可能。 |
| `lmyzmail.domains.<name>.receive-enabled` / `lmyzmail.domains.<name>.send-enabled` / `lmyzmail.domains.<name>.require-existing-mailbox` | `true / true / true` | 受信・送信の許可と受信箱の存在要件。SMTP AUTH を有効化する設定ではない。 |
| `lmyzmail.domains.<name>.dkim-selector` / `lmyzmail.domains.<name>.dkim-private-key-path` | `"" / ""` | DKIM セレクターと秘密鍵パスを対で設定し、対応する DNS TXT を公開。 |
| `lmyzmail.domains.<name>.list-unsubscribe-mailto` / `lmyzmail.domains.<name>.list-unsubscribe-url` | `"" / ""` | 送信メールの List-Unsubscribe 宛先。 |
| `lmyzmail.api-keys[n].key` / `lmyzmail.api-keys[n].label` | `required / api` | 0 始まりの連続番号。最大 256 件。キーは重複不可、最大 4096 バイト。 |
| `lmyzmail.api-keys[n].read` / `lmyzmail.api-keys[n].write` | `true / false` | 読取・書込権限を独立に付与。別名 readEnabled/writeEnabled。 |
| `lmyzmail.public-registration-enabled` | `false` | 公開登録の可否。管理 API によるメールボックス作成は別。 |
| `lmyzmail.session.expiry-days` / `lmyzmail.session.max-per-user` / `lmyzmail.session.track-last-used` | `7 / 10 / true` | セッション有効日数・ユーザー当たり上限・最終利用時刻の記録。 |
| `lmyzmail.rate-limit.enabled` | `true` | 認証・登録のレート制限。 |
| `lmyzmail.rate-limit.max-failed-login-attempts` / `lmyzmail.rate-limit.failed-login-window-minutes` / `lmyzmail.rate-limit.ip-ban-duration-hours` | `10 / 5 / 3` | ログイン失敗の観測窓と IP の停止期間。 |
| `lmyzmail.rate-limit.max-registrations-per-ip` / `lmyzmail.rate-limit.registration-rate-window-hours` | `5 / 3` | IP ごとの登録枠と期間。 |
| `lmyzmail.rate-limit.max-emails-per-account` / `lmyzmail.rate-limit.email-rate-window-hours` | `100 / 3` | アカウントごとの送信枠と期間。同時実行数を増やしても解除されない。 |

### 送信・キュー・DNS

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.outbound.spool-dir` | `<maildir>/.lmyzmail-outbound` | 大きなメールをキューの終端結果が永続化されるまで保持。旧別名 botmail.outbound.temp-dir。 |
| `lmyzmail.outbound.max-pending-tasks` / `lmyzmail.outbound.retry-count` | `10000 / 5` | 未処理タスクの上限と再試行回数。 |
| `lmyzmail.outbound.helo-hostname` | `domain` | 送信時の EHLO/HELO 名。 |
| `lmyzmail.outbound.connection-timeout-ms` / `lmyzmail.outbound.read-timeout-ms` | `30000 / 60000` | 接続と SMTP 応答読取のタイムアウト。 |
| `lmyzmail.outbound.pool-enabled` / `lmyzmail.outbound.max-connections-per-host` / `lmyzmail.outbound.max-messages-per-connection` | `true / 5 / 100` | 成功したセッションを RSET 後に再利用。失敗・結果不明の接続は閉じる。 |
| `lmyzmail.outbound.max-idle-time-ms` / `lmyzmail.outbound.connection-life-time-ms` / `lmyzmail.outbound.pool-cleanup-interval-ms` | `60000 / 300000 / 30000` | アイドル時間・接続寿命・プール清掃間隔。 |
| `lmyzmail.queue.worker-id` | `lmyzmail-<pid>` | リース所有者。設定例は lmyzmail-worker。同じ ID を別インスタンスで共用しない。 |
| `lmyzmail.queue.max-concurrent-sends` / `lmyzmail.queue.batch-size` / `lmyzmail.queue.poll-interval-ms` | `100 / 50 / 1000` | 同時送信上限・一度に取得する件数・ポーリング間隔。 |
| `lmyzmail.queue.migration-batch-size` | `1000` | 既存キュー回復時の走査単位。 |
| `lmyzmail.queue.lease-seconds` / `lmyzmail.queue.renew-seconds` / `lmyzmail.queue.processing-timeout-minutes` | `90 / 10 / 10` | リース期間・更新間隔・処理期限。更新値は検証条件を満たすこと。 |
| `lmyzmail.queue.retry-base-seconds` / `lmyzmail.queue.retry-max-seconds` | `30 / 3600` | 再試行バックオフの初期値と上限。 |
| `lmyzmail.outbound.dns.mx.l1-max-entries` / `lmyzmail.outbound.dns.mx.l1-ttl-minutes` / `lmyzmail.outbound.dns.mx.l2-ttl-minutes` / `lmyzmail.outbound.dns.mx.negative-ttl-minutes` | `10000 / 15 / 30 / 5` | MX ローカル容量・ローカル/Redis TTL・否定応答 TTL。 |
| `lmyzmail.outbound.dns.query-timeout-seconds` / `lmyzmail.outbound.route-deadline-seconds` | `15 / 30` | DNS 問合せと経路決定全体の期限。 |
| `lmyzmail.smtp.mta-sts-enabled` / `lmyzmail.smtp.mta-sts-fetch-timeout-ms` | `true / 10000` | MTA-STS の発見・HTTPS 取得・送信 TLS ポリシー。 |
| `lmyzmail.ssl.use-custom-certificate` / `lmyzmail.ssl.keystore-path` / `lmyzmail.ssl.keystore-password` | `false / "" / ""` | SMTP STARTTLS 用 PKCS12 証明書。HTTP を HTTPS 化する設定ではない。 |

### SMTP セキュリティ・コンテンツフィルター

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.smtp-security.tarpit-enabled` | `true` | 不正クライアントへの遅延応答。 |
| `lmyzmail.smtp-security.dns-server` | `""` | DNS の数値 IP:port 指定。空ならシステムリゾルバー。 |
| `lmyzmail.smtp-security.spamhaus-enabled` / `lmyzmail.smtp-security.spamhaus-zones` | `false / zen.spamhaus.org` | 受信 IP の DNSBL。設定例では明示的に有効。提供元の利用条件に従う。 |
| `lmyzmail.smtp-security.spamhaus-reject-on-listed` / `lmyzmail.smtp-security.spamhaus-timeout-ms` / `lmyzmail.smtp-security.spamhaus-cache-ttl-seconds` | `true / 3000 / 300` | 掲載 IP の拒否・問合せ期限・キャッシュ TTL。 |
| `lmyzmail.smtp-security.spamhaus-ignored-codes` | `[]` | 無視する応答コードの CSV。 |
| `lmyzmail.smtp-security.spamhaus-dbl-enabled` / `lmyzmail.smtp-security.spamhaus-dbl-zone` | `false / dbl.spamhaus.org` | ドメイン DBL 問合せ。 |
| `lmyzmail.contentfilter.enabled` / `lmyzmail.contentfilter.suspicious-threshold` / `lmyzmail.contentfilter.spam-threshold` | `true / 5.0 / 10.0` | 重み付きの要注意/迷惑判定閾値と Spam ヘッダー・分類。 |
| `lmyzmail.contentfilter.stream-buffer-size` | `65536` | ストリーミング走査バッファ。最大 1048576 バイト。 |
| `lmyzmail.contentfilter.rules.<RULE>.enabled` / `lmyzmail.contentfilter.rules.<RULE>.weight` | `true / 1.0` | ルールごとの有効化・重み。0..100。全ルールは下記参照。 |
| `lmyzmail.contentfilter.rbl.enabled` / `lmyzmail.contentfilter.rbl.servers` | `true / zen.spamhaus.org,bl.spamcop.net` | スコア用 RBL。接続段階の DNSBL 拒否とは別。 |
| `lmyzmail.contentfilter.rbl.timeout-ms` / `lmyzmail.contentfilter.rbl.score-per-hit` / `lmyzmail.contentfilter.rbl.max-score` | `3000 / 3.0 / 6.0` | RBL 期限・一致当たり加点・上限。 |
| `lmyzmail.contentfilter.keywords.enabled` / `lmyzmail.contentfilter.keywords.density-threshold` / `lmyzmail.contentfilter.keywords.base-score` / `lmyzmail.contentfilter.keywords.max-score` | `true / 0.05 / 2.0 / 8.0` | キーワードと密度による採点。 |
| `lmyzmail.contentfilter.keywords.spam-keywords` / `lmyzmail.contentfilter.keywords.phishing-keywords` | `[] (keywords profile)` | CSV/添字付きリスト。keywords プロファイルで同梱語彙を読込。 |
| `lmyzmail.contentfilter.url.enabled` / `lmyzmail.contentfilter.url.shortener-domains` / `lmyzmail.contentfilter.url.suspicious-tlds` | `true / [] / []` | URL 走査。短縮 URL ドメイン・疑わしい TLD は keywords で読込。 |
| `lmyzmail.contentfilter.url.shortener-score` / `lmyzmail.contentfilter.url.suspicious-tld-score` / `lmyzmail.contentfilter.url.ip-url-score` / `lmyzmail.contentfilter.url.max-score` | `1.5 / 2.0 / 3.0 / 8.0` | 短縮 URL・TLD・IP URL の加点と合計上限。 |
| `lmyzmail.contentfilter.attachment.enabled` / `lmyzmail.contentfilter.attachment.dangerous-extensions` | `true / exe,scr,bat,cmd,com,pif,vbs,vbe,js,jse,wsf,wsh,msi,msp,hta,cpl,reg,inf,scf,lnk,ps1,psm1,jar` | 添付検査と変更可能な危険拡張子リスト。 |
| `lmyzmail.contentfilter.attachment.dangerous-extension-score` / `lmyzmail.contentfilter.attachment.double-extension-score` / `lmyzmail.contentfilter.attachment.mime-type-mismatch-score` | `5.0 / 4.0 / 3.0` | 危険拡張子・二重拡張子・MIME 不一致の加点。 |

ルール：`RBL_CHECK`、`NEW_DOMAIN`、`MISSING_HEADERS`、`SUBJECT_ENCODING_TRICK`、`EXCESSIVE_RECIPIENTS`、`SPAM_KEYWORDS`、`SUSPICIOUS_URL`、`DANGEROUS_EXTENSION`、`DOUBLE_EXTENSION`、`MIME_TYPE_MISMATCH`。すべて実際の処理経路を持つ。`NEW_DOMAIN` は SOA serial による推定であり、登録日のデータベースではない。設定例は `spring.profiles.include=keywords` を読込む。省略時は語彙リストが空になり得る。

### Skibidi・InferX・ASCII 描画

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.smtp.skibidi-generator-mode` | `AUTO_SAFE` | AUTO_SAFE/AUTO/NATIVE/SCALAR/AVX2/AVX512。JAVA は Scalar C の互換別名。確率・seed/batch の仕様は固定 C 1.8.0 に従う。 |
| `lmyzmail.smtp.skibidi-generator-enable-avx512` / `lmyzmail.smtp.skibidi-generator-enable-simd-rng` | `true / true` | バックエンドの使用許可。CPU/OS の実行可否判定は常に適用。 |
| `lmyzmail.smtp.skibidi-insults-enabled` / `lmyzmail.smtp.skibidi-toilet-quiz-enabled` | `true / true` | SMTP の対話テキストと全 474 問のクイズ。 |
| `lmyzmail.smtp.asciiart.simd-mode` / `lmyzmail.mailrender.simd-mode` | `AUTO / AUTO` | 安全な実行時分岐。AUTO/SCALAR/AVX2/AVX512。後者はメール描画と Minecraft の色処理に使用。 |
| `lmyzmail.smtp.asciiart.max-width` / `lmyzmail.smtp.asciiart.max-fps` / `lmyzmail.smtp.asciiart.default-width` / `lmyzmail.smtp.asciiart.default-fps` | `450 / 20 / 120 / 10` | SMTP ASCII 動画の幅・FPS の上限と既定値。 |
| `lmyzmail.smtp.asciiart.default-contrast` / `lmyzmail.smtp.asciiart.char-aspect` | `1.2 / 2.0` | コントラストと文字の縦横比補正。 |
| `lmyzmail.skibidi-inferx.enabled` | `true` | Rust SafeTensors/BPE による生成。利用不可時は固定フォールバック文を返す。 |
| `lmyzmail.skibidi-inferx.model-path` | `/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors` | 読取専用 mmap 重み。同梱版は compact-20261022。旧重みは別途保持。 |
| `lmyzmail.skibidi-inferx.tokenizer-path` | `/usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json` | 重みに対応する BPE tokenizer。 |
| `lmyzmail.skibidi-inferx.temperature` / `lmyzmail.skibidi-inferx.top-k` / `lmyzmail.skibidi-inferx.top-p` | `0.85 / 50 / 0.92` | サンプリング設定。 |
| `lmyzmail.skibidi-inferx.max-tokens` | `80 (effective 120)` | 互換動作：値を検証・報告するが、生成の実効上限は 120 のまま。 |
| `lmyzmail.skibidi-inferx.timeout-ms` / `lmyzmail.skibidi-inferx.max-concurrent-generations` | `500 / 1` | 要求期限。実効 worker は 1。使用中は即フォールバック。1 より大きくしても推論並列数は増えない。 |
| `lmyzmail.skibidi-inferx.fallback-on-error` | `true` | 互換設定。false でも外側の例外・タイムアウト処理はフォールバックを返す。 |
| `lmyzmail.skibidi-inferx.simd-level` | `auto` | auto/scalar/avx2/avx512。AVX2 は FMA、AVX512 はさらに AVX-512F が必要。未対応時は安全に降格。 |

### HTCPCP

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.htcpcp.enabled` / `lmyzmail.htcpcp.default-brew-time-seconds` | `false / 30` | 設定例では有効。GET/HEAD/OPTIONS/PROPFIND/BREW/POST/WHEN の状態機械。 |
| `lmyzmail.htcpcp.pots[n].id` / `lmyzmail.htcpcp.pots[n].type` | `pot-0 / coffee` | 省略時は既定のポット 1 個。type=coffee/tea/both。最大 64、添字連続、ID 重複不可。 |
| `lmyzmail.htcpcp.pots[n].tea-varieties` | `darjeeling,earl-grey,peppermint` | 許可する茶の CSV。 |
| `lmyzmail.htcpcp.pots[n].supported-additions` | `Cream,…,Stevia` | 許可する添加物の CSV。全既定項目と 8 ポット構成は設定例を参照。 |

### Minecraft 1.8.9

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.minecraft.enabled` / `lmyzmail.minecraft.online-mode` | `false / true` | サービス有効化と Mojang セッション検証。ゲーム内では別途メールボックス認証が必要。 |
| `lmyzmail.minecraft.compression-threshold` / `lmyzmail.minecraft.max-players` | `256 / 20` | プロトコル圧縮閾値とプレイヤー上限。 |
| `lmyzmail.minecraft.motd` / `lmyzmail.minecraft.favicon` | `§6LMYZMAIL §7- Send emails in Minecraft / ""` | サーバー一覧の説明と favicon。 |
| `lmyzmail.minecraft.read-timeout-seconds` / `lmyzmail.minecraft.session-server-url` | `30 / https://sessionserver.mojang.com/session/minecraft/hasJoined` | 読取期限とセッション認証 URL。 |
| `lmyzmail.minecraft.world-template` / `lmyzmail.minecraft.view-distance` / `lmyzmail.minecraft.max-concurrent-videos` | `worlds/mailroom / 32 / 2` | ワールドテンプレート・描画距離・動画同時実行上限。 |
| `lmyzmail.minecraft.spawn.x` / `lmyzmail.minecraft.spawn.y` / `lmyzmail.minecraft.spawn.z` / `lmyzmail.minecraft.spawn.yaw` / `lmyzmail.minecraft.spawn.pitch` | `0.5 / 160 / 0.5 / 0 / 0` | スポーン座標と向き。 |
| `lmyzmail.minecraft.whitelist.enabled` / `lmyzmail.minecraft.whitelist.players` / `lmyzmail.minecraft.blacklist.players` | `false / [] / []` | 名前の許可/拒否リスト。CSV/[n] 対応。 |
| `lmyzmail.minecraft.auth.max-attempts` / `lmyzmail.minecraft.auth.lockout-seconds` / `lmyzmail.minecraft.auth.window-seconds` | `5 / 300 / 600` | メールボックスログイン失敗の期間・ロック。 |
| `lmyzmail.minecraft.video.center-x` / `lmyzmail.minecraft.video.center-y` / `lmyzmail.minecraft.video.wall-z` | `0 / 180 / -20` | ブロック動画壁の位置。 |
| `lmyzmail.minecraft.video.max-width` / `lmyzmail.minecraft.video.max-fps` / `lmyzmail.minecraft.video.default-width` / `lmyzmail.minecraft.video.default-fps` / `lmyzmail.minecraft.video.default-contrast` | `64 / 20 / 32 / 10 / 1.2` | ブロック動画の上限と既定値。 |
| `lmyzmail.minecraft.video.spawn-protect-radius` / `lmyzmail.minecraft.video.clear-margin` | `8 / 2` | スポーン保護半径と停止時の消去余白。 |
| `lmyzmail.minecraft.map-video.center-x` / `lmyzmail.minecraft.map-video.center-y` / `lmyzmail.minecraft.map-video.center-z` / `lmyzmail.minecraft.map-video.facing` | `0 / 180 / -20 / SOUTH` | 地図壁の位置・方向（SOUTH/WEST/NORTH/EAST）。 |
| `lmyzmail.minecraft.map-video.max-maps-x` / `lmyzmail.minecraft.map-video.max-maps-y` / `lmyzmail.minecraft.map-video.max-fps` | `10 / 10 / 20` | 地図壁の横・縦タイル数と FPS の上限。 |
| `lmyzmail.minecraft.map-video.default-maps-x` / `lmyzmail.minecraft.map-video.default-fps` / `lmyzmail.minecraft.map-video.default-contrast` | `5 / 10 / 1.2` | 地図動画の既定幅・FPS・コントラスト。 |
| `lmyzmail.minecraft.map-video.base-map-id` / `lmyzmail.minecraft.map-video.base-entity-id` | `10000 / 100000` | 地図 ID・表示エンティティ ID の開始値。独自ワールドとの競合を避ける。 |

### ハニーポット・リスクスコア・SSH 監視

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.honeypot.enabled` / `lmyzmail.honeypot.initial-delay-ms` / `lmyzmail.honeypot.post-banner-timeout-ms` | `false / 1500 / 10000` | TCP トラップの有効化・banner 前遅延・banner 後読取期限。 |
| `lmyzmail.honeypot.max-connections-per-trap` / `lmyzmail.honeypot.max-read-bytes` | `100 / 1024` | トラップごとの接続上限と読取量。 |
| `lmyzmail.honeypot.traps[n].port` / `lmyzmail.honeypot.traps[n].protocol` / `lmyzmail.honeypot.traps[n].label` / `lmyzmail.honeypot.traps[n].bind-address` | `required / NONE / trap / listen.host` | 最大 256。NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC。server-protocol は protocol の別名。 |
| `lmyzmail.cringe.decay.interval` / `lmyzmail.cringe.decay.amount` | `24h / 10` | 時間経過によるスコア減衰。現在値・履歴を保持。 |
| `lmyzmail.cringe.decay.check-interval` | `auto` | 既定は interval/4 を 1m..1h に制限。別名 `lmyzmail.cringe.decay.checkInterval`。 |
| `lmyzmail.cringe.decay.activity-retention-days` | `360` | 活動記録の保持日数。 |
| `lmyzmail.fail2ban.enabled` / `lmyzmail.fail2ban.ssh-log-paths` | `false / /var/log/auth.log,/var/log/secure,/var/log/messages` | 最初に読取可能な SSH ログを EOF から監視。過去ログ全体は再生しない。 |
| `lmyzmail.fail2ban.scan-interval` / `lmyzmail.fail2ban.max-retries` / `lmyzmail.fail2ban.find-time` | `10s / 5 / 10m` | 走査間隔・失敗閾値・観測期間。 |
| `lmyzmail.fail2ban.report-cooldown` / `lmyzmail.fail2ban.max-tracked-ips` / `lmyzmail.fail2ban.cleanup-interval` | `5m / 10000 / 5m` | 報告の再発行間隔・追跡 IP 上限・清掃間隔。 |

### XDP ファイアウォール・PPS

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.xdp.enabled` / `lmyzmail.xdp.interface-name` / `lmyzmail.xdp.bpf-object-path` / `lmyzmail.xdp.pin-path` | `false / eth0 / "" / /sys/fs/bpf/lmyzmail` | object が空なら固定の内蔵 BPF を使用。カーネル権限・bpffs は別途構成。 |
| `lmyzmail.xdp.ban-threshold` / `lmyzmail.xdp.unban-threshold` | `50 / -1` | スコアによる停止/解除。-1 は ban-threshold/2。 |
| `lmyzmail.xdp.force-generic-mode` / `lmyzmail.xdp.verbose` / `lmyzmail.xdp.sync-on-startup` | `false / false / true` | 汎用 XDP モード・詳細ログ・起動時スコア同期。 |
| `lmyzmail.xdp.whitelist` | `127.0.0.1,::1` | IP 許可リスト。CSV または連続 [n]。 |
| `lmyzmail.xdp.reason-code-default` / `lmyzmail.xdp.reason-code-pps-overlimit` / `lmyzmail.xdp.reason-code-syn-flood` | `0 / 5 / 6` | 既定・PPS・SYN の理由コード。 |
| `lmyzmail.xdp.pps-monitor.enabled` / `lmyzmail.xdp.pps-monitor.poll-interval-ms` | `true / 1000` | XDP 有効時の通信統計ポーリング。 |
| `lmyzmail.xdp.pps-monitor.pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.pps-critical-threshold` | `100000 / 200000` | 総 PPS の警告/重大閾値。 |
| `lmyzmail.xdp.pps-monitor.syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.syn-pps-critical-threshold` | `10000 / 20000` | 総 SYN PPS 閾値。 |
| `lmyzmail.xdp.pps-monitor.per-ip-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-pps-critical-threshold` | `1000 / 5000` | IP ごとの PPS 閾値。 |
| `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold` | `100 / 500` | IP ごとの SYN PPS 閾値。 |
| `lmyzmail.xdp.pps-monitor.consecutive-exceed-count` / `lmyzmail.xdp.pps-monitor.record-to-cringe` | `3 / true` | 連続超過回数とスコア記録の可否。 |
| `lmyzmail.xdp.pps-monitor.max-ips-per-poll` / `lmyzmail.xdp.pps-monitor.ring-buffer-size` | `10000 / 1024` | 1 回当たり処理 IP 上限と有界イベントリング。 |

### DMARC / TLS-RPT レポート

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.reporting.enabled` / `lmyzmail.reporting.auto-send-enabled` | `false / false` | レポート収集・生成と毎日 UTC 01:00 の自動送信。 |
| `lmyzmail.reporting.batch-size` / `lmyzmail.reporting.flush-interval-ms` / `lmyzmail.reporting.retention-days` | `500 / 2000 / 90` | 受理する互換設定。有界書込は内部予算を使用。これらの値だけで履歴が自動削除されるとは見なさない。 |
| `lmyzmail.reporting.min-volume-for-report` | `10` | 日付別の対象ドメイン抽出に必要な最小件数。 |
| `lmyzmail.reporting.dmarc-report-sender-address` / `lmyzmail.reporting.dmarc-report-sender-password` / `lmyzmail.reporting.tls-report-sender-address` / `lmyzmail.reporting.tls-report-sender-password` | `"" / "" / "" / ""` | レポート送信用メールボックスの認証情報。配送前に設定。 |
| `lmyzmail.reporting.organization-name` / `lmyzmail.reporting.organization-email` | `"" / ""` | 集約レポート内の組織名・連絡先。 |
| `lmyzmail.reporting.dns-server` | `""` | RUA 検索用 DNS の数値 IP:port 指定。 |
| `lmyzmail.reporting.http-delivery-enabled` / `lmyzmail.reporting.http-delivery-timeout-seconds` | `true / 30` | TLS-RPT の HTTPS 配送。設定例は明示的に false。宛先アドレスの安全制約を適用。 |

### 内蔵負荷試験・UI

| 設定キー | 省略時 | 用途・動作 |
| --- | --- | --- |
| `lmyzmail.stress-test-enabled` | `false` | 隔離試験時のみ有効化。管理 API は実際の SMTP・ディスク・DB 負荷を発生。 |
| `lmyzmail.stress-test-sender-prefix` / `lmyzmail.stress-test-receiver-prefix` | `stresstest_send / stresstest_receive` | 試験用メールボックス接頭辞。実運用の名前と分離。 |
| `lmyzmail.stress-test-password` | `explicit secret` | 有効化前に保護されたパスワードを明示。過去のフォールバックに依存しない。 |
| `lmyzmail.stress-test-count` / `lmyzmail.stress-test-warmup-count` / `lmyzmail.stress-test-warmup-rounds` | `5000 / 1000 / 2` | 本試行件数・予熱件数・予熱回数。/start で 1 回ずつ進行。 |
| `lmyzmail.stress-test-email-size-kb` | `100` | KiB、1..10240 に制限。大きなサイズにはディスク上限を設定。 |
| `lmyzmail.show-internet-nl-badge` | `false` | Web UI バッジの表示切替。 |

### 互換別名

編集可能な全体例は [lmyzmail.properties.example](config/lmyzmail.properties.example) を参照してください。主ドメインの例は `lmyzmail.domains.main.domain=example.com`。追加ドメインには別の `<name>` 項目を使用します。

通常設定は対応する旧名前空間の別名も受理します。単なる接頭辞変更ではない対応を以下に示します。同一名前空間では推奨する正規キーを優先します。ドメインは `receiveEnabled/sendEnabled/requireExistingMailbox/dkimSelector/dkimPrivateKeyPath/listUnsubscribeMailto/listUnsubscribeUrl`、API キーは `readEnabled/writeEnabled`、トラップは `server-protocol` も受理します。

| 推奨キー | 互換別名 |
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


## HTTP インターフェース

通常の業務ルートをすべて以下に示します。スキャナー誘導パスは前述の別一覧で処理します。`public` はセッション不要、`session` は `X-Session-Token`、`read/write` は該当権限の `X-API-Key` が必要です。API キーはメールボックスのパスワードを代替せず、Web セッション API への権限も与えません。パス要素は URI エンコードし、file は一覧で返された識別子を使用してください。

| メソッド | パス | 認証 | 用途 |
| --- | --- | --- | --- |
| GET | `/`<br>`/index.html`<br>`/cringe.html`<br>`/favicon.ico`<br>`/images/embed-badge-emailtest-internet.nl.svg` | `public` | Web メール・リスク画面・静的資産 |
| GET | `/api/health`<br>`/api/skibidi`<br>`/web/domains`<br>`/web/config` | `public` | 稼働・banner・ドメイン・公開機能設定 |
| POST | `/web/login`<br>`/web/register` | `public` | JSON address/password。登録は設定・制限に従う |
| POST | `/web/logout` | `public` | 指定 X-Session-Token を無効化。token なしでも呼出し可 |
| POST | `/api/status` | `read` | サービス状態 |
| POST | `/api/mailboxes` | `write` | メールボックス作成。JSON address/password |
| GET | `/api/mailboxes/{address}/exists` | `read` | メールボックスの存在 |
| POST | `/api/mail/send` | `write` | メールボックス認証とメール JSON。非同期キュー投入 |
| POST | `/api/mail/poll`<br>`/api/mail/raw`<br>`/api/mail/rawDecoded` | `read` | 別途メールボックス認証が必要。項目は下記 |
| GET | `/api/mail/status/{queueId}`<br>`/api/mail/status/message/{messageId}`<br>`/api/mail/quota` | `read` | キュー/Message-ID 状態。quota?address= |
| GET | `/api/reports/status`<br>`/api/reports/domains`<br>`/api/reports/addresses/{domain}` | `read` | レポート状態・?date=YYYY-MM-DD・RUA 宛先 |
| POST | `/api/reports/trigger`<br>`/api/reports/domain/{domain}` | `write` | レポート生成・配送。?date=YYYY-MM-DD 指定可 |
| POST | `/api/stress/start`<br>`/api/stress/reset`<br>`/api/stress/cleanup` | `write` | 1 回実行・回数リセット・試験データ清掃 |
| POST | `/api/stress/status` | `read` | GET ではなく POST |
| GET | `/api/xdp-firewall/status`<br>`/api/xdp-firewall/stats`<br>`/api/xdp-firewall/check`<br>`/api/xdp-firewall/whitelist/check` | `read` | 状態・統計。check は ?ip= |
| POST | `/api/xdp-firewall/ban`<br>`/api/xdp-firewall/unban`<br>`/api/xdp-firewall/sync` | `write` | ?ip=。ban は &reason= も可。sync でスコア同期 |
| DELETE | `/api/xdp-firewall/clear` | `write` | 停止一覧の消去。慎重に使用 |
| GET | `/api/cringe-ips/insults`<br>`/api/cringe-ips/export`<br>`/api/cringe-ips/above-score/{score}` | `read` | ページ検索・出力・閾値による抽出 |
| GET | `/api/cringe-ips/{ip}/activities`<br>`/api/cringe-ips/{ip}/decay-estimate`<br>`/api/cringe-ips/decay-config` | `read` | 活動・減衰予測・設定 |
| GET | `/api/cringe-ips` | `read` | IP 一覧のページング、スコア・件数・日時・IP による並べ替え、検索、XDP 状態 |
| GET | `/api/cringe-ips/stats`<br>`/api/cringe-ips/{ip}` | `read` | 宣言はあるが本候補版の成功処理は未実装。正しい認証でも 404 |
| POST | `/api/cringe-ips/decay` | `write` | スコア減衰を実行 |
| GET | `/web/mail/list`<br>`/web/mail/list/{folder}` | `session` | page=0&size=50&starredOnly=false |
| GET | `/web/mail/detail/{folder}/{file}`<br>`/web/mail/raw/{folder}/{file}`<br>`/web/mail/headers/{folder}/{file}`<br>`/web/mail/attachment/{folder}/{file}/{index}` | `session` | 詳細・原文・ヘッダー・添付 |
| POST | `/web/mail/send`<br>`/web/mail/send/multipart` | `session` | JSON またはストリーミング multipart 送信 |
| GET | `/web/mail/send/status/{queueId}`<br>`/web/mail/send/status/file/{fileName}`<br>`/web/mail/quota` | `session` | 自分のメールボックスの配送状態と枠 |
| DELETE | `/web/mail/{folder}/{file}` | `session` | メール削除 |
| POST | `/web/mail/star/{folder}/{file}`<br>`/web/userdata/stars/{folder}/{fileName}` | `session` | スターの切替 |
| GET | `/web/userdata/stars/{folder}` | `session` | フォルダーのスター |
| GET POST | `/web/userdata/preferences`<br>`/web/userdata/contacts`<br>`/web/userdata/labels` | `session` | 設定・連絡先・ラベルの取得/作成 |
| PUT DELETE | `/web/userdata/contacts/{id}`<br>`/web/userdata/labels/{id}` | `session` | 連絡先・ラベルの更新/削除 |
| GET | `/web/userdata/labels/email/{folder}/{fileName}` | `session` | メールに付与されたラベル |
| POST DELETE | `/web/userdata/labels/email/{folder}/{fileName}/{labelId}` | `session` | メールへのラベル付与/解除 |


IP 一覧の既定値は `page=0`、`size=50`、`sortBy=currentScore`、`sortDir=desc`、`search=` です。ページサイズの上限は 500。並べ替え項目は許可リストで制限し、不明な項目は現在のスコアに戻します。大文字小文字を問わず `asc` のみ昇順です。検索は大文字小文字を区別せず、`%`・`_` のワイルドカードを保持します。応答には元の `searchQuery`、各 IP の `xdpBanned`・`whitelisted`、総件数・総ページ数を含みます。不正なページング引数は 400 になります。

統計と IP 詳細は引き続き未実装です（G18–G19）。現在の 404 を完了済み仕様として扱いません。画面の接続処理は統計 API に依存するため、一覧 API の修復だけで画面全体が利用可能になったわけではありません。[一覧の検証記録](docs/cringe-list-validation-20261024.md)を参照してください。

実装済み insults 一覧は `page`、`size`、`search`、出力は `minScore`、`scoreType` を受理します。ユーザーデータ JSON は[型定義](crates/lmyzmail/src/userdata.rs)に従い、Web UI も同じ API を使います。

### 要求例

保護された設定に管理キーを追加し、プレースホルダーを置換して再起動します。

```properties
lmyzmail.api-keys[0].key=REPLACE_WITH_A_RANDOM_SECRET
lmyzmail.api-keys[0].label=operations
lmyzmail.api-keys[0].read=true
lmyzmail.api-keys[0].write=true
```

呼出元の秘密保管先から `API_KEY` を設定します。メールボックス作成時のパスワードは UTF-16 code unit で 8 以上が必要です。

```bash
curl --fail-with-body http://127.0.0.1:8080/api/mailboxes \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data '{"address":"alice@example.com","password":"REPLACE_WITH_MAILBOX_PASSWORD"}'
```

API キーとともに次の JSON を `POST /api/mail/send` に送ります。`to/cc/bcc` はアドレス配列、`inReplyTo/references` は任意です。添付本文は Base64 で、メール上限には MIME の増分も考慮します。

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

`POST /api/mail/poll` は `address,password,sinceEpochMillis,limit`、`/api/mail/raw` は `address,password,file`、`/api/mail/rawDecoded` はさらに `html` を受理します。互換 raw API の原文上限は 32 KiB です。全メールや添付にはセッションのダウンロード API を使ってください。全体サイズ設定でこの上限は解除されません。

`POST /web/login` に `{"address":"alice@example.com","password":"…"}` を送り、返された `token` を `X-Session-Token` に指定します。セッション送信ではパスワードの再送は不要で、送信者はセッションから決まります。大きな添付には JSON の `data` 部分と `attachments` 名のファイル部分を持つストリーミング multipart を使います。

```bash
curl --fail-with-body http://127.0.0.1:8080/web/mail/send/multipart \
  -H "X-Session-Token: $SESSION_TOKEN" \
  -F 'data={"to":["bob@example.net"],"subject":"Report","text":"Attached"};type=application/json' \
  -F 'attachments=@report.pdf;type=application/pdf'
```

`202` は受付であり配送完了ではありません。queueId/messageId で照会してください。主なエラーは `400` 入力不正、`401` 認証・セッション不正、`403` 権限不足・停止、`404` 対象なし、`413` サイズ超過、`429` レート制限、`500/503` バックエンド・容量問題です。JSON の `error` を読み、非 200 をすべて無条件に再試行しないでください。

## 運用と問題の切り分け

- **起動：** journal、所有者/権限、ポート、DB schema、Redis ACL を確認します。解析成功は接続成功ではありません。SMTP 25 と XDP は必要権限が異なります。同じ状態に複数のランタイムを起動しないでください。
- **配送待ち：** queueId/Message-ID、MX/DNS、外向き TCP 25、TLS/MTA-STS、送信枠、リース、再試行時刻を確認します。Sent/spool/キューの対応を保ち、片側だけ削除して件数をゼロにしないでください。
- **容量と背圧：** RSS、FD、タスク、キュー件数/最古タスク、遅延/失敗、PostgreSQL 接続/ロック、Redis メモリ/遅延、Maildir/spool の容量・inode を観測します。同時実行数・枠・プール・期限は別資源を制限し、一つを増やしても性能向上は保証されません。
- **耐久性：** 既定は fsync=true。false はデータ損失を許容する導入か、fsync なしに揃えた benchmark 向けです。DB の commit 方針は変更しません。耐久試験は有効状態でも行います。
- **停止と回復：** `systemctl stop lmyzmail` または SIGTERM を使い、有界停止を待ちます。プロセスの期限は 35 秒です。強制終了後は未完了状態を検証・回復しますが、未検証の障害境界は別管理です。intent や quarantine を手動で消さず、診断を残してください。
- **モデル・動画：** パス、権限、hash、metadata、選択バックエンド、期限を確認します。フォールバック文が返るだけではモデルの正常性を証明できません。設定・モデル・証明書の変更後は再起動します。
- **更新：** バックアップ後にインストーラーを再実行し、保持された設定を確認して明示的に起動します。同梱資産はアトミックに置換されます。検証までは旧実行ファイル・設定を残します。
- **削除：** `sudo tools/uninstall-lmyzmail.sh` は停止成功を検証してから実行ファイル・unit を削除します。設定、PG/Redis、Maildir/spool、ログ、モデル/動画、ユーザー、BPF pins は残します。停止や XDP detach の失敗時は削除しません。データ消去ではありません。

Prometheus exporter や汎用オンライン設定 API は提供を約束していません。API・journal・外部計測を利用してください。負荷試験と本番の状態は分離します。`/api/stress/start` は実際のメールを自発自受し 1 回実行、reset は回数をリセット、cleanup は試験所有データを清掃します。正式 benchmark は harness による分割なしの 1 回の完全呼出しです。資源上限と独立監査は[外部試験器](blackbox/src/lmyzmail_blackbox)が担当します。

## 既存データの引継ぎとロールバック

PostgreSQL の既存 schema・トランザクション、Redis キー/TTL、Maildir のバイト列、証明書、モデル、対応する設定別名を維持します。追加の `lmyzmail_*` 回復テーブルは既存列を置換せず、ロールバック時も保持します。PG、Redis、Maildir/spool 全体、設定、証明書、モデルを整合した状態でバックアップし、旧サービスと自動再起動を停止します。**同じキューを二つの送信 worker で処理しないでください。**

通常の既存アドレスは直接引継ぎ可能です。アンダースコア、連続ドット、文字列 v1-、Unicode には過去のパス別名が関係するため、[Maildir 所有権・引継ぎ](docs/maildir-takeover.md)に従います。異なる実所有者が衝突する旧別名は拒否し、脆弱な所有権を再現しません。旧読取器への回復では、[コピー専用・fsync 付きオフライン exporter](docs/maildir-offline-rollback.md)で新ディレクトリに出力し、元データを維持します。PENDING ファイルタスクは絶対パスを参照し得るため、元 spool のパスも保持します。

特殊な互換動作は InferX の実効 120 token/単一 worker/外側 fallback、`BDAT 0 LAST` の過去の確認・破棄動作、raw API の 32 KiB 上限等です。[互換記録](docs/compatibility.md)に証拠付きの例外を記載しています。C の確率仕様は明示的な動作選択です。検証済みの引継ぎだけで全 in-flight 障害境界に合格したとはしません。

## ビルドと検証

リポジトリには固定 native ソース、第三者基盤、モデル、資産、試験、golden、証拠を含みます。Rust は **stable 1.94.0**、対象は `x86_64-unknown-linux-gnu`、依存は `Cargo.lock` で固定します。ビルドには C/C++、Clang **18.1.3**、pkg-config、libbpf/libelf、zlib/OpenSSL、Cairo/FreeType 開発パッケージが必要です。FFmpeg 7.1 は同梱固定ソースから構築します。本番サービスに oracle は不要です。

```bash
rustup show
LMYZMAIL_BPF_CLANG=clang-18 cargo build --release --locked \
  --target x86_64-unknown-linux-gnu -p lmyzmail
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
tools/test-installation.sh
tools/verify-release-reproducibility.sh /absolute/path/to/new-verification-output
```

試験器は Python 3.12/pytest、raw socket、Playwright で、ポート・一時領域・PG/Redis を隔離して起動します。`blackbox/bin/bootstrap-python.sh` で固定依存を導入し、`provision-runtime.sh` / `provision-playwright.sh` で検証環境を用意します。Java は開発差分の oracle にのみ使用します。[本機検証記録](docs/local-validation-20261023.md)で前提条件と証拠を確認し、本番データに試験を実行しないでください。

既存証拠は HTTP/UI/権限/添付、安全回帰、SMTP/MIME/再試行/報告、Redis/PG/Maildir、スケジューラー/再起動、HTCPCP、Minecraft、ハニーポット、モデル、描画を対象とします。長時間負荷、異常/fuzz/障害入力、全要件には項目別の証拠が必要で、テスト総数だけでは網羅を証明できません。既存 golden を変更せず、実際の非決定値のみ正規化し、失敗も保持します。

関連資料：[キュー](docs/outbound-queue-contract.md)、[経路](docs/outbound-route-contract.md)、[報告実行](docs/reporting-trigger-contract.md)、[HTTPS 報告](docs/reporting-https-contract.md)、[SSH 監視](docs/fail2ban-contract.md)、[リリース](docs/release.md)、[受入](docs/acceptance-status.md)。過去の証拠は元 SHA を維持し、書換後の対応は[履歴マッピング](docs/git-identity-migration-20261023.md)に記載します。
