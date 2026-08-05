# Camellia Remote Management Server

Camellia Remote 的生产管理平面：提供账号与设备管理、地址簿、策略、审计以及锁定版本的 Web 客户端。生产环境只支持 PostgreSQL；SQLite 仅用于显式 `CAMELLIA_REMOTE_DEBUG=true` 的本地开发。在线插件签名目前保持禁用，直到仓库具备版本化 artifact envelope、实际验签消费者和受审批签发流程。

## 架构与边界

- `remote-client` 提供桌面、移动与 Web 客户端；本仓库通过 `web-client.lock` 固定一个已通过客户端 `CI / Required` 的完整提交。
- `remote-server` 提供身份发现、打洞与中继；`CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN` 和服务器公钥必须在两个服务间一致。
- 本服务监听 `21114`，应置于 TLS 反向代理之后。PostgreSQL 和内部网络不得直接暴露到公网。
- 生产基线为单区域，目标 SLO 99.9%、RPO 不超过 1 小时、RTO 不超过 4 小时。

## 本地开发

日常开发和 CI 使用 Python 3.13+、uv 0.12.0 和 PostgreSQL 18。仅快速开发时可使用 SQLite：

```bash
uv sync --locked --all-groups
CAMELLIA_REMOTE_DEBUG=true CAMELLIA_REMOTE_SECRET_KEY=dev-only-insecure-secret-key \
  CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN=development-device-token-00000000 \
  uv run python manage.py migrate
CAMELLIA_REMOTE_DEBUG=true CAMELLIA_REMOTE_SECRET_KEY=dev-only-insecure-secret-key \
  CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN=development-device-token-00000000 \
  uv run python manage.py runserver 127.0.0.1:21114
```

规范检查：

```bash
uv run ruff format --check .
uv run ruff check .
uv run python manage.py makemigrations --check --dry-run
uv run pytest
python scripts/test_release_metadata.py
```

`[tool.uv].required-version` 暂时允许 `>=0.11.8,<0.13`：截至
2026-07-30，GitHub 托管的 Dependabot uv 更新器仍使用 0.11.8，精确要求
0.12.0 会使自动依赖更新失败。CI 仍精确安装 0.12.0；托管更新器支持该版本后
应恢复精确约束。

## 生产配置

从 `.env.example` 生成权限为 `0600` 的配置。至少必须设置：

- `CAMELLIA_REMOTE_SECRET_KEY`：不少于 50 个字符的随机值。
- `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID` 与 `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY`：1–32 字符的稳定小写key ID，以及恰好32字节的规范Base64 primary key。首次升级时将`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`设为同一ID。
- `CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN`：32–512 个无空白字符。
- 非Compose运行可通过 `CAMELLIA_REMOTE_DATABASE_URL`，或完整的 `CAMELLIA_REMOTE_DATABASE_HOST/PORT/NAME/USER/PASSWORD` 独立参数配置；两种形式不得混用。生产Compose改用五套互不相同的`BOOTSTRAP/MIGRATION/RUNTIME/BACKUP/PROBE_USER/PASSWORD`，用户名和密码都不得复用，密码至少16字符，因此强密码中的URL保留字符无需编码。首次接管已有volume时，`BOOTSTRAP`必须填写该cluster原有superuser；它只允许出现在root-owned环境文件、PostgreSQL初始化和一次性bootstrap service中，不能交给应用。
- `CAMELLIA_REMOTE_ALLOWED_HOSTS` 与 `CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS`：显式公共主机和 HTTPS 源，不接受生产通配符。
- `CAMELLIA_REMOTE_API_SERVER` 与 `CAMELLIA_REMOTE_ID_SERVER`：分别使用 HTTPS 和带显式端口的 WSS；`CAMELLIA_REMOTE_RS_PUB_KEY` 必须是恰好 32 字节的规范 Base64 公钥。

密钥不得写入镜像、仓库或命令行历史。生产模式强制 TLS，OIDC 参数必须整组配置。未知OIDC主体默认拒绝，只能在Django Admin中预先绑定；开启`CAMELLIA_REMOTE_OIDC_AUTO_PROVISION`时还必须设置至少一个精确的已验证邮箱域或JSON claim allowlist。每个配置的claim都必须存在，标量或数组值必须精确命中allowlist；自动建号identity在每次登录时重新检查当前策略。所有布尔值、整数、日志级别和时区都严格校验，拼写错误会阻止启动而不会回退。只有反向代理确实覆盖来源头并且 `CAMELLIA_REMOTE_TRUSTED_PROXY_CIDRS` 精确限定时，才能开启 `CAMELLIA_REMOTE_TRUST_PROXY_HEADERS`。

Gunicorn访问日志只输出method、固定路由模式、status、bytes、duration和服务端生成的request ID；不会输出raw URL/query、Referer、User-Agent或客户端地址。反向代理必须采用同一边界，禁止重新记录OIDC code/state、分享token、audit/session/device参数或recording filename。

生产环境强制启用请求准入控制，设置`CAMELLIA_REMOTE_RATE_LIMIT_ENABLED=false`会直接阻止启动。每个进程先用有界、基于monotonic clock的内存窗口，在URL解析、session和数据库访问前约束global/source入口；`/health/live`与`/health/ready`只豁免共享数据库状态，仍受该本地入口上限保护。随后PostgreSQL以原子fixed window和短期concurrency lease统一约束多replica的global/service、IPv4 `/32`或IPv6 `/64` source、route、bearer credential、actor credential generation、device deployment generation以及recording声明字节。表中只保存domain-separated SHA-256标识和固定scope/group，不保存原始IP、token、actor或device值；这些hash是用于限流的pseudonymous标识，不应视为匿名化数据。

超限响应为429，并带有有界`Retry-After`、`RateLimit-Limit`和`Cache-Control: no-store`；共享admission后端异常时稳定返回503且不泄露数据库错误。五分钟cleanup timer回收过期bucket和崩溃残留lease，lease时间必须大于Gunicorn允许的最长请求生命周期。`.env.example`列出service、source、credential、recording bytes、concurrency和本地容量上限。应用限流不能替代edge/WAF、反向代理连接/body/带宽上限或只允许内部访问health endpoint；启用forwarded headers时，可信proxy CIDR必须覆盖且代理必须删除客户端自带的来源头，否则source预算没有可信安全边界。

地址簿和待处理OIDC中的secret使用带key ID的`secretbox:v2` envelope认证加密；数据库key inventory保存不含业务明文的canary和fingerprint，readiness会拒绝错误key或replica配置分裂。shared profile的默认连接密码不再存入通用`info` JSON，而是迁移到显式加密字段；profile列表永不加载或返回该字段，Client仅在目标RID已存在且当前地址簿权限有效时调用目标绑定的即时credential API。连接凭据只通过已认证且通过地址簿权限校验的运行时 API 返回。Django 管理表单将其作为只写字段，CSV/Excel 导出不包含连接凭据。

地址簿ACL审计与对应权限变更在同一事务提交。审计行保存profile GUID、名称和owner的不可变快照；删除profile会先写入tombstone，再把历史行的业务外键置空，因此API、Web、Admin或owner级联删除都不会抹除已有ACL历史。Django Admin只允许查看这些审计行，不允许新增、修改或删除。

设备身份使用一次性`camellia-device-proof-v1` challenge。已部署设备的密码/OIDC登录必须由当前Ed25519设备私钥签名；首次部署由新设备密钥签名；主动换钥必须由旧钥与新钥对同一challenge双签。旧钥丢失时，管理员只能通过`POST /api/devices/<device-id>/approve-recovery`预先批准一个精确的新公钥；批准有效期10分钟、仅可消费一次，成功后设备代际递增且旧bearer立即撤销。Client必须逐字段验证canonical message后才能签名，不能把Management响应当作任意消息签名请求。

设备heartbeat成功时返回绑定rid、UUID和deployment generation的60秒`device_lease`，并继续以15秒idle/3秒active节奏续租。禁用、删除、owner失效或统一credential撤销后，旧bearer的heartbeat返回绑定同一rid/UUID的显式`revoked`状态；Client必须立即停止新入站连接并关闭现有direct/relay/file/terminal会话。网络或Management故障不伪装成显式撤销，但最后一个有效lease到期后同样fail closed。

Identity Server对`POST /api/devices/verify-deployment`的每次请求提供随机32字节nonce；Management返回30秒有效、以共享验证密钥HMAC-SHA256签名并绑定rid、UUID、公钥哈希、设备代际与nonce的`camellia-deployment-assertion-v1` JSON。旧的静态204契约已删除；Management、Client和Server必须协调升级，Server只允许更高代际替换已持久化身份。

轮换时先把新ID/key设为primary，将旧key按`old-id:Base64`放入`CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS`，并让`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`继续指向产生旧v1行的key。先运行`python manage.py rotate_data_encryption --dry-run`，再以有界batch正式运行；命令可以用`--max-batches`中断并安全续跑。所有batch完成后必须再执行一次不带`--max-batches`的命令，认证验证全部primary envelope。只有该完整验证和readiness通过，并确认所有保留backup不再依赖旧key后，才可运行`--retire-key-id OLD_ID`；删除旧secret时还要把`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`切换到仍配置的key。key inventory只记录ID、SHA-256 fingerprint和加密canary，不记录key material。

## OCI + systemd 部署

```bash
sudo install -d -m 0755 /opt/camellia-remote-management /opt/camellia-remote-management/deploy /etc/camellia-remote-management
sudo install -m 0644 docker-compose.yaml /opt/camellia-remote-management/
sudo install -m 0755 deploy/bootstrap-postgres-roles.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/backup-postgres.sh /opt/camellia-remote-management/
sudo install -d -m 0755 /opt/camellia-remote-management/scripts
sudo install -m 0755 scripts/backup_envelope.py /opt/camellia-remote-management/scripts/
sudo install -m 0755 deploy/restore-postgres.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/management-maintenance-guard.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/management-maintenance.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/start-management-stack.sh /opt/camellia-remote-management/
sudo install -m 0600 .env.example /etc/camellia-remote-management/management.env
sudo install -m 0644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now camellia-remote-management-stack.service
sudo systemctl enable --now camellia-remote-management-backup.timer
sudo systemctl enable --now camellia-remote-management-cleanup.timer
```

生产环境应把 `CAMELLIA_REMOTE_MANAGEMENT_IMAGE` 固定为发布清单记录的 `ghcr.io/...@sha256:...`，不得使用浮动标签。systemd没有在线`reload`入口；升级必须使用显式stop/start或受审部署流程。每次stack start由单飞controller先停止旧Management，启动PostgreSQL但不等待尚未创建的probe，使用bootstrap superuser在advisory-lock事务内创建/收敛角色、ownership、membership、当前ACL与migration default ACL，再以probe执行真实`SELECT 1`健康检查。随后只用migration owner运行一次性`migrate`，再次bootstrap验证新对象，最后用runtime DML credential启动`restart: no`应用。Runtime不是database/schema/table owner，且始终为`NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`；`django_migrations`对runtime只读，不能伪造schema ledger。Backup只拥有业务读取能力，probe没有public schema或业务表权限。Controller与maintenance enter/leave共用root-owned deployment lock，maintenance lease存在时不会执行Docker命令。Engine或container restart不会自动拉起Management；任何直接启动仍会由`run.sh`的`migrate --check`在Gunicorn绑定端口前拒绝未应用migration。应用崩溃必须告警并进入受控stack start，不能用Docker自动restart绕过migration gate。

首次升级已有volume前必须确认环境中的`BOOTSTRAP_USER/PASSWORD`就是旧cluster的现有superuser；错误映射会fail closed，不能通过临时把runtime升为superuser绕过。五类密码轮换时先在受保护环境文件中写入互不相同的新值，再通过controller离线收敛并验证；旧目标密码随事务提交失效。Bootstrap本身是root-only break-glass凭据，轮换或使用必须审计，不能作为日常migration、备份、探针或排障登录。
systemd 运维单元仅允许通过本机 Unix socket 调用 Docker；该 socket
等同宿主机 root 权限，必须只允许 root 访问，并保护部署目录和环境文件不被非特权用户修改。

Compose 默认仅在同主机、不可从外部路由的 `backend` 网络内使用 PostgreSQL，因此该链路显式采用 `sslmode=disable`。外部或跨主机数据库强制使用 `verify-full`、可信 CA 和与证书匹配的主机名；私有 CA、客户端证书和私钥可分别通过绝对路径 `CAMELLIA_REMOTE_DATABASE_SSLROOTCERT`、`CAMELLIA_REMOTE_DATABASE_SSLCERT`、`CAMELLIA_REMOTE_DATABASE_SSLKEY` 配置，其中客户端证书与私钥必须成对提供。这是唯一保留的无数据库 TLS 特例。

## 备份、恢复与运维

每小时定时器使用受审固定版本（当前基线 `age v1.2.1`）的 `/usr/bin/age` recipient，从一次性`database-backup`客户端以只读backup角色输出custom-format dump后立即封装并认证加密；脚本不再进入server容器或接触`POSTGRES_USER`。明文不会写入备份目录，最终文件是 `postgres-<UTC时间>-<随机backup-id>.dump.age`，并在完整写入后原子重命名。`CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT`、`CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID` 和 `CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID` 必须显式配置。recipient 对应的恢复 identity 只能放在 root/管理员拥有的 0400 或 0600 文件中，不能放入普通 management runtime 容器、镜像、环境文件或备份 artifact；identity 与应用数据加密 key 必须分离。备份目录必须位于独立、加密且受监控的存储；至少每天复制到故障域外，并按季度执行恢复演练。锁竞争返回退出码 75，监控应将其视为本轮跳过而非成功。

backup/cleanup unit没有启动业务栈的权限：它们只在stack已经是`active`且不存在root-owned maintenance lease时运行；否则`ExecCondition`记录`skipped:not-running`或`skipped:maintenance`并退出，不会创建容器。仅停止stack不再可能被5分钟/hourly/Persistent timer反向解除，但正式维护仍必须显式停timer并保留lease。

恢复流程（必须先在隔离环境演练）：先从反向代理摘流并执行 `sudo /opt/camellia-remote-management/management-maintenance.sh enter --reason restore-INCIDENT-ID`。该命令先原子创建`/run/camellia-remote-management/maintenance.lease`，再停止两个timer、正在执行的backup/cleanup和stack，最后确认官方Compose项目没有残留容器；任一步失败都会保留lease并fail closed。随后只启动隔离的PostgreSQL service、创建空数据库，准备root拥有且权限为0400/0600的identity，设置与备份一致的 `CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID`、`CAMELLIA_REMOTE_DATABASE_NAME`、`CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR` 和 `CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID`，然后执行 `CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE=/etc/camellia-remote-management/backup-identity.txt /opt/camellia-remote-management/restore-postgres.sh /var/backups/camellia-remote-management/postgres-<UTC时间>-<backup-id>.dump.age`。脚本先让age完整验证密文，再bootstrap空库角色，只用migration credential通过`database-restore`执行 `pg_restore --single-transaction --exit-on-error --no-owner --no-acl`，成功后再次收敛owner/ACL并运行probe；任何密文、manifest、数据库、PostgreSQL主版本或角色边界不匹配都会fail closed，且恢复用的短暂明文临时文件在退出时删除。

在lease存在且timer停止期间完成migration、schema/key和隔离readiness验证；不要恢复外部流量。验证后停止所有隔离Compose容器，再执行 `sudo /opt/camellia-remote-management/management-maintenance.sh leave --confirm-validated`。该命令只解除lease，不会自动启动任何服务；随后手动启动stack，验证`/health/ready`，最后才恢复流量并手动启动backup/cleanup timer。`status`子命令可读取当前lease和stack状态。不得通过删除lease文件、让lease自动过期或只停止stack来绕过该状态机，也不得在未演练时覆盖现有数据库。

备份密钥轮换：先生成新的 age recipient/identity，更新 `CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID` 与 recipient 并等待一轮成功备份；保留旧 identity，直到旧文件名范围内的备份均已迁移、恢复验证或按保留策略过期，再撤销旧 recipient。恢复 identity 不得与 `CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY` 共用，任何 key material 不得写入日志。

告警至少覆盖就绪探针、5xx、认证失败激增、数据库容量/连接池、备份新鲜度和证书到期。部署失败时回滚到上一镜像摘要；数据库变更按前向修复处理。

## Web 来源与发布

跨仓体系审查与正式发布门禁见逻辑客户端仓库中的
`docs/production-readiness-audit.md`；物理仓库名由完整且受审的
`REMOTE_REPOSITORY_MAP` 解析，不在代码中固化。

```bash
./sync_web_client.sh --build-from ../remote-client
```

生成的 `static/web_client` 不提交。CI 从逻辑仓库映射解析客户端，
构建 `web-client.lock` 指向的精确提交并记录来源。正式发布还要求该
提交对应唯一的、已完成且不可变的客户端正式 Release，并复用当前
Management 提交的精确成功 CI Web 产物。Release App 通过受审
`release/next` PR 生成版本和标签；冻结多架构 OCI、扫描、SBOM、
provenance 与依赖证据全部成功后才进入 `release` 环境。GHCR 与
Docker Hub 按映射逐项发布或跳过，所有已配置目标使用同一摘要。
GitHub Release 的全部资产会签名并公开回读。`latest` 只指向最高的
已完成稳定版，部署仍必须使用摘要。完整状态机见
[发布规范](docs/releasing.md)。

## 许可证与来源

本仓库以 GNU AGPL-3.0-only 发布。网络部署修改版时必须按 AGPL 向用户提供对应源代码。来源快照和上游归属记录在 `SOURCE_PROVENANCE.json` 与 `NOTICE`。

安全问题请按 `SECURITY.md` 私下报告，不要创建公开漏洞 issue。
