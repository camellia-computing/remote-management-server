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
- PostgreSQL 可通过 `CAMELLIA_REMOTE_DATABASE_URL`，或完整的 `CAMELLIA_REMOTE_DATABASE_HOST/PORT/NAME/USER/PASSWORD` 独立参数配置；两种形式不得混用。Compose 使用独立参数，因此强密码中的 URL 保留字符无需特殊编码。
- `CAMELLIA_REMOTE_ALLOWED_HOSTS` 与 `CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS`：显式公共主机和 HTTPS 源，不接受生产通配符。
- `CAMELLIA_REMOTE_API_SERVER` 与 `CAMELLIA_REMOTE_ID_SERVER`：分别使用 HTTPS 和带显式端口的 WSS；`CAMELLIA_REMOTE_RS_PUB_KEY` 必须是恰好 32 字节的规范 Base64 公钥。

密钥不得写入镜像、仓库或命令行历史。生产模式强制 TLS，OIDC 参数必须整组配置。未知OIDC主体默认拒绝，只能在Django Admin中预先绑定；开启`CAMELLIA_REMOTE_OIDC_AUTO_PROVISION`时还必须设置至少一个精确的已验证邮箱域或JSON claim allowlist。每个配置的claim都必须存在，标量或数组值必须精确命中allowlist；自动建号identity在每次登录时重新检查当前策略。所有布尔值、整数、日志级别和时区都严格校验，拼写错误会阻止启动而不会回退。只有反向代理确实覆盖来源头并且 `CAMELLIA_REMOTE_TRUSTED_PROXY_CIDRS` 精确限定时，才能开启 `CAMELLIA_REMOTE_TRUST_PROXY_HEADERS`。

Gunicorn访问日志只输出method、固定路由模式、status、bytes、duration和服务端生成的request ID；不会输出raw URL/query、Referer、User-Agent或客户端地址。反向代理必须采用同一边界，禁止重新记录OIDC code/state、分享token、audit/session/device参数或recording filename。

地址簿和待处理OIDC中的secret使用带key ID的`secretbox:v2` envelope认证加密；数据库key inventory保存不含业务明文的canary和fingerprint，readiness会拒绝错误key或replica配置分裂。连接凭据只通过已认证且通过地址簿权限校验的运行时 API 返回。Django 管理表单将其作为只写字段，CSV/Excel 导出不包含连接凭据。

设备身份使用一次性`camellia-device-proof-v1` challenge。已部署设备的密码/OIDC登录必须由当前Ed25519设备私钥签名；首次部署由新设备密钥签名；主动换钥必须由旧钥与新钥对同一challenge双签。旧钥丢失时，管理员只能通过`POST /api/devices/<device-id>/approve-recovery`预先批准一个精确的新公钥；批准有效期10分钟、仅可消费一次，成功后设备代际递增且旧bearer立即撤销。Client必须逐字段验证canonical message后才能签名，不能把Management响应当作任意消息签名请求。

Identity Server对`POST /api/devices/verify-deployment`的每次请求提供随机32字节nonce；Management返回30秒有效、以共享验证密钥HMAC-SHA256签名并绑定rid、UUID、公钥哈希、设备代际与nonce的`camellia-deployment-assertion-v1` JSON。旧的静态204契约已删除；Management、Client和Server必须协调升级，Server只允许更高代际替换已持久化身份。

轮换时先把新ID/key设为primary，将旧key按`old-id:Base64`放入`CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS`，并让`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`继续指向产生旧v1行的key。先运行`python manage.py rotate_data_encryption --dry-run`，再以有界batch正式运行；命令可以用`--max-batches`中断并安全续跑。所有batch完成后必须再执行一次不带`--max-batches`的命令，认证验证全部primary envelope。只有该完整验证和readiness通过，并确认所有保留backup不再依赖旧key后，才可运行`--retire-key-id OLD_ID`；删除旧secret时还要把`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`切换到仍配置的key。key inventory只记录ID、SHA-256 fingerprint和加密canary，不记录key material。

## OCI + systemd 部署

```bash
sudo install -d -m 0755 /opt/camellia-remote-management /etc/camellia-remote-management
sudo install -m 0644 docker-compose.yaml /opt/camellia-remote-management/
sudo install -m 0755 deploy/backup-postgres.sh /opt/camellia-remote-management/
sudo install -m 0600 .env.example /etc/camellia-remote-management/management.env
sudo install -m 0644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now camellia-remote-management-stack.service
sudo systemctl enable --now camellia-remote-management-backup.timer
sudo systemctl enable --now camellia-remote-management-cleanup.timer
```

生产环境应把 `CAMELLIA_REMOTE_MANAGEMENT_IMAGE` 固定为发布清单记录的 `ghcr.io/...@sha256:...`，不得使用浮动标签。迁移由一次性 `migrate` 容器完成；迁移成功后应用容器才会启动。
systemd 运维单元仅允许通过本机 Unix socket 调用 Docker；该 socket
等同宿主机 root 权限，必须只允许 root 访问，并保护部署目录和环境文件不被非特权用户修改。

Compose 默认仅在同主机、不可从外部路由的 `backend` 网络内使用 PostgreSQL，因此该链路显式采用 `sslmode=disable`。外部或跨主机数据库强制使用 `verify-full`、可信 CA 和与证书匹配的主机名；私有 CA、客户端证书和私钥可分别通过绝对路径 `CAMELLIA_REMOTE_DATABASE_SSLROOTCERT`、`CAMELLIA_REMOTE_DATABASE_SSLCERT`、`CAMELLIA_REMOTE_DATABASE_SSLKEY` 配置，其中客户端证书与私钥必须成对提供。这是唯一保留的无数据库 TLS 特例。

## 备份、恢复与运维

每小时定时器生成 PostgreSQL custom-format 备份并在写入完成后原子重命名。每五分钟的清理任务删除过期登录失败记录、OIDC 会话、设备证明challenge、设备恢复批准和访问令牌，标记过期分享链接，并按配置的保留期删除已消费或已过期链接。备份目录必须位于独立、加密且受监控的存储；至少每天复制到故障域外，并按季度执行恢复演练。

恢复流程：停止应用、创建空数据库、用与生产相同主版本的 `pg_restore --clean --if-exists --no-owner --no-acl` 恢复、执行迁移和 `manage.py check --deploy`、验证 `/health/ready`，最后恢复流量。不得在未演练的情况下覆盖现有数据库。

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
