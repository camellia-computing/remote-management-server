# Camellia Remote Management Server

Camellia Remote 的生产管理平面：提供账号与设备管理、地址簿、策略、审计以及锁定版本的 Web 客户端。生产环境只支持 PostgreSQL；SQLite 仅用于显式 `CAMELLIA_REMOTE_DEBUG=true` 的本地开发。在线插件签名目前保持禁用，直到仓库具备版本化 artifact envelope、实际验签消费者和受审批签发流程。

## 架构与边界

- `remote-client` 提供桌面、移动与 Web 客户端；本仓库通过 `web-client.lock` 固定一个已通过客户端 `CI / Required` 的完整提交。
- `remote-server` 提供身份发现、打洞与中继；`CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN` 和服务器公钥必须在两个服务间一致。
- 本服务监听 `21114`，应置于 TLS 反向代理之后。PostgreSQL 和内部网络不得直接暴露到公网。
- 生产基线为单区域，目标 SLO 99.9%、RPO 不超过 1 小时、RTO 不超过 4 小时。

## 本地开发

日常开发和 CI 使用 Python 3.14、uv 0.12.0 和 PostgreSQL 18。Username identity v1固定使用Python 3.14内置的Unicode 16.0.0数据；其他Python/Unicode数据版本会在迁移或启动检查时fail closed。仅快速开发时可使用 SQLite：

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

OIDC callback在任何discovery、token exchange、JWKS读取或本地建号前，先以随机owner、单调generation和有限lease把pending state短事务claim为`processing`；外部HTTP期间不持数据库锁。只有仍匹配owner/generation且lease未过期的worker可以把user/identity provisioning与pending `done`在同一事务提交，provider error和旧worker不能覆盖活动或更新一代claim；过期claim可由重试提升generation后接管。`CAMELLIA_REMOTE_OIDC_CALLBACK_CLAIM_LEASE_SECONDS`必须至少覆盖discovery、token、JWKS和未知`kid`轮换刷新四段OIDC HTTP deadline加15秒本地余量，过短配置会在启动时fail closed。

OIDC discovery与JWKS统一使用外部文档合同v1。响应必须是最多1 MiB、无BOM的UTF-8 JSON，Content-Type只允许`application/json`或`application/jwk-set+json`及唯一`charset=utf-8`；duplicate/NFC等价key、非有限数、64位外整数、8层外嵌套、单container超过64项、总node超过2,048或字符串超过8 KiB都会在JOSE处理前拒绝。Discovery只保留匹配配置issuer、allowlisted HTTPS authorization/token/JWKS/userinfo endpoint及最多16个唯一安全签名算法。JWKS最多32把带唯一1–128 printable ASCII `kid`的公开signature key，只接受2,048–8,192位RSA、P-256/384/521 EC或Ed25519，严格绑定`alg/use/key_ops/curve`并拒绝私钥、未知字段与非规范key material；有界x509 metadata只校验后丢弃，不交给JOSE import。两类已验证文档共享最多16项LRU、5分钟fresh TTL、ETag revalidation与single-flight；只有transport/HTTP失败可额外使用15分钟stale已验证副本，schema错误不污染cache。未知token `kid`只强制一次JWKS刷新，仍不匹配则fail closed。

Gunicorn访问日志只输出method、固定路由模式、status、bytes、duration和服务端生成的request ID，以及trace/span和可选业务event ID；不会输出raw URL/query、Referer、User-Agent或客户端地址。最外层middleware只接受严格canonical的W3C v00 `traceparent`和UUIDv4 `X-Camellia-Event-ID`，永不接受外部`X-Request-ID`，并在response回传服务端span的`traceparent`、`X-Request-ID`及合法event ID。`api.*`请求事件与后台cleanup使用`schema_version=1`的单一JSON object，包含service/version、UTC timestamp、level、route template、method、request/trace/span/event ID以及适用的status、duration或error class；请求context在结束和异常路径都必须reset。反向代理必须采用同一边界，禁止重新记录OIDC code/state、分享token、audit/session/device参数或recording filename。

生产环境强制启用请求准入控制，设置`CAMELLIA_REMOTE_RATE_LIMIT_ENABLED=false`会直接阻止启动。每个进程先用有界、基于monotonic clock的内存窗口，在URL解析、session和数据库访问前约束global/source入口；`/health/live`与`/health/ready`只豁免共享数据库状态，仍受该本地入口上限保护。随后PostgreSQL以原子fixed window和短期concurrency lease统一约束多replica的global/service、IPv4 `/32`或IPv6 `/64` source、route、bearer credential、actor credential generation、device deployment generation以及recording声明字节。表中只保存domain-separated SHA-256标识和固定scope/group，不保存原始IP、token、actor或device值；这些hash是用于限流的pseudonymous标识，不应视为匿名化数据。

超限响应为429，并带有有界`Retry-After`、`RateLimit-Limit`和`Cache-Control: no-store`；共享admission后端异常时稳定返回503且不泄露数据库错误。五分钟cleanup timer回收过期bucket和崩溃残留lease，lease时间必须大于Gunicorn允许的最长请求生命周期。`.env.example`列出service、source、credential、recording bytes、concurrency和本地容量上限。应用限流不能替代edge/WAF、反向代理连接/body/带宽上限或只允许内部访问health endpoint；启用forwarded headers时，可信proxy CIDR必须覆盖且代理必须删除客户端自带的来源头，否则source预算没有可信安全边界。

所有JSON API请求只接受未做`Content-Encoding`的`application/json`（可带唯一的`charset=utf-8`），必须携带唯一且准确的canonical十进制`Content-Length`，并拒绝`Transfer-Encoding`。解析器在任何mutation前按auth、普通控制、audit、管理批量和地址簿批量路由分别实施字节预算，同时拒绝重复或Unicode NFC等价key、非有限数字、超长数字/字符串/key、超过64层的嵌套、单容器超过10,000项或总计超过250,000个node；已知格式错误稳定返回JSON 400，超限返回413，错误media type/encoding返回415。`/api/share`只从一个有界的URL-encoded或multipart `data`字段解析同一strict JSON合同。TLS edge必须有界缓冲HTTP/1.1 chunked或HTTP/2 DATA、移除`Transfer-Encoding`并生成准确长度；不能建立边界时须在转发Gunicorn前拒绝。`.env.example`中的JSON预算独立于recording chunk配置，增大录像chunk不会扩大login或控制面输入。

用户、设备、设备组和策略管理mutation按method使用精确字段allowlist；unknown、只读字段、缺失必填字段、同时提交`name`与`username`别名以及不含任何可变字段的PATCH会在数据库查询/保存前返回400。错误包含固定`field_contract_version=1`、机器码`invalid_request_fields`和排序后的字段名，但绝不回显字段值。合法PATCH和设备assign只保存显式字段，成功审计只记录有界`changed_fields`；状态和DELETE请求只允许空object或空body。策略status暂时同时接受JSON boolean和精确`{"enabled": BOOLEAN}`object，object中的任何额外字段都会拒绝。

策略批量分配、设备组批量加入/移除、用户批量强制登出，以及单个用户/设备启停和设备删除都必须携带canonical UUID形式的`Idempotency-Key`。Management在同一PostgreSQL事务中持久化operation receipt，并以transaction-scoped advisory lock串行化这些低频控制mutation；批操作先锁定并核对完整目标集合，状态/删除操作则锁定权威row，把状态或删除与适用的token、proof challenge和recovery approval撤销作为同一commit。禁用用户会推进credential generation并删除其bearer；禁用设备会推进deployment generation并删除该设备的bearer、proof challenge和未消费recovery approval，因此后来重新启用设备也不能复活由旧generation授权的recording upload、audit session、proof challenge或recovery approval。重复、缺失、generation耗尽、错误成员关系、竞争删除或注入数据库故障只能保留完整旧状态或完整新状态。response receipt包含`management_operation_receipt_version`、operation ID/单调generation、canonical request/result digest以及精确`requested`/`applied`计数；单目标receipt只保留目标数据库标识、最终状态和撤销数量，不把profile note、email、host metadata或IP复制进receipt表。相同ID和相同请求在响应丢失后返回原receipt，即使设备row已经删除也可重放，ID被不同actor、操作或target复用则409。管理员不能禁用或删除当前bearer所在设备，因为这会销毁响应丢失后重放receipt所需的authority；此类操作必须从另一台active管理员设备执行。批处理CLI会在发送前打印ID并支持`--operation-id`；其他调用方同样必须在发送前持久化ID并核对receipt后才能报告成功。cleanup timer按`CAMELLIA_REMOTE_MANAGEMENT_OPERATION_RETENTION_DAYS`和有界batch删除过期receipt，超过该窗口不得把旧ID重放当成幂等恢复。

录像上传只接受`version=2`协议；旧`new/part/tail/remove`请求返回426，Client与Management必须协调升级。Client先持久化随机`create_id`，Management签发绑定device owner与deployment generation的`upload_id`。每个chunk携带offset、revision、随机chunk ID、长度和SHA-256；服务端只有在staging文件`fsync`且数据库receipt提交后才确认新的权威offset/revision，相同chunk可在响应丢失后幂等重放，status也必须精确匹配该chunk receipt，不能只凭offset前进就确认。部分写会按独立的ciphertext `storage_offset`截回最后已提交record，API与quota仍只使用plaintext offset。Client重启从Unix 0600/Windows录像目录ACL保护的双槽校验sidecar恢复待确认chunk/finalize，无法证明本地录像已正常关闭时只执行幂等abort。

`/api/record`的每个POST都必须携带唯一一个有效十进制且准确的`Content-Length`，空`new/status/finalize/abort`也必须显式发送`Content-Length: 0`。Management在storage admission、文件或数据库mutation前拒绝`Transfer-Encoding`/chunked（400）、缺失或空length（411）、非法/歧义length（400）以及超过chunk上限的length（413）；query `length`仍必须与transport length和实际读取bytes完全一致。生产TLS edge必须把HTTP/1.1 chunked或HTTP/2 DATA有界缓冲到`CAMELLIA_REMOTE_RECORD_UPLOAD_MAX_CHUNK_BYTES`以内，删除`Transfer-Encoding`并只生成一个准确CL；不能完成缓冲/计数时必须在转发前拒绝，禁止把streaming body直接交给Gunicorn。Gunicorn只允许从可信内部edge访问；其重复CL与CL+TE解析拒绝是第二道防线，不能替代edge合同。当前Client使用`Bytes`/`Vec`固定body，reqwest会生成准确CL，无需协议兼容层。

Management为每个upload生成独立32-byte data key，只把其规范Base64值通过现有data-encryption keyring认证封装进PostgreSQL；record volume从第一个字节起只保存版本化、带认证的header与顺序SecretBox chunk records，不保存明文WebM/MP4。header绑定format与upload UUID；每条record绑定upload UUID、revision、plaintext offset/length、chunk SHA-256和payload。SecretBox的24-byte nonce由canonical upload UUID（16 bytes）与单调revision（8 bytes）注入式组成：header独占revision 0，chunk只能从1严格递增，所以即使随机源故障或data key意外复用，同一key下也不会跨upload/revision复用nonce。即使零字节录像也必须有非空认证header。`finalize`按数据库receipt有界流式认证解密，复核顺序、完整plaintext长度和SHA-256，但不产生任何临时明文文件；bit flip、wrong key/key ID、截断、乱序、重复或尾部额外record都fail closed，只有验证完成后才在同一filesystem原子rename并`fsync`目录发布。当前没有录像读取/下载API；未来读取必须另建RBAC、审计和有界流式解密边界。retention、legal hold、abort和orphan回收只移动或删除opaque ciphertext，不需要解密key。

`0016_recording_encryption`与`0017_recording_inventory_backup`都是明确的no-legacy前滚迁移：前者拒绝任何旧明文upload，后者在切换随机object identity、不可复用namespace和一致备份权威前拒绝已有encrypted upload。项目尚未发布，因此不提供不受审的在线路径搬迁器；升级已有开发/测试环境前必须停写，并按数据处置要求从一致的空数据库和空record volume重建。不得只删upload/usage行、保留旧volume继续启动，亦不得绕过migration ledger。需要保留的旧录像只能在独立离线隔离环境走另行审查的转换流程，不能重新挂入生产record root。

数据库usage ledger在同一事务按device、owner与global锁定并约束active upload、保留文件数、committed bytes，以及Connection/event数量；持续请求的分钟级429预算不能替代这些硬上限。每个upload另有随机UUIDv4 storage object ID、由该随机值域分离得到的独立namespace，以及不可变owner/device PK、RID、UUID和deployment generation快照；物理文件名不再使用用户文件名。device删除、重建或业务标识复用不会重新进入旧对象路径。容量超限稳定返回507和有界`Retry-After`，Client保留sidecar并等待，不会每帧重试。readiness与每个已认证record mutation验证record root仍为真实目录、生产专用mount、可写且保有配置的bytes/inodes reserve；volume丢失、只读或接近满时在读取request body前拒绝。

五分钟cleanup以有界batch把stale active录像变为可恢复abort tomb、删除过期finalized bytes/receipt，并把超过数据库时间connection lease的`starting/active`审计标为`expired/telemetry_lost`后清理达到retention的终态Connection/File/Alarm event；`expired`保留`conn_end=NULL`，不会伪造成正常断开。找不到权威inventory row的`.recording/.part/.aborted/.deleting`不会直接unlink：scanner在候选选择和rename之间重新锁定backup control与object identity、复核inode/mtime/类型后，先同filesystem移入0600/0700保护的`.quarantine`；只有超过`CAMELLIA_REMOTE_RECORD_ORPHAN_QUARANTINE_DAYS`后才在后续有界轮次删除。DATA-004保证每个upload使用全局唯一namespace，因此file mutation直接在该0700 namespace目录的稳定FD上持有非阻塞内核`flock`；进程退出由内核释放，不创建额外lock inode，也绝不按wall clock/mtime抢占或unlink锁路径。device删除只清live FK，所有归属、generation、object、quota和retention快照保留到权威清理。合法保留可用`set_ingestion_hold recording|audit UUID --actor ADMIN --reason TEXT --hold|--release`显式设置，Admin页面不能直接改写。不要手工删除usage rows、backup-control row、数据库状态、quarantine或把`.uploads`中的part/tomb当成完成品。

所有应用拥有的自动主键和PostgreSQL sequence均为signed 64位。五分钟cleanup unit在retention完成后运行`check_sequence_capacity --fail-level critical`；它为每个当前sequence保留一个固定大小的上次采样状态，并向journal输出schema v1 JSON，包括last/max/remaining、百万分比消耗量、每日增长率和预计耗尽天数。默认warning/critical阈值分别为80%/95%，可通过`CAMELLIA_REMOTE_SEQUENCE_CAPACITY_WARNING_PERCENT`与`CAMELLIA_REMOTE_SEQUENCE_CAPACITY_CRITICAL_PERCENT`收紧；达到critical会令unit失败，监控必须对该失败告警。可手工使用`python manage.py check_sequence_capacity --fail-level none|warning|critical`排查，但不得重置、回绕或复用sequence。64位容量只把耗尽窗口推远，不替代摄入rate limit、持久quota、partition或retention；运维仍须同时监控增长率、索引/磁盘容量和cleanup lag。

地址簿、设备、待处理OIDC和recording data key的当前业务写入使用带key ID的`secretbox:v3` context-bound envelope。每个密文字段从master key和规范context经HMAC-SHA256派生独立SecretBox subkey；context固定包含schema、model、field、不可复用且数据库唯一/不可变的`secret_context` UUID，以及该对象适用的profile、RID、owner、deployment generation、upload/object identity等authority。删除后以相同业务RID重建也会生成新UUID，旧密文不能重新归属。`secretbox:v1`和无上下文`secretbox:v2`只保留为迁移/rotation reader；不含业务明文的key inventory canary刻意继续使用v2。raw SQL、bulk update、import、restore或migration不得把envelope直接复制到另一字段/行；合法复制必须先解密、重新检查当前授权、把plaintext赋给目标model instance并save，让它按目标context产生全新密文。数据库writer即使没有data key也不能通过移植合法密文替换credential；context或envelope篡改会在返回任何plaintext前fail closed。shared profile默认连接密码位于显式加密字段而不在通用`info` JSON中；profile列表永不加载或返回该字段，Client仅在目标RID存在且当前地址簿权限有效时调用即时credential API。连接凭据只通过已认证且通过地址簿权限校验的运行时API返回；Django管理表单将其作为只写字段，CSV/Excel导出不包含连接凭据。

Django逻辑fixture不是credential恢复格式。项目覆盖标准`dumpdata`：只要实际模型选择包含任一`EncryptedTextField`，命令会在数据库查询和`--output`文件创建之前列出有界model label并fail closed；显式排除全部secret model后仍可导出普通模型。字段本身也拒绝JSON/JSONL/XML/YAML等程序化serializer，因此直接调用Django serializer不能绕过命令门禁。不存在`--include-secrets`、warning-only或明文stdout模式；包含credential与row context的恢复只能使用认证加密的物理backup set，避免fixture泄漏、raw envelope双重加密或跨行context错绑。

控制面用户、设备和设备组列表使用`control-filter-contract-v1`。不带`%`的值是精确匹配；`term%`是大小写不敏感的前缀匹配；`%term%`是子串匹配，子串至少3个字符。设备`id`（RID）只允许精确匹配；设备hostname/系统用户名/所属设备组、owner username/Django Group名、用户username/Group名以及设备组名允许三种模式。重复参数、其他通配符位置、空通配符、过短或超过128字符/256 UTF-8字节的筛选值在数据库查询前返回typed `400 invalid_control_filter`。PostgreSQL复用RID和username既有唯一B-tree，并只为公开且经测量的hostname/系统用户名、设备组名和Django Group名建立B-tree或`pg_trgm`表达式GIN索引；不能通过给所有文本列盲目加索引来替代选择性和写放大评估。生产调用方必须限制子串筛选长度、频率和并发，并优先使用精确或前缀筛选。

五个地址簿browser导出使用`address-book-export-v1`合同。只有完全缺失`format`时才默认`csv`；显式值严格区分大小写并只接受`csv`、`xls`、`xlsx`，其中旧调用方的`xls`是生成OOXML `.xlsx`的明确alias，当前UI统一发送`xlsx`。单地址簿导出的`kind`只有缺失时默认`peers`，显式值只接受`peers`或`tags`。空值、重复query、大小写变体、未知或超长值都会在数据查询和artifact构建前返回有界JSON 400、机器码`invalid_export_parameter`及支持值，不回显原始输入。成功响应通过`X-Camellia-Export-Schema`、`X-Camellia-Export-Format`和适用时的`X-Camellia-Export-Kind`声明实际schema；调用方必须同时校验这些header、Content-Type、扩展名与CSV/ZIP magic，不能把请求参数当成实际artifact格式。

用户、设备、设备组、peer inventory以及三个地址簿列表统一使用`pagination-contract-v1`。`current`与`pageSize`仅在完全缺失时分别默认`1`和`100`；显式值必须是唯一、无符号、无前导零的正ASCII十进制，空值、重复值、Unicode数字及其他非规范形式均返回`400 invalid_pagination`。`pageSize`最大500，页码模式的数据库OFFSET最大10,000；超过预算会在列表数据源查询前返回带合同版本、字段名和上限的typed错误。语法合法且超出实际总数的页面统一返回200空`data`，所有成功分页响应都返回合同版本、`current`和`pageSize`。`/api/peers`在首个响应后应优先沿用`nextCursor`；有效签名cursor是位置权威并使用数据库offset 0，`current`只保留为严格校验后的响应元数据。其他列表在下一页将超过offset窗口前必须缩小精确筛选范围，禁止无界自动遍历或把400伪装成空页。

设备API和Web工作台使用显式的窄字段inventory projection：管理员只查询全局device，普通用户只合并本人device与本人精确`personal-<owner-id>` profile中的peer，并以`source/owner/rid`标识数据来源；数据库在构造Python对象前完成权限过滤、稳定排序和分页。`/api/peers`保留页码参数并额外返回绑定viewer、权限范围和status filter的一小时签名`nextCursor`，新调用方应使用cursor避免并发插入/删除造成重复页。首页用独立聚合和top-6查询。`DeviceInfo-v1.xlsx`只读取版本化allowlist，通过数据库iterator、write-only workbook、受限memory spool和`FileResponse`交付；行数、压缩输出字节与生成deadline任一超过`.env.example`预算时拒绝导出，不允许通过增加worker内存绕过。

所有基于浏览器session的页面、导出、根跳转和WebUI2状态响应，无论成功、重定向、方法拒绝、CSRF拒绝或应用错误，都统一返回`Cache-Control: no-store, private`、`Pragma: no-cache`、`Expires: 0`和`Referrer-Policy: no-referrer`。edge、CDN和APM不得覆盖或缓存这些响应；静态资产与health端点不套用session响应策略，继续使用各自的缓存与可用性合同。Management不注册service worker或CacheStorage写入；若未来新增，必须显式禁止保存authenticated response并补充浏览器缓存生命周期测试。logout不发送`Clear-Site-Data`，避免清除同源静态资产或干扰其他活动窗口，它不能替代每个敏感响应自身的`no-store`控制。

地址簿ACL审计与对应权限变更在同一事务提交。审计行保存profile GUID、名称和owner的不可变快照；删除profile会先写入tombstone，再把历史行的业务外键置空，因此API、Web、Admin或owner级联删除都不会抹除已有ACL历史。Django Admin只允许查看这些审计行，不允许新增、修改或删除。

Alarm与地址簿ACL审计都按`created_at DESC, id DESC`稳定排序，并在PostgreSQL使用与该顺序匹配的B-tree索引。其本表文本搜索字段和`UserProfile.username`使用`pg_trgm`表达式GIN索引；执行人/报告人username先以最多1,000个匹配ID的独立索引查询解析，不能把跨表username join混入审计大表的OR条件。每个搜索词限制为3–344个字符，过短、过长或匹配用户过宽时页面明确拒绝并要求收窄。地址簿ACL页面使用绑定当前搜索条件的签名`(created_at,id)`keyset cursor，只提供较新/较早方向且不执行全表count或尾页offset；ACL历史不由连接审计的90天retention误删。Alarm Django Admin关闭完整总数，并把任一筛选下可浏览窗口硬限制为最新10,000条，更早记录必须先用时间或字段筛选定位。新增索引由非原子migration以`CREATE INDEX CONCURRENTLY`构建；生产migration角色必须保持数据库/`public` schema owner以安装trusted `pg_trgm`，runtime角色不获得扩展或DDL权限。

连接审计只接受`version=3`；v2 Client固定返回426并必须与Management协调升级。Host设备用一次性UUIDv4 event创建`starting`连接后，由Management签发绑定host device、owner和deployment generation的不可猜测`audit_session_id`；Host确认controller身份后状态单向进入`active`。Client每20秒用单调heartbeat revision刷新默认90秒的数据库时间lease，响应同时绑定event acknowledgement、event/state/heartbeat revisions与剩余lease；过期heartbeat、controller active查询和新事件都不能复活终态。正常active关闭记为`closed`，认证前结束记为`aborted`，没有close遥测则由请求路径或cleanup reconciler记为`expired/telemetry_lost`且不填写`conn_end`。controller只有在host lease未过期且双方身份均已证明时才能领取capability；close后同一bind event也稳定返回409。关键连接事实只能从未设置值单向确定，终态永久冻结；note每次写入都保留previous/new值、actor和单调sequence。File与Alarm只有在host和controller两端都完成绑定、两端设备代际仍有效且连接仍active时才会写入，并分别通过真实外键引用同一Connection和append-only event。重复event ID只有在session、kind、actor、设备和完整payload完全一致时才幂等确认；冲突、旧代际、owner变化或跨session重放均fail closed。设备或用户删除会让实时authority引用失效，但创建/绑定时的device PK、RID、UUID、owner、generation和每个event actor ID快照仍保留。Connection与File页面只显示host create和controller bind时从已认证`RemoteDevice.hostname`保存的不可变设备名快照；它们绝不从全局或个人Address Book借用alias，也不反查当前设备名。迁移前历史行没有可信快照时明确显示`UNKNOWN`，不能用当前alias/hostname猜测或回填历史。Connection、Event、File和Alarm在Django Admin中全部只读，任何纠正必须新增可追踪事件，不能改写历史行。

File与Alarm evidence还必须携带`receipt_version=1`和正数reporter sequence。Management在同一事务中保存由规范化payload、session、actor、reporter device PK/generation、event ID和reporter sequence计算的SHA-256以及原始确认收据，数据库唯一绑定session内reporter sequence。完全相同的replay即使发生在后续事件或close之后也返回该不可变收据；不同内容复用event ID或reporter sequence固定409且不产生child row。

设备身份使用一次性`camellia-device-proof-v1` challenge。已部署设备的密码/OIDC登录必须由当前Ed25519设备私钥签名；首次部署由新设备密钥签名；主动换钥必须由旧钥与新钥对同一challenge双签。旧钥丢失时，管理员只能通过`POST /api/devices/<device-id>/approve-recovery`预先批准一个精确的新公钥；批准有效期10分钟、仅可消费一次，成功后设备代际递增且旧bearer立即撤销。Client必须逐字段验证canonical message后才能签名，不能把Management响应当作任意消息签名请求。

设备heartbeat成功时返回绑定rid、UUID和deployment generation的60秒`device_lease`，并继续以15秒idle/3秒active节奏续租。禁用、删除、owner失效或统一credential撤销后，旧bearer的heartbeat返回绑定同一rid/UUID的显式`revoked`状态；Client必须立即停止新入站连接并关闭现有direct/relay/file/terminal会话。网络或Management故障不伪装成显式撤销，但最后一个有效lease到期后同样fail closed。

Identity Server对`POST /api/devices/verify-deployment`的每次请求提供随机32字节nonce；Management返回30秒有效、以共享验证密钥HMAC-SHA256签名并绑定rid、UUID、公钥哈希、设备代际与nonce的`camellia-deployment-assertion-v1` JSON。旧的静态204契约已删除；Management、Client和Server必须协调升级，Server只允许更高代际替换已持久化身份。

轮换时先把新ID/key设为primary，将旧key按`old-id:Base64`放入`CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS`，并让`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`继续指向产生旧v1行的key。先运行`python manage.py rotate_data_encryption --dry-run`，再以有界batch正式运行；命令可以用`--max-batches`中断并安全续跑。命令为每列同时锁定并读取model声明的完整row context，认证旧v1/v2或当前v3后统一重写为primary-key v3；任何context错位都会停止轮换，而不会退回无绑定v2。rotation inventory包含每个recording的data-key envelope并同步`data_key_kek_id`，只重封装data key，不重写大型volume ciphertext。所有batch完成后必须再执行一次不带`--max-batches`的命令，按每行完整context认证验证全部primary v3 envelope。只有该完整验证、隔离restore的完整context验证和readiness通过，并确认所有保留backup不再依赖旧key后，才可运行`--retire-key-id OLD_ID`；命令会在仍有recording或其他v1/v2/v3数据库envelope引用时拒绝retire。删除旧secret时还要把`CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID`切换到仍配置的key。key inventory只记录ID、SHA-256 fingerprint和加密canary，不记录key material；recording data-key明文不得进入日志、Admin、API、backup manifest或诊断包。

## OCI + systemd 部署

```bash
sudo install -d -m 0755 /opt/camellia-remote-management /opt/camellia-remote-management/deploy /etc/camellia-remote-management
sudo install -m 0644 docker-compose.yaml /opt/camellia-remote-management/
sudo install -m 0755 deploy/bootstrap-postgres-roles.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/run-compose-operation.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/backup-postgres.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/run-cleanup.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/run-maintenance-backup.sh deploy/run-maintenance-cleanup.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/check-maintenance-freshness.sh deploy/maintenance-ledger-notify.sh /opt/camellia-remote-management/deploy/
sudo install -d -m 0755 /opt/camellia-remote-management/scripts
sudo install -m 0755 scripts/backup_envelope.py /opt/camellia-remote-management/scripts/
sudo install -m 0755 scripts/maintenance_ledger.py /opt/camellia-remote-management/scripts/
sudo install -m 0755 deploy/restore-postgres.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/management-maintenance-guard.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/management-maintenance.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/start-management-stack.sh /opt/camellia-remote-management/
sudo install -m 0755 deploy/check-management-health.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/supervise-management-stack.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/stop-management-stack.sh /opt/camellia-remote-management/deploy/
sudo install -m 0755 deploy/shutdown-budget.sh /opt/camellia-remote-management/deploy/
sudo install -m 0600 .env.example /etc/camellia-remote-management/management.env
sudo install -m 0644 deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo install -d -m 0700 /var/lib/camellia-remote-management/maintenance
sudo systemctl daemon-reload
sudo systemctl enable --now camellia-remote-management-stack.service
sudo systemctl enable --now camellia-remote-management-backup.timer
sudo systemctl enable --now camellia-remote-management-cleanup.timer
```

生产环境应把 `CAMELLIA_REMOTE_MANAGEMENT_IMAGE` 固定为发布清单记录的 `ghcr.io/...@sha256:...`，不得使用浮动标签。systemd没有在线`reload`入口；升级必须使用显式stop/start或受审部署流程。`CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS`是唯一可调的应用排空窗口；`deploy/shutdown-budget.sh`严格派生Docker `G+15s`并验证固定的systemd `660s`外层窗口。Compose的`stop_grace_period`、controller的`docker compose stop`和systemd的`ExecStopPost`都使用该校验结果，任何值漂移都会在Gunicorn绑定端口或Docker操作前fail closed，不能只增大systemd预算伪装成安全排空。每次stack start由单飞controller先停止旧Management，启动PostgreSQL但不等待尚未创建的probe，使用bootstrap superuser在advisory-lock事务内创建/收敛角色、ownership、membership、当前ACL与migration default ACL，再以probe执行真实`SELECT 1`健康检查。随后只用migration owner运行一次性`migrate_with_lease`：它以固定的`CAMELLIA` PostgreSQL session advisory lock在整个Django migration plan外建立数据库级单飞，输出release revision、actor、operation ID、holder backend和每5秒等待heartbeat；等待最长由`CAMELLIA_REMOTE_MIGRATION_LOCK_TIMEOUT_SECONDS`限制，超时以75退出。Holder连接消失时PostgreSQL自动释放锁，follower取得锁后才重新构造executor和migration plan。迁移完成后再次bootstrap验证新对象，最后用runtime DML credential启动`restart: no`应用。Runtime不是database/schema/table owner，且始终为`NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`；`django_migrations`对runtime只读，不能伪造schema ledger。Backup只拥有业务读取能力，probe没有public schema或业务表权限。Controller与maintenance enter/leave共用root-owned deployment lock，maintenance lease存在时不会执行Docker命令。Engine或container restart不会自动拉起Management；任何直接启动仍会由`run.sh`的`check_release_schema`核对版本化manifest、精确migration set/leaf和关键table/column/type/validated constraint/ready index，再由`check_username_identity`检查canonical authority，任一失配都会在Gunicorn绑定端口前fail closed。`/health/ready`持续执行同一schema capability合同；ledger缺失、超前、分叉或关键schema对象漂移都返回not-ready。应用崩溃必须告警并进入受控stack start，不能用Docker自动restart绕过migration gate。

Stack 的长期健康所有者是 `deploy/supervise-management-stack.sh`，不是 Compose 的 `restart` 策略。它以 `Type=notify` 常驻运行，每次检查只接受唯一的 Management 容器；进程退出才允许调用完整的 start controller，数据库/密钥/record root 等依赖故障只摘流并告警，不会盲目重启。连续 `CAMELLIA_REMOTE_SUPERVISION_STABLE_SUCCESSES` 次 `/health/ready` 成功后才发布 `/run/camellia-remote-management/admission.state` 的 `ready`，反向代理必须主动消费这个有界 readiness（或该状态文件）摘除故障节点，独立的 `/health/live` 只用于进程存活与运维观测，不能作为业务准入。健康检查控制面超时、Docker daemon 不可用、状态含糊或通知失败都会让 unit 以失败状态退出；进程恢复尝试受 `CAMELLIA_REMOTE_SUPERVISION_RECOVERY_ATTEMPTS` 与 `...RECOVERY_WINDOW_SECONDS` 硬限制，超过上限保持摘流并等待人工处置。监督器使用 `WatchdogSec=45s`，每至多10秒发送心跳；依赖恢复必须重新经过稳定窗口，避免 flapping 立即重新接流量。

`/health/ready`还使用当前runtime credential检查PostgreSQL primary/recovery、session/default read-only状态以及release manifest声明的RemoteDevice表和序列DML ACL；只读切换或权限撤销会在接收mutation前返回not-ready。该探针只读取数据库原生状态和ACL，不写业务行或制造周期性WAL。

已提交的历史migration是不可变的Python API。`api/migration_compatibility_manifest.json`锁定全部历史文件实际使用的`EncryptedTextField`、`MyUserManager`、`share_link_expiry`和`AuditSearchDocument`路径及deconstruct语义；`api.test_migration_compatibility`会扫描每个migration的显式runtime import，验证路径仍可导入并在新增、删除或重命名时fail closed。未来若移动业务实现，只能在旧路径保留等价shim并新增migration，不能修改0001或其他已提交历史文件。

所有PostgreSQL应用连接在握手时即取得非零`statement_timeout`、`lock_timeout`和`idle_in_transaction_session_timeout`。`RUNTIME`默认分别为45/5/15秒，数据库操作有50秒单调预算；最外层HTTP请求另有默认65秒的monotonic总预算，并始终短于Gunicorn默认75秒worker故障边界。Gunicorn显式使用`gthread`，其heartbeat timeout只用于最后的进程故障保护，不能被当作单请求SLO；请求线程不会被Python强杀，所有数据库、请求body、录制文件和OIDC下游操作都必须消费剩余request budget。执行SQL前若剩余总预算更短，会用当前事务/session的更小值收紧而不会重新延长。连接同时启用10秒idle、5秒interval、3次探测的TCP keepalive和30秒`tcp_user_timeout`，使半开链路也早于operation边界失败。Migration、cleanup与backup分别使用30/5/2分钟、3分钟/15秒/30秒、40分钟/30秒/1分钟的独立profile，并由更长的operation deadline包围；配置要求lock不长于statement，statement、idle、TCP与keepalive检测都短于总预算，0和无限值在启动时被拒绝。请求预算必须覆盖OIDC discovery/token/JWKS/key-rotation四段HTTP deadline；若耗尽，API返回504、`retryable=true`和`result=unknown`，数据库超时仍返回503、`retryable=false`和`result=unknown`。调用方必须通过幂等operation receipt或读回权威状态判断结果，不能盲目重放mutation。

Compose还为Management、一次性migration、PostgreSQL和每个数据库client分别设置有限的CPU、memory reservation/max、PID、nofile/nproc、IO weight与OOM优先级；默认容量包络为稳定态PostgreSQL+Management约3 CPU/3 GiB，migration只在controller停止Management后使用独立2 CPU/1 GiB profile，backup使用既有1 CPU/512 MiB profile。PostgreSQL的`max_connections=128`、`shared_buffers=512MB`、`work_mem=4MB`和`maintenance_work_mem=128MB`必须与cgroup和Gunicorn/限流并行度一起按真实设备/记录/导出负载校准，不能把默认值当作1/100/10k规模的测量结论。生产Management/migrate容器启动前要求cgroup v2的`memory.max`、`pids.max`和`cpu.max`为有限值且不低于安全底线；触顶时应由edge准入和受监督controller摘流/退避，不能依赖宿主OOM随机选择进程。修改任何预算必须保留同一容量证据、PSI/cgroup事件、p95/p99和恢复时间，不能只增大limit掩盖过载。

Username identity v1先对去除首尾空白的输入执行NFKC，再执行Unicode full casefold和第二次NFKC；显示用户名保存第一次NFKC结果，登录、OIDC分配、账号查找及登录限流桶只使用对应UTF-8 binary canonical key。PostgreSQL的`lower/iexact`和locale不再参与账号身份。新Compose cluster固定为UTF8、builtin locale provider、`C.UTF-8`和collation version 1；已有volume、外部数据库及恢复目标必须满足相同契约。迁移0026发现历史collision时只输出有界user ID与canonical digest并停止，不自动合并、改名或转移账号；管理员必须在离线审计后显式解决冲突再重跑迁移。

`POST /api/users`只有在username canonical预检命中，或user insert的独立savepoint失败后再次读到同一canonical账号时，才返回`409`与机器码`username_conflict`。指定的新Group发生并发创建时，服务会在savepoint回滚后锁定并复用已提交Group，保证不同新用户可加入同一目标；Group无法读回、M2M或其他未知完整性错误保持5xx并回滚整笔user创建，不会冒充用户名已存在。

首次升级已有volume前必须确认环境中的`BOOTSTRAP_USER/PASSWORD`就是旧cluster的现有superuser；错误映射会fail closed，不能通过临时把runtime升为superuser绕过。五类密码轮换时先在受保护环境文件中写入互不相同的新值，再通过controller离线收敛并验证；旧目标密码随事务提交失效。Bootstrap本身是root-only break-glass凭据，轮换或使用必须审计，不能作为日常migration、备份、探针或排障登录。
systemd 运维单元仅允许通过本机 Unix socket 调用 Docker；该 socket
等同宿主机 root 权限，必须只允许 root 访问，并保护部署目录和环境文件不被非特权用户修改。

Compose 默认仅在同主机、不可从外部路由的 `backend` 网络内使用 PostgreSQL，因此该链路显式采用 `sslmode=disable`。外部或跨主机数据库强制使用 `verify-full`、可信 CA 和与证书匹配的主机名；私有 CA、客户端证书和私钥可分别通过绝对路径 `CAMELLIA_REMOTE_DATABASE_SSLROOTCERT`、`CAMELLIA_REMOTE_DATABASE_SSLCERT`、`CAMELLIA_REMOTE_DATABASE_SSLKEY` 配置，其中客户端证书与私钥必须成对提供。这是唯一保留的无数据库 TLS 特例。

## 备份、恢复与运维

每小时定时器先锁定数据库中的recording backup singleton；它会等待已经开始的record mutation/retention/hold操作完成，并让后续录像变更以503和`Retry-After`暂停。锁内逐对象认证`PRIV-011`密文、核对finalized plaintext/ciphertext size与digest、拒绝missing/extra/corrupt对象，并把owner/device generation、upload/object identity、storage/encryption/KEK版本、retention/hold和时间快照写入不可变epoch inventory。随后在同一冻结时点生成数据库和recordings密文。每轮使用128-bit随机且不可复用的backup ID和私有0700 work目录；三个final path都用exclusive hard-link发布，碰撞立即失败，cleanup只删除本轮已成功发布的inode，绝不删除预先存在的同名恢复点。最终路径发布后，脚本用受保护的age identity重新认证解密：数据库custom archive必须让`pg_restore --file=/dev/null`读取并解压全部data block，recordings bundle必须重新解析每条metadata和payload digest。两项都通过后才发布第三个`backup-set-<UTC时间>-<随机backup-id>.manifest.age`完成标记；该认证manifest绑定正数单调generation、前一backup ID、两个密文的精确bytes/SHA-256、deployment/database、PostgreSQL major、source revision、image digest、release schema generation、key ID与recording epoch。manifest最终路径再次认证并重算两项密文摘要后，才完成数据库epoch并原子推进含generation链头的`latest-verified.json`。

`CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT`、`CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE`、`CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID`、`CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID`、`CAMELLIA_REMOTE_RELEASE_REVISION`和固定digest的`CAMELLIA_REMOTE_MANAGEMENT_IMAGE`必须显式配置。identity secret只能放在root/管理员拥有的0400或0600独立文件中；环境文件只保存绝对路径，普通management runtime容器、镜像和artifact都不能获得identity。数据库、recordings和set manifest三件套必须不可分割地复制、保留和删除。每轮开始会认证全部匹配manifest并要求generation连续、前驱精确、ID/generation唯一且属于当前deployment/database；缺失、重复、分叉或无效set会保留并fail closed，不能静默重置generation。Retention按generation保护最新`CAMELLIA_REMOTE_BACKUP_RETENTION_MINIMUM_COUNT`个实际成功集合，只把单调化的认证`completed_at`作为额外年龄条件，不读取mtime；检测到回拨、当前时间早于链头或超过`CAMELLIA_REMOTE_BACKUP_MAX_CLOCK_STEP_SECONDS`的前跳时，本轮只记录`retention-skipped:*`而不删除。正常轮次也最多删除`CAMELLIA_REMOTE_BACKUP_RETENTION_MAXIMUM_DELETIONS`个最老集合，避免一次时钟/配置错误清空历史。不完整或无效集合保留待调查；备份目录必须位于独立、加密且受监控的存储，至少每天复制到故障域外。

Kernel `flock`仍是单飞权威；holder metadata另记录run ID、start、phase和30秒heartbeat。正常竞争输出结构化`skipped:active-run`并返回75；超过有界heartbeat阈值的holder返回失败告警，无锁残留metadata明确记录`recovered:orphan-run-state`，不会伪装成本轮成功。任一创建/验证失败会删除本轮未完成三件套并abort epoch；SIGKILL/宿主掉电导致的残留冻结必须先调查artifact和holder状态，再显式运行`python manage.py recording_backup abort --backup-id ID`，不得直接改control row。

backup/cleanup unit没有启动业务栈的权限：wrapper先写入`scheduled`，再检查stack是否`active`及是否存在root-owned maintenance lease；不满足时写入`skipped:not-running`或`skipped:maintenance`并退出，不会创建容器。每个wrapper随后以systemd invocation ID作为不可重复operation ID，持久化`started`、有界heartbeat和唯一终态；backup active lock的exit 75保留为可告警skip。所有bootstrap、migration、cleanup、backup和restore数据库动作都通过具名一次性container运行，容器标签绑定operation ID；宿主取消或内部deadline后先TERM、再按有界grace kill/remove，并确认该精确容器已经不存在，因此不再把`docker compose exec`客户端退出误认为远端Python/pg_dump已取消。cleanup的两个阶段各限5分钟，systemd总边界11分钟；backup内部45分钟且systemd总边界50分钟。仅停止stack不再可能被5分钟/hourly/Persistent timer反向解除，但正式维护仍必须显式停timer并保留lease。

运行账本位于root-only `/var/lib/camellia-remote-management/maintenance`：`maintenance-events.jsonl`是带摘要链的append-only事件文件，`latest-backup.json`和`latest-cleanup.json`只保存固定字段、计数、artifact generation与last verified success，不含环境变量、数据库URL、PII、密钥或artifact内容。账本写入或摘要提交失败会使维护任务失败；systemd的`OnFailure`模板只记录固定的`unit-failure`，不会递归启动stack或复制journal原文。外部监控应轮询：`sudo /opt/camellia-remote-management/deploy/check-maintenance-freshness.sh all`。机器JSON区分`never-run`、`running`、`healthy`、`stale`、`failed`、`skipped`、`unknown`和`clock-anomaly`；backup默认新鲜度预算90分钟（覆盖hourly timer抖动），cleanup默认15分钟（覆盖5分钟timer抖动）。非零返回必须告警，尤其是连续failure/skip、timer停止、heartbeat超期、backup generation不再推进、cleanup output长期追不上input；`last_success_at`不会被失败或skip推进。账本不是备份artifact本身，必须与备份目录独立复制和监控。

数据库导出与全读验证固定运行在digest锁定的PostgreSQL 18 `database-backup`一次性客户端，不在在线PostgreSQL container内执行。该客户端的Docker cgroup硬限1 CPU、512 MiB memory和64 PIDs，并使用较低CPU/blkio权重与更高OOM分值；systemd的CPU/内存/任务上限只约束宿主侧age、pack和Docker控制进程，不能冒充container内`pg_dump`资源边界。custom archive默认使用`CAMELLIA_REMOTE_BACKUP_COMPRESSION=zstd:3`，只接受`none`、`gzip:1..6`或`zstd:1..9`；变更前必须以代表性数据同时测量dump wall/CPU/RSS/bytes、完整restore耗时和业务p95/p99，不能为了极小体积收益恢复gzip 7–9。资源硬上限触发OOM、deadline或RPO告警时应扩展backup窗口/受控replica或重新评估数据与压缩参数，不能移除cgroup让backup与在线数据库争用。

恢复流程（必须先在隔离环境演练）：先从反向代理摘流并执行 `sudo /opt/camellia-remote-management/management-maintenance.sh enter --reason restore-INCIDENT-ID`。该命令先原子创建`/run/camellia-remote-management/maintenance.lease`，再停止两个timer、正在执行的backup/cleanup和stack，最后确认官方Compose项目没有残留容器；任一步失败都会保留lease并fail closed。随后只启动隔离的PostgreSQL service、创建空数据库，并准备空recordings volume；脚本会机器化拒绝非空数据库或volume。设置与manifest完全一致的deployment/database/PostgreSQL major/key ID/source revision/image digest，设置受保护identity路径、`CAMELLIA_REMOTE_RESTORE_TARGET_ID=DRILL-ID`、绝对`CAMELLIA_REMOTE_RESTORE_EVIDENCE_DIR`，并在本次调用中设置动态确认值`CAMELLIA_REMOTE_RESTORE_CONFIRM=restore:<backup-id>:DRILL-ID`后执行`restore-postgres.sh postgres-....dump.age`。同目录同代际的recordings与set manifest必须存在；确认值不能持久化为可复用开关。

脚本先让age完整认证三件套并重算两个ciphertext digest，验证component envelope与set manifest完全一致，再对空库/空volume执行门禁。随后只用migration credential执行完整`pg_restore --single-transaction --exit-on-error --no-owner --no-acl`，运行leased migration并再次收敛ACL；runtime检查release schema、username identity及`rotate_data_encryption --dry-run`的全部context/key inventory，之后才按epoch snapshot以O_EXCL写回recordings并核对双向object count。完整probe成功后才原子写入不可覆盖、age认证的restore receipt和`latest-restore-verified.json`，记录run ID、成功时间与RTO秒数。失败不会推进恢复新鲜度；partial restore必须在maintenance lease内调查并从重新清空的目标重做，不能手工清gate或拼接备份。

收据成功落盘后仍须在maintenance lease与timer停止期间对隔离`/health/ready`和业务canary做最终核对，不得恢复外部流量。随后停止全部隔离Compose容器，再执行 `sudo /opt/camellia-remote-management/management-maintenance.sh leave --confirm-validated`；该命令只解除lease，不会自动启动服务。手动启动stack并验证`/health/ready`后才能恢复流量和两个timer。`status`子命令可读取lease与stack状态；不得删除lease、依赖超时或只停stack来绕过状态机。

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
