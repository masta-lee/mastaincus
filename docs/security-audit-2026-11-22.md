# PayIncus 整程序安全审计与数据库防脱库报告

日期：2026-11-22。结论：**发现可复现的账号接管、内网访问及凭据保护问题，当前不能据此认定程序达到安全上线标准。** 部分问题在数据库只读泄漏后即可利用；部分需要数据库写权限、合法普通用户账号或网络劫持条件。随后按owner要求联网核公开公告，新增内嵌Incus认证／隔离／导入及正式Agent旧Go编译等上线风险，详见第5节及[联网公告附表](security-advisories-2026-11-22.md)。没有证据证明生产已经被攻击，本次也没有查看生产日志来判断是否发生过入侵。

## 1. 审计基准、范围与证据

- 审计分支：`codex/financial-integrity-audit`；产品代码基准：`a5251f0cab9c7fdaf861f36d2c7563f838984d33`，源码版本 `1.8.14`。
- 此基准包含已推送、尚未发行的资金加固 `5f02d45fa8cab1aee5dd4f574d1e77531c86d30a`。正式 v1.8.14、该分支源码与生产实际部署是三个不同状态；本次没有登录生产核部署 SHA。
- 本轮为全库入口清点、危险调用与信任边界审查、相关守卫、本机真实 PostgreSQL／HTTP／TLS／SSH／FTP 隔离复现及依赖公告核对。没有攻击公网服务，没有运行大流量／内存耗尽攻击，没有修改产品代码、生产配置或资金，没有提交、推送或发版。
- 源码目录清点包括 `server/src`、`client/src`、`agent`、`scripts`、`deploy`、Prisma schema／迁移与 `.github/workflows`。路由 AST 清单得到 **77 个模块、766 个注册点**，包括循环生成和继承 hook，注册点数量不等于独立 URL 数量。对缺少直接鉴权选项的注册点继续追查继承 hook、handler 内鉴权和回调签名，没有把它们机械判成匿名接口。
- 本轮两批守卫 **18/18、13/13** 自然退出 0，合计 31 次执行、29 个不同守卫。通过守卫不否定下述复现结果，反映当前测试缺少相应攻击场景。本轮未重跑全量类型、双端构建或双架构发行；上一轮资金验证单独见[资金审计](financial-audit-2026-11-22.md)。
- 成功复现程序与结果保存在本机 `logs/security-audit-*`；汇总 SHA-256／文件大小见 `logs/security-audit-evidence-manifest-20261122.json`。凭据只使用合成夹具，报告不含真实密码、token、cookie、数据库连接字符串或私钥。证据日志为 ignored 本地文件，没有上传 GitHub。

严重性按本项目实际影响和利用前提评定。**“已复现”指本机当前源码的结果，不代表线上利用已发生；“源码确认”指已查明代码缺口，但没有实施完整攻击；“条件风险”不得当成已经取得权限。**

## 2. 发现总览

| 编号 | 问题 | 严重性与证据等级 | 主要前提 |
|---|---|---|---|
| S01 | 刷新令牌数据库摘要本身可换取登录 JWT | 高；真实 PG＋HTTP 已复现 | 读到未失效会话摘要；管理员会话可导致管理员接管 |
| S02 | 可写数据库插入会话后，无原密码取得管理员 JWT | 高；真实 PG＋HTTP 已复现 | 能写 `refresh_tokens`，已有有效管理员账户 |
| S03 | 替换未签名的 2FA 恢复码可绕过第二因素 | 高；真实 PG＋登录已复现 | 数据库写权限＋目标原密码；与 S02 分开 |
| S04 | 普通用户远程存储绕过 SSRF 防护 | 高；DNS 变化与重定向均已复现 | 普通登录用户能配置、测试自己的远程存储 |
| S05 | Incus 终端不验证宿主服务器证书 | 高；假证书替身已复现 | 能劫持／替换主控到宿主的连接路径 |
| S06 | 同一 OAuth 授权码／刷新令牌并发兑换成功两次 | 中；真实 PG 并发已复现 | 已持有相应凭据及正确 OAuth 客户端密钥 |
| S07 | 部分系统与通知凭据明文入库 | 高；真实 PG 入库已复现 | 数据库／明文导出泄漏 |
| S08 | SFTP 服务器密钥改变仍连接并交出密码 | 高；同地址换密钥已复现 | 存储连接遭劫持／替换 |
| S09 | FTP 明文传输，凭据 CRLF 可注入额外 FTP 命令 | 中；本机 TCP 已复现 | 使用 FTP；命令注入输入来自已登录用户配置 |
| S10 | 日志脱敏遗漏重要字段及下载／终端票据 | 中；合成输入已复现 | 相应内容进入日志且攻击者可读；未查生产真实泄漏 |
| S11 | 业务数据库角色拥有数据库，读表／DDL 权限过大 | 中；安装代码＋独立角色已复现 | 业务数据库凭据或执行权限失陷；属损害扩大的防御缺口 |
| R12 | 大附件、存储连接与响应缺少一致资源预算 | 中；源码确认，未实施耗尽攻击 | 普通用户并发请求或恶意远端响应 |
| R13 | HTTP 模式 Agent 更新缺少独立包身份验证 | 高条件风险；源码确认 | Agent 被配置为 HTTP，且更新响应／下载可被网络劫持 |
| R14 | 长期浏览器 JWT、较宽 CSP／HTTP 配置扩大损害 | 中条件风险；源码确认 | 另有 XSS、前端供应链或明文部署失陷 |
| R15 | CI 动态 Action 与安装器外部可变供应链 | 中条件风险；源码确认 | 上游 Action／安装源／发布身份失陷 |

依赖公告单列第 5 节，不与以上项目重复计数。

## 3. 已确认发现与修复验收

### S01：刷新令牌摘要成为登录凭据

定位：`server/src/lib/security.ts:561`、`:739`；`server/src/routes/auth.ts:822`。

`getRefreshTokenStorageKey()` 对形如 `sha256:` 加 64 字符的输入直接返回；`verifyRefreshToken()` 用该值查表。外部 Cookie 输入与内部数据库存储值没有区分，攻击者可把泄漏摘要当作原刷新令牌使用。`/refresh` 随后按当前用户角色签发 JWT，无需原密码或 2FA。

证据：`logs/security-audit-refresh-passhash-result.log`。启用本轮资金签名、创建合成管理员及正常会话后，仅提交数据库摘要，HTTP 200，并取得对应管理员 JWT。正常资金签名没有挡住该路径。目标被封禁、恢复保护或会话不存在等情况不属于此成功前提；本轮不声称这些门禁被绕过。

影响：只读数据库泄漏会升级为账户接管，而不只是离线破解密码。如果泄漏包含管理员有效会话，可接管管理员。不能把“SHA-256 保存刷新令牌”继续作为防脱库有效结论。

修复建议：外部令牌始终按原始随机值进行摘要计算，绝不接受数据库摘要作为原令牌；内部摘要标识和会话 ID 用不同函数、不同类型。旧明文记录兼容只能在受控迁移中处理，不能让外部摘要走迁移分支。修复后的会话处理须考虑历史失窃摘要，提供安全吊销与重新登录流程；不得静默使长期泄漏凭据继续有效。

验收：数据库摘要、伪摘要、截断和大小写变体均 401；原始随机令牌正常；内部会话枚举／吊销仍工作；管理员和普通用户各测；升级、回滚、OSS 恢复后的旧会话政策明确。现有 `test-refresh-token-storage.ts` 钉住了摘要幂等，却没有测试外部拒绝摘要，必须调整覆盖范围。

### S02：数据库写者能自建管理员会话

定位：同 S01；会话存储不在 `server/src/lib/financial-integrity.ts:20` 的账户签名范围内。

攻击者选择自己的原始刷新令牌，计算其摘要，插入归属已有管理员的 `refresh_tokens` 记录即可通过验证。这与 S01 是不同问题：即使修复外部摘要输入，攻击者仍知道自己插入记录对应的原始令牌。

证据：`logs/security-audit-db-write-session-result2.log`。启用资金签名，原管理员账户行保持签名有效，只用直接 SQL 增加会话，调用 `/auth/refresh` HTTP 200，**没有提供原密码就取得管理员 JWT**。

修复建议：对会话身份、令牌摘要、到期／吊销与当前认证版本建立应用密钥认证，校验后才签 JWT；对更新、删除、恢复、轮换等生命周期作完整设计，不能只签创建时的一行。关键鉴权表访问与业务角色权限同时收紧，外部可验证的登录审计另存，避免 DB 写者同时伪造本地证据。

验收：直接 SQL 插入／转属／延期／复活会话拒绝；正常登录刷新／吊销／退出全部可用；签名损坏失败关闭；恢复旧会话不重新放行被撤销会话。账户合法变更和全部会话更新须在事务中保持一致。

### S03：2FA 恢复码可被数据库写者替换

定位：`server/src/lib/financial-integrity.ts:20`；`server/src/routes/auth.ts:289`；`server/src/lib/security.ts:1036`。

账户签名包含密码 hash、角色、状态、2FA 开关及 seed，但遗漏 `twoFactorRecoveryCodes`。读取恢复码使用兼容解密函数，遇明文或解密失败返回原内容。数据库写者可把该列替换为自己选择的明文 JSON 恢复码。

证据：`logs/security-audit-db-write-session-result2.log`。签名保持启用，替换恢复码后使用合成账户**原密码＋替换码**登录，HTTP 200。此项需原密码，不能表述为单靠恢复码免密登录；S02 的无密码接管单独成立。

修复建议：恢复码一次性 hash 保存，并绑定账号、认证状态版本；若继续加密，必须严格认证解密，不能异常回退明文；将其纳入版本化认证完整性检查。历史明文迁移要在受信流程中显式完成。

验收：SQL 改码、跨账号复制、坏 tag／坏 key、原码重用、两并发消费均拒绝；正常 2FA、恢复码更新及单次消费可用；签名版本演进兼容已有备份。

### S04：远程存储存在 DNS 变化与重定向 SSRF

入口：`server/src/routes/storage-configs.ts:130` 的配置创建及 `/:id/test`，普通用户已可访问自己的配置。定位：`server/src/storage/providers/WebDavProvider.ts:27`、`:69`；其他三适配器同样仅预检查目标，见 `SftpProvider.ts:24`、`FtpProvider.ts:24`、`S3Provider.ts:87`。有效连接期防护已存在于 `server/src/lib/outbound-security.ts:212`，但存储 SDK 未接入。

两个已复现路径：

1. 预检查 `dns/promises.lookup` 返回公网地址，SDK 实际连接时 `dns.lookup` 返回回环地址，WebDAV 请求进入本地服务，并发送配置的 Authorization。证据 `logs/security-audit-storage-dns-result.log`；使用 `safeFetch` 的对照正确拒绝。
2. 原 URL 预检查通过后，WebDAV SDK 跟随 307 指向字面回环 IP，无第二次目标校验。证据 `logs/security-audit-webdav-redirect-result.log`。只用本地替身模拟公网源，并非真实访问云内网。

影响：可探测／请求主控可达的内网 HTTP 服务，可能触达云元数据等资源；具体取决于协议、方法、响应是否返回及内网端点权限。**此实验没有证明通过 HTTP 直接读 PostgreSQL、拿到云角色凭据或执行主控命令。** FTP／SFTP／S3 的同类连接期缺口为源码确认，本轮没有对三者分别复现全部内网读取。

修复建议：每次 DNS／实际 socket 连接使用同一受限解析与地址校验；重定向逐跳验证或直接禁止；FTP 被动数据连接、S3 bucket 虚拟域名、IPv4／IPv6 和跨协议变化均覆盖。加入主控出站边界，禁止普通用户远程存储连接管理网段、云元数据、回环与链路本地。仅在创建时再检查一次 DNS 无法修复。

验收：四协议配置、测试、上传、下载、列目录、删除；DNS 多地址混入私网、变化、重定向、IPv4-mapped IPv6、数据通道均拒绝；公网合法存储可用；原受信宿主管理通道保持独立，不能误封正常控制路径。

### S05：Incus 终端忽略服务器身份

定位：`server/src/lib/terminal-proxy.ts:456`，HTTP Agent `:478`、data WS `:559`、control WS `:567` 均 `rejectUnauthorized:false`，未使用登记服务器证书／指纹。终端授权回查身份与权限，不能替代连接层服务器身份校验。

证据：`logs/security-audit-terminal-pin-result.log`。本机登记证书与替身证书不同，替身服务器仍被终端连接接受；传登记 pin 的正常 IncusClient 对照拒绝。

影响：网络劫持者能替换终端服务、观察／篡改终端输入输出及操作回执。mTLS 只让服务端验证客户端，不自动完成反方向验证；**客户端私钥不会因为正常 TLS 握手被发送给服务端**，不能误报成直接泄露私钥。

另有旧宿主连接入口：`server/src/routes/hosts.ts:1941` 的 `/:id/test` 创建 IncusClient 不传存储服务器 pin；`server/src/lib/incus/incus-client.ts:121` 对无服务器证书保留忽略验证。正常已传 pin 的客户端有防护，不能把全部 Incus API 说成没有校验。

修复建议：HTTP 和两个 WS、初连与自动重连全部共用已登记 pin，缺失／改变时失败关闭；旧手工登记宿主通过受信通道迁移，不能自动接受网络侧新身份。网关域名诊断虽也出现 `rejectUnauthorized:false`，随后检查回执证书 hash 和域名，因此没有按关键词重复报成同类漏洞。

验收：假证书、旧证书轮换、缺 pin、同地址新身份、初连／重连／VM console 回退均测；正常原服务器通过；失败清理 socket、lane 与终端会话，不影响库存。

### S06：OAuth 一次性消费不是原子的

定位：`server/src/lib/oauth-provider.ts:424`／`:450`、`:497`／`:529`；HTTP 入口 `server/src/routes/oauth-provider.ts:234`。

先读“未使用／未撤销”，再按 id 无条件更新；两个事务可同时通过读取，然后排队更新并各签发一组令牌。

证据：`logs/security-audit-oauth-races-result2.log`。独立真实 PG 行锁控制两请求进入竞争，同一授权码成功兑换 2 次，同一刷新令牌也成功兑换 2 次。另确认授权码兑换缺少账户状态检查，封禁用户仍能 mint；**公共 API 的后续状态校验会拒绝该封禁用户令牌**，未证明封禁用户因此可操作实例。

修复建议：条件更新领取或锁行后重查，一次成功才签发；应用 enabled／密钥、grant 撤销、用户状态与 scope 在同事务确认，避免锁前授权变更。刷新令牌轮换建立重用检测及令牌族策略。

验收：同一凭据并发至少两请求仅 1 成功；兑换与封禁／禁用 app／撤销 grant 并发；过期、重放、scope 变化拒绝，正常 OAuth 授权与刷新保持可用。

### S07：敏感配置与通知渠道明文保存

定位：`server/src/db/system-config.ts:320`，有任意冒号便跳过加密；Telegram bot token 本来就含冒号。`server/src/db/notifications.ts:118`、`:141` 直接写通知 config JSON。

证据：`logs/security-audit-secret-storage-result.log`。真实 PG 中合成 Telegram token、含冒号 SMTP 密码及个人通知 bot token均原文可读；不含冒号的 Turnstile secret对照被加密，说明不是测试未启用加密。

影响：脱库／明文导出会泄露机器人与邮件凭据；webhook config 同样直接保存，URL 中凭据和签名 secret也需保护。管理端输出的星号不能替代入库加密。

修复建议：敏感字段统一、版本化加密封装和严格格式判定，禁止以任意 `:` 判断已加密；通知渠道按 schema 拆出秘密，UI 只返回是否配置与掩码；既有明文在受信迁移中加密。不能给坏密文继续原样执行请求。

验收：包含任意冒号／引号／Unicode 的密码、标准 Telegram token、旧明文、有效及无效密文，创建／更新／保留掩码／测试／发送全部测；SQL 与日志不能看到秘密原值，用户只能管理自己的渠道。

### S08：SFTP 没有服务器密钥固定

定位：`server/src/storage/providers/SftpProvider.ts:27`，`client.connect()` 未配置 `hostVerifier`，配置结构也无受信服务器 fingerprint。

证据：`logs/security-audit-sftp-host-identity-result2.log`。本机同 host／port依次启动两套不同 SSH host key，两次均连接成功，第二套收到合成密码。第一次测试夹具的 DNS mock误拦回环监听导致未启动，原失败日志保留；修正夹具后成功，不作为产品修复。

修复建议：首次受信登记 SFTP 指纹并持久固定，后续连接与所有存储动作核对，变化失败关闭；自动重试不能自动信任新密钥。SSH 加密防窃听的前提包含认证服务器身份。

验收：首次登记、已登记旧 key、同地址新 key、DNS 变化与升级／恢复配置；拒绝时不能发送密码；正常大备份可流式完成。

### S09：FTP 明文及凭据 CRLF 命令注入

定位：`server/src/storage/providers/FtpProvider.ts:33` 明确 `secure:false`；配置输入只限 username／password长度，未拒绝 CR／LF。锁定 `basic-ftp` 的登录代码直接拼接 `PASS` 并写控制 socket。

证据：`logs/security-audit-ftp-credentials-result.log`。本机明文 TCP 服务能读取密码；包含 CRLF 的合成密码产生第二条无害 `NOOP`。未删除文件、未发送攻击性 FTP 指令。

影响：FTP 链路可被窃听或篡改，额外命令突破“设置密码”的数据边界；执行位置是该存储 FTP 服务，**不是主控 shell**。这是用户远程存储适配器问题，主控 OSS 备份的固定 HTTPS endpoint走另一套路径，不能混称其默认使用 FTP。

修复建议：FTP改用可验证的 FTPS或迁移SFTP；服务端拒绝全部控制字符，依赖同步升级；普通用户不能借远程配置扩大内网访问。兼容原配置时要显示需要迁移，不能静默退回明文。

验收：username、password、目录／文件名全部控制字符变体；异常响应、断连、TLS变化；确认没有额外命令写到线上存储。

### S10：日志脱敏有确定遗漏

定位：`server/src/lib/log-sanitizer.ts:12`、`:99`、`:183`。字段精确列表遗漏 `DATABASE_URL`、`rootPassword`、`accessKeySecret`、`backupPassword`；URL规则未覆盖 `dt`、`ticket`及 Telegram `/bot…/`。备份下载 `server/src/routes/backups.ts:601` 与终端 `server/src/routes/terminal.ts:198`实际使用这类票据。

证据：`logs/security-audit-log-redaction-result.log`。7类合成值通过当前脱敏函数仍保留，标准 password对照被遮盖。没有查询生产日志，所以“字段遗漏”不能写成“生产密码已经泄漏”。Nginx 安装模板只给 caddy-script关闭 access log，普通 API可能记录带 query请求；真正访问日志格式／权限需线上只读核实。

影响：有日志读取权限者可能得到短时下载／终端 bearer票据，在到期或消费前抢先使用；其它凭据影响按实际入日志字段而定。一次性和短时有效降低窗口，但不消除泄漏。Pino serializer也不自动覆盖全部 `console.error`、任意字段或第三方 stdout。

修复建议：结构化统一秘密字段分类；URL先解析再按 endpoint及query/path遮盖；请求／异常／后台任务／Nginx／TG错误统一覆盖，避免把整个SQL、SDK配置或原始远端报错写日志。日志权限最小化并检查历史泄漏，只在确认后制订有目标的凭据轮换。

验收：7种本次输入和大小写／下划线／嵌套／编码变体；从实际 logger到journald／Nginx端到端验证；正常诊断信息可读且无真实secret。

### S11：数据库角色权限与部署防护不足

定位：`scripts/install-panel.sh:936`、`:951`～`:953`；同一 `DATABASE_URL`用于业务Prisma与服务启动迁移，见 `deploy/incudal-backend.service.example:19`。安装创建数据库归 `incudal`所有，没有业务／迁移角色分离。创建语句并未主动授予 SUPERUSER，但复用既有角色也没有完整核查危险属性与成员关系。

证据：`logs/security-audit-db-privileges-result.log`。独立非superuser、非createdb／createrole／bypassrls测试角色，作为自己测试库 owner能读全部合成表、disable自有表保护trigger。默认 PG 的 PUBLIC CONNECT存在；**PUBLIC CONNECT仍需通过网络和认证，并不意味着免密码登录**。

防御缺口：应用凭据失陷后不仅能做必要DML，还能改变对象结构、防护规则与删除数据。减少权限可限制破坏和横向范围，不能保证应用必须读取的数据不被应用身份导出。表owner／superuser下RLS也不能按普通租户隔离效果宣传。

修复建议：无登录owner／专用迁移角色与仅必要DML的业务角色分离；按实际业务核schema、sequence、function、CONNECT／TEMP；启动核SUPERUSER／CREATEROLE／CREATEDB／REPLICATION／BYPASSRLS／危险成员，禁止不合规运行账号。受限备份恢复执行器承担创建 staging与迁移，不把管理权限放回业务URL。

验收：业务账号合法销售／资金／续费／调度正常，禁止DDL、建角色、危险函数／跨库；备份／恢复／旧版迁移和OTA回滚保持可用。没有足够证据支持当前线上PG一定公网暴露；网络层待查内容见下一节。

## 4. 数据库防脱库：当前能力和缺口

### 4.1 按攻击权限区分

| 攻击者获得的能力 | 当前已确认影响 | 现有保护能做什么／不能做什么 |
|---|---|---|
| 匿名公网访问 | 未确证匿名任意SQL／全库导出入口 | 鉴权、签名回调、速率与schema有保护；依赖／资源风险仍需修 |
| 普通登录用户 | S04可经远程存储发起内网请求；可造成资源压力的调用边界需收紧 | 当前归属校验不能解决主控发起的SSRF |
| 只读数据库／dump | 用户资料／密码hash、明文通知凭据；S01摘要可接管有效会话 | bcrypt降低密码离线破解；GCM保护正确加密的字段；不保护明文、可直接使用的摘要或正常明文业务资料 |
| 可写数据库 | S02伪会话接管；S03恢复码替换；未签表／DDL破坏 | 资金HMAC能检测其覆盖字段的改动，不能认证所有鉴权表、阻止读表或阻止破坏 |
| 后端进程任意执行 | 能读取本进程DB／JWT／加密密钥及应用可访问数据，调用其有权限的管理操作 | root-owned代码与受限helper有价值，但进程内部密钥不构成对RCE的秘密边界 |
| 主控root／解密完整OSS归档 | 数据库、JWT／加密／控制和管理身份材料可能一起失陷 | 单机无法承诺抵御其root；必须依赖主机防护、独立审计／备份权限与恢复处置 |

### 4.2 分层检查表

| 层次 | 源码审查结果 | 建议与尚需验证 |
|---|---|---|
| PG网络与认证 | 默认业务URL连接 `127.0.0.1:5432`；未找到安装器主动约束PG listen／HBA／公网防火墙的完整逻辑 | 实际 `listen_addresses`、HBA顺序及IPv6、容器暴露、5432 ingress、WireGuard路由只读核查；默认回环URL不证明PG没有其它监听 |
| 账号与权限 | 业务账号为数据库owner，迁移同账号；备份metadata只查superuser不足以代替启动权限审计 | 分离角色；收紧PUBLIC及默认权限；核历史角色和成员；远端PG用验证服务器身份的TLS，当前备份工具默认 `sslmode=prefer` 不等于 `verify-full` |
| SQL注入 | 查了Prisma raw调用、批量traffic数值、分页／排序／归属，未确证可控字符串直入SQL | 将结构和参数严格分离；保留拒绝越界与枚举；`Unsafe`函数名本身不是证据，仍要逐新增调用审查 |
| 密码与会话 | 密码正常bcrypt12；刷新摘要存在S01／S02；认证恢复码S03 | 优先修会话及恢复码；会话、PAT／OAuth token的数据库写伪造边界须统一设计；不能只保护用户role列 |
| 字段加密 | 正常GCM与随机nonce存在；宽松解密回退及敏感配置明文例外S07 | 版本封装、严格验tag、按字段／记录绑定，迁移明文；不能把磁盘加密／数据库TDE当作抵御合法SQL读表 |
| 财务完整性 | 当前分支HMAC覆盖关键账户／流水／定价渠道，有独立基线与恢复验证 | 它防的是未掌握应用key的指定篡改，不是全库保密；覆盖遗漏必须独立修；新签名版本不破坏旧备份 |
| 日志／导出 | 备份SQL诊断已分类避免回显，普通日志S10仍遗漏；授权导出包含业务资料是预期 | 核实际日志ACL、轮转、保留和下载票据；审计谁能导出，防日志／备份文件被Web静态目录或artifact公开 |
| OSS归档 | 项目使用scrypt＋AES-256-GCM认证归档、随机salt／nonce、文件hash及路径白名单；完整认证后再提取，临时文件0600／目录0700 | 强独立备份口令，私有bucket与prefix最小权限，服务端审计／版本／防删除能力；配置ACL及真实OSS未在本轮验证 |
| 归档身份材料 | 为保留灾备身份，归档包含DB、runtime.env、控制签名／管理SSH／Incus等材料，外层统一加密 | 这是完整灾备必要内容，不能为“安全”删掉导致原宿主无法重连。解密归档应视同高权限材料，口令与读写凭据分离保存、恢复受限 |
| 主机／执行器 | 后端非root，代码及任务有root-owned完整性和受限sudo；NoNewPrivileges=false为现有helper所需 | 核真实sudoers与文件owner，不能仅改该开关令更新失效；后端RCE与root权限边界应实机测试，不声称本轮已突破helper |
| 独立审计 | 业务与部分安全记录在同一数据库／主机，DB／root失陷能影响本地证据 | 关键登录、导出、角色、备份恢复、资金证据写独立受限审计目的地；读写最小化及告警，避免所有证据同失陷 |

### 4.3 修复不能破坏OSS恢复

会话签名、恢复码迁移、敏感字段加密版本、业务／迁移角色分离都可能影响旧备份恢复。要求在源码修复后验证：当前生产版本原包→候选升级；原数据库与旧签名／无签名备份→新B；坏tag／错误口令／恶意schema或权限拒绝；恢复保护中不得签出可操作客户的旧会话；撤销／墓碑／快照之后的新付款、续费与退款仍必须独立对账。

本次只复用了上一轮本机加密pg_dump／pg_restore证据来说明既有保护。**真实OSS传输、Linux最终权限、双架构全新安装、A整机失联后B恢复、原宿主重连与客户连续服务，仍未因此验收完成。**

## 5. 依赖漏洞公告：命中不等于业务已被攻破

本机锁文件扫描原始结果：`logs/security-full-dependency-audit-20261122.json`；去重分组 `logs/security-advisories-grouped.json`；详情 `logs/security-advisory-details.json`。审计工具自然完成并以1退出，表示命中公告，不能记为安全通过。

工具返回263条advisory记录、236个不同公告URL、38个模块；metadata计数critical5／high99／moderate139／low21，含传递依赖及同公告不同版本分支，**不能称263个已经可利用的业务漏洞**。各修复下限来自本次公告快照，后续修复应选满足全部相关公告且兼容Node／插件的版本，不只满足一条下限。

| 依赖及当前版本 | 本项目可达性判断 | 处理建议 |
|---|---|---|
| `ws 8.18.3` | 终端公网WS入口与宿主WS使用；1MiB maxPayload不能限制无限小fragment的对象数量。内存泄漏／tiny fragments公告需优先处理，未做大流量复现 | 对应公告GHSA-58qx-3vcg-4xpx、GHSA-96hv-2xvq-fx4p；后者修复≥8.21.0。升级并验证fragment／连接／消息预算与终端重连 |
| `webdav 5.8.0` → `fast-xml-parser 4.5.3` | WebDAV响应解析可达，恶意存储服务器控制XML；实体扩展／DOCTYPE风险不是纯开发依赖。没有证明能读主控文件的XXE | 公告含GHSA-jmr7-xgp7-cmfj、GHSA-m7jm-9gc2-mpf2及后续修补；升级并禁止不需要的DTD／实体，限制响应和解析预算 |
| `basic-ftp 5.0.5` | 凭据控制字符问题本轮已复现S09；list和control-response内存公告也可达。`downloadToDir()`路径穿越公告的方法当前未调用 | 升级与输入拒绝共同修；不能把未调用方法的任意文件写说成现有主控路径可达 |
| `fastify 5.6.2` | 多项请求／schema公告命中。本机最小例子：按Content-Type分派body schema时tab变体绕过；当前根object schema对普通／tab均400。未找到业务使用该content分派模式 | 保存 `logs/security-audit-fastify-schema-result.json`；按全部公告更新兼容5.x并测malformedURL、schema、header、代理及not-found。当前实验证据不支持称业务付款校验已绕过 |
| `fast-jwt 5.0.6` | 当前固定、非空HS256 key；RSA空白、空异步key、custom cacheKeyBuilder等critical前提未见配置。不能用critical数宣布JWT任意伪造成立 | 升级兼容 `@fastify/jwt`版本；明确允许算法、payload形状、过期／cache、crit头策略，保存原正常登录与吊销回归 |
| `undici 7.16.0` 及传递6.x | HTTP请求可达；响应／解压预算有必要核。WebSocket、EventSource、cache／retry interceptor等公告不能全部移算为当前业务调用 | 更新兼容版本并核嵌套版本；真实pin／mTLS／lookup、取消、流、重定向、压缩响应逐验。升级不能丢既有TLS和SSRF参数 |
| Prisma工具链中的Hono及其它传递包 | 不同依赖角色混在扫描结果；本项目不是用Hono JWT给用户鉴权 | 分生产实际启动／安装迁移／构建工具核可达，兼顾发行包会带工具。未逐236公告动态复现，不把它们都标“已修”或“无影响” |

JS公告扫描不覆盖系统Linux／OpenSSL／PostgreSQL／Incus／LXC／内核、预构建镜像与所有Go内嵌组件。随后已补公开程序公告、正式双架构Agent和内嵌daemon二进制Go扫描、固定来源tar源码检查；结果如下。这些仍不等于生产安装版本和原生漏洞利用验收。

### 5.1 联网来源、版本清单与扫描结果

2026-11-22重新联网执行 `pnpm audit --json` 与 `pnpm audit --prod --json`，另直接读取GitHub官方仓库公告、PostgreSQL、Node.js、OpenSSL、OpenSSH、Nginx、curl、Go漏洞库、Alpine v3.24 secdb和Debian Security Tracker。36个直接来源请求中35个HTTP200；一个候选GHSA地址404，已排除，不作为有效公告。程序官方库得到Incus74／LXC3／Caddy23／cloudflared2条公开公告，LXCFS库空；空列表不能证明程序无漏洞，已用发行版tracker补查。

| 扫描 | 当前结果 | 解释 |
|---|---|---|
| 全部npm依赖，含开发工具 | 310条记录、264个不同URL、49个包；metadata critical7／high123／moderate158／low25 | 包含同公告多个版本分支及工具链，不能视作310条业务可利用漏洞 |
| 生产npm依赖图 | 263条记录、236个URL、38个包；metadata critical5／high99／moderate139／low21 | 与前次生产图结果一致；Prisma安装工具链仍需按实际运行判断 |
| 正式Agent v1.0.16 AMD64／ARM64 | 文件SHA与先前正式公开记录一致；两份均Go1.22.12；Go扫描各65个不同公告ID匹配 | 版本／符号匹配，未实施攻击；不是65个独立公开利用入口 |
| 固定Incus daemon AMD64／ARM64 | manifest原源码SHA一致、Incus7.0.1、Go1.26.11；两份各19个不同Go公告ID匹配 | 主要传递库；自身module标记devel，扫描没有覆盖全部Incus自身版本公告，必须另查官方源 |

Go工具为联网安装的`govulncheck v1.10.0`，数据库`https://vuln.go.dev`快照更新时间2026-11-11。四项binary／symbol扫描自然完成；JSON模式exit0不表示“无漏洞”。二进制扫描缺完整业务调用栈，且可能有符号匹配保守误报，因此下文结合配置、协议与源码判定。没有执行Linux二进制或入侵宿主。

锁文件直接依赖清单105项已提取；例如Fastify5.6.2、JWT插件9.1.0→fast-jwt5.0.6、Nodemailer7.0.11、undici7.16.0、前端axios1.13.2、Vue3.5.25／i18n11.2.2、Vite6.4.1。依赖声明中的`^`最低版本不能代替锁定版本。DOMPurify锁定3.4.17，本次registry未命中公告，这也不是安全认证。

原响应、请求URL／状态／时间／SHA和提取索引：`logs/security-online-20261122/sources.json`、`followup-sources.json`、`evidence-manifest.json`。逐条npm／程序／Go条目均纳入[联网漏洞公告附表](security-advisories-2026-11-22.md)，不只列数目或严重性。

### 5.2 E01：内嵌Incus7.0.1遗漏后续认证、导入及隔离修复

本项为**高优先级，官方公告＋固定源码确认**；本轮没有在真实Incus实施逃逸／任意写／认证绕过。源码来源`logs/incus-7.0.1.tar.gz`重新hash匹配构建脚本固定SHA；从归档读取的go.mod与官方tag一致。`scripts/build-incus-sysinfo-compat.py:6`、`:230`和双架构manifest固定7.0.1，现有patch只覆盖特定sysinfo、生命周期、存储及内存问题，不能覆盖所有上游安全公告。

| 公告／官方修复 | 本项目核对 | 影响与前提 |
|---|---|---|
| [GHSA-xg75-xf37-cph9](https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9)，critical，修复≥7.6.0 | 原`cmd/incusd/daemon.go:502`、`:573`、`:582`遍历未经链验证的全部PeerCertificates，与公告根因一致；项目构建patch未改这些函数 | 能访问Incus HTTPS监听时，可能把受信证书公有部分附加到自己的证书链，以该身份认证。官方指出服务器公有证书可由握手取得，不需其私钥。正常绑定管理IPv4／防火墙减少可达性，不能修认证函数；此项与面板终端S05是不同方向的认证缺口 |
| [CVE-2026-81496／GHSA-26gp-p5fw-3r2h](https://github.com/lxc/incus/security/advisories/GHSA-26gp-p5fw-3r2h)，critical，修复≥7.3.0 | 原`instances_post.go:851`从backup.GetInfo读名，`:992`送入存储创建；`:1452`校名在JSON分支，构建patch未改此导入路径 | 有导入权限或能影响备份内容时，metadata名／快照名可越界写宿主。项目正常恢复发送受校验`X-Incus-name`，覆盖主名，不能称主名攻击对该包装函数必然成立；快照／metadata及直接Incus入口仍需分别验 |
| [GHSA-5pgx-q9xx-j3qv](https://github.com/lxc/incus/security/advisories/GHSA-5pgx-q9xx-j3qv)，critical，修复≥7.6.0 | 客户远程备份下载后交给`restoreFromStream`，见`server/src/services/host-replacement.ts:182`、`server/src/lib/incus/incus-restore.ts:83`；未发现项目对整个备份metadata认证及特殊文件规则的完整修复 | 可替换客户控制的远端备份或恶意镜像metadata时，特殊设备／硬链／符号链导致宿主读写或阻塞风险；面板归属正确不等于归档安全。不能用“用户页无快照”否认底层导入的攻击面 |
| [GHSA-9c46-v3hw-v6m8](https://github.com/lxc/incus/security/advisories/GHSA-9c46-v3hw-v6m8)，high，修复≥7.6.0 | 原`driver_common.go:731`／`:732`删除pending和last idmap，`driver_lxc.go:2045`只在nextMap非nil时重新分配；本项目Rebuild patch未改该条件 | 从未启动成功的非特权容器重装再启动，可无user namespace而配置仍显示非特权。已经正常启动过的实例不满足此前提。需对首次失败→重装、重建恢复及首次启动实际uid_map检查，不能只看security.privileged=false |
| [GHSA-v736-5xp3-jghf](https://github.com/lxc/incus/security/advisories/GHSA-v736-5xp3-jghf)，high，修复≥7.6.0 | 当前项目cgroup回补取最先lxc.payload／lxc.monitor组件，正是官方要求的锚定方向；manifest列原83eaa5e1安全修复 | 此项**已有对应回补证据**，不重复当作未修漏洞。仍需双架构有效payload与原生伪造子cgroup拒绝回归；version7.0.1标签本身不能覆盖patch事实 |

源码保存证据`logs/security-online-incus-source-result.log`，精确读取文件在本机pinned-source目录。其它后续公告包括VM迁移NBD socket、事件泄漏、S3、限制项目／OCI config与更多归档路径，已逐条进附表；需要按是否使用VM／S3／restricted project及原生路径继续判定，不能把74条都当本项目当前匿名root入口。

修复建议：更新经过验证的安全基线，或按正式上游修复逐项回补、留manifest与源码hash，核动态LXC／CGO库。**仅更新系统incus包不一定更新本程序固定内嵌daemon，反而可能随后被旧兼容payload覆盖。** 必须同步Agentpayload、原身份／API／schema兼容、已有客户保持、旧worker升级回滚与双架构原生验收，不直接强推宿主升级。先修认证、metadata和idmap再做容量性能回归。

### 5.3 E02：正式Agent和内嵌daemon编译／传递依赖风险

正式AgentSHA重新核：AMD64 `08e2dd4cb9a9939a1987b014a6c1f527c6a7f10c8aa819186efe5ef991c34a21`，ARM64与已公开记录对应；读build info确认Go1.22.12，不是凭本机`go version`推断。该发行已编入旧stdlib，更新宿主系统Go不会修已经编译的Agent。

| 代表性官方Go公告 | 项目路径／前提 | 修复方向 |
|---|---|---|
| [GO-2025-3751／CVE-2025-4673](https://pkg.go.dev/vuln/GO-2025-3751)：跨源重定向不清敏感头 | AgentHTTP客户端有心跳／下载，需核实际头类型与redirect策略，不能把全部自定义HMAC头等同此公告标准Authorization条件 | 官方原修复1.23.10／1.24.4；使用仍维护且覆盖后续公告的Go重编，逐跳origin／TLS规则同时收紧 |
| [GO-2025-4007／CVE-2025-58187](https://pkg.go.dev/vuln/GO-2025-4007)：X.509 name constraints消耗资源 | Agent连接恶意或被劫持TLS服务的证书处理，rootAgent可用性受影响；正常pin和可信路径减少前提 | 原修复1.24.9／1.25.3，不能继续Go1.22.12 |
| [GO-2026-4918／CVE-2026-33814](https://pkg.go.dev/vuln/GO-2026-4918)：恶意HTTP2设置使transport循环 | AgentHTTP客户端与daemonHTTP2组件的可用性，binary命中不等于已打断线上连接 | stdlib原修复1.25.10／1.26.3，x/net0.53.0；全新受支持编译基线 |
| [GO-2026-6354／CVE-2026-78662](https://pkg.go.dev/vuln/GO-2026-6354)、[GO-2026-6355／CVE-2026-56855](https://pkg.go.dev/vuln/GO-2026-6355)：SSH channel死锁 | 内嵌daemon x/crypto0.54.0，IncusSFTP等SSH路径；与面板JS ssh2不同 | x/crypto≥0.56.0并核后续公告；不能仅升级server的ssh2 |
| [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)、[GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610)、[GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611)：HTTP2内存／framing／window风险 | daemon标准库Go1.26.11已包含部分修复，但独立x/net0.57.0仍命中；编译器升级不自动更新所有module | x/net对应HTTP2至少0.60.0，其它HTML公告需0.62.0；核真实用途，避免盲改所有module |
| [GO-2026-6348／CVE-2026-84304](https://pkg.go.dev/vuln/GO-2026-6348)：gRPC DATA fragmentation OOM | daemon gRPC1.82.0，只有实际gRPC服务／相关功能可达才成立，不能当成普通IncusAPI必然可利用 | 对应≥1.83.1并覆盖后续panic／RBAC公告，核功能兼容 |

其余匹配含压缩、DHCP、GoBGP、x/text和openpgp；附表保留全部19项ID及所需模块版本。Go数据库缓存不是当前生产证据，符号存在与攻击输入可达分开。只更新Agent主程序但仍嵌旧daemon及其CGO／module，不算此项闭环。

### 5.4 E03：数据库、TLS与Web入口配套程序公告

| 程序／官方来源 | 联网发现和修复版本 | 本项目适用性 |
|---|---|---|
| [PostgreSQL官方](https://www.postgresql.org/support/security/) | 11月12日修复系列含[CVE-2026-120151](https://www.postgresql.org/support/security/CVE-2026-120151/) plpgsql type confusion低权限对象创建者执行DB OS代码、[CVE-2026-120154](https://www.postgresql.org/support/security/CVE-2026-120154/) ON CONFLICT绕RLS读行；16系列对应16.16，17.12／18.7／15.20／14.25 | 安装器只选PG16，不锁最新小版本；本轮未查主控actual版本，不能称线上受影响。S11数据库owner失陷可能满足对象创建前提；这不是无需SQL访问的匿名API注入。RLS不能代替正确补丁或权限最小化 |
| [Node.js 10月](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)／[11月安全发布](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) | 10月对应24.22.1／22.23.4，11月24.22.3／22.23.5；含DNS／TLS身份、Brotli、HTTP2及HTTPS heap泄漏。版本随后续发布核 | 本机24.18.0只为审计工具，不代表主控；线上Node22兼容不代表任意22小版本安全。私有Fastify当前HTTP1回环，不直接套用原生HTTPS／HTTP2服务器前提，但HTTP客户端／解压／TLS依赖仍需检查。OTA不自动升级系统Node，必须另有受控更新流程 |
| [OpenSSL 11月17日公告](https://openssl-library.org/news/secadv/20261117.txt) | SuiteB TLS1.3边界读、PEM caller-stack UAF、QUIC stream保留；目标3.5.10／3.0.24等；**源码已修，发行计划12月1日，在查询日尚未公开** | 新目标未发行不能写“升级已解决”。SuiteB／非空PEMstack／QUIC有特定前提，正常GCM归档不等于这些攻击面。系统OpenSSL、Node内置OpenSSL、GoTLS是不同来源；本机Node内置3.5.7只说明审计环境 |
| [Nginx官方](https://nginx.org/en/security_advisories.html) | CVE-2026-123007 HTTP2 flow-control内存破坏、CVE-2026-118899 TLS1.3 request-body无限循环等；官方最新不受影响mainline1.31.9／stable1.30.7 | 本项目反向代理在公网边缘，核实际HTTP2／TLS／resolver／rewrite等开关。Debian13回补例为1.26.3-3+deb13u11，因此不得仅见1.26.3就判未修；也不能用NginxHTTP2修复说明私有NodeHTTP2已修 |
| [OpenSSH官方](https://www.openssh.com/security.html)／[Debian tracker](https://security-tracker.debian.org/tracker/source-package/openssh) | CVE-2024-6387 Portable8.5p1～9.7p1服务器race，9.8修；CVE-2025-26465客户端VerifyHostKeyDNS，9.9p2修；CVE-2025-26466服务器preauthDoS，9.9p2修；tracker另含2026客户端UAF／GSSAPI／tunnel restrict等 | 服务器、客户端、ssh-agent条件不同，不能把客户端特有漏洞列成普通sshd匿名RCE。主控／网关／宿主及客机镜像的发行版回补版本均待实际核；不用LoginGraceTime=0等功能退化代替正确升级 |

数据库备份与恢复工具同样需配套最新PG patch，保证archive工具链兼容；不要擅自升级PG大版本或覆盖原数据库。主控、宿主及网关系统库应保留身份与客户数据，遇必须重启的原生修复先计划维护，不能以无感自动修复口头承诺替代实证。

### 5.5 E04：网络、容器、存储与可选程序

| 程序／来源 | 已核公告与判断 | 需要的验收 |
|---|---|---|
| Linux内核／WireGuard／Btrfs／device-mapper；[Debian linux tracker](https://security-tracker.debian.org/tracker/source-package/linux) | 容器共享宿主内核，内存／磁盘quota和AppArmor不能防住全部内核本地提权。例CVE-2025-38236 AF_UNIX UAF，Debian13修复6.12.37-1；CVE-2025-0927经CVE记录确认已REJECTED，不能照旧漏洞库宣传为有效CVE | 实际uname、package版本与运行内核、userns／seccomp／capabilities、WireGuard和netfilter／Btrfs模块；更新包但未加载新内核不算修复；不执行逃逸攻击生产 |
| dnsmasq；[Alpine secdb](https://secdb.alpinelinux.org/v3.24/main.json)、[Debian tracker](https://security-tracker.debian.org/tracker/source-package/dnsmasq) | 客户DNS路径用宿主dnsmasq。2026 name parsing／DNSSEC公告组CVE-2026-2291／4890～4893／5172；Alpine修复2.92_p2-r0，Debian13回补2.91-1+deb13u1 | 监听接口／客户触达范围／upstreamDNS、DNSSEC与cache，实际apk／dpkg版本；不能因未来安装拉最新版就认为所有旧宿主已经修 |
| LXC／LXCFS；[LXC官方](https://github.com/lxc/lxc/security/advisories)、[LXCFS tracker](https://security-tracker.debian.org/tracker/source-package/lxcfs) | LXC命令socket不可信指针GHSA-4xwm-pr6h-55r8修复≥7.0.1；官方前提包括与宿主共享网络namespace以访问abstract socket，正常独立NAT网络不能直接等同可达。lxc-copy symlink及user-nic公告按工具／权限前提核。LXCFS官方GHSA为空，但tracker有历史cgroup权限问题 | 内嵌daemon动态LXC依赖、实际socketACL和网络namespace；LXCFS真实挂载只读及namespace，不只字符串检查；新版本不机械列历史CVE为活漏洞 |
| curl／libcurl；[curl官方](https://curl.se/docs/vulnerabilities.html) | 安装与更新下载、外部探测依赖curl；2026安全数据库有多批协议／认证／连接重用问题。例CVE-2026-19931涉及Negotiate连接重用，项目常规curl下载不等于使用Negotiate | TLS／proxy／redirect规则与实际curl版本；前端axios、Nodefetch、GoHTTP不因系统curl更新而修复 |
| LVM2／libdm；[Debian tracker](https://security-tracker.debian.org/tracker/source-package/lvm2) | CVE-2026-19617恶意深层LVM metadata递归DoS；需能让工具读取恶意metadata。不能称用户正常私有30G盘必能控制宿主LVM元数据；共享内核device-mapper风险另查 | 分配／回池／恢复／metadata保护，原宿主控制权限及实际库版本；不为审计改用ZFS或破坏既有池 |
| QEMU／qemu-guest-agent；[Debian tracker](https://security-tracker.debian.org/tracker/source-package/qemu) | 只有VM路径需QEMU设备攻击面；例CVE-2026-48914 virtio-blk descriptor问题，Debian13修复1:10.0.11+ds-0+deb13u1；其它9pfs／migration依具体设备。guest-agent在客机安装是另一程序／权限面 | AMD／ARM不同device和VM型号、宿主QEMU、客机agent、live migration和9p启用情况；不把所有NAT容器当KVM |
| chrony／systemd；[Debian tracker](https://security-tracker.debian.org/tracker/data/json) | chrony历史PIDsymlink等，3.5.1或发行版回补已修；systemd-machined259root namespace公告CVE-2026-40224，Debian13对应257系列tracker不受影响。journald输出前提不同 | 实际NTP／cmdport、服务权限、后台任务与日志输出，尊重管理员配置；不能停止校时或放宽时间门禁掩盖失败 |
| Caddy；[官方公告](https://github.com/caddyserver/caddy/security/advisories) | 23条含mTLS fail-open／vars_regexp泄漏／admin路径与file_server规则，后续范围到2.11.8。当前模板是localhost2019＋basic-auth反代，没见forward_auth／php_fastcgi／{host}文件根，不把这些条件漏洞说成现有入口已利用；建站功能删除仍不等于旧安装程序已卸载 | 检查是否仍安装／运行、配置与版本／admin可达性；未知版本不自动卸载服务 |
| cloudflared；[官方公告](https://github.com/cloudflare/cloudflared/security/advisories) | 历史CVE-2023-1314为32位Windows installer本地提权≤2023.3.0；CVE-2020-24356同样是Windows配置目录权限问题，修复2020.8.1，**两者不能套用到项目Linux原始binary安装**。installer取latest也不证明既有daemon及Go依赖已更新 | 正在运行binary／Go依赖／文件权限与隧道配置；保持原token及网络，不输出凭据；按OS和实际安装路径判公告 |

发行版secdb包含`0`、not-affected／resolved／open及回补revision；已下载的Alpine／Debian筛选文件不能被简化成“所有列出的历史CVE都未修”。内核、libc、OpenSSL和包版本需要线上只读补证，未知项始终标待核。

### 5.6 E05：新增JS工具链／前端／出站库公告可达性

| 依赖 | 联网公告补充与项目检查 | 验收方向 |
|---|---|---|
| @fastify/multipart9.4.0→@fastify/busboy3.2.0 | [GHSA-xjh9-v7x6-24jw](https://github.com/advisories/GHSA-xjh9-v7x6-24jw) boundary DoS、[GHSA-x8mw-p69m-v3mx](https://github.com/advisories/GHSA-x8mw-p69m-v3mx) prototype命名header；工单multipart可达，文件bytes上限不保证parser安全 | 全相关修复至少3.2.2并核后续版本；小数据异常boundary／header隔离测试与正常附件流程，配合R12并发预算 |
| AWS SDK→fast-xml-parser5.2.5；WebDAV→4.5.3 | 两不同major均命中，SDK响应XML与WebDAV不同路径；[GHSA-37qj-frw5-hhjh](https://github.com/advisories/GHSA-37qj-frw5-hhjh) numeric实体RangeError，后者已见第5节 | 更新整个传递图并保持真实OSS／S3签名、stream与错误处理；不能只override4.x解决5.x |
| Nodemailer7.0.11 | 20条命中含envelope.size／transport.name CRLF、raw／jsonTransport读文件、SMTP身份和地址parser。当前mailer显式固定transport字段，未接收用户raw消息对象／envelope.size／自选name；不能机械称用户已可读主控任意文件 | [原始公告](https://github.com/advisories/GHSA-c7w3-x93f-qmm8)及全部附表，逐匹配字段；升级跨major要核TG／邮件验证码、SMTP和禁文件URL；收件人长度／格式及S07凭据一起修 |
| axios1.13.2／follow-redirects1.15.11／form-data4.0.5 | axios含NodeHTTP SSRF／proxy、proto gadget和stream预算公告；本项目显式axios import主要前端浏览器，不把Nodeadapter的NO_PROXY当浏览器可利用。传递follow-redirects和form-data按真实服务器路径核 | axios全部已知范围更新，浏览器session／跨源／上传回归；[follow-redirects](https://github.com/advisories/GHSA-r4q5-vmmm-2653)≥1.16.0、[form-data](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx)≥4.0.6及后续范围；proto gadget需另一污染入口，未确证该前提 |
| ip-address10.1.0／fast-uri3.1.0 | IPv4非规范形式、IPv6linklocal分类与超长输入风险；项目SSRF核心用NodeisIP／自定义fe80::/10分类，未用Address6.isLinkLocal作门禁，不能把该公告直接归因S04 | 依赖更新且核地址库存／host monitor其它调用、输入长度；fast-uri作为schema解析依赖不等于公开用户可设任意schema |
| Vue3.5.25／vue-i18n11.2.2 | i18n参数escape／srcdoc公告修复≥11.4.14；server-renderer3.5.25有SSR属性名XSS公告。项目双SPA，无当前后端VueSSR；未见动态不可信translation直接HTML渲染入口 | 浏览器实际翻译／v-html回归，不能把SSR公告称现有SPA存储XSS；运行前端包与Node工具链分开 |
| Rollup4.53.3／Vite6.4.1／esbuild传递0.18.20、0.19.12／PostCSS等 | [Rollup路径穿越](https://github.com/advisories/GHSA-mw96-cpmx-2vgc)修复≥4.59.0；esbuilddevserver公告原修复0.25.0，根esbuild0.25.12不消除传递旧版。构建工具风险有不可信插件／输入／开发服务前提 | 完整锁图更新，CI最小权限、dev不公网、双端build和dist边界；别用生产静态网站不会运行Vite来忽略维护者／CI攻击面 |
| Hono／Effect／mysql2／AJV／nanoid／glob／yaml等 | 全量49个包都有逐条明细。项目PG不调用MySQL，nanoid固定安全API长度不等于公告non-secure负size入口，AJV$data需该选项 | 可达性分组与按major升级；公告无修复值或特殊范围保持待核，不把包名匹配称已获取权限 |

这些外部公告分组E01～E05属于本轮补查结果，与S01～S11的本机复现数量不混算；已有S09与相关FTP公告重复关联而不重复计数。修复优先级新增：**Incus认证／归档／idmap、正式Agent编译基线与可达解析库须作为上线前阻断项审查**，其余依版本、功能和攻击输入判定。不得因本次联网检查直接更新生产或提前发版。

## 6. 其它源码确认风险

### R12：资源耗尽防护不一致

`server/src/lib/ticket-attachments.ts:5`允许6张、每50MiB，`:66`以toBuffer收集，单请求bodyLimit304MiB；创建／回复工单已有5／20次每分钟限流和读body前鉴权，但没有统一每账户／全后端在途字节预算。限请求频率不能防几个合法大请求并行占满唯一Node进程。

远程存储测试无专项并发预算，FTP／SFTP超时6小时；WebDAV SDK上述 `maxContentLength`／`maxBodyLength`设置未构成可靠限制，当前request适配也未传这些限制。SFTP `downloadStream()`实际调用无destination的`client.get()`，先接收整个备份Buffer再包装Readable，`server/src/services/host-replacement.ts`有实际调用。Incus响应 `server/src/lib/incus/incus-client.ts:232`／`:443`有不限制总bytes的text读取。

建议用有界流／解析、短连接测试时限、用户＋全局并发／累计内存／磁盘预算与取消；长期大备份允许合理任务预算，但不能占用在线API连接数和整个堆。必须保留单后端不变量，不能靠开多个worker掩盖该问题。本轮没有做OOM或最大承载压力，严重性与真实阈值待隔离容量验收。

### R13：HTTP Agent更新可能被网络替换

定位 `agent/internal/config/config.go:78`允许http；`agent/internal/upgrade/upgrade.go:142`同origin下载允许http，`:110`只验证升级指令给出的SHA256。升级指令来自心跳响应，没有与独立发行公钥绑定的包签名，摘要和包若一起被改，hash校验仍过。

**条件前提是HTTP或等价可信TLS失陷；正常新接入HTTPS与受信控制配置的Ed25519保护不能忽略。** 在可劫持的HTTP模式中替换升级指令和二进制可能取得root Agent执行权限，本轮没有下载或执行恶意Agent。

建议生产Agent拒绝明文管理／更新，升级包增加独立签名、版本／架构／用途／来源绑定和防降级；全部响应动作的信任边界一起核对。正常HTTPS、坏签名／旧指令／错误架构与下载中断回退均需真实升级测试。

### R14：浏览器与明文部署的损害放大

`client/src/stores/auth.ts:8`保存JWT于localStorage；正常JWT7天、刷新会话30天。生产CSP `server/src/app.ts:234`保留unsafe-inline，connectSrc允许广泛ws／wss；HSTS `:286`关闭，Cookie支持显式不secure／共享domain兼容设置。没有确证一个现有XSS入口，所以不能写“已通过XSS盗号”。

建议公网HTTPS／Cookie／两端独立源作为部署核验项；收紧CSP脚本和连接源，逐功能验证Turnstile／终端，缩短高权限access有效期并给敏感操作重验。Cookie配置与HTTP隔离环境分开，不把默认值和线上实际值混为一谈。GeoIP另有`server/src/lib/geoip.ts:134`明文HTTP查询用户IP，属隐私与观测完整性风险，不是核心权限旁路。

### R15：供应链与CI权限

工作流使用`actions/...@v4/v5`及`softprops/...@v2`等可变tag；release build带contents write。未找到pull_request_target直接执行不可信PR的路径，不能误报已经泄露CI密钥。安装器 `scripts/install-panel.sh:367`以HTTPS下载NodeSource脚本并root执行，cloudflared从latest获取；上游HTTPS身份不等于对内容的独立固定来源验证。

建议Action固定审核commit SHA；build只read、实际发布job才write；核外部下载的签名／hash与更新来源，发布签名／身份恢复材料与GitHub写权限分离。真实仓库branch protection／Actions默认权限／密钥策略本轮没读GitHub设置，不能称已检查通过。

## 7. 模块覆盖与未确认问题

| 模块 | 本轮检查重点 | 当前结论与限制 |
|---|---|---|
| 登录／注册／找回／2FA／会话 | status／role／sid、一次性码、Turnstile、IP可信代理、恢复保护 | S01～S03；注册限额和正常身份门禁已有；未对生产批量账号实施测试 |
| Web／管理员／PAT／OAuth | route hook、scope、归属、数据库权限回查、授权撤销 | S06；PAT正常token先hash＋prefix检查，未确认其摘要可直接登录；可写DB伪造其它token表边界需一并加固 |
| 充值／余额／购买／续费／退款 | 上一轮锁内金额、签名回调、幂等及当前资金签名 | 原资金修复证据继续成立；不能据此排除本次账户接管造成合法权限下的资金滥用 |
| 实例／重装／停启／销毁／库存 | 主人／管理员权限、过期、原身份、后台任务、客户数据保护 | 未确证新增匿名销毁／越权改价；销毁邮箱码与远端确认已有；本轮没重装或停删生产客户 |
| Agent／网关／宿主接入 | HMAC／nonce／时间、受信SSH／配置签名、管理入口、TLS | S05与R13；正常签名／身份保护存在；不沿旧报告搬运已经修复的root执行缺口 |
| 远程存储／备份／OSS恢复 | 实际连接、DNS／重定向、server身份、密码／归档与SQL权限 | S04、S08、S09、S11、R12；OSS代码独立，不把客户FTP结论扩大到OSS默认路径 |
| TG／邮件／webhook／日志 | 明文入库、返回掩码、用户内容／内部信息、错误和下载票据 | S07、S10；已有客户通知过滤不代表凭据入库与日志没有泄漏 |
| 工单／帮助／前端内容 | 图片权限／类型／大小、markdown／v-html、下载／路径 | DOMPurify过滤存在，未确证stored XSS；资源预算R12，未做巨大包耗尽 |
| 全库SQL／文件／进程危险点 | raw SQL、参数化、数值枚举、shell／exec、静态根与路径校验 | 未确证可利用SQL注入或匿名主控RCE；客机自定义初始化命令是授权客机功能，不把它当主控shell注入 |
| 安装／OTA／发行／恢复执行器 | 非root业务、root-owned helper／manifest、env清理、sudo与包完整性 | 旧升级事故守门仍必要；本轮没产新包／执行OTA；条件供应链风险R15 |

本轮不属于逐条URL fuzz、完整浏览器渗透、每236公告复现、系统与内核漏洞鉴定或正式第三方渗透认证。全库清点和高风险调用链审查已经完成，但不能保证未知漏洞不存在，特别是生产实际网络／权限和未执行的动态边界。

## 8. 修复顺序和上线门槛

1. **先处理账户与主控边界**：S01／S02／S03；S04连接期与重定向；S05终端完整pin；新增E01的Incus认证、归档与真实idmap及E02正式Agent编译基线列为同级上线阻断审查。每项补真实拒绝攻击的回归，而不只钉函数名字或字符串。
2. **处理脱库与存储凭据**：S07严格加密／迁移；S08服务器key；S09控制字符和安全传输；S10日志／票据；S11分离DB角色与启动权限检查。会话与凭据轮换按实际泄漏证据制定，不擅自让生产全部用户下线。
3. **处理重放及可用性**：S06原子消费／授权回查；R12统一预算；可达的ws、XML、FTP、Fastify、JWT、undici依赖公告和HTTP Agent安全一起精修，保留原功能与受信管理路径。
4. **验证修复包及恢复**：相关type-check／守卫／双端构建／Go检查；隔离PG并发与连接攻击对照；当前正式旧包双架构升级／回滚；旧OSS归档版本／角色／认证迁移；真实端到端流程各自留证。
5. **补生产只读验收**：部署SHA、监听和HBA／防火墙、PG角色／成员／默认权限、sudoers／root文件权限、HTTPS／Cookie／CSP、日志ACL、OSS bucket ACL／口令／版本与独立审计。在未取得这层证据前，报告仅认定源码缺口，不能断言线上已被脱库或已经防住脱库。

本轮任务到报告为止，所有发现均记为**待修／待验**，不得因这份报告或旧授权直接修改生产、提交新修复或发布新版。此前“暂不发版”保持。

## 9. 复现与清理记录

| 实验 | 结果文件 | 已观察结果 |
|---|---|---|
| 刷新摘要 | `logs/security-audit-refresh-passhash-result.log` | 200、合成admin JWT |
| 伪造会话／恢复码 | `logs/security-audit-db-write-session-result2.log` | 伪会话无密码刷新200；原密码＋伪恢复码登录200 |
| 存储DNS变化 | `logs/security-audit-storage-dns-result.log` | WebDAV请求进入回环；safeFetch对照拒绝 |
| 存储重定向 | `logs/security-audit-webdav-redirect-result.log` | 307到字面回环被跟随 |
| 终端假服务器 | `logs/security-audit-terminal-pin-result.log` | 替身接受；正常pin对照拒绝 |
| OAuth并发 | `logs/security-audit-oauth-races-result2.log` | 单码／单刷新各兑换两次 |
| DB权限 | `logs/security-audit-db-privileges-result.log` | 非superuser owner读表／关自有trigger |
| 明文凭据 | `logs/security-audit-secret-storage-result.log` | token及冒号密码明文；加密对照有效 |
| SFTP新host key | `logs/security-audit-sftp-host-identity-result2.log` | 同地址更换key仍发送密码 |
| FTP凭据 | `logs/security-audit-ftp-credentials-result.log` | 明文PASS及额外无害NOOP |
| 日志脱敏 | `logs/security-audit-log-redaction-result.log` | 7类遗漏，password对照被过滤 |
| Fastify最小例 | `logs/security-audit-fastify-schema-result.json` | content分派可绕；当前根schema对照拒绝 |
| 守卫两批 | `logs/security-audit-targeted-guards.log`／`logs/security-audit-protection-guards.log` | 18／18、13／13自然exit0 |
| 最终清理 | `logs/security-audit-cleanup-result.log` | 本轮审计临时PG库／角色无剩余 |

OAuth首轮因夹具无法读取预期锁等待证据、SFTP首轮因夹具DNS影响监听而失败，失败日志保留，后续修正的是本机实验准备，产品代码未变。所有临时监听／socket由finally关闭；临时库／角色按本轮专用命名核验，原财务测试库和本机PostgreSQL保持，没有清理其它任务文件。

本轮写入仅owner要求、此报告及联网附表、两份交接台账与两份报告的文档忽略例外，另有ignored隔离实验、公开联网响应与本机扫描工具证据文件。没有产品代码／迁移／依赖变更，没有生产动作、commit／push、PR、tag或Release。
