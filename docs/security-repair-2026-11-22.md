# 两轮安全审计统一修复台账

基准：`a5251f0cab9c7fdaf861f36d2c7563f838984d33`；2026-11-22 owner授权全部源码修复、依赖更新、代码审视与精修。原[安全报告](security-audit-2026-11-22.md)及[公告明细](security-advisories-2026-11-22.md)保留审计时事实；此台账记录后来实现与验证，未完成项不写通过。生产／正式发行暂不执行。

## 续接实施状态（2026-11-22，尚未完成）

本轮已修产品源码及锁图，准备阶段提交推送并运行无tag发行预览；尚未正式发行／部署生产。以下逐次补记与表格记录较新验证事实，早期过程不代最新验收。

2026-11-22接续补记：原公开v1.8.14 AMD64包在本机systemd VM已实际启动，唯一后端`/api/health`返回businessStartupReady=true、管理员存在、244迁移已完成（`security-systemd-lab140/current317.log`）。较早连接超时和组件目录检查失败保留原日志；当前目录root:root/0700及lock0600正确，不能据固定stage推断身份坏或修改权限。模拟器前置安装超过原systemd90秒默认，仅隔离观察增加10分钟fixture上限；不是产品修复证据，原worker升级仍待自然终态。

本轮复审修复系统库存覆盖待激活状态：`system-security-inventory.py`按root私密receipt锁合并精确待激活包，定时刷新与后续无变更更新不能清除，失败/准备状态与待激活清单共同保留，兼容此前格式；不据安装版本宣称运行服务已装载补丁。六专项含真实root策略权限测试全过，原10项systemd补丁待激活receipt实际保留（`security-systemd-lab140/inventory328.log`），最新本机planner终态全过（`security-repair-planner329.log`）。激活完成的产品回执／全配套自动更新仍未闭环。

继续补上实际loaded-code巡检，限定宿主PID namespace与固定服务清单、5秒/256进程/单maps1MiB预算；只保存服务/PID/已删除映射数量，不收集客户进程或映射文件名。Alpine补lxc-libs/lxcfs-openrc、Debian补当前运行kernel的精确安装包。Linux实际7项全过（`security-systemd-lab140/inventory336.log`），检出了此前已换库但尚未重启的sshd/nginx/postgres，库存版本不能代替生效。Windows对应runner已过（`security-repair-planner335.log`，两项原生检查明确跳过由Linux实证补齐）。

最新原worker首次运行未过：真实v1.8.14任务1完成候选下载/hash后，在tar解压180秒超时；尚未切换代码/数据库，没有backup可回退，任务failed（`security-systemd-lab140/workerdetail353.log`、`fixturedeps354.log`）。TCG本地兼容夹具有388MiB根依赖和356MiB独立server依赖重复，仅精简本地夹具后再验，保持原worker180秒及签名/依赖/迁移守卫，不将失败改成通过。复审另修发行`incudal.sh`快捷入口：start走唯一systemd service，migrate走root私密迁移helper，不再用业务角色执行DDL或直接启动第二个backend。新版签名完整包与双架构六升级仍待。

2026-11-23新增S05旧宿主兼容修复：已有受信WireGuard/SSH登记但缺Incus pin者，由原受限gateway `probe`固定读取公有server.crt；root/无链接/无可写父目录/16KiB/非阻塞/隔离Python均限定，前后原SSH/peer/节点一致，再以公有证书实际验证TLS trusted后一次保存。已有pin/cert变化拒绝，原配置/客户不重建；取消/超时关闭读取通道。真实PG缺pin/完整登记不重采/错误pin0Incus请求/失败TLS不保存/非root不读取及既有恢复/撤销/轮换回归通过（`security-repair-management400.log`），最新取消变更复验进行。Linux固定探针专项已过（`probetarget395.log`），较新代码专项/全部gateway tests仍待终态。普通缺SSH登记宿主不凭空信任；尚未生产部署。

S05进一步消除旧缺pin与排队stop/delete/rebuild互等：已有任务只阻止Agent配置写，固定公有身份核验可完成，再让原实例任务续接；不改客户状态或任务、不执行Agent写。真实PG新回归`security-repair-management425.log`自然退出0，保持原PENDING stop与Stopped实例，TLS失败不保存、非root/错旧pin拒绝和原凭据轮换/恢复全部过。较早新夹具缺image/宿主默认0CPU分别由Prisma及DB触发器拒绝，补真实测试输入，不放宽业务配额。新增guard括号错误已修，`security-repair-guards420.log`及最新type421过；latest后端build427进行。Python公有读取进一步用-I/-B、NOFOLLOW/NONBLOCK与父目录校验，最新Linux专项probetarget413过，完整gateway套件仍running。

本轮第二次原worker任务2已解压精简fixture、备份/替换代码、原CLI执行246迁移（新增money/auth各一次），但随后旧chown封存120秒在TCG超时，正在真实自动回退（`currentworker394.log`）；当前未降权，不提前说新backend成功或回退健康。保留迁移留库状态，不恢复旧DB覆盖新账目。最新types3项、backup4、install5、system-update、security-repair和planner分项通过；完整最新冻结点全量尚未重跑。

- 四项隔离真实 PostgreSQL 认证／OAuth／正常业务／资金回归终态通过（`security-repair-pg-final47.log`）；外部摘要不能换 JWT，数据库伪造会话、恢复码、OAuth 并发重放和余额／明细篡改拒绝，正常登录与单次入账保持。新增抽奖凭据专表补加密／验签／旧配置迁移／关联读取和删除签名清理，`security-repair-pg-final54.log`正常业务部分通过。升级会退休旧 refresh、PAT、OAuth bearer 与一次性码，需要重新登录／重新签发；原账户密码、实例及资金资料保持。
- SFTP／FTPS 实际本机传输与错误服务器身份拒绝、S3 签名流 CRUD／XML预算、WebDAV连接期DNS／真实流及取消预算已验；取消附件请求后，处理器退出前继续占用预算。具体本机日志见此前证据，不能当作生产存储或真实 OSS 验收。
- 所有通知发送路径补64KiB读取后再解析／预览及错误脱敏，包括流量、抽奖和管理员告警。真实业务 Telegram发送回归通过（`security-repair-telegram-final58.log`，外部Telegram由隔离响应夹具替代）：客户消息不含宿主／OCI／内网，管理员HTML详情、归类边界与HTTP失败落库正确。新增真实TLS SMTP发送、假证书拒绝、明文端点收到0次AUTH及禁止文件／URL附件通过（`security-repair-smtp-final63.log`）。
- 面板发行清单精确绑定请求版本，不再改写另一个已签名包版本；预览格式与安装器一致。更新日志按完整有界行脱敏，跨数据块凭据／中文保持；超过4MiB capture明确失败而非截断当完整结果。相关更新专项通过（`security-repair-system-final48.log`）。面板与Agent实际安装器shell／OpenSSL双架构正签名、错误签名／包内容／版本／架构拒绝通过（`security-linux-lab/signatures-policy-final59.log`，只将测试公钥替换为合成publisher，真实密码学未mock）。
- S11业务DML／root私密迁移身份分离，SCRAM同口令、HBA与安全补丁提前核验、固定旧包回退runtime与旧worker入口已实施。Linux连续两次真实角色准备无异常（`security-linux-lab/database-policy-final62.log`）；先前真实低权限dump／迁移role restore／原数据与DDL拒绝通过。复审新增数组事务兼容修复，配置批量更新／网关DNS入队保持同一验签事务；完整低权限全schema／资金／认证备份恢复与公开旧包原worker六场景仍待。
- 系统维护政策增加独立随机token与私密回执，硬中断后只有精确原策略、无APT／dpkg锁时清理；管理员已有或修改后的策略保持。Linux4项planner／实际文件权限测试通过。Agent同branch叶子补丁补apk版本排序、安装后回读与精确main／community源。系统组件库存不等于旧loaded libraries／kernel已生效；配套全部服务更新与激活仍待原生闭环。
- 双架构Incus7.6／新Go工具链和原功能补丁已构建并扫描；WindowsAgent全包最终第5轮通过。E01／E02实际daemon热换／回退保客户和最终双架构发行payload仍待。依赖全图／生产图audit0是上一冻结点证据，不能当作后续发行完成。
- 最新230项全套仍运行（`security-repair-suite-final6.log`）；前轮227全量226/227的唯一旧邮件断言已修，不能把它写成全部通过。新增签名、系统planner、Nginx配置守卫已登记总清单，SMTP实传测试单独分类。最终类型／构建与最新全量自然退出后补最终记录。

复审实测拦下的兼容缺陷均保留失败日志：Prisma联合delegate类型不可调用、fixture缺createdBy、抽奖删除留下seal、配置数组事务被安全代理拒绝、空fixture缺默认配置和Linuxfixture缺bash。后四项分别区分产品／环境根因，不放宽验签或跳过失败测试。

最新补记：230项完整回归自然退出0、230/230通过（`security-repair-suite-final6.log`）；其后恢复／超时改动的5专项再次全过（`security-repair-final78-guards.log`），最终build77退出0。资金最新真实PG与加密archive／pg_restore全过（`security-repair-finance-final75.log`）。Linux147表演练已捕获完整dump，夹具缺runuser路径／业务OS用户／runtime.env及临时DB ACL分别补齐；实际写入暴露验签后Prisma5秒默认超时，已设有界30秒且显式调用超时优先，最新原生恢复仍进行。恢复授权补齐非public schema受限DML／sequence和精确staging，未放宽生产新备份认证；旧schema没有seal仅显式历史兼容允许。

原生补记：完整147表加密备份／restore、schema与全部行／序列、余额11.23／原密码／money和auth seals、业务DDL与迁移写拒绝及恢复后篡改拒绝通过（`security-linux-lab/full-restore86.log`）。这只证明本机Alpine PostgreSQL17.12完整库／加密归档分项，不等于真实OSS／整机灾备。新增Incus跨版本数据库风险：7.6迁移后旧7.0.1不能打开新schema，不能只换回旧binary。已补精确版本回执，跨版本保留验证后的新binary自动前进重试，同版本只停止精确daemon后回退；不恢复旧DB覆盖新stop/delete。原生实际运行容器验证中。另修复原生工作流仍残留旧namespace hash导致真实新artifact被拒绝，模块hash与构建源同步。

随后真实旧迁移／CRLF历史／金额原值保持、拒绝较新备份／PG大版本／schema漂移／目标变化／未知迁移checksum全部通过（`security-linux-lab/backup-compat89.log`）；双前端生产dist在实际CSP header下Chrome三语登录／主题样式正常且inline脚本被拒绝（`security-repair-csp-final99.log`）。抽奖真实传输fixture补密文config，实际正常／私网／DNS变化／redirect／15秒超时和socket取消全部过（`security-repair-lottery-final90.log`）。Incus本机原生先失败于未挂cgroup，补本机挂载后首次建池卡住；真实goroutine显示CLI读未关闭stdin中的YAML，已精确给原生脚本stdin EOF，不改产品功能或资源守卫。

Incus进一步实证：旧7.0.1→7.6启动故障后的前进重试通过（`incus-reload106.log`）；正确cgroup启动基线再次实际升级后，原UUID／PID／Running／boot／磁盘marker保持，真实sysinfo134217728通过（`incus-success143.log`）。先前sysinfo探针反复被Go异步信号打断只发生TCG慢速模拟器，专用probe明确asyncpreemptoff且真实syscall仍执行；产品未改用户Go环境。旧实例继承未挂cgroup启动的采样基线另列失败，不称已自动修旧启动。原生测试新版null internal/ready响应、普通API null拒绝、同版／跨版版本别名和rollbackcopy守卫通过（`go-final138.log`）。同版本实际故障回退及新版首次重装/停启仍继续，双架构完整包旧worker验收未执行；新systemd隔离VM正在准备，生产未操作。

同版本实际失败回退已恢复原守护进程／guest；完整演练120秒不足，保持产品单次deadline不变并将演练总上限240秒（含失败→回退→再升）。原回执自然续接通过（`same-retry149.log`），新测试binary再次幂等通过（`forward155.log`），两次sysinfo134217728。早期删除接口文件注入被已started OpenRC网络标记绕过，未当通过，改精确start_pre一次失败并恢复原服务脚本。预安装新增只读DB/Node安全preflight，在root helper／unit替换前拒绝不支持版本，保旧worker正常回退。仍待实际完整旧包首装／升级／回退与系统服务patch激活，不能因分项数量忽略。

最新认证／OAuth／正常业务／Telegram真实PG四项再次终态全过（`security-repair-pg-final158.log`），Agent全包第6轮过、最终ARM Agent与LinuxAMD／ARM编译过；安全安装／split／update三专项全过（`security-repair-install-final162.log`）。回退runtime必须复制与hash当前`server/templates`，否则其alpine-ssh模块加载缺文件；已补守卫。预安装staging中断EXIT仅清理精确本轮目录，原runtime／备份／客户保持。systemd新VM的云镜像seed最初没有读取正确文件名导致SSH无banner，修专用rock-ridge cloud-init seed／固定hostkey与新overlay，尚未实证原包worker，不能记通过。

原生Incus更新后的真实stop／start／restart全部通过，原UUID和磁盘marker保持／sysinfo正确（`guest-actions164.log`）。新的真实备份完整性演练已过同snapshot并发写、每表SQL／schema、partition／materialized view／largeobject、GCM ZIP/ZIP64往返、余额同count篡改、array下界、sequence和largeobject损坏拒绝（`integrity166.log`）；missingtable／foreigntable最终仍待日志终态，不先写全部通过。DB只读预安装preflight真实退出0（`db-preflight168.log`）。当前systemdSSH无banner改为隔离offline检查，原disk仅新建测试overlay，生产与历史磁盘保持。

完整性演练`integrity166.log`现已自然退出0，missingtable／foreign table最后两项均过；临时restore／check／verify数据库空清单、Incus测试容器精确删除并验空（`cleanup192.log`）。systemd新VM现已running且通过固定key SSH；真实公开v1.8.14包hash核对通过，原installer正在执行，仍未到候选升级/原worker终态。候选新版全量第7轮230项继续，前轮230/230只代表前冻结点；后修内容与最终自然退出分别记录。

最终第7轮230/230自然退出0（`security-repair-suite-final7.log`）；全依赖和prod最后联网audit均0（`security-repair-audit-all-final215.json`／`security-repair-audit-prod-final214.json`）。随后仅修首装恢复smoke的签名写入／真实管理员actor／hold actor兼容，相关backup专项复验，不能据此说真实整个恢复worker通过。原公开包systemd安装仍在PG16依赖阶段；本地候选夹具保持旧依赖与签名组件，只验证升级兼容，不是最终签名发行包且不可发布。已完成Alpine原生VM与FTPS进程结束，仍保systemd单VM和精确测试文件。

首轮兼容窗口补修：已降权但新backend未完成auth baseline时，旧root worker重试仅映射经完整hash／权限核验的新版migration runtime；有auth baseline才启用完整安全资料bridge。不扩大业务DDL权、不提前信任未验签旧bearer。修复已对应守卫（`security-repair-final229-guards.log`），真实旧worker仍待本机原包完成安装。Node前置安全patch要求22.23.5／24.22.3，接口存在本身不能证明补丁。新发布仍禁止；新版签名CI与真实双完整包首装／六旧worker必须完成后才能进入发行。

进一步精修：OAuth TTL使用本次current session.role；新版保留配置助手写密文时bridge认证并保持原envelope，不双重加密，真实PG正常业务`security-repair-auth-final254.log`过。HBA临时文件独立mkstemp支持中断重试。真实Nginx语法／reload／加固幂等、票据请求不落访问日志、精确测试站清理全部通过（`security-systemd-lab140/nginx258.log`）。原公开包安装仍在tar／助手逐项提取，current fixture依赖／新generated client已准备；真正签名发行／全部旧worker场景继续未完成。未commit/push/Release/生产写入。

实际Ubuntu系统库存`inventory275.log`过，运行kernel与发行版revision、PG16.16／Node24.22.3区分保留；patchplanner补已安装systemd/OpenSSL/LXC/LVM/QEMU依赖显式allowlist、APT架构和依赖annotation、dpkg严格升级排序。仍禁止新增包／删除／大版本；真实`--apply`测试在执行，安装后的activation待确认，不能只看库存宣布系统已修。新repo策略/预算及patch持久state继续审查。首装恢复smoke还补当前管理员／恢复hold actor与正常签名写，相关guard过，实际root恢复worker完整流程仍未验。

仍需完整旧包升级／回退、Incus实际热换保客户、最终静态CSP浏览器及系统组件补丁激活验证。数据库行与其签名同时删除、整组旧签名重放、主机密钥整体失陷等能力边界继续保留，不承诺DB最高权限可防所有破坏。真实OSS／A整机失联B恢复仍是独立未完成门槛。

| 范围 | 修复目标 | 当前状态 |
|---|---|---|
| S01／S02／S03 | 外部拒绝摘要；认证资料防DB伪造、恢复码严格认证和一次性消费 | 已实施；隔离真实PG认证、OAuth、正常业务及资金最新回归通过，147表加密恢复/原密码与签名/篡改拒绝通过；原worker整体迁移和真实OSS仍待 |
| S04 | 四协议实际连接期DNS、重定向及数据通道SSRF门禁 | 已实施；最终DNS拒私网无凭据、真实S3签名流CRUD、FTPS控制/数据TLS与错误证书、SFTP真传/坏hostkey均过，WebDAV流/XML/拒redirect过；均为本机传输夹具，生产存储未验 |
| S05 | 终端HTTP／WS／重连及旧host test共用服务器pin | 已实施；假TLS0POST、原终端回归过，旧缺pin原受信SSH+TLS后补齐/错误旧pin拒绝/排队stop不互等真实PG425过、Linux固定探针413过；完整最终签名包/宿主实机仍待 |
| S06 | OAuth授权码／刷新原子消费及锁内当前权限 | 已实施；真实PG并发码／刷新各一次、封禁／禁用client／撤销grant拒绝、复合upsert／select关联／aggregate篡改拒绝及app级联清理全过；恢复待 |
| S07 | 敏感配置／通知凭据统一严格加密、旧资料安全迁移 | 已实施；真实PG迁移/正常配置/通知/邮箱并发、抽奖专表、SMTP真TLS/错误证书/明文AUTH0、TG业务回归及147表恢复通过；外部TG及真实OSS另验 |
| S08／S09 | SFTP host身份、FTP安全传输及控制字符拒绝 | SFTP固定hostkey、FTPS证书验证与控制字符门禁；真实SFTP/FTPS控制及数据上传、流下载、删除、错误服务器身份拒绝通过；旧不安全存储配置需管理员提供可验证身份/安全服务 |
| S10 | 日志字段、URL票据、代理／错误输出完整脱敏 | 应用/数据库审计/通知/更新chunk脱敏与Nginx实际语法、reload、票据URL不记录、幂等通过；原worker自身旧日志及生产日志ACL/旁路未全部验证 |
| S11 | DB业务／迁移角色分离、权限／网络核验、备份恢复兼容 | 实际低权限dump、root迁移restore、147表加密恢复/DDL与迁移写拒绝通过；业务DML/root私密角色/SCRAM/HBA持续保持。原worker任务2实际246迁移后封存与回退均在TCG超时failed，未降权；同提交完整root恢复worker/双架构回退与真实OSS待 |
| R12 | 有界流／响应／解析、连接测试与全局并发预算 | 真流与XML预算/远端成功后上传结束、取消请求后handler退出前继续占用预算、429后恢复通过；S3/WebDAV/SFTP/FTPS本机流CRUD已验，不等于任意32GiB满额文件实传 |
| R13 | Agent生产HTTPS和升级真实性、防重放与origin限制 | 已实施HTTPS、同origin／无redirect、nonce绑定全部响应动作HMAC；增加固定独立发布公钥Ed25519包签名（版本／架构／真实二进制hash），Go正确／坏key／篡改／版本架构及正常替换与重启中断通过；发布链／真实旧Agent升级待 |
| R14 | CSP／高权限access时间／Cookie／HTTP公网边界 | 管理员15min/用户1h、主题外置/拒inline/生产拒共享Cookie已实施；双端build、Chrome生产CSP三语登录主题/inline拒绝通过，实际Nginx配置通过；生产入口未部署 |
| R15 | Action固定SHA、发布最小权限及下载来源验证 | 已固定外部Action真实SHA／发布job最小权限；下载链完整复审待 |
| E01／E02 | Incus安全基线与原功能补丁、AgentGo／嵌入module升级 | 双架构编译/WindowsAgent全包6轮、Incus7.0.1→7.6保UUID/PID/boot/磁盘/sysinfo、跨版故障前进及同版回退再升、停启重启实证过；Go公告适用性已核。ARM实际daemonreload/正式签名payload/原Agent升级仍待 |
| E03／E04 | 配套程序补丁策略／新旧安装与自查，已有客户与管理员配置保护 | 实施中：系统有界库存／待更新／运行kernel／未公开OpenSSL条件持久巡查，Alpine Agent限定签名同branch安全leaf补丁自动重试且不影响可售；内核／Incus／DB／服务维护不擅重启；Node首装安全patch检查；完整原生／升级待 |
| E05 | 全锁图公告更新与不适用入口核对、UI／邮件／支付回归 | 全图/prod联网audit0；新锁图双前端build、CSP浏览器、邮件/通知/支付及147表GCM恢复过；完整新包/root恢复worker/真实OSS仍待 |

最终须保留本机攻击对照拒绝、真实PG并发和恢复、对应类型／守卫／双端build／Go及可执行原生验证。系统未知版本和未发布补丁继续明确边界；本机源码通过不等于生产或完整OSS灾备已经完成。

2026-11-22补充实证：最终双前端build／dist边界、Node24.22.3 ARM64认证正常业务、真实PG资金全部流程及加密dump→restore通过；Linux低权限runtime导出／root迁移role恢复和回读／DDL拒绝通过。全量第二轮225/227、两项旧CSP/迁移断言修正专项通过；第三轮最新227全量进行，尚未写全过。AgentWindows全包测试发现历史Linux Statfs未按平台隔离，已按Linux／其它平台拆文件，不猜其它平台磁盘；新全量Go仍待终态。两临时VM只在本机、身份独立记录，生产未改。

复审补记：认证代理原先将复合unique直接传findMany，且关联字段可能提前裁掉签名事实；已修准确选择、批量写锁定原ID集合、保留CAS和最终投影。禁用配置／验证码／公钥／TG绑定防DB伪造一并覆盖。数据库迁移凭据不得传业务OS用户子进程（同UID可读/proc环境），已改root执行且严格核固定私密文件及目标。全部新增正常业务路径继续实测，不能只根据守卫数量判断安全完成。
