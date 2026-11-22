# 两轮安全审计统一修复台账

基准：`a5251f0cab9c7fdaf861f36d2c7563f838984d33`；2026-11-22 owner授权全部源码修复、依赖更新、代码审视与精修。原[安全报告](security-audit-2026-11-22.md)及[公告明细](security-advisories-2026-11-22.md)保留审计时事实；此台账记录后来实现与验证，未完成项不写通过。生产／正式发行暂不执行。

## 续接实施状态（2026-11-22，尚未完成）

E03/E04新回执：Agent叶子补丁checked后每5min最多5sec读取host PIDnamespace可执行旧映射，客户namespace/共享memfd不采、路径/argv不回传，256host/1MiB每maps预算；旧code报activation-required、不完整报verification-pending，service/客户不操作、销售ready不依赖它。Linux759/766真正proc fixture、双编译/vet760/764/Windows762与backendtype758/build765/receipt765全0准备保存。仍缺全配套宿主patch/服务及kernel自动激活完整策略，未称E03/E04闭环。最终230第8全量228/230进行，原完整包第九45065735752双构建/Agentready成功首装/升级待，继续终态；不正式发行/生产。

较新第八45063248456全终态failure/六旧worker成功，types/functions先于table导致fixed comment归一旧定位失效，已88a7精确改session紧邻block，第九45065735752同source在途。新的patch计划重复target拒绝/APT拒weak/unauth override，原生LinuxGo+10rootplanner749、安全755/更新753均0；当前保存待，完整E03/E04全宿主自动patch/服务kernel激活仍未完成。全量final8执行中50+，最终包/root恢复/真实OSS继续，未正式发行/生产写入。

最新第八45063248456failure已全部终态，六旧worker全部成功；首装745/750唯一schema差异仍在，完整平台有enum/functions先于table，归一定位首table失效。改精确session前导紧邻的public comment，不改SQL/body，types-first专项/真实导出749/backup749/type749/build749自然0；新同source完整包仍需跑，不称已恢复。E03/E04复审补Go patch重复/conflicting版本拒绝、APT拒弱源/allowunauth，真实LinuxGo+10项rootplanner749过、原库存/cache权限保持，完整自动patch/activation继续缺。230最终8轮仍执行，旧31bCI最后已27成功/3失败全日志读后700/713/716本机修0，最新CI待，正式发行/生产/实际OSS仍未完。

最新0b17fd1b已推，复审stage迁移child环境也设JITI_FS_CACHE=false防installed release内再生成代码cache，backup731/types731/build731自然0准备保存。第八45063248456（537source）双包/双Incus已过，候选Agent queued、首装/rootbackup完整待；旧31b CI45061369559余137327818869仍在途与3已读失败保持（700/713/716本机修），继续跟终态。E03/E04仍只有inventory/leaf安全patch/独立激活核验，完整全宿主服务及kernel策略未闭环，不谎称全修。正式发行/生产/完整OSS灾备保持未完成。

最新复审补同owner-comment比较至preview/final restore的原始schema文件，两条路径保持同规则与SQLbody完整；初装密码传递去envargv，仅子shell导出给Python且peer psql仅固定PATH，真实PG721两次/错密码拒绝0。backup719/722/726、实际schema725、types724/build724/726自然0；本批保存待。第八45063248456当前537d3590原包在构建，尚未实际双首装/root恢复；新sourceCI45061369559原最后137327818869在途，adminemail/注册cleanup/deadline失败已700/713/716全修验证0但最终CI待。正式Release/生产、E03/E04全配套宿主自动patch/服务activation和实际OSS灾备仍未完成。

最新第七45061365903终态failure、六旧worker全部success，双首装完整执行到backup比对仅schema失败（双708/711）。不同owner pg_dump→no-owner restore在真实PG709仅固定public-schema初始化注释差异，实际SQL一致；新schemaFingerprint只归一化表前精确生成注释、旧signed literal可匹配两原空行形态，保完整SQL/function，真实两份导出与column type篡改拒绝715过/backup715/types715/build715自然0。全表689自然完成只有实时logs新增差异，不与同snapshot产品备份证据混同。注册删除新JWT普通user session补713真实PG全过、admin-email700过；新Agent-upgrade-deadline16缺签名夹具已补实际Ed25519复制route716仍进行。新CI剩失败继续读；完整root restore/最终包/全配套宿主patch activation与实际OSS未完，正式发行不执行。

最新第六45059247490终态failure、六旧worker全部success。首装Jiti权限修复后真实安装、唯一backend/双前端/admin/网关/Agent/原Prisma事务全部过，后backup完整性比对失败OSS_DATABASE_INTEGRITY_MISMATCH（双681/684），不是启动仍失败；新增4固定布尔诊断、不泄表/数据且保拒绝，继续查。local PG schema dump→restore686一致、全部147表689仍在途。初装setup_database原明文SQL已改SCRAM/verifier/固定身份/重复真实认证，隔离真实PG672两次幂等/错误口令拒绝过，split/panel/security/types/build688均过。当前第三PR61success/5failure/1skipped＋1在途，5日志全部读后terminal675、hostextend677、notification679、port680、Agentpublisher concurrency687真实PG/TLS/签名回归全过；最终新CI/包恢复待。

首装根因进一步实证：第五双首装657/660分类显示node_modules root0/mode0666，current/release不存在/certs和migration.url正常，排除旧空目录猜测。Prisma7 config经c12/Jiti生成磁盘代码缓存，root启动命令缺显式umask导致新缓存可写；helper补umask077和JITI_FS_CACHE=false，不复用或放宽未知cache，真实Linux原Jiti TypeScript import且fsCache=false/无磁盘cache661过、security659过。既有flat+releases安全分支另已3320f6b2推送并真实652验，不混称此首装根因。完整新同source包/原worker仍需重验；当前第五其它任务/新PR要继续跟终态，正式Release/生产暂停。

最新root权限复审：`apply_secure_ownership`旧以releases目录存在代atomic布局，平铺active仍root时跳过当前code硬化。按resolve_app_dir结果独立处理flat，保mutable缓存/certs原规则；实际Linux完整函数+真实nobody文件属主回归652自然0、空客户原服务健康650，security/update651过。这是可复现产品缺陷，首装分类第五45057633656尚未终态，不认定唯一根因。f56新CI/压力/compat保留；226及fe05普通CI与重复压力四旧轮定向取消，它们未跑完项继续由最新source补、cancelled不报绿。state/instance完整与42鉴权/完整TLSverification最新自然全过，正式Release/生产/全池系统配套闭环待。

较新源码226539f2已推；本机637完整恢复state已自然退出0（1001宿主/分页/陈旧source/Boperator/旧口令/注销/历史资金/事务回退），633整实例订单/原身份/转让换机、631replacement/624gateway、638当前鉴权42请求及完整真实TLS验证码、626改续费价/PUSH/upload全部自然0。state新增私密baseline/真实资金fixture待本轮保存；类型635过、split643过/update643仍在途。第五45057633656仍构建中（fe05c5a5诊断来源），新PR仍执行，不能阶段停工或把未终态写绿。第四双首装code明确runtime权限拒绝，root/current/migration.url正常，下一轮脱敏分类metadata进一步取证；六原worker成功已分别保留。

最新第四45055789848终态failure：双签名实包/Incus构建与候选Agent全部过、六个公开v1.8.14原worker正常/保留迁移/后半程回滚再升**全部自然success**（含rollback137313703512/529日志）；双首装helper固定码DATABASE_MIGRATION_RUNTIME_UNTRUSTED，已证current不存在/root与migration.url权限正确，仍需定位哪个server运行文件被拒绝。fe05c5a5追加仅分类uid/mode、不含文件名/资料的metadata并推送，第五45057633656无tag预览在途，正式发行暂停。

当前source PR第二轮56success/11failure/1skipped，11日志全部查：4memory openssl未装；snapshot-recovery-state旧baseline；expiry后轮继续terminal ticket无真实session/缺pin；price与auth旧JWT无session；PUSH与backup删除验证/verification旧plaintext channel。已有本机626价格/PUSH/upload全部终态0、632terminal实际单实例3/账户5pending和可再用mTLS连接过、638auth42请求与完整真实TLS验证码全过、633整个实例/账务/转让/换机恢复终态0、624gateway与631replacement过；state637千宿主全流程仍进行，historyDockerrestore待。临时fixture历史funding/charge/refund改实际记账；原流水金额/归属改写直接拒绝，零金额历史记录仍保持实际语义。新源码/夹具未全CI过，不报安全清单完成。

2026-11-23当前HEAD`2bcb2dc5`已推、PR19草稿。第三预览45049591755已failure全部job日志读取：双首装DB角色准备后helper exit1尚未定位，新增固定stage/路径/环境/CLI分类与metadata，不能将空current推断当根因实证；六旧worker实际生产检查Agent404，回退成功，新预览补同source signed Agent本地输入并保正常验签。首轮PR50success/17failure/1skipped的17日志已读，递归与HTTP/明文旧fixture、history缺依赖/recovery缺baseline、模块TLS超时分别修；未全复验不称全部闭环。

本轮新增自然终态证据：认证proxy固定原transaction/独立override避免向底层写覆盖后的栈递归，真实PG559 Agent/snapshot/auth、batch/hosting600、expiry/finance592、auth/OAuth590、真实TLS销毁576全过；真实进程提升605冷mTLS/坏pin/三90秒timeout/无晚写/单DB连接自然过。三types+6相关guard609共9/9、最新security618、backendbuild614、WindowsGo固定binary616过。Go模块固定zip不变、fetch最大3次30秒、32MiB/64KiB预算；TLS cert/404/超预算不重试，4Python专项过、固定script SHA同步`025e7a6456f97e4b28fad8d2d2b437cc177452001e65248345158f914f07c4a3`，新双daemon实际构建/源hash待CI。原生Agent测试HTTPS/合成CA/response nonceHMAC已补，真实原生待新CI。

恢复state已补私密独立baseline和Boperator money/auth签名，历史资金输入改真实记账；首次余额直改/批量ledger/退款归属变更由安全层拒绝，旧fixture适配还在验证。state/instance完整、history真实Docker恢复、双首装/六旧worker/root恢复worker及E03/E04全部配套宿主自动patch/激活继续未完成。Linux私有mount604只证明protected runtime到缺迁移凭据拒绝，原服务606健康；空current猜测未复现，保持诊断。真实OSS/A整机失联B恢复范围独立保留，无正式发行/生产操作。

本轮已修产品源码及锁图，准备阶段提交推送并运行无tag发行预览；尚未正式发行／部署生产。以下逐次补记与表格记录较新验证事实，早期过程不代最新验收。

当前已保存源码`aec5f0f8d10d80454511ebd54a2ccae9d2bfb2e8`并核origin同分支相同；无tag发行预览45045980526已启动、未终态。187文件不含本机logs/凭据/隔离库或无关taste目录，staged私有凭据检查通过；分支保存不代表全部问题已验收或正式发行。

预览45045980526已自然failure：双构建/双Incus/Agent准备过，原生230/230和双实际签名包/3461文件校验过；双首装在run_migrations失败（对readonly ENV_FILE临时赋值），六原worker在新backup installer失败exit64（旧PATH chown wrapper拒绝root retained runtime目录）。均已读每个固定job失败日志并定位源码：改env子进程传路径、不重赋readonly；保留runtime用/usr/bin/chown，不放宽原wrapper参数。新增真实Bash readonly回归、相关守卫480/system481过，split旧断言更新复验。没有重跑旧输入或正式Release；修复阶段后再新预览完整验。原本机任务2failed/迁移246保留，旧目录原helper封存复原后旧service已启动，17:05自然到期巡查执行；fixture只加DB连接30秒改善TCG预算，不能作为原版零故障证据。

第二轮源码82238c8d预览45047726936已failure，双包/双Incus/Agent准备和230全量过，双首装已完成迁移后被Nodepreflight拒绝，六升级/回退启动同样失败。完整读取8个失败job：harden-database子进程继承service的NODE_OPTIONS回退预加载，`node -e`没有app入口却进入shim的pg定位而报错，被错误归类为版本未补丁。已把版本probe精确清环境PATH，无NODE_OPTIONS/注入，真实PG preflight在父级必报错preload下通过（dbpreflight525）；原补丁版本要求保持。诊断grep追加固定DB/auth/finance分类避免遗漏启动根因。不能把两轮双构建过写成首装/升级通过，修后第三轮继续。

系统激活精修：新的--verify-activation只受root维护锁读取，全部hostPIDnamespace/可执行文件支持映射/256进程/5s预算确认补丁版本，无客户进程/路径/环境。准备阶段便持久待激活以覆盖中断，失败不丢计划；忽略正常/dev/zero、SYSV、memfd/JIT，旧library真正可执行映射仍拒。实际空客户VM重启后原10系统包已加载、无旧代码/重启待办，生成boot绑定回执（activation527）。新Linux测试拦变量覆盖并修，libraries529九项全过；已完成回执二次核验/定时刷新持久补修，activation536仍核终态，最新planner537过。此项不等于全部宿主自动patch/内核/真实OSS已闭环。

activation536现自然退出0：最新完整映射扫描/同10包boot回执保留、再次核验/库存刷新全过；libraries538最新10项Linuxroot全过。已记录中途误判共享内存和变量覆盖、空字段/完成状态遗漏并精修，不抹失败日志。Nodepreflight与系统/升级专项521/531/532/537过，下一第三轮同源码完整包继续。

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
