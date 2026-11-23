# 12台宿主持久不可售修复与热更新测试

2026-11-23，北京时间。Owner先授权只读取证，随后明确授权本问题源码修复后，将此前已做安全修复同批热更新主控作为测试；不正式发版。

主控实际v1.8.14／ced7c10cd17d、唯一后端健康。208台专属宿主中12台故障一致：#16、#21、#24、#26、#30～#36、#46。均管理在线、无客户实例、Agent工具/网络防护有效、AppArmor维护已完成，后续检查反复`HARDENING_JOURNAL_CONFLICT`。它们不是离线宿主。

只读逐台远端证据：旧SSH journal为version2／verified／root0600，原node ID、公钥、SSH固定指纹及架构匹配，原任务进程结束。旧boot/template变化符合已完成维护之后的系统/程序更新；唯一baseline差异为`/etc/ssh/sshd_config`内容，属主/模式保持，账户、密码文件、SSH host-key与其它基线文件一致。当前SSH配置有效／监听进程加载当前代码。新HOST_HARDENING_SCRIPT以allowUpdate=false在全部12台真实运行通过，SSH补丁和AppArmor均确认，hostSshUpdated=false，没有宿主写入／重启／主控状态修改。

根因：已完成SSH补丁任务把当时配置摘要当永久不变量，后续合法SSH配置变化仍被逐字节旧快照拒绝。主控每6小时再次检查同样拒绝，维护虽完成也无法取得可售回执。

修复：只对原identity验证的completed verified journal，在当前patched listener／固定标准service／sshd语法有效且主配置root普通单链接、原mode/owner保持时复核主配置变化。账户、密码、host-key、其它文件与未完成/失败journal仍严格拒绝变化；只读复核不改远端journal。检查前后再次比较完整当前基线，不允许扫描期间变更。明确更新路径若接纳已完成主配置变化，先保旧terminal journal再写新baseline。

主控保存一次journalPolicyRevision调度标记：修复后旧JOURNAL_CONFLICT立即进入完整检查，不等旧6小时；标记只改变调度，不能放行身份/权限/实际防护核验。库存仍要求完整finished/verified/当前identity有效，不能手工标绿。

验证：Python8项对应守卫、类型/后端build，真实PG自动加固队列→库存/公开目录/管理员→原锁分配器双架构通过；12台只读新探针全部通过。最终整批231守卫／双端构建／signed candidate包及旧升级验证仍在进行，热更新尚未执行。

本次热更新前置发现主控Node22.23.4／PG16.15低于已修安全迁移所需22.23.5／16.16。保原大版本与官方签名源，准备补丁、原代码/数据库/管理身份备份与回退；不以跳过迁移检查修升级。主控还有4台运行客户，无在途实例/恢复/上传/更新任务；热更新与PG补丁不操作客户Incus实例。首次seal迁移会退休旧refresh/PAT/OAuth等会话，需重新登录签发；原余额/账单/已付账期核对保持。

Agent测试候选版为v1.0.17-security.1，使宿主能通过原版本比较/签名升级接收此前安全修复；不正式Release，实际候选部署与全池结果后续记录。剩余安全自动激活/world/真实OSS灾备未完成项沿原安全交接保留，不因本次热更新测试宣称完成。

热更新首次实测：source `fc353af0`本机231/231、同source主CI30/30、双原生/内存/SSH/Agent与完整预览`45131756357`（双首装root恢复／六原v1.8.14worker）全部通过；独立双包publisher/SHA和ARM15关键文件核过。2026-11-23约15:58北京时间执行授权热更新，精确Node22.23.5／PG16.16／libpq18.7安装加载通过，安全安装钩子因3个旧测试／恢复数据库仍归原runtime角色所有而拒绝。尚未创建迁移角色或改变业务DB，自动恢复原ced7代码、唯一后端健康，客户未停启。旧库保持；不能把回退称更新完成。

新增源码精修：原`REASSIGN OWNED`具有共享DB／tablespace转交语义，不能为过检查删旧库或改变其它库owner。改为事务内精确转交public支持的表／序列／视图／函数／类型与schema，核当前业务DB不再残留runtime owner；其他库／tablespace保持。未支持本库对象原事务拒绝并回滚。准备真实PG重复／残留／失败事务验证和新完整候选验收后继续热更新。

第二次source `f6fc3021`：本机231/231，主CI`45136874843`30/30及完整预览`45136888916`13success／Release预期skipped，全native/memory/SSH/Agent成功。新增保留旧DB实景的六旧升级及双首装/root恢复全部通过；独立dual包签名/SHA与ARM15文件核过。约16:45北京时间真实完整候选热更新成功，246迁移／384资金seal／530认证seal完整验签，角色低权限及私有迁移身份核过；其它DB归属、原12宿主身份及.env秘密保持，仅signed Agent目录更新。正常管理员口令登录、me/hosts/users/Agent manifest及双域页面/health均200，4客户原UUID/PID/config与Running保持。未正式发行。

线上自然队列恢复9/12可售、12台均自动升级Agentv1.0.17-security.1。实际并发再发现两点并从源码修：兼容待核验被全局加固队列误当未完成重启，卡在已terminal的维护上；IPv6只拿instance advisory后锁host、Agent观测拿instance row后检查host，构成实际PG死锁。新queue区分重启维护与单宿主兼容fence，所有门禁保持／仅该host等待，后续due目标继续；IPv6先按instance→host拿row锁。真实PG1404加固队列（含他机compat阻塞不饿死）／IPv6 Agent并发回归全部0、对应guards/types/backendbuild过。准备同批精确3模块热补并刷新受信root兼容runtime，不能手改DB状态假装剩余3台通过。

后续source `10927334e030bce0d530ba6bede1400de5ada468`已推。主控约17:04北京时间热补3个编译模块且逐SHA核对，root兼容runtime同步／seal完成，唯一backend健康。17:06／17:08／17:10／17:12／后续真实销售条件快照12/12全部verified/finished与可售，旧JOURNAL_CONFLICT消失；没有手动DB清状态。208台管理在线／均已自动升级signed候选Agent／加固verified，全池当前销售查询208通过。兼容回执在后台正常跟进，目标实机抽查journal verified、当前incusd、无旧代码映射；不把瞬时prepared维护说成永久故障或将其全局阻塞其它宿主。

真实客户#58～#61均Running、原PID/UUID/created/rootDisk保持。#58/#60完整config摘要变化仅Incus `volatile.last_state.ready`被daemon更新：原宿主compat journal完整配置hash与更新前相同，其余所有key不变；#59/#61全部原key一致。不能说原字节完全相同，也没有恢复volatile状态或重启客机。资金19类原余额/账单/支付/退款/价格/客户配额密码与已付期限最终比对保持，384资金seal和认证seal全库验证；观察IPv6自然同步单字段独立记录，首份与切换基线均保留。

实际主控正常admin口令登录／只读me/hosts/users/manifest及双端页面和health200；测试用户原密码登录／自己的实例200、管理users/hosts403、伪造roleJWT401通过。实际双架构Agent下载hash/ELF/publisher再核过，原身份/密钥和其它DB归属保持。自然五分钟expiry巡检17:05/17:10等success，4付费未到期客户无stop/delete测试注入；traffic/status成功且新热补后无再现PG死锁。最后109源码完整231和CI/原生仍在进行，保持不正式tag/Release/main，真实OSS等旧缺口继续保留。

观察另发现Agent empty-host维护判据：兼容fence会让主控暂不发资源客机列表，Agent误把空列表当空宿主，再次请求LXCFS维护；签名permit实际仍有客户。新增candidate同时检查permit占用（远端原精确空库存/签名门禁不变），避免持久反复待核验。测试候选Agent递增v1.0.17-security.2，等待Go／真实Linux／signed双Agent后由主控原自动升级跟进；不把已部署.1写成.2已通过。
