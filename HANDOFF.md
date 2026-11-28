# MastaIncus 当前交接

本文件保留当前可用结论、未完成项及下一步。原完整版本证据已逐字节保存至 [历史台账](docs/archive/handoffs/HANDOFF-through-2a0309c0.md)，不是删除历史或改写旧发行包。

## 仓库与版本

| 内容 | 当前事实 |
| --- | --- |
| 唯一维护仓库 | [masta-lee/mastaincus](https://github.com/masta-lee/mastaincus)，公开；main 与工作分支分批同步 |
| 原正式版 | [v1.8.14](https://github.com/masta-lee/mastaincus/releases/tag/v1.8.14)；原 tar、签名、校验及 tag 保持 |
| 原配套 Agent | [v1.0.16](https://github.com/masta-lee/mastaincus/releases/tag/agent-v1.0.16) |
| 最近已核源码 CI | 278c44f8 的 [CI](https://github.com/masta-lee/mastaincus/actions/runs/46131138206) 30 项通过 |
| 最近完整成功预览 | 278c44f8 的[双架构具名预览](https://github.com/masta-lee/mastaincus/actions/runs/46131138638) 17 项通过，含两次首装、10 个原 worker 升级／回滚；正式发布步骤按预期跳过 |
| 命名测试包 | v1.8.14-test.278c44f，AMD64 与 ARM64 实际 tar 独立核验通过，运行主控的候选仍为 ad2ca04 |
| 最新已保存产品修复 | 278c44f8 安装三个固定 root 工具时只遍历一次完整签名包。主控上的运行时门禁由 ad2ca04d 提供 |
| 已保存 CI 修复 | 47accbab：原 v1.8.14 两个固定资产下载最多 3 次、每次独立临时目录；原 SHA 保持。真实 Bash 故障控制、同提交 CI／完整预览通过；线上该轮首次下载成功，不冒称发生过真实重试 |
| 当前安装精修 | 31b10f94已推送main和工作分支。installer 3cc6304b…、guard 221a4506…；完整包认证后续接、原配置／证书保持、真实身份残留写前拒绝及失败传播。Windows完整守卫自然0（877.934秒），同提交Linux双架构各69续接／25文件操作／7升级控制通过且无跳过；未正式发布或生产部署 |
| 本批实质修复 | 库存读取 template 87f84759…；测试 8a88d4a6…，Linux 89/89、零跳过、原环境保持；已随当前31b10f94通过源码CI及完整双架构预览 |
| 本批仓库展示 | README 与 10 个文档文件统一 MastaIncus，新仓库入门/更新/发行链接、文档旧 base 路径已修，文档构建及 8 个本地入口通过 |
| 生产版本 | 主控任务 68 更新至 v1.8.14-test.ad2ca04，签名包 25,763 文件、唯一健康后端、原资金／身份／运行实例比对通过。Agent 最近登记为 security.10 |

安装、更新和匿名下载入口均使用新仓库。当前源码中旧官方地址的匹配用于识别并迁移已有旧安装；旧签名包与历史记录仍保持，不能机械替换匹配值而破坏迁移。

## 安全清单：20 项，17 项源码修复与对应验证，3 项未闭环

原清单为 S01–S11、R12–R15、E01–E05，见[审计](docs/security-audit-2026-11-22.md)和[逐项修复](docs/security-repair-2026-11-22.md)。17 项为 S01–S10、R12–R15、E01–E02、E05；这项统计指源码与已有对应验证，全部生产生效及上线验收仍需完成。

| 未闭环项 | 当前剩余 |
| --- | --- |
| S11：低权限数据库与备份恢复 | LO 按原 OID 恢复运行账户所有权的源码、守卫与双架构CI原生读写／损坏拒绝通过；双向角色继承、未知 owner/ACL 在写前拒绝。原3116同版完整恢复与独立PG22仍未完成 |
| E03：主控/网关系统补丁 | Zstandard归档审核源码、Linux原生10项和两原Ubuntu包解析通过；独立PG22及Debian13／glibc2.41的完整受认证systemd事务、真实客户端修复和后端收尾仍待，固定caller fixture不代替后者 |
| E04：宿主补丁及内核 | AMD64/ARM64 的真实 GRUB 准备、pre-barrier 回滚、候选激活、barrier 后原系统启动回滚；全部通过前不开放生产许可 |

资金链前一批的源码、真实 PG 篡改/回调/余额/购买/续费和加密备份往返证据见[资金报告](docs/financial-audit-2026-11-22.md)。未备份的较新交易不能凭空还原，主机/应用密钥整体失陷的信任边界见[安全事件](docs/security-incident-2026-11-24.md)。

## 本轮实机进展

紧急主控安全交付（2026-11-28）：任务 68 已成功。新鲜完整备份在仓库外逐文件校验，19 组账目／客户数据、208 组宿主身份和 5 台运行客户实例均完成更新前后比对。上线维护服务运行新版门禁，PostgreSQL 仍有 8 个被替换的 OpenSSL 映射。指定账户双架构实购、启停重启、Alpine 重装 Debian 13、SSH 和按月续费／重放通过，实扣合计 95.00。详见[主控交付与账户回归](docs/security-urgent-controller-update-2026-11-28.md)。

安装器分项（2026-11-28）：旧安装器为取出三个 root 工具，分别重复解压整包，B1 的 1,800 秒同版续接窗口耗尽。本次统一流式读取三个固定普通文件，分别核唯一性、大小和 shell 语法；整包路径检查仍完整消费 tar，尾部损坏会返回失败。原 a241daf 的 221,264,571 字节 AMD64 包中，三个工具与 Git 原始内容逐字节相同。Windows 完整安装守卫通过（68 个续接场景，本地跳过 1 个 Linux 链接场景；25 个文件操作、7 个升级控制），宿主安装脚本和分层部署守卫通过。实际 278c44f 双包均通过原公钥签名、归档和 321 份源码独核；AMD64 为 221422168 字节、SHA256 34762c14654aaef79ec9a3e563e45127681f11b08814e5bb4f0aee8aefd59da1；ARM64 为 220452060 字节、SHA256 3ec29f257049ec27a9b8c31aeeadb8171fc0333cc63221b8e8a3ed8e7932099f。正式发行仍为 v1.8.14，主控仍为已验证的 ad2ca04 候选。

Windows 规划器测试修正（2026-11-28）：Python 3.14 的路径 stat 和文件描述符 fstat 对同一个文件可返回不同的 ctime_ns。旧用例在 9 次中失败 4 次。修正后分别核两种原生来源前后稳定、包装后的 fd 等于同一原生 fd，继续核路径与句柄属于同一个文件；Linux 保留 ctime 跨接口比对。原单例连续 100 次通过，Windows 完整规划器 228 项退出 0，53 项 Linux 专用跳过。产品代码和线上运行状态保持。

宿主内核维护修复（2026-11-28）：ARM 原盘安装及 GRUB 配置已通过，重启前核服务时发现 Alpine 包安装的是 /etc/init.d/incusd，原维护代码固定查询 incus。现在按受保护的原生 OpenRC 文件选择 incusd 或历史 incus，拒绝不明别名与两份冲突定义。宿主本地 Incus 的实例和任务清单查询同时核对 socket 对端进程与已安装 incusd 的设备和 inode。Windows 守卫 92 项退出 0（60 项为 Linux 专用），维护计划和加固守卫均已通过，两个现有架构 CI job 已加入完整 Linux 守卫。AMD／ARM 真机的补丁激活与回滚仍需单独验收，生产许可集为空。

Debian 13 软件来源校验修复（2026-11-28）：已由旧签名候选实测定位到 snapshot_release_fields 对 Debian 官方归档公钥环的拒绝。原 .gpg 名称是 root 所有的 26 字节相对链接，指向同目录的 debian-archive-keyring.pgp。修复仅接受这个发行别名或旧版普通文件，验证目标文件的属主、权限、文件身份与打开后的内容，再把相同字节交给 gpgv。基础安装与平铺升级显式安装及核查 gpgv。独立 Debian 13 实机用 55,918 字节的正式公钥环验证三签 InRelease，7 项原生守卫无跳过，客机正常退出 0；Windows 230 项规划器退出 0，其中 54 项 Linux 专用跳过。完整安装守卫、宿主安装脚本与分层部署守卫通过。完整系统更新、重启后数据库恢复与客户端故障验收仍待新签名包实测。[旧版拒绝回执](https://github.com/masta-lee/mastaincus/actions/runs/46136722308)

独立验收还剩 S11／E03／E04。R9 已在原 B1 盘完成 Debian 13／glibc 2.41 的同启动身份核验。新安装器已实际备份、解包、创建 systemd 服务并收到数据库角色就绪回执，随后测试调用器 1,800 秒到期。原 QEMU 正常关机、退出 0、端口释放。原 3116 备份尚未进入传输或恢复。PG R23 已在两台原 Ubuntu 客机执行真实 worker，after-intent 与 after-dump 两个预期场景通过；后续历史 PostgreSQL 18 只读身份查询尚待精确核验。见[PG 实机台账](docs/security-pg-native-resume-2026-11-27.md)。AMD 宿主已实测 helper 安装后唯一变化是新建 /etc/machine-id；旧内核、启动文件、模块、fstab 和五项既有管理身份一致。Debian 13 实机已观察到默认 networkd 路径被原保护拦截，静态 IPv4 对照通过原生资格。Debian 独立 KVM 初轮在 90 分钟到期时没有任何通过身份校验的 guest 阶段回执。签名包下载与验签通过，运行时事务未取得验收结果。此次修正明确系统盘启动顺序、网卡 MAC 与 NoCloud 配置，记录固定的 Linux／cloud-init 启动阶段；8 分钟无首个回执即以具体阶段失败。详见[原运行日志](https://github.com/masta-lee/mastaincus/actions/runs/46127289729)。

- 实际双包：同一31b10f94来源，AMD64完整tar为221404915字节／c96a13d95354014562a0ea583b34f04f176cec931c4fe0632ec6c1a0a7fbd21a，ARM64为220452011字节／d5c442f76baeea4e441932dd43ba439d2ee850e87f0b620178e76072ce6e9769。两份API digest／大小、原公钥签名及4反控、321份完整源码、8个ELF及两组件21文件签名、权限／祖先／链接／完整gzip和双零尾均通过；根独立核终态和两报告SHA。仅RAM归档，C盘小证据381113字节。首轮审计器变量覆盖失败已修且保留；这不是正式发行或生产部署。
- PG R15：两原身份和就绪全核通过；首次8秒systemctl start查询超时后，初始循环按实际active状态再次完整核同进程／配置／OID，未重复start，随后执行exact continue和真实source重启。重启后的单次fixture调用再次超时便退出，22次worker与native controls均0、finalPlan未创建。完整私有两流／退出及原B最终保护保留，两原进程句柄和端口收口；实际累计source10／target8。R16仅在原300秒fixture预算内观察已提交的原unit，再全核原native进程／SQL，保留原8秒查询超时事实。
- 内核R3：AMD在实际QEMU265.887秒完成原pin认证，随后原APK helper安装成功但严格boot／modules／identity／fstab比较拒绝。原短路判定未保存after组，当前不能猜哪组变化；原finally也未保留shutdown／waitStopped具体异常，因此没有正常guest关机实证。原进程均停、端口释放，失败盘与所有原日志保留。新R4仅先补具体变化组／完整退出／收口原因及只读postfailure诊断，不放宽保护；ARM尚未执行。

- PG R14：实际读回source的start.conf为空0字节，target为auto、317字节，权限和完整SHA均与原database-proof一致。原冻结Matrix重启后立即查询，缺少对未自动启动原服务的就绪步骤；只启动本次会在下一次重启再次失败，不能用外部并发抢跑补齐。原stop自然0，原B最终保护通过，两原QEMU均exit0、句柄关闭、端口释放，原disk/seed保留；没有SQL、worker、service或配置写入。R15仅补真实重启后核原身份并有界启动原既有unit的隔离fixture步骤，继续保留API内部实际stop／产品恢复startCount=1；不把fixture就绪当完整上游系统补丁激活通过。
- 内核库存误拒：真实 APK exit 0，206 条 stdout 全部有效，两行损坏全局缓存警告被旧 command 拼入包名。新代码只让库存读取消费 stdout，两流仍受共同 4 MiB 上限，非零、无效行、超时和遗留子进程保持拒绝。Linux 89 项自然通过，294.734 秒；原后端 PID93844、PG88982、boot/包库/防火墙与上传输入保持。原始日志 SHA256 为 9b3a6de3a3679e216ef696d90639244b3491eeaaa2d0f4ada7faee8ff6715471。
- PostgreSQL R12：原身份与 intent 通过，缓存修复实际执行后在归档格式审核被拒。真实已缓存 Ubuntu16.15 server/client 为 control.tar.zst/data.tar.zst；client SHA 与原 APT 元数据一致，18/19为xz，19未执行。22 calls 为0；两原测试进程已收口，额外异常被旧工具泛化且未保留详细主因，不能猜测。后续先修产品解析与完整私有错误记录，再绑定实际已耗5次及必需3次的新有限范围；不改旧失败或产品30/8/20秒。
- Debian13 B1：原420/120资格已通过；首次正常安装在创建systemd服务阶段触发1800秒工具超时。普通完整签名包升级续接随后进入备份／提取，但原7200−230工作窗到期，broker及调用器非零，自己的QEMU被强制收口、端口释放；不能记正常关机／首装成功。原disk的FileID、seed/key/prepared保持，当前5512560640B、SHA0887871d…独立留存，原3116从未读取／上传。新入口正修精确超时绕过预留关机路径的问题，并从这份真实stop锚继续；不改历史失败、原包／身份或预算。
- 仓库文档：68d96160 的 CI 检出精简时漏保留更新来源、单后端和 README 部署契约。操作手册已纠错推送；README 已补回必要操作说明，split-deploy-config、security-config、repository-source 与部署文档守卫全部通过。d4119e62 文档站运行 46058208787 的构建/部署均成功；其他源码 CI 与预览按各自实际 headSha 继续跟进。
- LO 恢复：297889f6 的完整预览已成功；e4d75a94 双首装再次实际通过多页／空LO原OID、原生读写／删除、自动恢复续接与损坏内容拒绝，ARM PG16、AMD PG18。原主控3116备份及独立完整拒绝场景仍待，17/20闭环统计保持。
- CI旧包下载：e4d的唯一失败在下载v1.8.14前置步骤，日志为release not found，尚未进入该场景的旧worker。47accbab同提交完整预览已通过，原对应AMD迁移原子布局场景实际下载、SHA和旧worker升级均成功；有限重试的异常分支由实际Bash故障控制验证，坏SHA不重试或放行，耗尽仍失败。
- PG R13：完整20源、两角色包及数据库准备和source真实重启／原身份通过；随后原Matrix在native PG API退出／两流门禁失败，原22调用仍0。原guest两流／退出未落地，不能猜具体根因。原finally正常收口、端口释放，完整B／Windows保护通过；实际source7／target6次boot。新具名诊断先补完整私有回执，明确原8失败范围及后续source10／target9有限总范围，原Matrix4／3次attempt／72小时与产品30／8／20秒保持。
- 内核H/D：AMD原normal入口实际启动后在SSH连接失败，未执行诊断或产品动作；自有QEMU强制收口，原盘及FileID保持，不记正常停机。新r2有界握手观察与严格pre-key判断41项接口控制通过，AMD原生只读plan通过并明确旧forced stop；两架构实际四阶段仍待。程序源码87f8、原3600秒scope及产品8／20秒保持。
- B1后续：上一同盘入口SSH原pin认证成功，原120秒完整资格中的cloud-init等待子命令90秒超时，未进入repair或读取3116；原QEMU正常关机、自然0、无强制清理、端口释放与原FileID保持。已根审R3先在原420秒内核真实cloud-init状态，再执行完整120秒资格，并在动作前复核实际QEMU与540秒界限；24项实际函数控制自然0。原7200／230、worker30、同版签名包及3116隔离门保持，实际恢复结果仍待。
- 本机空间：清理18份与保留tar／sig逐成员相同的ZIP外层（3959432764字节）、4份与原正式包SHA一致的下载副本（856899050字节），以及最后4份逐成员／CRC核对一致的旧ZIP（879892492字节）。合计5696224306字节；第三批通过已核原文件句柄删除，全部原tar／sig／审计／盘／seed／key与当前输入保持。三份清单和实际结果留在logs/security-cache-cleanup-20261128-r1／r2／r3。
- Zstandard：产品680e1bb4…、测试cd192ba2…；Linux10/10、零skip、2.939秒，原client/server两包SHA与已认证Ubuntu归档一致，分别解析266/1476条真实manifest。使用已安装同架构root库的已开FD，保持64MiB窗、8/128/256MiB输出、单frame和原tar/签名审核；原B后端/PG/boot/包库/防火墙与身份前后全同。私有验收JSON SHA256 b3cf5710a45d21f1d0bb7c01316b5a61d5a44b485cef94514361b49eced2137e；这不等于22场景或生产已部署。

详细当前证据见[实机进度](docs/security-validation-progress-2026-11-27.md)、[PG接续](docs/security-pg-native-resume-2026-11-27.md)及[内核检查](docs/security-host-kernel-validation-2026-11-27.md)。原始日志、密文备份和凭据留在仓库外私有目录，不上传源码仓库。

## 接下来的顺序

1. 已保存库存修复、仓库展示和精简台账；保存 LO 源码与 README 纠错批次后，继续跟进同提交 CI/双架构完整预览和实际包。S11 原生恢复未验收，17/20 的闭环统计保持。
2. 并行完成 S11 恢复权限精修、PG22场景、B1原备份恢复及两架构内核四阶段；先备齐修复代码再开受限测试窗口，减少无必要的准备/重复验证。
3. 全部相关验证通过后，通过原可信 worker 完整热更新主控，执行指定测试账户回归和问题精修复验。
4. 验收完成后正式发新版；不先发版再验证。

本阶段 owner 已明确采用真实主控备份保存本机后的隔离模拟。真实阿里OSS传输、A整机失联后公网原宿主重连、独立备用/切回、千台/72小时与外部生产存储等未做范围继续单列，不冒充本轮模拟通过。

历史台账原文 SHA256：7c44ef5710320559ce4139e104c528f87fafd5d15148c404339ef9fdb261da67。Git历史、原稳定tag与资产均保持。
