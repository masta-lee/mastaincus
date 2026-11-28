# 2026-11-27 安全验收当前进度

2026-11-29 接续：bc07782e 已保存推送两分支，30 项源码 CI 和具名预览的 17 项必需任务通过；双包独审尚待，不作为正式发行。后续恢复进程隔离修正、原函数七场景守卫、真实客户端 /proc smoke 与 Debian 原生空白修复已完成对应本机验证，最终 server build 与安全修复守卫通过，Linux /proc 和完整系统事务继续验收。E04 两架构 setup/base 与原 GRUB 启动通过，后续 AMD 包计划拒绝、ARM 下载期限失败保留，补齐原生私有输出与实际拒绝行后继续定位。S11/E03/E04 仍未闭环。

B1 R15 原 SSH、cloud-final 和完整资格通过（256.177 秒），随后新观察器返回 B1_ORIGINAL_UNIT_FACTS_INVALID；原运行 probe 与 3116 未读。QEMU 16556 正常关机、exit0、无强制清理、端口释放，actor 与日志排空通过，原主异常保留。现盘 7,533,297,664 字节、SHA256 80001f0ef43dca4f548f9b37db1fb5449ecef6c6386da2b2d73f8daecf7f50d7；下一步仅核实际 systemctl 输出并修入口，不以反复开机代替诊断。

2026-11-28 10:28 当前结果：原20项安全清单仍为17项源码与对应验证、S11/E03/E04三项未闭环。当前源码31b10f94的主CI46084175047全部30项成功，完整预览46084236332的17项必需任务全部成功，Release预期跳过。两架构各69个续接、25个文件操作、7个升级控制无跳过，双首装及10个原worker升级／回滚通过；实际AMD64／ARM64双包独审自然0，321份源码、原签名和完整归档均通过。根已核两报告SHA；证据为logs/mastaincus-preview-31b10f94-artifacts/dual-audit-terminal-success.json，不等同生产热更新或正式发行。

PG R15已完成原两角色身份／完整就绪，初次8秒start查询超时后未重复start、按实际原native进程全核后自动exact continue；随后真实source重启的单次fixture调用又在8秒查询超时退出。native controls／worker22仍0、finalPlan未创建，实际已耗source10／target8，原两流和最终保护／收口保留。R16只补原<=300秒内观察已提交原unit并全核，保留原8秒timeout及30／8／20、4／3／72h，不改配置或重复启动。

B1 R3未通过原420就绪，正常关机、未进入120 probe或读取3116。AMD内核R3在265.887秒通过原认证，后续helper APK安装后触发boot／modules／identity／fstab严格比较；当前缺after组与完整shutdown异常，不能猜变化或记正常guest关机。R4先补原保护下的真实变化／退出和只读postfailure诊断，ARM未启动。完整Debian13／glibc2.41上游系统事务仍待，PG固定caller fixture不替代。当前源码和生产均未因此直接改动。

B1 R4新增只读启动任务／依赖／条件诊断，8项实际函数控制通过，根及独立复审通过；原classifier／资格／恢复流程保持，原3116仍未读取。累计清理仅经完整核对的22份ZIP重复外层及4份原正式包下载副本，共5696224306字节；原正式包／盘／身份／签名和失败证据保持。

下方为逐轮历史记录，旧“正在准备／待审”不代表当前状态。整体安全、恢复与最终部署仍未完成。

- 内核：固定 r11 已实际执行，但在 `guard-package-inventory` 被 `HARDENING_KERNEL_PACKAGE_INVENTORY_UNKNOWN` 拒绝；发生在锁、续接状态、APK 安装及 GRUB 写入之前。随后固定只读取证确认 `/sbin/apk info -v` 实际 exit 0，stdout 的 206 条包记录全部有效，stderr 的两行官方仓库缓存 `unexpected end of file` 警告被原 command 拼进包清单，导致误拒。包数据库与三项原状态前后相同；原 H 已正常关机，私有双流及新后停完整锚保留。正在精修通用读取与受信索引处理，不改产品 8／20 秒、忽略无效包行或清原状态。
- PostgreSQL：R10 后停完整读取自然通过，两盘原身份及 seed／client key 保持，历史与当前磁盘哈希分列。独立 B／Windows 复核也自然通过：原 2410 条日志加 204 条合法巡检记录，完整旧 SQL、账目及其他数据库仍投影回原 `9de03503…`。这不证明 R10 当时丢失的次要保护异常原因。新 R11 的 19 项窄控制和原生 preflight 已通过，受限执行已开始；整体测试范围明确为已耗 3 次加后续必需 3 次，SSH 观察窗为 600 秒，原同 boot 1800 秒、72 小时、22 次 worker 调用及产品限制保持。先读取真实安装状态，尚未完成 PG 矩阵。
- 备份恢复：单独修改本机 QEMU 的 `q35,smm=off` 后，对照实际进入 Linux，并在原 420／120 秒门槛内通过原 SSH pin／认证、Debian 13、glibc 2.41、NoCloud 完成状态及原 seed 完整哈希。对照随后正常关机，exit 0、原句柄与端口释放、无强制清理，原 backing 盘／key／seed 保持。此为固件问题的对照结果，不能代替独立无 backing 磁盘上的最终首装和原 3116 备份恢复；该续接正在准备。

最新 GitHub 主 CI、SSH 安全及完整双架构预览终态已再次只读确认成功。当前产品源码仍为 287，未因上述测试工具或台账改动重复构建；最终主控热更新和新正式版均未执行。

2026-11-28 01:30 接续状态：下方阶段记录保留，本段说明最新实际结果，整体安全／恢复验收仍未完成。

- 内核：原 H 同盘诊断已实际确认 root/root、0777、单链接的 `vmlinuz → /boot/vmlinuz-virt`；默认类型读取拒绝，显式 `linux-virt` 通过 1154 条清单。原状态目录只有 failure／phase／空锁三项，完整身份及哈希已核。五处类型参数修复和仅此 H 的精确续接代码已完成；最后补齐超时私有输出留存、部分写回执与原动态预算，相关控制均通过。准备耗时使该 3600 秒窗口只余 1353 秒，低于原 1380 秒开始门槛，未执行 setup。按原固定协议正常关机、原 PID 与端口释放均已实际确认；下一具名窗口仅窄更新认证的 owner／boot 数据和对应来源哈希，不重做资格或清状态。原失败与全部证据保留，候选激活和两类回滚仍待。
- PostgreSQL：R8 新有界启动器实际采集／清理成功，但原 B 保护在启动 PG 客机前拒绝，未消耗第三次 boot，22 次 worker 调用仍为零。只读完整差异已确认：原 2410 条日志新增 188 条合法巡检记录，原边界超出最后 128 项盲搜；旧 SQL、旧行、其他表／账目与身份均严格投影回原 `9de03503…`。R9 未执行草稿仅绑定原 32 条前缀，当前正在补绑定已经认证的 R2／188 条前缀；原类型、128／512 限额、基线和数据库不改。实际原依赖准备的 3398 原因仍待同盘取证，不能把本次日志定位说成完整 PG 通过。
- 备份恢复：独立 Debian13 B1 已完成一次准备及原文件／身份审计，但首启动在原 420 秒 SSH 门槛超时。自有进程与端口已确认清理；原 1,002,897,920 字节磁盘及其 `2b12ac7f…` 完整哈希与 prepared 相同，原 key／seed／来源未变。串口只有 GRUB 启动标记，不能据此判断内核是否启动；实际原因正在通过固定只读 QMP／SSH 阶段分类查证。新 overlay 只作为诊断，不替代最终 standalone 无 backing 的真实首装与恢复。原 3116 备份尚未在 B1 恢复，未读其明文；后段同版首装／恢复工具的精修和控制已准备好。

以上仅为隔离测试进展；生产主控未热更新，新正式版未发行。已通过的源码／CI／签名包证据不重复运行，未完成的实际链路继续推进。

本阶段代码来源为 `287c8527ce525be5d05b33d11f54c81a3c37d0e6`，交接来源为 `a8311b2f1ea75fee904c25f18580711b48e83212`，均已分批保存到公开仓库 `masta-lee/mastaincus`。原正式 v1.8.14 与 Agent v1.0.16 保持原资产、签名及身份。本阶段未正式发行或更新生产。

2026-11-28 接续：phase①的最终 r4 执行来源已经根审，验证 manifest 为 `86fd526573fc95217ae2ecd414c7a96c17b7a720217d4e78e9c9e523e175a13a`，计划为 `73aa963057cd081b956091490085fc9268da2a0877c4a029f0cd68406c725451`。两份原生 plan、八项预算边界和八项真实生成 Bash 语法／完整 helper 字节控制自然 0。r3 的 String.replace 字符串展开会改变 helper 内的特殊替换序列；r4 仅改为 replacement callback，完整反向字节比较与固定来源核验通过，旧失败保留。原 setup 执行预算 1650 秒、总预约 2490 秒及产品 8／20 秒限制保持，parent／VM／policy／receipt／owner 共用新具名 3600 秒观察窗。原 H 盘 AMD 已实际启动，尚未取得 setup／GRUB 成功结果；原 D 盘 ARM 接续尚未执行。三项后续维护阶段仍必须完成：pre-barrier 回滚、候选真实启动／激活、barrier 后真实启动原 release 再回滚。生产自动许可继续关闭。

后续原系统资格已完成：AMD H／ARM D 两原测试盘的只读启动核验均自然退出 0，root 分别核完整结果与终态。AMD206／ARM203条包记录、原 node／SSH pin、Alpine3.24.3／linux-virt6.18.58-r0、原 boot 布局、全部上传源码、无维护／控制器标记及正常关机／端口释放均通过。旧 prepared／started／failure／serial 保持，正常 OS journal 引起的 disk 变化单列，未重做 prepare 或执行 APK／GRUB。原系统资格不代替候选内核激活和回滚。

PG R7 后续实际结果：同原两盘／seed 的 virtio-SCSI 启动已读取并应用 cloud-init，原 SSH pin、两独立 machine／boot 身份均通过；随后 source 软件准备自然失败 `PG3398_GUEST_PREPARATION_FAILED`。两原 QEMU 通过原句柄停止，端口释放、cleanup errors 为零，原盘和失败证据保留；finalPlanCreated=false，原22调用仍为0。当前正查具体 bootstrap 失败与部分包／intent 状态，不能将启动突破当完整 PG 通过。每台已实际启动两次；后续原流程另需 bootstrap 启动及两次重启，须明确新的有限整体预算并保留旧4次 scope，不漏算失败启动或重做原 prepared。

新的总 5 范围已经按规格通过根审：已耗 2 次加原后续必需 3 次，原每 plan 4／3 attempts／72 小时／22 calls 保持；具体可执行 freeze 尚未通过，尚无新诊断 boot。下一步在同一 boot 先取原失败日志及 partial 状态，再冻结精准续接配方，避免额外诊断重启。取证 helper 正精修为运行中共同 deadline／两流 1 MiB 上限并保留私有原始错误，不把通用 3398 码推测成某个安装根因。详细历史和实际后停锚见[PG 接续](security-pg-native-resume-2026-11-27.md)。

## 已完成的源码、CI 和实际安装包

第七批修复固定 kernel metadata 三路径、原备份／重入／回退及旧 journal 兼容、根目录和 boot 峰值空间、固定模块 128 KiB 传输与完整读取。相应 Linux 守卫、类型／构建及原失败证据见[内核验收](security-host-kernel-validation-2026-11-27.md)。

本批[主 CI](https://github.com/masta-lee/mastaincus/actions/runs/45990216078)的 30 项、[SSH 安全](https://github.com/masta-lee/mastaincus/actions/runs/45990216229)的 9 项及[完整发行预览](https://github.com/masta-lee/mastaincus/actions/runs/45990416441)的 17 项必需任务全部成功，两个实际预览包完整独核通过。Release 预期 skipped，不是正式发布。

另外，分支构建的[命名测试包](https://github.com/masta-lee/mastaincus/actions/runs/45999861137) `v1.8.14-test.a8311b2` 已完成 17 项必需任务和实际双包独核。此提交只比 287 多五份文档，315 份直接复制源码与六份网关副本的 Git blob 保持。VERSION 的 gitTag 元数据为该精确测试版号，实际构建来自源码分支；没有创建发行 tag 或发布 Release。

| 架构 | 实际 tar 字节 | 实际 tar SHA256 |
|---|---:|---|
| AMD64 | 221331179 | 40f454470b290fe6e6cec5edf6dc887fd4ca43651a100463da183a133f63e6bf |
| ARM64 | 220577700 | a959391950749c55960e129c5851fff750c5d33d1be80fd7d9444aede06a0b5c |

各 ZIP 仅下载一次，复用已保存的唯一 API 元数据。下载、核心审计、测试模块排除与完整独立复核均自然退出 0；原 Ed25519 和四类反控、各 321 份源码完整字节、root 属主／权限、全部链接／祖先、ZIP CRC、gzip 结束和双零尾块通过。八个网关 ELF 架构头独立核验，编译后 Vue／TS 由完整签名包认证。证据见 `logs/mastaincus-named-a8311b2f-artifacts/AUDIT_SUMMARY.md` 与 `completion-status.json`，测试原始材料不上传。

新命名审计工具只精确派生目录／来源／运行／版本／API 摘要，以及该版号的 gitTag 判断；原签名、路径、权限、源码、CRC 和尾块保护保持，反向恢复字节等于原已验工具。首次准备器因 Windows Python 3.14 的 named／held ctime 表示不同误拒；两种 ctime 各自前后稳定，其他身份和完整 SHA 保持。r2 分别比较它们，失败源和证据保留，未改产品守卫。

## 正在完成的真实系统验收

| 项目 | 已有证据 | 尚未完成 |
|---|---|---|
| AMD64／ARM64 宿主内核 | 原 H/D 两同盘完整只读资格已通过；phase① r4 来源／两原生 plan／预算与完整生成命令均通过，原 AMD H 盘已实际启动 | 基础 GRUB 准备／重启核验尚未通过；随后两架构的候选激活和两类回滚仍待，生产自动许可仍未放行 |
| PostgreSQL 双独立测试机 | 可信 ROM／paused loader 和实际 SCSI 媒体通过；R7同原seed的 cloud-init、新hostname、原SSH pin及两独立系统身份已通过；原盘／key／两轮失败保留 | R7 source依赖准备失败3398，正在查具体阶段及安全续接；PG／22调用尚未执行，真实总boot预算必须含已失败两次 |
| 原主控备份隔离恢复 | 原 3116 密文／完成回执与原 a241 双签名包保持；恢复工具版本修正最终 22 项纯测自然通过，原九组数据／身份／hold 保护主体保持 | 全新 Debian13 B1 首装、glibc 2.41 资格、原同版实际恢复、余额／账单／每表／序列／大对象／身份与 recovery gate 核验 |

内核 RO 原 r5 未能启动：排他 serial 写句柄阻止 QEMU 打开文件，且 runner 在 started.json 完成前按路径存在读取。r6 修为同 identity 的 read-only／share-read+write、全程禁止删除的串口交接，以及同一 held wrapper 持久回执后的 stdout ready。真实无盘无网 QEMU writer 与拒 unlink／replace 对照自然成功。随后旧 QEMU PID 被 Windows WMI 复用导致误拒，原停止回执加稳定 OS image／creation 证明的四个实际对照已通过；plan-only 硬编码“旧 PID 不存在”的标记也经 r9 修正，三项字段逐个与真实 OS 检查一致。最终 r9 沿 AMD新r2／ARM原r1窗口完成原1800秒scope内的实际只读资格并正常关机；原失败、错误输出与两份 root 资格记录分别保留。候选内核的后续动作另验，不停止其他进程或忽略未知身份。

PG R6 的两 QEMU 已通过原句柄停止并确认端口释放，失败盘和 seed 保留。离线取证确认 cidata／Joliet、原标识、公钥和产品源 hash 正确，但新配置未实际生效。QMP 只读采集已证明 SATA seed 存在；采集器误将默认空 CD 槽算成额外数据文件而拒绝，原失败保留。新独立解码自然退出 0，严格核两个原只读 inserted 后端和一个具名默认空 CD、PCI／qtree／原 raw replies、stderr 为零及原句柄收尾；不追认旧 collector 成功，也不是 guest 挂载证明。原初始与合法启动后 disk 证明分别保留；后续受审固定硬件调整不得改原 seed 或产品 worker。

## 恢复、部署与发行边界

原备份应用版本为 `1.8.14-test.a241daf`，原包为 `v1.8.14-test.a241daf`，组件签名版本为 `1.8.14`。应用与组件版本分别认证，完整提交由原签名 catalog／两 manifests 绑定。原备份只能在完全同版原包恢复，不改 manifest、去 test 后缀、重 seal 或重造旧包。

B1 从完整原包正常首装后建立该新机器自己的受信 current 布局，网络隔离确认后调用原 preview／root restore；所有金额、账目、实例记录和管理身份实际比较，保持 recoveryHeld。纯测不替代 Linux FD、原 verifier、真实恢复或宿主重连，不伪造心跳或删除 hold 来升级。新版恢复代码与后续候选升级／备份的验收另列。

Owner 本阶段已明确采用真实主控备份保存本机后的隔离模拟，不要求先配置阿里 OSS。真实 OSS 云传输、公网 A 整机失联后原宿主重连、客户公网连接保持、独立备用、千台与 72 小时目标继续单列未验收。安全事件整机信任与秘密外传边界以[事件报告](security-incident-2026-11-24.md)为准。

未完成项继续推进；对应实际验收后再通过原可信 worker 热更新主控，完成指定测试账户回归及发现问题的精修复验，最后正式发行。安装包和 CI 通过不等于已部署或全部安全／灾备完成。
