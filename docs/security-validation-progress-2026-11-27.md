# 2026-11-27 安全验收当前进度

本阶段代码来源为 `287c8527ce525be5d05b33d11f54c81a3c37d0e6`，交接来源为 `a8311b2f1ea75fee904c25f18580711b48e83212`，均已分批保存到公开仓库 `masta-lee/mastaincus`。原正式 v1.8.14 与 Agent v1.0.16 保持原资产、签名及身份。本阶段未正式发行或更新生产。

后续原系统资格已完成：AMD H／ARM D 两原测试盘的只读启动核验均自然退出 0，root 分别核完整结果与终态。AMD206／ARM203条包记录、原 node／SSH pin、Alpine3.24.3／linux-virt6.18.58-r0、原 boot 布局、全部上传源码、无维护／控制器标记及正常关机／端口释放均通过。旧 prepared／started／failure／serial 保持，正常 OS journal 引起的 disk 变化单列，未重做 prepare 或执行 APK／GRUB。原系统资格不代替候选内核激活和回滚。

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
| AMD64／ARM64 宿主内核 | 原 H/D 两同盘完整只读资格已通过；原 node／pin、206／203 包记录、6.18.58、boot／上传源码／无维护标记、正常关机和端口释放完整核对；工具 ready／实际 QEMU writer／身份守卫通过 | 候选内核激活／重启／故障回滚；新有限观察窗计划准备中，生产自动许可仍未放行 |
| PostgreSQL 双独立测试机 | 可信 BIOS／ROM、无盘无网 paused loader 自然通过；实际 Linux 6.8 启动；原 seed 与 client key 保持；QMP 已采到原只读 SATA 媒体 | R6 在原 300 秒 SSH 启动窗口自然超时，尚无 bootstrap 或 22 worker 调用；继续核 NoCloud／网络并执行维护、故障、重启、清理矩阵 |
| 原主控备份隔离恢复 | 原 3116 密文／完成回执与原 a241 双签名包保持；恢复工具版本修正最终 22 项纯测自然通过，原九组数据／身份／hold 保护主体保持 | 全新 Debian13 B1 首装、glibc 2.41 资格、原同版实际恢复、余额／账单／每表／序列／大对象／身份与 recovery gate 核验 |

内核 RO 原 r5 未能启动：排他 serial 写句柄阻止 QEMU 打开文件，且 runner 在 started.json 完成前按路径存在读取。r6 修为同 identity 的 read-only／share-read+write、全程禁止删除的串口交接，以及同一 held wrapper 持久回执后的 stdout ready。真实无盘无网 QEMU writer 与拒 unlink／replace 对照自然成功。随后旧 QEMU PID 被 Windows WMI 复用导致误拒，原停止回执加稳定 OS image／creation 证明的四个实际对照已通过；plan-only 硬编码“旧 PID 不存在”的标记也经 r9 修正，三项字段逐个与真实 OS 检查一致。最终 r9 沿 AMD新r2／ARM原r1窗口完成原1800秒scope内的实际只读资格并正常关机；原失败、错误输出与两份 root 资格记录分别保留。候选内核的后续动作另验，不停止其他进程或忽略未知身份。

PG R6 的两 QEMU 已通过原句柄停止并确认端口释放，失败盘和 seed 保留。离线取证确认 cidata／Joliet、原标识、公钥和产品源 hash 正确，但新配置未实际生效。QMP 只读采集已证明 SATA seed 存在；采集器误将默认空 CD 槽算成额外数据文件而拒绝，原失败保留。新独立解码自然退出 0，严格核两个原只读 inserted 后端和一个具名默认空 CD、PCI／qtree／原 raw replies、stderr 为零及原句柄收尾；不追认旧 collector 成功，也不是 guest 挂载证明。原初始与合法启动后 disk 证明分别保留；后续受审固定硬件调整不得改原 seed 或产品 worker。

## 恢复、部署与发行边界

原备份应用版本为 `1.8.14-test.a241daf`，原包为 `v1.8.14-test.a241daf`，组件签名版本为 `1.8.14`。应用与组件版本分别认证，完整提交由原签名 catalog／两 manifests 绑定。原备份只能在完全同版原包恢复，不改 manifest、去 test 后缀、重 seal 或重造旧包。

B1 从完整原包正常首装后建立该新机器自己的受信 current 布局，网络隔离确认后调用原 preview／root restore；所有金额、账目、实例记录和管理身份实际比较，保持 recoveryHeld。纯测不替代 Linux FD、原 verifier、真实恢复或宿主重连，不伪造心跳或删除 hold 来升级。新版恢复代码与后续候选升级／备份的验收另列。

Owner 本阶段已明确采用真实主控备份保存本机后的隔离模拟，不要求先配置阿里 OSS。真实 OSS 云传输、公网 A 整机失联后原宿主重连、客户公网连接保持、独立备用、千台与 72 小时目标继续单列未验收。安全事件整机信任与秘密外传边界以[事件报告](security-incident-2026-11-24.md)为准。

未完成项继续推进；对应实际验收后再通过原可信 worker 热更新主控，完成指定测试账户回归及发现问题的精修复验，最后正式发行。安装包和 CI 通过不等于已部署或全部安全／灾备完成。
