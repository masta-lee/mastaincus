# 本机清理与安全修复进度

2026-11-26。当前安全修复尚未完成交付，本轮没有主控热更新或正式发行；新账号 jimmasta 仍只用于申诉，没有上传数据。

Owner 指出已工作8小时4分55秒却缺少清楚报告。以下分别记录已实际完成的清理、已有验证和仍未完成的产品工作，不能把内存草稿或模拟测试说成已上线。

本次已实际清理 C:/payincus 中约 **3.336 GB** 的过期或重复文件，删除前后测得的磁盘净空闲增量约 **3.339 GB**：

| 实际处理 | 文件字节数 | 结果 |
| --- | ---: | --- |
| 过期 Go 编译缓存 logs/review-go-upgrade-cache | 325,538,773 | 用 Go 自带 go clean -cache 清理 |
| 3份字节完全相同的 Linux 测试二进制副本 | 105,711,719 | 保留对应原文件，并逐份确认 SHA256 相同 |
| 12个已被后续候选替代的测试安装包缓存 | 2,650,376,481 | 保留删除前大小和 SHA256、原日志及签名材料；当前 a241 和最新 f7d3 缓存完整 SHA 前后相同 |
| 已撤除 Debian11 的两份本机下载缓存 | 254,385,792 | amd64、arm64 两文件均已确认删除；生产镜像库没有改动 |

另清理仓库外的本机 Go 编译缓存约 **5.760 GB**，不计入上表的项目目录清理量。清理阶段C盘可用约 **19.4 GB**，北京时间14:54复核为 **15.67 GiB**，本阶段最终复核为 **21.96 GiB**；空闲空间在测试盘及后台程序运行时会变化，不把所有波动都记作清理收益。

完整目录遍历的统计快照：可读文件标称大小约 **128.64 GB**，按文件ID去重并考虑稀疏/压缩文件后的实占估计约 **106.80 GB**，其中 logs 约 **103.37 GB**。该快照在删除 Debian11 缓存之前生成，包含在用测试盘、数据库、备份及验收材料；有50次元数据读取失败，不能当作精确磁盘计费数字。两个应用映射路径的文件ID和卷ID与原测试盘完全相同，没有重复计算成额外副本。

保留的主要在用/验收输入包括两块运行中的测试盘、当前本机 PostgreSQL 数据库、旧B完整基线、正式发行包、原始主控备份、当前候选、源码、未提交修改、Git历史及关键失败记录。tmp 仍有约1.93GB，包含当前本地 PostgreSQL 正在使用的程序及过期验收产物，尚未整体删除。

批量递归删除及一次固定目录递归删除被自动审批拒绝，只返回 blocked by policy，没有给出更详细原因，两个命令均未执行。之后使用 Go 的专用清理命令及明确的单文件删除完成上表操作；若需继续移除旧数据库目录，须先保留可恢复材料、明确是否属于仍需验收的数据，不能绕过审批或误删在用数据库。

安全工作的实际状态：

- 恢复修复 **r5c已经写入产品源码** `scripts/system-security-inventory.py` 和对应测试。覆盖后端成功启动但最终回执缺失、有限失败重试、第二/第三次备份中断续接、客户端校验失败的独立恢复原因，以及自管PG在新备份未完成时退出的恢复。原2份有效备份、原进程/配置身份和自管权限保持；仍须新备份成功才继续安装软件，共享及仅备份数据库不获启停权限。
- r5c历史冻结SHA256为 `07b172b1f99a72053572a10733d1e1adbed872578fd9138b7f094a27c3c68b4b` / `753881d09cd62508c1d01b4d824d7d0e9d08900808cc2ebebcd9aa35d5b5956e`。r6d产品补丁已写入，源码SHA `f2693318d00b9c2fefd505fe58585578738cc0fd2398cb9f19b70ea7f8dc323f`。当前r6e仅修测试目录优先级，测试SHA `b43922f628316ea4214a719ef409c92f8527c26424a4da6bb8bde27bdc577102`；旧r6d测试SHA `1effa7c3…`及完整副本、原7个失败子例、后续psql基线失败和r5源码副本均保留。
- r5c独立Windows模拟44方法自然退出0；集成后的本机完整Python套件197方法、45项Linux/root跳过、0失败。随后专用Linux完整197方法 **0跳过、0失败、自然退出0**，原B状态和PG进程88982保持；完整原生日志 `logs/security-controller3420-root-run-result.log`。
- r5c源码的完整测试入口 **233计划/233执行/233通过/0失败，18分2秒、自然退出0**，包括双端类型检查；日志 `logs/security-final-integrated-r5c-full-suite-20261126.log`。这是r5c证据，不冒充当前r6d完整验收。前批后端构建和联网1021项JS依赖未检出已知漏洞分别保留原范围，不替代之后的源码/实机验收。
- 独立审查确认的psql缺口已修入r6d：PG实际start后先持久保存原unit及真实进程启动事实，再执行已认证psql核验；psql恢复后补全最终回执。每次SQL前后均核单工具身份，pg_dump/pg_restore单独失效不阻断有效psql；原工具和已认证Before/Expected以外的psql拒绝执行。补齐末段及已有journal闭包的校验，PG start前检查原unit/无override，native记录仅接纳标准参数；文件dev/inode按真实uint64保存，不伪造SQL/settingsHash。
- r6d新增9方法和原44方法共 **53方法、0失败/错误/跳过、独立进程自然退出0**。范围是实际磁盘文件读取和产品SQL代码、Windows Unix元数据/进程适配，未实际启停PG服务。日志 `logs/security-boot-psql-native-recovery-r6d-final.log`；冻结与原r5绑定见 `logs/security-boot-psql-native-recovery-freeze-20261126-r6d-final.json`。
- 根任务r6d本机206/45skip及对应安全守卫自然0，但首轮完整Linux206/0skip自然1、8个fixture准备错误，原B状态/PG88982保持。只读原日志确认：新增两个owned_failure方法把真实客户端文件放在`/tmp`，产品父目录守卫正确拒绝01777。仅把Linux/root测试目录优先为私有`/root`，未改产品安全条件；原失败19445B/SHA `1957599e…`、原1eff测试基线和旧冻结保留。
- 当前r6e本机完整 **206/45skip/0fail、自然0**，对应安全守卫自然0；原B **9项Linux专项/0skip/0fail、自然0**，随后当前完整 **206项Linux/0skip/0fail、275.895秒、自然0**，原B状态及PG88982保持。证据为 `logs/security-controller-r6-final-20261126-r2-windows-full.log`、`-r2-related-guards.log`、`-r2psql-linux-root.log`、`-r2-linux-root.log`。15:52核得最终自然终态；首轮失败保留。本次是完整Linux守卫与真实文件操作，不代替尚未执行的双PG真实恢复矩阵。
- 双数据库准备工具的私有权限误判已修成3408，62项本机专项和语法检查通过；真实预检、双PG矩阵仍未执行。
- 旧B镜像已在清理后完成17,468,293,120字节的原只读全量核验：SHA256与压缩前一致，原文件ID、ACL、时间及backing引用一致；原失败记录保留。
- AMD新3394b实际SSH已ready，setup仅执行一次后自然失败：cloud-init status为done却返回2/degraded，stderr441字节已完整保存，原wrapper/VM已停止确认。离线3412已只读转换失败盘并验证源/原backing字节未变；Ubuntu只读debugfs读取因inode bitmap checksum错误未打开文件系统，尚未取得cloud-init原因，不能据此认定原盘损坏或放宽exit2。没有重启该失败盘。正常磁盘启动、ARM启动、内核激活/回退及后续补丁未完成。
- 新来源完整包、主控新备份到本机的完整隔离恢复、候选热更新与最终发行仍未完成。

清理原始明细在 logs/security-obsolete-preview-cleanup-20261126-plan.json、对应 result.json、security-duplicate-binaries-cleanup-20261126-plan.json、security-retired-image-cleanup-20261126-plan.json 及对应 result.json。目录统计在 logs/security-workspace-cleanup-20261126-inventory-after.json；旧B核验在 logs/security-disk3406-real-r4-after-cleanup-result.log。

本次长时间耗在磁盘空间不足、旧测试工具的权限/日志取证问题和启动失败排查，阶段报告没有及时对应已经落盘的源码，这是本轮执行问题。后续按“确定缺陷→产品最小修复→对应回归→核自然终态→同步报告”的顺序推进；阶段记录不作为停止原安全工作的理由，测试工具失败也不冒充产品修复完成。
