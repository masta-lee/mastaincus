# 2026-11-27：CI 终态与双 PostgreSQL 隔离测试接续

本记录只说明已取得的证据。双 PostgreSQL 原 worker 矩阵尚未启动完成，不能据下列预检宣布完整恢复、最终生产热更新或新版发行通过。

## GitHub Actions 失败已核对

源码 `933f79362d1e0e7296016901c67e2e946821a605` 的 [Build & Release 45949821213](https://github.com/masta-lee/mastaincus/actions/runs/45949821213) 两个 current rollback 作业失败：AMD64 `140346817504`、ARM64 `140346817559`。原失败日志的断言位于 `smoke-legacy-online-upgrade.mjs:95`，要求 root/root、0600、单链接等证据元数据。原重定向先于子 shell 的 umask，生成了 0644 文件；后续修订把重定向移至 umask 生效之后，保留原权限、身份与内容检查。

新源码 `eca80074366852a5113752989cabf4077dbf3902` 已逐 job 核对终态：

- [普通 CI 45967552390](https://github.com/masta-lee/mastaincus/actions/runs/45967552390)：30 项全部 success。
- [完整预览 45968108311](https://github.com/masta-lee/mastaincus/actions/runs/45968108311)：17 项必需作业全部 success，包含双架构构建、全新安装和原 worker 升级／回滚；Release 按预览预期 skipped。
- 原失败没有删掉或当成通过；上述成功不等于正式发布或目标主控部署。

## QEMU 与原 B 保护的真实问题

原启动把根盘 serial 放在 `-drive` 中，当前 QEMU 拒绝，第一台退出、第二台没有启动。原 prepared 两个根盘各 260177920 字节，四个 disk/seed 的初始身份与字节保持，原 prepared、密钥、失败源和日志均保留。

当前派生只将 serial 移至一个精确 `virtio-blk-pci` 根盘设备，并使用本次独占的私有 serial 日志。其余资源与原 argv 保持，14 个纯控制拒绝多盘、额外网络、额外文件设备、错误 serial、可写 seed 等情况。这不是客机启动实证。

失败后 B 的 `historicalDatabasesSha256` 变化，旧结果不能称“原 B 所有字节未变”。另发现旧快照误盯不存在的 `incudal.service`；实际后台是 `incudal-backend.service`。旧错误基线未补写成已经保护过真实后台。

新只读核验保存当前完整 SQL 摘要，并只在内存中投影严格验证的原五分钟巡检新增行和对应日志序列增量。所有旧 COPY 行、其它表／SQL／账目、原权限和目录仍须完整匹配旧摘要；不排除整个日志表、不重写旧锚。仅允许 NULL 用户／实例、固定两 action、严格唯一六字段、schema 1、零失败、开始结束配对、UUID 不重放；未完成或序列不一致只作有界只读重取。

实际 B 的 `instance_id` 是最后追加的物理列，第一次新原生核验因此被精确 COPY 布局检查拒绝；只读 catalog/COPY 取证后支持两个具名列次序并固定 header SHA，未知或执行期间变化仍拒绝。原失败报告保留。

新原生只读结果 `native-b-guard-read-r2-summary.json` 自然退出 0：32 条巡检追加经过审计，投影后的完整历史数据库集合摘要与原锚 `9de0350388596145fd4ca6fb89df29a5a6676e61ec7253177e24ecbd6b655f3b` 完全相同。当前真实摘要另存，不声称原所有字节没有正常变化。实际后台 PID 93844、startTicks 2332973、原已观察 InvocationID／NRestarts 5、unit／加载 exe／cmdline／UID／GID 均完成新观察。

## 当前来源与已验证范围

本机隔离来源和证据位于 ignored 的 `logs/security-controller-pg-execution-20261127-r3/`；私有 SQL 和完整身份材料不上传。

- 42 个 B 追加／完整保护纯控制、29 个执行器控制、14 个精确 QEMU 控制、10 个 Matrix 控制自然通过。
- 9 个真实 Windows 句柄停止／精确删除控制，以及两目录四叶在首删前持有、目标污染保留的原生控制自然通过；无 QEMU／PG 启动。
- 原 16 个 Linux root0600 FD 读写控制只作为其原来源证据，生成器验证当前两个 inline body SHA 与原原生证据完全相同；不拿它代表整份新执行器已运行过。
- 完整 preflight-only 自然退出 0：195 个真实持有输入，111 runtime、32 native query、原 Windows B／PG、完整原 B 摘要和真实后台、两组 QEMU proposal 全部核验。没有执行客机／PG bootstrap，也没有创建未来运行计划。
- 实际 immutable runtime 最大成员恰为 64 MiB；原 64 MiB cap 未放宽。原代码已正确把自己的可变 disk／seed／role 目录延后到已确认停止后核验，未为早先猜测修改正确逻辑。

R3 源 freeze 为 `692eae9955fcab53de371c0436bcded3dccdce1601eef5e8373375c4a45c00b8`。该 preflight 的独占 before 证据保持原路径，真实未来启动不能覆盖或冒用。相同 runtime 字节已派生至独立 `r4` 目录，仅生成新执行计划和证据 namespace：freeze `4032b36426883c49243d72f09581f88b09837a6269c667e1adce3e1e89eab60d`，计划 `49e11e92ffcf35303d6834c3ff695368c03ff41897301d3ffd7430877f2455b9`。原磁盘、seed、密钥与 prepared 未重新准备。

固定 G/S／Matrix／execute 和 R4 namespace 的独立代码审查已通过，未见已定位代码阻断；结论为 R3 的 `independent-review-final.json`，SHA256 `1998d405508c2d877b3bae96a354bc337faffd04c81eda2abb3c24940813c5af`。该结论只证明审查范围，不等于真实客机矩阵执行成功。R3 原生双目录报告绑定的 R 源为 `654e4f53…`，最终 R 为 `d43b395d…`；`native-batch-receipt-only-delta-result.json` 保存完整旧 SHA 精确重构和逐方法字节比较，只有最终报告字段的准确措辞变化，首删门禁与实际清理前全部逻辑相同，原生测试未被移作功能变化的证据。

集成方核对固定来源和门禁后，继续启动原 prepared 的两台独立 Ubuntu 24 AMD64 PG 客机，完成原 capture／restore／故障／真实重启／同状态再入／确认清理。完整 Debian 13 glibc 2.41、主控新备份本机完整模拟恢复、最终候选热更新和正式发行仍未完成。

## R4 实际失败与 R5 ROM 启动取证

R4 实际启动仍自然退出 1，日志明确 `could not load PC BIOS 'bios-256k.bin'`。原持有句柄确认该辅助 QEMU 已退出并关闭，第二台未启动；旧失败、原 prepared 与四个 disk/seed 保留。

R5 在独立受控目录准备原 QEMU 9.2 安装器中的 SeaBIOS：完整原归档与官方 HTTPS SHA512 匹配、固定 7-Zip 身份和字节核验、流式提取后与原缓存成员完全相同。信任范围是 HTTPS＋SHA512，没有 detached PGP 声明。旧 111 成员 runtime、原缓存及原 BIOS 档案未修改。R5 的固定 13 文件 freeze 为 `a64e56c58cfa36d864904c00b824ce83d9eb2764ad66cbab2ccabaff53a5e094`；独审结论 `b5fdf002f048a1c956f7d81af8f81267b5405913f62da58ce64ba489586e110d` 只代表该代码审查范围。

经集成方批准，单独使用无盘、无 seed、无 NIC／TCP、CPU 暂停的 QMP 辅助进程验证 ROM 加载；30 秒／2 MiB 限制保持。第一轮已取得暂停状态与空 block 清单，但严格 stderr 检查失败，旧采集器未在失败路径保存 stderr。原源码与失败保留，不能宣称完整 loader 通过。

新的具名 r2 采集器补齐到达时落盘与失败 finally 报告，11 个纯控自然通过，argv 和 environment AST 与原轮完全相同。实际 r2 自然退出 1：stderr 105 字节完整保存，内容明确缺少 `kvmvapic.bin`；两次 `running=false/status=prelaunch` 和 `query-block=[]` 为真实结果。原句柄终止／signaled／关闭、双 reader join、三份 raw 日志 flush／close 均已取得。另有 `PG_EXECUTION_HELD_INPUT_CHANGED` 被实际输入保护拒绝，r2 未保逐句柄差异，不能倒推其具体路径或称原全部输入已保护通过。

随后一次新的只读逐句柄／四材料核验自然退出 0：当前 145 个持有输入无身份／facts 差异，四个原 disk/seed 的完整 SHA 和身份均匹配；没有启动 QEMU 或 PG。这只是当前状态，不能回填 r2 的瞬时失败。下一候选需在失败当场记录逐句柄差异，并把隐式 `kvmvapic.bin` 纳入固定完整 ROM 来源；未知错误仍拒绝，不修改旧 runtime 或忽略 stderr。

最新 `287c8527ce525be5d05b33d11f54c81a3c37d0e6` 的主 CI 30 项、SSH 安全 9 项、完整预览 17 个必需作业和双实际包均已由集成方核对通过，发行作业按预览预期 skipped。双 PG 原 worker 矩阵、真实 Debian 13 glibc 2.41、新主控备份完整模拟恢复、最终热更新与正式新版仍未完成。

## R6 实际启动超时与 R7 有界续接准备

新的受控 ROM 目录位于原 stage 的 private 输出目录，目录恰含 SeaBIOS 与 `kvmvapic.bin`，来源 metadata 在目录外。32 位十六进制目录名使 Windows 目录／文件路径分别达到 249／263 字符，首次准备失败；新具名准备器将这一输出标识缩至 16 位并检查最长路径，实际 247 字符自然通过，旧失败源码保留。原 32 位 prepared ID、盘／seed／密钥、111 runtime 与缓存未修改。

R6 freeze `a8ec52673656904490f308ec68426a32ab4c3a5d575da44dca6d37166978b1a9`、plan `039df5f18234a060f7deecad183ebc99232bba74404196cf3e61d84979569ee7` 的双 ROM 来源与精确参数变更经过根审。原 `r3` 观察器存在 checkpoint 后再次追加最终 JSON 的确定缺陷，根审在实际运行前发现；保留该源与 17 纯控，`r4` 统一覆盖写最终 checkpoint，20 纯控包含多次大／小 checkpoint 后由原严格 JSON 解析器读取恰一个对象的回归。实际无盘无网 `r4` 及独立 FD 回读均自然 0：stderr 为空、双 prelaunch／running=false、block 清单为空、两次 153 个 held 输入无差异，四个原盘／seed 完整哈希与身份保持，辅助进程和管道／线程／raw 日志均确认关闭。实际 private 报告 15533 字节、SHA `e6f828ff0b874f3eadd8df23ec3bc3c4021ee836fed906cd6f56f7a6daf45c9f`。原 r2 瞬时 held 拒绝仍未归因，不追认其通过。

经根审批准，R6 使用原两盘和原 seed 启动两台真实 QEMU；原 B／本机 PG 的 fresh before 保护通过。两台均进入 Ubuntu 24.04、内核 `6.8.0-147-generic` 和登录提示，原 300 秒 SSH 启动窗口自然失败 `PG_EXECUTION_GUEST_STARTUP_TIMEOUT`。未进入 PG bootstrap，未创建最终运行计划，原 22 次 worker 调用均尚未执行。两个原持有句柄均确认 signaled／关闭、21165／21167 空闲、cleanup errors 为零。旧盘与 seed 保留，不重新 prepare。

只读 post-stop 取证明确区分原始和运行后的数据：两盘原 FileID 保持，合法系统启动后 source 为 271777792 字节／`5052f16e6a53dea3ef11cb0fe4e50887db95cf3adee8950abda2b62a9bf097b2`，target 为 271843328 字节／`46f688d84536c7b675d11f3a11214ef5ee246a7090a844462d16dd626470e25a`；各虚拟容量 3758096384 字节。原 `3839f148…`／260177920 的初值仍保在原 prepared。两原 seed、client key 的全文与身份保持；ISO 为 cidata／Joliet，user-data／meta-data 严格解析、角色 hostname／instance-id／原 host pin／client 公钥和原产品源均匹配。没有显式 network-config，依赖 cloud-init fallback；实际没有新 hostname／cloud-init 标记，不能据串口未显示 CD-ROM 就断言设备不存在。

根要求的无 boot／只读 QMP 映射实际证明旧 seed 在 `ich9-ahci` SATA 控制器的 `ide-cd` 上。原采集器错误地要求 query-block 恰两项，未计入一个无介质的默认光驱，结果保留为 False；新独立 FD 解码将两插入的原只读后端与具名默认空槽分列，完整 raw replies／qtree／PCI 对齐，自然 0，不重标旧采集器通过。新 virtio-SCSI／scsi-cd 只读、CPU 暂停映射也实际自然 0，PCI 为 1af4:1004/class0100，原盘全文与身份保持；它仍不证明客户系统已读取 seed。

当前 R7 只把同一原 seed 从 SATA-CD 换为角色专属 virtio-SCSI／scsi-cd，精确参数从 33 项变 37 项。新 continuation coordinator 先验证原 prepared、R6 的启动／确认停止／超时原日志和 post-stop 证据，再按上述已观察数据核实际盘全文与原 FileID；输出分列 originalInitial／currentContinuation，不伪报旧初值通过。9 个锚／篡改负控、109 个执行器／布局控制、13 个原生 ROM 绑定控制、9 个原生停止／删除控制自然通过；实际 native preflight-only 自然 0、148 个 held 输入，没有启动 VM 或创建未来 Matrix.before。

R7 freeze `b057e4db5c1abee6b5c093aa462b6ce710e23293bb43ad8433eadaa6c1d55a34`、plan `e286faf736701c1e79c5ca54a388a187a4b6739fbabf6de99c9752ba21a6c682` 已由根完成固定源／依赖／原输入／37 参数和重启清理链路审查并批准执行，记录为 R7 的 `root-execution-review.json`。新增 coordinator／guard 按独立固定 SHA／FD 和计划登记核验。每台原机器此前实际已启动一次，本窗口计划最多三次，总数不超过原四次；原三 attempts、72 小时、22 worker 调用和 B／本机 PG 保护保持。

R7 的 fresh before 原 B／本机 PG 保护已实际通过，两原 VM 启动后均见 virtio-SCSI／CD-ROM／cloud-init／新 seed hostname。随后通过原 SSH 精确 pin、原角色 marker 和真实 amd64 系统检查，source boot ID 为 `3263c4a8-0146-44d5-bdda-09f08c2e4927`，target 为 `efc7372f-3693-4309-979b-627cd674ec51`，machine ID 摘要不同。CSI 路径下同一原 seed 已实际被读取／应用，与 R6 的失败分列保留。

R7 最终自然退出 1，失败码为 `PG3398_GUEST_PREPARATION_FAILED`，发生在 source 软件准备；没有报告 packages-prepared，也没有进入 target 包准备。原 Windows 私有 stdout 的完整 SHA 为 `278d3379ff6bfbfa5425c6b52cf620f1d6c5c7217e81b151b968b78221150a9b`／1749 字节，stderr 为 `f1b7a22a3a50b8a26bccffd9b710e164eb4f86e9749cb903caa9b8575f87ed54`／93280 字节。stderr 大部分是早期 SSH banner 尚未就绪的连接栈，不能将其当成最终包准备异常。最后一次原 pin 下只读进度显示 apt／dpkg 正在推进 postgresql-common，日志继续写入且未见网络失败；该观察不证明最终安装完成，也不证明具体失败原因。

原 bootstrap 将不符合 `PG3398_GUEST_*` 命名的异常合并成通用错误，且 run 捕获的命令输出没有持久保存。当前没有受资格认证的离线 guest 文件系统读取通道，故最终 guest 包日志、partial 状态与具体异常尚未取得；不能猜定为超时、软件源故障或产品归档验证失败。下一候选应先经原身份读取原日志和 partial 状态，并保留具体阶段／私有错误；不能删除原 packages-intent、重新 prepare 或伪装全新安装来绕开续接。

R7 两台 QEMU 原持有句柄均实际 signaled／关闭，21165／21167 空闲，cleanup errors 为零。**最终 Matrix.before 没有创建，原 22 worker 调用仍为 0；完整 PostgreSQL 恢复验收未通过。**

R7 后停输入只读封存自然 0，证据为原 stage 的 `private/r7-after-failed-preparation-inputs.private.json`，3761 字节／`c5bca7d130c5da63c83ee5ecb07d641832973415bf781804aaac8f53504f3a66`。两原盘 FileID 保持，source 当前为 1212940288 字节／`d66efc1033ecf03f933c72c2d56fe19ab3ec2aec5e1debc2230c80e1ce184f61`，target 为 287965184 字节／`eeb6bc35b71b3fbd3216b6ed8dc178862b02afc8065c990e5f0f64f729f1bd64`；各虚拟容量仍为 3758096384 字节。原 prepared、四份 seed／client key 的完整字节与身份保持。原 `3839f148…` 初值、R6 的 `5052f16e…`／`46f688d8…` 后停锚和 R7 当前值分列保留，不能复用 R6 锚声称当前材料未变。source 已合法增长至超过旧 512 MiB 当前材料读取边界；本次封存按已经观察的角色精确大小读取，不放宽现行执行计划的任意镜像边界。

两台各实际 boot 已累计 2 次，原总 4 范围只剩 2 次；完整后续仍需启动、原 native API 重启及原 worker 重启共 3 次，原范围不足。若继续，应经集成方根审采用明确的新有限 scope：**总 5 = 已耗 2 + 必需 3**，保留每 plan 原 4、3 attempts、72 小时、22 calls、原 B／本机 PG／身份保护及确认清理，不暗增预算或追认旧范围通过。当前未启动新窗口。完整 Debian 13 资格、新备份完整模拟恢复、最终热更新或正式发行仍未完成。

R8 已准备原身份下的只读取证 helper，源 `ee4f8d061d9957b4c40a16350ffbc0555d19a275998e2c70f20d544a6f0d5840`／16789 字节；23 项纯控制自然 0，测试源为 `295e27cddc43f0853cf731333f0e40c96a137ebcbcf46ce017e8b4e97e0f660a`／14202 字节，原输出日志为 2956 字节／`293cc1a6364ec3c5681e89ad48afab5ae662ef88d595409a3975c023b8b72683`。只允许原两个角色／machine SHA、原 bootstrap／产品源、当前观测 boot 和固定包 intent／apt 日志；文件全文及具体异常仅传至私有证据接收端。包状态／dpkg audit、三客户端原始归档／passive 文件、客户端18的最终 runtime proof、InRelease 与残留 policy 分步骤采集；命令退出码、超时前 stdout／stderr、完整有界 traceback 仅进入私有 ledger。未知异常不公开任意内容，也不在被 product 合并为通用码后丢弃原始命令结果。只允许固定 dpkg-query、`dpkg --audit` 与原客户端 16／18／19 的 apt-cache show，显式禁用两个磁盘 cache；拒绝安装／更新／下载、PG19 执行、SQL／服务／worker、任意文件、凭据与修改旧 intent。每文件及命令 stdout／stderr 共同上限保持 1 MiB，整体共同输出 2 MiB、查询 30 秒、每 probe 最多16查询；超过边界明确保留 size／hash并拒绝，不伪报完整输出。此 helper 尚未在 guest 中执行，纯控制不是原生包日志或失败原因实证。

新有限范围提案保存在 ignored 的 R8 `limited-continuation-proposal.json`，明确总 5 与原 4 的不同范围。它不是可执行计划：具体 partial 包准备配方、后停锚的 coordinator 派生、最终 freeze 与根审尚未完成，也没有新 Matrix.before 或 VM。不能先只做一次诊断 boot 又额外停启，再隐瞒实际次数声称完整流程仍在该范围内。

集成方随后批准总 5 的规格层范围，执行仍须新 coordinator／freeze 根审。原 `ee4f8d06…`／23 控制源已按完整 SHA 精确重构保存在 R8 的 `historical-ee4f-forensic_guest.py` 与 `historical-23-test_forensic_guest.py`，原 r3 输出不改；它们只代表原先退出后才检查 PIPE 的草稿范围，不能冒用作运行中有界读取证据。新具名 reader 沿现成双管道 selector 读取方式，在子进程运行时检查共同 30 秒 deadline 与 1 MiB 上限，超限／超时只停止本次持有的 Popen 子进程、有界 1 秒 reap、关闭两管道，明确 partial 标记并把底层异常及观测 size／hash 留在私有 ledger。新源 `44ed6f2b3f5b3fa2f03ee8157d3d76e21ce26a47b1b410f61c811c794a051025`／20379 字节，新测试 `042ffcbcdf3cde33e7191a959b5e2292a2fb806c6b5fab66689f76fcaae61af2`／17985 字节，25 项纯控制自然 0，原 r4 输出 3284 字节／`a5dbe222a24fcda9c60571e7b7956b93300544a715a9662aedd0bfd8bdfdae66`；尚无 guest 原生运行。

当前正在冻结最小同盘诊断微阶段：沿原身份取得真实 pkg／旧 intent／客户端18 proof 异常后，持原 QEMU／FD 留在同一次 boot 内等待精准配方；等待上限拟保持现成1800秒，不重设 deadline。未知状态不执行 apt 修，精准配方必须单独根审，续接前核原 intent 未清除与当前 proof，之后仍走原 PG 准备及22次矩阵。根审或执行终态尚未取得，不据本阶段源码／文档保存声称恢复通过。
