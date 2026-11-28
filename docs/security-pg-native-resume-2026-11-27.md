# 2026-11-27：CI 终态与双 PostgreSQL 隔离测试接续

## 11 月 28 日双 PostgreSQL 实机结果

R24 完成源端 4/22。前两个 capture 在持久 intent 及 dump 写完后分别触发预期故障，第三次 capture 自然退出 0，第四次 check 自然退出 0。原 seed 的表行、序列和三个大对象完整核验。源机生成四个完整的 PostgreSQL 自定义格式备份，分别为原客户端的 live/drain、客户端 16 的新备份以及由原 Before 记录验证的客户端 18 新备份；传输后在目标机核对字节及 SHA。第三、第四步完整回执 SHA256 分别为 `db97a2453b61a2087d5e27504d18b0e39d9ca9dfdbc0f3518020b9110afda9f0`、`1b8594fad3d4e34020b0939ebdce93695a30cf7bea5dbd73903d2bbe574109f6`。

目标端第 5 次调用返回 `SCRATCH_CREATE_UNCONFIRMED`，尚无已接受的 restore 步骤。检查调用器发现它用普通对象注释去读数据库的共享注释；需用真实目标库验证新库 OID、归属、共享注释和空库，再继续。R24 已保存四份源转移材料及两台原盘，双 QEMU 均观察到原句柄结束和端口释放；外层 launcher 又报告所属子进程退出未同步，故该轮外层 captureComplete 为 false，原 stdout／stderr 摘要及错误回执均保留。

R23 已通过原 worker 的两个中断场景（2/22）。源机执行真实 capture，写入持久 intent，按指定故障点返回 `INJECTED_AFTER_INTENT`。调用器随后从客机读回 state，核实 capture 进行中、seed 已校验、本轮尝试序号为 1。实际计划 SHA256 为 `5609ae0466c9f0d4e8428356f7b4447efe3fb62534b3044403d64cad780007f7`，第一步回执 SHA256 为 `88f8fccd97822f8ce2915053e51af9288b0c997ae7c08027e332100407c0a7e1`。第二次 capture 在实际 dump 后的指定中断点返回 `INJECTED_AFTER_DUMP`，在磁盘读取的第二步回执 SHA256 为 `ab2de63a1c66a517d1e331af8ca43e1e3bcc24d406a8e8f7fb53c5f1e0ae16d4`。第三次 capture 真实运行至旧备份客户端路径，测试程序以 `UNREVIEWED_CLIENT_EXECUTION` 拒绝。最终两台 QEMU 的句柄及端口完成原收口，库、两份历史 dump 和种子数据均留存。

该轮在进入测试之前逐字节核实、归档了 R19 留存的两个 dump、R22 两份 worker bundle 和源端初始 state；原目录身份和文件内容均保留，源端库在写入测试数据前再次核为空。此前 R22 的首次拒绝单独保留。

两台独立 Ubuntu 客机已核对原磁盘、SSH 身份、PG16 实例和角色 OID。R22 首次由实机数据生成完整运行计划，并在两台客机校验、安装同一套 worker。首次源端 capture 已实际执行，返回 `UNKNOWN_SECURITY_STATE`，未到预期的 after-intent 中断点。**本轮实际调用 1 次，达到预期的矩阵步骤 0/22。** 原计划 SHA256 为 `8f75d9c83222a3366fa27a6ae0a5504d43b94344c46da74b2c9052f133718d6a`。两台 QEMU 已按原句柄停止、释放端口，Windows 禁止目标进程与只读 SQL 复核通过。

| 轮次 | 取得的证据与停止原因 |
| --- | --- |
| R19 | 修正 Windows 旁路保护反复发起短 SQL 会话的问题，在启动和收尾分别对原本机 PG 做完整只读 SQL，窗口内按进程、镜像、PID 文件和监听归属持续核对。两台 PG 准备通过，源机真实重启且重新认证。Ubuntu 调用夹具缺少新 boot 的 systemd 来源记录，产品在缺失客户端分支拒绝该 journal；源机原调用记录及两份 dump 均留存。 |
| R20b–R21 | 核实指定 R19 旧 journal 的内容、文件身份、唯一 token 和两份 dump。将旧调用目录在原客机内保全归档，保留两份原 dump；以后的基线检查仍拒绝其他控制。R21 两台真实 SQL 返回数据库 OID 16386、两个角色 OID 16384／16385，原测试计划把 PostgreSQL 返回的十进制文本直接当作整数而拒绝。 |
| R22 | 在夹具与 SQL 的交界处只接受规范正整数 OID，保留数据库原值并拒绝非法输入。通过完整计划校验和两份 worker bundle 核验，随后触发上述首个 worker 拒绝。此时源端安全状态根仍有不同于当前 worker 备份名的条目；已保留的 R19 dump 目录是已知的一个，重开前需逐项清点，不能假定没有其它条目。 |

本专项绑定候选 `ad2ca04d` 的产品和测试 Git 源码字节。共享 B 的实时全库只读审计仍在单独核验，已观察到的两条失败巡检和其中一条缺少开始记录的事实保留。原 3116 备份同版隔离恢复、完整系统补丁生效分别取证。主控任务 68 已完成的安全候选热更新见[主控交付](security-urgent-controller-update-2026-11-28.md)。

下列内容保留较早轮次的运行记录。

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

R8 微阶段已冻结16份来源，freeze `6cb283d9e9a950497d05e29531467c8c9b163ffe7a6327416f5cbacfe2c4e1ae`、plan `30bc9c39d017b66f1881508646eba2a51cc5c607d2a7fbf9ab8b177ce7619424`。112 项新对应纯控制自然0（25 forensic、8 lineage guard、12 diagnosis、29 execution、10 Matrix、28精确QEMU）；新无VM原生preflight自然0、151 held／111runtime，`a76b9533…`／2140字节明确原3839、R65052／46与当前R7d66／eeb分列，原FileID保持。只对这两原角色的已观察精确大小／hash采用新读取边界，其它512MiB等cap不变；原prelaunch保留8623489024字节，实际入窗保固定1GiB+32MiB余量。新9项原生own-stop/delete及13项完整ROM绑定也自然0。没有新的PG VM／worker调用或未来运行计划。

根审在原canonical launcher `2d74cd2d…` 中发现无限 readline／queue／wait／join与异常不收子进程的确定缺口；该源精确保存在 `historical-2d74-launcher.py`，旧范围不改。新具名 `launch_bounded_r1.py` 为 `e493078c70b85df56b0f8d9f6847a2e55684a11824bc72b2154201ce954daed4`／17281字节：先把暂停的新child纳入仅本次的kill-on-close job后再运行，运行中两流32KiB chunk在producer锁内收费，共16MiB、64KiB line及8项queue上限；读／put／get都使用共同72小时deadline，异常只停止该job并有界确认、reap／join／关闭。任意trace仅私有保存，最终安全结果另存。8项新纯控自然0；4项实际Windows normal／shared-limit／line-limit／退出遗留后代均自然0，原B与本机PG两个原持有handle仍alive，本次job与child／reader／pipe／stream停止和关闭完整确认。原生报告 `e73fe592…`／4397字节；这些Python fixture没有启动QEMU／PG，不代表目标客机取证通过。

新启动器仍等根最终审，与原16份冻结来源分别绑定；16源／112／151／9／13未因这次launcher修订重复运行。实际启动必须使用根审通过的新具名入口，保持1800秒同boot等待，精确原intent全文／原生facts与指定packages-proof校验；独立精准SSH recipe仍须先取得真实状态再冻结审查。当前客机具体package异常、合法partial续接及22次矩阵仍未完成，不提前发版。

根最终审后，R8 仅一次通过真实held `e493` 源与exact `6cb` 启动，实际自然退出1：原B before保护先返回序列采样移动，下一次完整历史投影被 `B_LEGACY_SQL_TRANSITION_UNPROVEN` 拒绝，最终独立保护也拒。没有任何 owned-guest-started，stop集合为空、没有新PG／VM／22调用，实际boot仍各2、总5仍余3。启动器真实capture完整404字节、stderr0，原job／child／reader／pipe／stream停止和关闭全确认；完整失败源及私有结果保留，不重用该输出namespace。

新的原B只读取证查明原始日志2410条、当前2598条，188条追加均按原类型、顺序、起止配对、零失败和原32条审计前缀严格通过。原find_original_boundary只盲搜最后128个cutoff，原边界已经落在范围外；使用原已认证R3报告 `ff3cf37e…`／25076字节中的原logBoundary后，完整旧SQL／所有旧row／其它表／catalog／权限及实际backend仍投影到原 `9de03503…`，没有留存删除或旧数据变化。私有SQL1265969字节／`24a81800…`，完整R2私有报告1765233字节／`39b816c5…`，只保存于原stage/private。首个取证wrapper的一次大block写入被原1MiB守卫拒绝，原失败源／空证据保留；R2仅采用原1MiB分块后自然0，没有修改B。

未执行的R9 initializer初稿仅绑定原R3与旧32前缀，随后审查收紧为R10：仍只从原R3取原边界，另对已认证39b8 R2报告使用唯一固定路径／SHA／确切1765233字节的2MiB私有FD读，先validate R3→R2原32，再validate R2→current完整188前缀后建立current before；其余cap、128盲搜、MAXAPPENDS512、类型和原9de全不变。新3项188前缀控制、6项原边界／126／128／188／source／schema／anchor控制与受影响10项Matrix回归自然0。R10 freeze `f6a45410f217c8c7a315162aeae42078e86f0b25d298ee6797b031250f657bfe`，plan `94e56223…`，唯一Matrix变更 `eb641af1…`，其他15份冻结源、e493／9cd保持字节。旧R9 `d8b85ae8…`、6／10控制与全部R8失败保留；当前R10待根审，仍未再次启动，原3398具体软件准备异常与22调用完整验收未完成。

## R10 实际终态：启动超时，原两个句柄已停止

上述“待根审”是该冻结时的状态。根于2026-11-27 17:38:06 UTC批准R10，原 `e493` 启动器于17:39:38实际开始；source／target两原QEMU分别于17:40:55／56启动。此轮自然退出1，主失败码为 `PG_EXECUTION_GUEST_STARTUP_TIMEOUT`，没有 `owned-guest-inspected`、同boot诊断完成、packages准备、finalPlan或任何原22次worker调用。

17:46:07 UTC的完整终态确认两台原持有句柄signaled、exit0、句柄关闭、两控制端口空闲，cleanup errors为空。启动器也确认captureComplete、executionCloseObserved、ownedChildReaped、ownedJobStopped、readerThreadsJoined、streamsClosed和pipeHandlesClosed全部为true。完整私有stdout为1470字节／`012e27b73fdb47d48eba1f124dffe25cb99a6344c5f275693f3927ddf5f7d662`，stderr为127825字节／`15b7a00476497bdddec817392b07146e87b52ca0dab4a0b65c93ce0547ffbb8a`；原输出、源码、盘和seed不覆盖。

两份原串口可见Ubuntu原hostname、正常DHCP与默认路由、cloud-init Network Stage和SSH socket；source约172、target约168 guest秒出现网络就绪。未见最终SSH服务Started，不能仅据此认定包错误、网络永久失败或身份变化。stderr主要是早期SSH banner读取失败，不是原3398包准备的具体异常。该轮是每台实际第三次启动，原4范围余1，已批准整体5范围余2；下一步仍需诊断启动和原API／worker两次重启，不能把失败启动漏计或继续声称余3。

终态同时存在独立 `same-boot-final-protection-failed`。历史holder在已有主异常时仅写verificationCompleted=false，丢弃了次要保护异常的具体类型和内容；stderr未保留该异常，因此目前不能猜定是B或Windows哪条保护失败，也不能将before成功当作最终保护通过。正在准备独立固定来源的无boot只读复核和具名错误留存修订，原R10不改、不追认保护成功。

后停只读目录观察为source1219166208、target294584320字节，原R7的1212940288／287965184已经是历史锚。新R10后停封存reader已从原已验R7 reader `6e14fe26…` 精确派生，源码8527字节／`8de088182d9ce286bff563cb798a4a66251b7c1448b8824a514a2c789450edaa`，固定原stdout／stderr、两原pid、原R6／R7证明和这两已观察size，并分别保留原4／新5预算。派生与语法已自然通过；尚待根审执行，没有新VM／PG／worker启动，尚未核全文后停磁盘或重新声明seed／key不变。

根随后批准该一次无boot只读封存，实际自然退出0。两原FileID和虚拟容量3758096384均保持，source当前全文为1219166208字节／`c61e983d9858448089e6f7a6fdbf42fac97b1cc01f26fbbbb5b66209ee6f6144`，target294584320字节／`bc82e11ace9da1162050a1286a08acf3ab2e38c6fe43beab0b8fc0d8fe536939`；两原seed、clientKey的完整身份和字节保持，prepared未改。R10私有后停证明4293字节／`6afdc5dba105cad9649c31646792701aa180ba7c6eb5599b7140ea8f743e0085`，原初值、R6、R7和R10当前值分别保存。两控制端口再次确认空闲、原22调用仍为0，没有新VM／SQL／worker；原final保护错误仍未证明，独立fresh B／Windows读者沿原协议准备待根审。

根又批准最小fresh B／Windows只读reader `2ac6326a…`，实际自然退出0。当前Windows原B进程／本机PG的完整保护通过；原B当前2614条日志相对原2410条追加204条，原ff3→R10 before→fresh三段完整前缀和旧SQL／账目／其他DB均严格核回 `9de03503…`。B私有完整报告1776688字节／`adc0f82d3d7f672780b439c0a95add5abc8a506d84e74a6895974c2fa5616d3c`，Windows报告4065字节／`e7ae90c8f9f49a8bf6bf68471a4948eb25b12dafa40f0963097ab4a3fff23bcf`。本次只读SQL没有启动客机、PG服务或worker，也没有改原基线。**这只证明新的当前状态通过，R10当时secondary保护错误的底层原因仍未捕获，不追认当时通过。** 原3398对应R7包准备，R10对应新SSH启动超时；两份Windows stderr均只有早期banner栈，不能拿它们替代尚未取得的guest包日志／partial状态。下一步原同盘同boot诊断须先确定新的有限真实启动范围并经根审，原当前三次boot／原22调用0保持。

## R11 最小受限接续已准备，实际启动待根审

根明确批准新的有限整体6＝已耗3＋原必需3，仅把测试SSH就绪窗口由300改600秒；原1800秒同boot诊断、72小时总窗、每plan4、3attempts、22calls及产品8／20秒保持。新coordinator仍实际持有并运行原R6／R7验证器和完整旧证据，再核 `6afdc5db…` 的R10后停证明及两当前全文／原FileID；Matrix保留原ff3／9de和原188，再绑定 `adc0f82d…` 的完整204前缀。没有重prepare、清intent、新基线或放宽任意文件／签名／身份门槛。

新holder把次要保护异常的完整trace只写现有私有writer，公开固定错误码、hash／size和是否完成留存；留存失败明确报告，不覆写主错误、不阻止原自有句柄收尾。R10历史源码与未知原因保持。新来源在 `logs/security-controller-pg-execution-20261127-r11`：freeze `a349e770cdd1a80a81169a3339c7fdfd4f1910325d3ea462e96a75ab4203cdbb`，plan `3a76f3c6cc8497239f32b51e35ac638367a7482b73052f442bea71fd9fc8b2a7`；16核心来源中12个保持完整字节，原 `e493` 有界launcher也完整保持。

对应谱系10、204前缀4、私有异常留存／主错误与cleanup5，共19项纯控制自然通过。首轮测试缺少已存在B helper和假Matrix.plan字段的夹具失败分别保留，补齐原helper字节和fixture字段后通过，没有据此改16核心源。直接PowerShell的原样preflight因非canonical CRT引用被 `PG_COORDINATOR_PROCESS_ARGUMENTS_CHANGED` 拒绝；保留原严格参数检查，改用原已验canonical launcher／only两个helper完整原字节后，实际native preflight自然退出0、154held／111runtime、原三段盘／seed／key／prepared与当前范围通过，无VM／SQL／future Matrix.before。该原生结果SHA `ab3ec19cf4662639d1e8d38fbd45fa796ec32013f4d353c67e25e1762bfc7d48`；最终16核心源再次完整核对一致。

两处完整diff和本次全部纯控／原生结果已经交根审。尚未启动R11、原22次worker调用仍为0；下一步实际启动成功后先沿原forensic读取原3398日志／intent／包审计／client18 proof，再按真实状态在同boot执行独立精准续接，不能直接调用原fresh packages或删intent。完整PG、B1原备份恢复、最终主控热更新与正式发行仍未完成。

以上为准备阶段记录。根随后核完整功能diff、19项控制、原生preflight和实际预算后，批准R11一次受限执行。原B／Windows启动前保护实际通过，source PID2932／21165、target PID16748／21167均已报告owned-guest-started，分别为原盘实际第四次启动；新整体6次范围剩原API和worker两次重启。原held `e493` 启动器／两原盘和seed保持，实际600秒SSH观察及固定1800秒同boot诊断进行中，尚未取得新boot ID、forensic结果或22次worker调用。此启动不等于完整PG通过。

## R11 已完成真实诊断并停止，缓存修复未执行

R11两角色原pin、serial、独立machine身份和SSH均实际通过。source boot为 `7faea7aa-0ce0-49f2-9314-e905c2d8c41a`，target为 `7da17145-d942-4059-89f3-5a220d456620`；source原intent11622字节／`61c080606f5612fa10a8ada41a274ab3d9b458be72a15629be0fa2c06ad0ba80`的身份、全文和历史R7事实通过，packages-proof不存在，target包准备文件均不存在。完整私有诊断SHA为 `2eaaceed3e34aa49da7315fcd3c1e0e077b64013b2b99927557dafcad44533e4`。独立target一次只读pin对照也通过，boot与主holder一致；这没有代填未来Matrix身份或改变期限。

实际包状态全部REQUIRED已installed，`dpkg --audit`没有待配置项。三次 `/usr/bin/apt-cache` 显式禁用两种磁盘cache后，读取精确16.15、18.7、19.0安装版均在30秒共同查询门槛超时，查询子进程已停止／reap、管道已关闭。这是当前确切冷元数据查询瓶颈，不能追认成旧R7未留存的原始异常。另一次source原pin下只读 `apt-config` 实际返回 `PKG='pkgcache.bin'`、`SRC='srcpkgcache.bin'`，证明默认磁盘缓存本已启用；无需改APT配置或以替换命令返回值绕开产品真实30秒查询。

根审过的source精准recipe准备为guest6915字节／`21d8db9fa3e89024db383e69d141cc9a2f6ffc92a980f9add1c64f4a754d13f7`和controller5245字节／`102eb912cc0271e92ca7115c817996f78fbe5344b3451aa099999a74f1406168`。它只重建原默认APT缓存，保留原intent／完整states／全部signed索引／精确版本，随后执行原归档和vendor18验证及原proof最终代码；不安装／更新、不运行19、不调用PG服务／SQL／worker、不改APT配置或产品30秒。此次实际一次执行却在**本机连接／执行guest之前**因原窗口剩余不足45秒，被 `PG_R11_CACHE_INSUFFICIENT_ORIGINAL_WINDOW` 拒绝。因而没有gencaches、下载／改归档或新packages-proof的原生成功证据，不能报告该问题已修好。

R11的原1800秒窗口自然到期，子holder退出1、主码 `PG_R8_CONTROLLER_DIAGNOSIS_WINDOW_EXPIRED`，原两句柄均signaled、exit0、关闭、端口空闲，cleanup errors为空。最后完整B／Windows保护实际通过，218条合法追加仍严格回原 `9de03503…`，实际backend93844保持；没有新的secondary错误。启动器captureComplete、executionCloseObserved、ownedChildReaped、ownedJobStopped、readerThreadsJoined、streamsClosed和pipeHandlesClosed均确认。stdout3771字节／`ff6f43d1988adccead84f470d41d08a6145f0aa5784c28f64cfac09941515551`、stderr131030字节／`b9427a989e3b7cfb9b3365a988baca3e664bf635442609902e159fb0dfcd6438`完整私有保留；外层capture命令完成0不是PG通过。

每台已耗四次实际boot、原22调用仍为0；原4范围已用尽、获批整体6余2，下一完整流程仍需一次启动和原API／worker两次重启。不得重置原1800期限或把原6范围擅自变为7。后停新目录观察为source1225850880、target300875776字节；原FileID／全文与seed／key的精确新封存reader `40271a00…` 已准备待根审，旧R10锚只作历史。下一步复用本轮已核实的包状态和已审cache recipe，在经过明确根审的新有限范围成功启动后立即精准续接，不重复30秒冷查询调查或重新prepare。完整PG、B1恢复、生产热更新和正式发行仍未完成。

## 2026-11-28：R12 归档拒绝与 R13 最终接续候选

R12 已实际使用原两盘完成第五次启动和原身份诊断。source 的默认 APT 缓存重建真实执行后，归档审核拒绝了 Ubuntu PostgreSQL16 的 `control.tar.zst`／`data.tar.zst`；此前产品只处理 tar/gzip/xz/bzip2。client19 始终是被动归档，没有执行。原22次 worker 调用仍为0，未生成 finalPlan。

该轮先在20:00:13 UTC写出失败终态，外部 stop 文件到20:01:36 UTC才创建，没有接受 stop 的回执；不能把失败记成主动正常停止。旧 holder 把另一个主异常泛化且未保留详细 traceback，具体历史主因仍未证明。原两句柄确认停止、关闭，端口空闲，旧失败及7次范围保持。根审后的后停封存为4656字节／`16dc73209f4288390c16416f35feaf85541ec2cc2a17d2fd3f8136ae5b995aaa`：source全文1293221888字节／`2a5fac5a9529c083be5fd74973106331fea04e938f7cbe765ecfafeeb613d784`，target307036160字节／`065bd8fea41f065c781a3392178bfe4e67d9adedaa983e6579798902b4420254`，原FileID、3758096384虚拟容量、prepared、seed、keys及全部历史锚保持。

产品 Zstandard 修复为 `680e1bb4…`、测试 `cd192ba2…`。受认证专用 Linux B 上实际10项、零skip、2.939秒自然通过；原client/server两包完整SHA匹配原APT归档，解析出266／1476条真实manifest。原B后端93844、PG88982、boot、包库、防火墙及上传材料前后保持。该证据只证明归档和对应原生分项，不代表22项恢复矩阵或生产已部署。

R13 固定来源审查另外发现两个确定准备缺陷：新plan保留了R12 coordinator／guard的旧指针；新bootstrap把当前产品SHA用于校验旧seed的marker来源。前者已绑定当前 `3af3662f…`／`0b0774b7…` 并单独保留历史指针；后者只将原marker固定 `f2693318…` 与当前product固定 `680e1bb4…` 分开核验，原marker、seed、intent和工具字节不改。新bootstrap30741字节／`7d686e778c94b57dd99b221d1b021fc4b1525c689d7ca3ff35092eff27501437`，stager与forensic同步重绑。

最终相关29项自然0、零skip：原身份函数IO适配5、wx／partial5、来源／完整20源闭包9、exact continue6、cache请求4。身份控制实际调用原identity函数，精确重构旧 `492cba82…` 候选并复现拒绝；原marker两版身份相同，当前／未知SHA冒充旧marker及旧product冒充当前product仍被拒绝。此前90项保存其原freeze和IO适配范围，不冒充全部最终源码已原生执行。

R13 最终freeze3018字节／`b3d7e87fef04fe9bc628810a13a394ced352d11ce1087c2aa9b9c80bf2b732c0`，plan15901字节／`927c6598e64a8b44cd556e7c9a5bbb4292069328c1606202deecb22255f72a6a`，最终只读审查台账10772字节／`dd4ac394fe674912bbd7d272e9ab8a25c5cd9247ac1ae07833bab8fa6dbec92f`。原native `1ab67a24…` 只证明161 held／111 runtime的coordinator预检；未验完整20源／Matrix原生流程。按根要求不再新增预检、不提前占用正式before：原 `e493078c…` 启动器进入 `Execution.start` 后，先完整freeze与原Matrix.preflight并生成正式before，再启动两原客机。

新的有限范围为总8＝实际已耗5＋原必需3；每Matrix原4、3attempts、72小时以及产品30／8／20秒保持，旧失败窗口不延长、不追认。**本次记录时R13尚待根执行审查、没有新VM或worker调用；完整目标仍需真实新工具／包准备、原22次worker及实际重启、最终B／Windows保护和确认清理通过。** 正式发行、主控热更新和完整灾备仍未完成。
