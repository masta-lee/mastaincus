# 安全剩余工作：并行精修与实际验证

## 2026-11-27 库存超时的自动恢复与当前来源

新内核测试已把首次准备失败定位到本机`apk info -v`读取超过原8秒预算。独立测量执行原命令自然exit0，输出5680B，进程寿命9.124369秒、总调用9.458322秒、CPU约7.89秒；这是TCG测试范围，采样未确认APK锁等待。测量首轮浮点秒数被原strictJson拒绝，原消息与失败保留，后续使用整数微秒对已保存真实消息完成12项严格解析对照，不重派旧盘。

产品仅在`installed_packages`遇到精确`HARDENING_KERNEL_STEP_TIMEOUT`时自动重试一次。首次保持8秒，第二次重新核验受信APK程序后给20秒，并继续按原请求expiresAt限制实际预算；过期、子进程清理、权限、其它失败及重复/非法版本记录仍拒绝。原全局command默认8秒保持，未修改内核/启动/包安装等其它命令预算。模板SHA68aef3317b18574cbc28bfadcbca43c8be04a7b92a7be14f980b7e2a034ebbd9，守卫SHA59bf556955d135193205eeff6f4caa446382058f374227b977ca1b2deba5b73c。

对应48项Linux原生全部自然通过、0skip，包含第一组writer已清理才第二lookup、许可过期不启动第二进程、原参数/输出/副作用边界；原B/PG88982/boot/服务/包库/nft及输入前后相同，本次没有B单元修改。Windows48项中29项Linux专用明确跳过，剩余通过。server types、host-kernel-maintenance-plan及security-hardening守卫自然0。加固守卫第一次因缺DATABASE_URL在导入前退出，按项目测试入口的占位URL补跑后通过，原失败保留。证据为logs/kernel-inventory-retry-20261127-r1-native-result.log及其输入冻结。当前新模板实际boot/rollback和完整备份恢复仍在验收，未据本机/工具测试声称宿主已部署。

仓库迁移已有阶段提交6399ccea、ca11550a、dc071a0e，main/工作分支均已同步。ca完整双架构预览45945358636自然17项必需job全success/Release skipped；普通ca CI唯一目录顺序测试误判已完整原生209/209/0skip修复，新dc普通CI45948929272在途。源码、实际包独核、目标主控热更新与正式新版的状态继续分别记入HANDOFF。

本记录区分源码、工具回归、真实 Linux、完整发行预览及生产部署。Owner 已授权三个子智能体并行工作；主智能体统一整合和操作测试环境、Git、主控热更新。生产程序仍为完整 `v1.8.14-test.a241daf`，本批尚未热更新或正式发行。

## 2026-11-26 15:52：psql精修及当前206完整Linux通过

r6d产品精修已写入；当前r6e两产品冻结为：源码368042B / `f2693318…`，测试390356B / `b43922f6…`。PG实际启动后先保存独立native launch；psql单工具缺失/权限/原hash漂移及查询间替换均有回归，不执行原clientTools或已认证Before/Expected之外的工具。末段及已建立journal的闭包查询补齐原身份校验；PG start前和native捕获核原unit/无override，并限制标准pg_ctlcluster参数。文件身份保留实际uint64 dev/inode，不复制旧SQL/settingsHash作为新证明。

新增9＋原44共53方法，r6d Windows独立候选进程自然0、0fail/error/skip；范围是实际文件字节及产品SQL代码，Unix元数据/进程/服务仍由明确适配器提供，没有实际启停PG。首轮完整Linux206/0skip自然1、8个准备错误，原B保持；已只读确认两个新owned_failure方法的客户端文件被放在01777的/tmp，产品守卫正确拒绝。仅修测试目录Linux/root优先私有/root，产品f269保持，旧1eff测试及原8子例失败保留，差异/冻结为 `logs/security-boot-psql-native-recovery-tests-delta-20261126-r6e-linux-private.diff` / `-freeze-20261126-r6e-linux-private.json`。

根任务最终r6e完整本机206/45skip、对应安全守卫和原B9专项均自然0；随后完整 **Linux206/0skip/0fail、275.895秒、自然0**，原B状态/PG88982/出站隔离前后保持。最终证据 `logs/security-controller-r6-final-20261126-r2-linux-root.log`；当前源/测冻结为 f269/b439，不用旧197/233代替本轮验收，也不把完整Linux守卫当双PG真实恢复矩阵完成。其余内核boot/回退/后续补丁、旧组件来源、双PG矩阵、当前完整包与主控新备份完整模拟恢复仍未完成，无生产/Git提交推送/发行，jimmasta仅申诉不上传。

## 2026-11-26 14:54：恢复源码已集成及真实终态补正

恢复r5c已写入两产品Python，SHA `07b172b1…` / `753881d0…`。独立Windows44方法、本机完整197方法（45项Linux/root跳过）均自然0；专用Linux3420完整197方法 **0跳过/0失败/自然0**，原B状态及PG88982保持。当前全量233计划/执行/通过、0失败、18分2秒、自然0。原7故障子例和旧基线失败保留，不能把下文r4未落盘文字当当前状态。

新的独立代码审查发现真实单工具缺口：自管PG start成功后，`database_runtime_proof()`依赖psql先取SQL，psql缺失/不可执行会使launch尚未持久，下轮拒绝这个无回执PID。正在最小修订为先保存原unit与真实进程启动事实，再执行已认证psql核验；必须补真正psql单工具缺失、权限和哈希变化回归，不用整体mock数据库取证代替验证。不接纳intent-only或陌生PID，不把旧settingsHash冒充新SQL结果。

项目内3.336GB和仓库外Go5.760GB已实际清理；14:54C余15.67GiB，在用本机PG11036保持。旧B17.47GB全只读SHA/身份/ACL/backing自然0已核，旧失败保留。AMD3394b仍cloud-init exit2/degraded，3412离线只读debugfs因inode bitmap checksum未打开文件系统，具体初始化原因尚未读到；不能放宽非零、认定原盘坏或重启旧失败盘。真实内核boot/回退/后续补丁、双PG矩阵、当前来源完整包及主控新备份本机完整模拟恢复仍未完。无新生产/客户/密码/Git提交推送/发行，jimmasta仅申诉不上传。详细阶段报告见 `docs/local-cleanup-and-security-progress-2026-11-26.md`；以下保留历史证据。

## 2026-11-26 接续：旧组件复建终态及三层实际原因已分开取证

`3386` 已结束，下面的两次 pending 是当时历史。原完成回执为 `not-reproduced`／native exit 1；生成的 ELF SHA `863da3a1…` 与参考 `040e3e9c…` 不同，候选没有被执行。旧 read 将首次状态失败与最终核验覆盖为通用错误，不能从该通用码推断原生编译原因，也不能因 fresh SHA 恢复便改写首次结果。

根任务独审 `3396` 的5来源、5证据和5份原核心文件，SHA／大小15份全部匹配；freeze SHA `e57b48cc…`。只执行一次原20130／原host-key的固定仅读命令，`logs/security-channels3396-real-r1-result.log` 自然退出0，明确：

- 原 native summary 的 `childExitCode=1`，`errorCode`／`nativeErrorCode` 原字段均缺失；两 ELF 不一致仍独立保留。worker-failure 是预创建的0字节文件，不能编造缺失错误。
- 原 completion 固化 `CHANNEL_DRIVER_STATE_VERIFICATION_FAILED`、`originalStatePreserved=false`、首次 SHA `6bdc5669…`。首次仅 `mountInfoSha256` 不同，其余7域相同；fresh 完整八域回到原 `3483d4e4…`，不是首次没有变化。具体挂载时序来源仍待核查，不先归因系统服务的私有 namespace。
- unit 前后均 loaded／failed／exit-code、MainPID0、ControlGroup空，无状态变化；当前 unit／child 清理确认。原 completion 的旧 cleanup=false 和首次失败保持，不覆盖原证据。
- 未调用旧 CLI、重新编译、执行候选或改写远端文件。后续仅准备两 ELF 的只读静态构建元数据对照，尚未证明完整原编译环境或原组件可信来源。

新 AMD `3394` 33专项、四语法及34／11项逆变换归一过，root原8份独审也匹配。根入口第一次把 `import.meta.url` 全文替换，破坏了 flow 内嵌源码字符串，import前被固定拒绝，无 main／prepare／VM；已改成原冻结 `heldEntrySource` 相同的 URL 前缀，只移除尾部自动CLI，保留 r1 失败。第二次正式调用 base-flow 在 preflight 阶段自然1，尚未创建阶段或派发动作；一次原准备器 plan 仅读已确认 `KERNEL_NATIVE_HOST_DISK_RESERVE_LOW`，不是 SSH 或客机故障。

C盘可用约2.010GiB，原AMD门槛3,246,931,968B，差约1.014GiB。11个旧内核阶段实际仅约60.9MiB，删除也不足且旧证据须保留。当前仅准备对已关机、可独占打开的旧B本机镜像做NTFS无损压缩的可审查工具：固定单文件、保持完整SHA／路径／FileID／ACL／逻辑大小，不删除或改字节，真实操作仍待root独审；共享原底盘、旧失败、活动clone和运行库保持。PG3398双独立环境准备的40个本机模拟已通过，实际创建仍待空间及最终独审。

36份产品源码不变，233全量与原155／40 Linux证据沿用。真实内核启动／回退／后续补丁、双PG矩阵、当前来源完整包和新的主控备份本机完整模拟恢复仍未完成。新账号jimmasta仅申诉、不上传；本轮未生产、客户、密码、Git提交推送或发行。下面保留当时阶段历史。

## 2026-11-26 接续：新组件重建已启动，首次 SSH 已前进到执行阶段

根任务接续核对原在途 `3387`，该轮已经自然结束。新日志 `logs/security-kernel3387-amd-flow-real-r1-result.log` 保留 `setup / KERNEL_GUEST_EXECUTION_FAILED`，`completed=[]`、仅一次 `setup` 派发、`ownedWrapperAndVmStopped=true`；原 QEMU8348、wrapper9896 及执行进程均已不存在。24 次初始候选的最后一次正确核原 host key 并 ready，`guestExecCalls=1`，初始有限 reset 处理已让执行前进，但正常 GRUB 磁盘启动和内核维护尚未通过。失败路径提前关闭日志可能丢失待写字节，不能用 setup 日志0字节断言没有 stderr。新 `3394` 仅加入固定执行阶段／退出值／信号／双流字节和 cloud-init 状态诊断，保原失败判定、原命令、单次执行及1800秒预算；未运行新 VM、不重派旧失败盘。

旧接入组件新 `3386` 已有根任务117份冻结／保护文件独审全匹配。根任务以持有并核验的入口 bytes 仅执行一次新 prepare，`logs/security-channels3386-real-prepare-r1-result.log` 自然退出0，输入完整且原八域状态 SHA 仍为 `3483d4e4…`。随后 `security-channels3386-run.mjs --run` 自然退出0，原专用 ARM 实验机上的独立 `security-channels3386.service` 已启动；两次完整只读查询均为 pending／active-running。真实逐字节 ELF 复建及最终八域／child／unit 清理仍在途，不把启动或 pending 写成复建通过。原生产、旧输入及所有失败证据保持。

ARM 独立受保护运行时的实际 r2 准备已自然成功，`logs/security-arm-runtime3370-prepare-real-r2-result.log` 明确111成员、10组进度、未启动 VM。新 `3390` 冻结回执 SHA `3c22689e…` 已交根任务：Python12、JS25及7文件语法自然退出0，限定差异逆向归一后与冻结3387完整字节一致；根任务尚待独审，实际 ARM base-flow 未运行。PG3345 的29份冻结／保护记录仍全部匹配；真正缺口是两台新独立 PG16 guest、16／18／19客户端包与真实身份／持续协调器。新 `3398` 仅准备最小本机可审查段落，不把104个模型回归当真实PG验收。

产品36份冻结源码没有新增变化，已通过233全量与原155／40 Linux证据沿用。后续仍需实际内核启动／回退／后续补丁、PG双VM矩阵、当前来源完整包、最终主控新备份本机完整模拟恢复。新账号 `jimmasta` 仅申诉、不上传；本轮没有新的生产程序、客户、密码、Git推送或发行操作。

## 2026-11-26 接续：目录绑定实测通过，首次握手取得真实重置证据

根任务已独立核对新 `3378` 冻结及保护材料共 34 份，SHA／大小全部一致，freeze SHA `c35f8d2c72e261298e733f9a8691cc6cc62eef84bf955779d49aa8da724c9040`。仅一次新 run 和自动 read 自然退出 0，`logs/security-channels3378-real-r1-result.log` 的 26 步全部成功、`failedStep=null`／`errno=NONE`；原 before、first-after、final 的完整八域均保持 SHA `3483d4e4…`，恢复次数 0、child／unit 清空，旧失败及输入保持。此项没有编译或执行候选；新的实际 ELF 复建 `3386` 正把同一 FD 修正接入真实路径，仍未实跑。

根任务独审新 `3384` 的 11 文件和 11 固定依赖后，以持有并校验的源码 bytes 执行一次全新 AMD stage。`logs/security-kernel3384-amd-flow-real-r1-result.log` 自然退出 1：仅 dispatch setup、完成列表为空，原 wrapper／VM 已确认停止。实际首次候选超时；第二候选在任何 host key 之前先报 `ECONNRESET`／`client-socket`，随后才报协议握手断开。握手记录 SHA `8f5bc43d…`、2 次尝试、实际 guest exec 0；串口 SHA `687008df…` 只确认 EFI／Limine／Linux/root 挂载。未完成 SSH／GRUB 或内核维护，不重派该失败盘。新的 `3387` 只收紧到 setup 初次连接范围、未观察或拒绝 key 的精确 reset 有限重试；其它连接、身份、鉴权、预算及未知回执边界保持。

ARM 源证明已完整覆盖 111 成员／85 个实际源包、4 固定固件、33 系统签名组件及 17 API-set。根任务对新准备器 14 份最终字节独审全匹配；原 manifest `c321e542…` 保持。root 第一次入口包装在 prepare 调用前，因将 Windows 路径 stat 与 FD 的不同 `st_ctime_ns` 域直接比较而误拒绝，未创建目标；只读核验差异仅该字段，模块加载成功。入口改为分别保存并复核两份完整 META，跨域仍严格核共同身份／内容；新 r2 准备正在原私有目录创建独立运行时，旧日志／目录／ACL 保持。未启动新 ARM VM；新 `3390` 固定运行时 ARM 流程在准备。

本批产品源码没有新增变化，不重复已通过的 233 全量／原 Linux 轮。后续仍为可信 ELF 复建、AMD／ARM 实际启动／回退和后续补丁、两个独立 PG VM 矩阵、当前来源完整包及新的主控备份本机隔离恢复。新账号 `jimmasta` 仅申诉，禁止上传；没有新的生产、客户、密码、推送或发行操作。

## 23:39 接续：最终守卫通过，目录绑定取得真实 errno

新账号 `jimmasta` 仍仅用于申诉，没有建仓、改远端、上传或推送。本批没有新的生产程序、数据库、客户或密码操作；最后生产版本证据仍为 `a241daf`／Agent `.10`。

当前产品输入的全量 `logs/test-run-20261125-231207` 自然退出 0：233 项全部执行、全部通过，15 分 22 秒，包含用户端和管理端类型检查。根任务在运行前后核对 36 份变更源码，全部 SHA／大小保持，记录为 `logs/security-root-final-source3378.json` 与 `security-root-final-source3378-after.json`。随后后端构建自然退出 0；重新联网的 npm 依赖审计 `logs/security-root-audit-20261125-late.json` 为 1021 项，各级已知漏洞均 0。这不代替系统包、真实启动和恢复验收。

根任务沿原 B pin 只读核对既有 `3318` 的真实 Linux 原生日志，没有重跑：kernel `e1324acc…`／test `b01f4aa6…` 原 40 项、无 skip、117.16 秒全部通过；原日志 SHA `a9526cae4a1911ccd4b2127061aec7e31cab2605dbc7a5bedb2a256b74d72712`。原 driver 回执的 122.904 秒包括外层操作，不把两个时长混用；其 PG18 客户端检查明确 unavailable，仍需后续矩阵。

新诊断 `3368` 四文件与保护输入共 18 份 SHA／大小经根任务独立核对，freeze SHA `6fc1c7f99862cd9a0ad962340bb7b14cd727759010c360abed7dd1efa59cbc71`。修正 Python／Node 先报告成功再清理的问题后，本机 Python 50／Node 30 项自然 0；根任务只执行一次新的 `--run` 和自动 `--read`，`logs/security-channels3368-real-r1-result.log` 自然退出 0：

- 独立 mount／network namespace、递归 private 和只读核验均成功；首个 `bind-sysroot-usr` 返回 **EINVAL**。
- 原 before、first-after、final 的完整八域均一致，SHA 均 `3483d4e4…`，恢复尝试 0；旧失败、原输入、child／unit 清理全部确认，没有编译或执行候选。
- 宿主子任务已核官方 Linux 6.12 的 `__do_loopback`／`check_mnt` 和 `proc_fd_link`：继承的 FD 保留原 `f_path.mnt`，不属于新 namespace 的源挂载被拒绝。新 `3378` 正准备在 unshare 后、覆盖目录前重新取得并完整核身份的目录 FD；尚未实跑，不把根因说明当修复通过。

AMD 的新只读 `3384` 独审修正 hash 后按路径重新 import 的漏洞：从持有并核验的原源码 bytes 加载，固定 `import.meta.url` 并仅去掉自动 CLI，原 `3352` 保持。25 项本机与真实临时路径换码／恢复回归自然 0；根任务对旧 `3364` 串口做一次只读实查 `logs/security-kernel3384-readonly-real-r1.log`，完整 SHA `2f70b712…` 保持，观察到 EFI、Limine、Linux 和 root 挂载，没有 GRUB／SSH／cloud-init 完成信号。该结果只说明串口记录，不证明 OS 从未启动，也不证明内核维护成功；新的首次握手事件诊断与有界执行器仍在实施。

ARM 运行时已只读解析 3 exe＋104 DLL 的静态闭包，并核 33 个系统组件的实际签名与所有者、17 个 API-set；官方索引、三 QEMU 包和两 ARM 固件有各自来源证据。其余旧版本 DLL 的来源映射、新受保护目录和完整准备器仍未完成，未启动新 ARM guest，不把静态闭包称动态运行通过。

接续顺序保持：新目录 FD 的真实最小复验与受信 ELF 复建；AMD 首次连接／真实 GRUB 和新内核激活、回退、后续补丁；受保护 ARM 运行时及同范围原生验收；两独立 PG VM 的跨 boot／16、18、19 客户端矩阵；当前来源完整包与新的同版本主控真实备份→本机→完整隔离模拟恢复。全部本轮实证和发行门槛未闭环，不热更新草稿或提前发行；GitHub 受限与新账号禁止上传仍分别保留。

## 22:23 接续：实际隔离失败已分层取证，后续测试继续

新账号 `jimmasta` 仍按 owner 最新要求仅用于申诉，本阶段没有建仓、改远端、上传、推送或发行。生产部署的最后已保存证据仍是完整 `a241daf`／Agent `.10`；本阶段只操作本机和已认证专用隔离环境，没有新的生产程序、数据库、客户或密码变更。

旧接入组件工具 `3342` 已完成独立同字节审查：冻结 JSON SHA `118718a22c753b8489af1616a65bc730bfb42827e12f4972c914e3c604fe2fa0`，31 份记录全部 SHA／大小匹配；93 项本机回归和三个入口检查自然退出 0。这只证明本机工具边界。原认证 Debian ARM 的新 `3342` 输入准备与 unit 启动实际退出 0，但 `read-native-r2` 的最终结果为 **not-reproduced**，原生退出 1，cgroup 已清空，不能写成旧 ELF 来源证明已完成。

固定只读观察器 `logs/security-channels3360-read-failure.mjs`（SHA `a65358579b2aef4f3f3a5fbb7aeb8ae3862c6991b6507c60c9aeedac5b28cc44`）实际自然退出 0，证据在 `logs/security-channels3360-read-failure-r1-result.log`：

- 原生 `summary.json`、`worker-failure.json` 和原生日志均为 `CHANNEL_NAMESPACE_BIND_FAILED`；不再根据最终通用错误猜测验签失败。
- `run-complete` 将该错误覆盖为 `CHANNEL_DRIVER_STATE_VERIFICATION_FAILED`，`read` 又覆盖为 `CHANNEL_DRIVER_FINAL_VERIFICATION_FAILED`。原生原因和最终状态原因须分开保留。
- 首次 saved-after 只在 `mountInfoSha256` 与 before 不同；本次 current 的完整八域均与 before 相等，saved-after 的摘要与原回执一致。历史失败标记没有清除，也没有把现态恢复视为复建通过。
- unit 实际 `exit-code`、cgroup 清空；未执行来源候选 ELF、未安装系统包。旧 `3262/3301/3334` 和新 `3342` 失败材料均保持。

下一步只对新独立 namespace 工具 `3368` 获取同参数绑定步骤和固定 errno，并核实际完整原状态恢复；该工具尚在本机实施，未实跑，不直接重派 `3342`。

内核初次 SSH 工具的独审发现本机 `ssh2 1.17.0` 实际错误级别为 `protocol`，此前 `3349` 的 `client-protocol` 模拟正例不代表真实错误已修。已保留 `3349` 与 50 项旧日志，另建 `3352`：工具 SHA `81a8351698bd11bf3b33487b188b09a20ffea02fffaf3af25b416f33ad891cfc`，fixture SHA `29be6d2eb64b365d249a0114030a5047c86eaa3f70b311029862b7f5377f24b4`。两语法和 52 项本机回归自然退出 0，并经独立同字节审查。新正例核实际依赖三文件 SHA、原 `makeError` 构造器和调用点；只在未观察任何 host key 时接受精确的初次握手断开。观察正确 key 之前的 ready 拒绝，拒绝 key 后静默超时仍拒绝。原 1800 秒 wrapper、300 秒观察、160 次和单次命令／未知重启回执保护保持。

AMD 新盘 `3354` 的 plan／prepare 实际退出 0，原 wrapper 启动 VM PID5684；主任务取证等待耗掉初始操作窗口，`setup` 在 `owned-listener` 被真实剩余时间检查拒绝，**未建立 SSH、未下发 guest setup 或内核维护**。这不是正常 GRUB／新内核验证成功。已按完整 argv、原父进程与持有的原生 process handle 精确停止该测试 VM：`security-kernel3369-stop-r1-result.log` 自然退出 0，21161 已无监听；原 wrapper 95038 最终自然退出 1／`processStopped=true`，失败资料保留。

停止工具的首轮 `3363` 因 CIM 只保留微秒、原生 FILETIME 多出 2 个 100ns tick 正确拒绝；`3369` 绑定本次已观察的原生与 CIM 两份完整整数和原父 PID，仍用持有的原生句柄执行，未扩大为近似时间或按 PID 盲停。两份原日志保留。后续 `3364` 正在实现原 wrapper 启动后立即接一次 setup 的有界流程，尚未实跑；不延长旧预算、不重派旧失败 VM。

ARM 对应新工具 `3353`／fixture 的 SHA 分别为 `7af367ad59ea7452c7010d1022659441577dc3a189a97ec61b2c2442cfea42c6`／`94a6928da008e57a10bd8e9c7ac6ac0b23202b5bef32384b46e63f33da04d4e8`。两语法、62 项本机回归自然 0，保原 21163、完整 preparer argv、五输入和 64MiB vars；**ARM guest 未启动**。实际只读发现原日志目录 ARM QEMU 有额外普通 SID 的 Modify 权限，SHA 相同也不当作安全运行时。后续先另建受保护、固定来源与依赖闭包的运行时，不修改旧目录／原 pin／旧证据。

当前 AMD 私有 clang bin 的只读 ACL 检查：243 叶文件只有当前用户与 SYSTEM；PE 静态递归闭包为 2 exe＋104 DLL，摘要 `535955b91d2318e92f993fd455cc2671452f62955d456940a88188a98aa58f78`，33 个系统库和18个 API-set 单列。原工具并没有固定这104个 DLL，这项观察不能写成真实动态模块加载或 ARM 闭包已验收。

PG Windows 外层模型 `3345` 已冻结：model `46ebf5787ef4b0a8508495ab7175875535e53df78ed6ae37b496ebc91138829c`，test `286b0dbcfe98b3e7f4215c0d38aad3c404dff1a73c5529b136dd679f860933bb`，freeze `0387c0dc840a308b0d27a2586d53e7c89ce91ab61882a81a5c11740342db41c0`。104 项本机回归无 skip、自然 0，五个错误身份探针自然 1；系统 PowerShell 保留真实 TrustedInstaller 所有权和系统签名，不改系统 ACL。真实两独立 VM、跨 boot PG16 服务／16/18/19客户端和最终同版本主控真实备份→本机→完整隔离恢复仍未执行。

本轮后续顺序：完成 namespace 真实失败诊断与最小修复；原预算内自动推进新 AMD 测试；准备受保护 ARM 运行时并实测；推进 PG／最终模拟恢复与当前来源完整安装包。此前全量233、155 Linux unit和旧发行预览只属于各自原冻结输入，不能替代本段新增工具、真实失败或剩余验收。

## 21:12 接续：旧接入通道精修与实际数据库复验

Owner 最新明确：新账号 `jimmasta` 目前仅用于原账号申诉，不上传或推送任何数据。本批继续本机代码与隔离验收；没有改 Git 远端、创建新仓库、推送、正式发行或生产更新。

独立审查发现旧 helper 的 `dnsProtocolVersion=2` 不能证明它支持新增内核维护。已精修为独立维护协议和两份固定模板的完整 SHA256；原身份与路由不变，缺失、异常或部分发布不派发内核操作，健康宿主只保存独立 `waiting-channel` 摘要。刷新先发布依赖、最后发布入口，释放原锁后从真实 helper 回读身份与能力。本机类型、原路由守卫、新行为段、Python 6/6、升级器 11/11 自然退出 0；原两模板未改，生产内核许可表仍空。精确 14 项文件 SHA 与前置失败证据见 `logs/security-gateway-maintenance-capability-20261125-results.json`，不能把该回执称已部署。

根任务对冻结产品独审后，在原专用本机 PostgreSQL 数据目录顺序运行四项：`host-kernel-maintenance`、`gateway-dns-channel`、`security-hardening-queue`、`host-security-maintenance`，全部自然退出 0，迁移入口亦 0。日志前缀 `logs/security-all-projects3220-20261125T130609445Z-`。覆盖旧通道零派发、受信能力恢复后续接、主健康回执/身份/限额保持、当前会话与撤销/授权锁，以及真实锁内维护时 HMAC 心跳可完成。真实旧外部 helper 升级与完整同来源安装包仍须另验。

内核旧 3335 失败证据已核：初次 setup 连接早于 DHCP/sshd 就绪，旧 VM 已由原期限停止，未执行内核维护。新入口 3340 只对初次传输拒绝/超时有界观察，每次比较原 PID、完整命令、创建时间和剩余期限，ready 后仅一次 setup；41/41 本机 fixture 自然 0，真实 Windows ACL/GNU timeout 范围明确，BusyBox/真实 boot 未代验。根任务已独审，新 3341 仅进入全新私有覆盖盘准备，尚未写启动/内核验收成功。

旧 channels 3334 失败的两项证据分别保留：缺 `/usr/bin/gpgv`，以及当时完整 mount snapshot 不同（随后已恢复相等）。Debian 13 的真实 `sqv` 官方源码已认证；它对显式输出执行 `create_new`，`/dev/null` 会失败，`-` 是真实文件名。旧 3338 probe 的 `filesWritten=false` 判定不准确：3339 已核 `/root/-` 的实际创建与完整字节摘要，原文件保留作为证据，不重写。新独立 3342 只修验签输出与固定受信工具选择，准备/本机回归中，原冻结及失败材料保持。

本轮新源码尚未热更新。实际双架构内核 boot/回退、旧 ELF 完整字节来源证明、PG3317 两独立 VM 多 boot/真实客户端矩阵、最终新同版本主控备份→本机→隔离恢复，以及新的完整发行验证仍未完成。下方全量 233/233 与旧发行预览只属于各自当时冻结输入，不替代上述新增源码和实际验收。

## 11:25 接续：最新全量与实际失败闭环

当前源码全量守卫 `logs/test-run-20261125-110346` 自然 exit 0：233 项全部执行且通过，17 分 43 秒。该轮包含最终主控产品 `2bc25161…`／测试 `dbaf0a04…` 的 Windows 155 项（44 项明确 Linux/root skip）；此前 `security-controller3296-unit-result.log` 已在真实 Linux 对相同冻结源码运行 155 项、无 skip、111.649 秒自然 0，原 B／PG88982／出站隔离保持。`security-agent3308-current-result.log` 本机 Go 全套自然 0。真实 PG16 服务与 16／18／19 客户端并存、跨 boot 安装及最终整平台恢复仍未执行，不由全量守卫代验。

内核准备器最新 19 项与启动器 10 项本机回归自然 0，日志 `security-kernel3303-prepare-final-result.log`／`security-kernel3303-launcher-final-result.log`。原完整 AMD3304 已在压缩前准备，恢复时再次 prepare 被原证据保护拒绝、没有覆写原私有文件；随后按原 prepared/proof 启动，QEMU12992／wrapper3524（11:04:08 创建）保持原 1800 秒上限。旧入口 read 在 SSH 连接阶段失败，未执行远端命令；本机串口只读固定字段核到旧内核 6.18.58-0-virt／登录提示，无 panic 或磁盘错误。不能把该 boot 当新内核或完整维护通过。

复审确认旧 setup 把动作最大时长当最低剩余时间，导致 wrapper 启动 120 秒后即拒绝配置。新入口 `b7ef6198…`／fixture `4bbb0ef7…` 保留总上限，按第二次真实剩余时间分配有界 whole-body timeout 并留后续窗口，补固定连接诊断；29 组本机回归（含真实 Windows ACL／GNU 无害超时）自然 0，BusyBox 和真实 setup 尚待，不扩大生产内核许可表。原四份 guest 产品 payload 保持。

channels3301 真实 prepare 自然非零，仅收到通用 `CHANNEL3301_REMOTE_FAILED`，日志保留。已定位测试入口吞掉执行器固定失败码的诊断缺口；子任务继续只允许固定 schema／枚举／阶段透传和只读 probe，不重试 bootstrap、不修改旧 VM。原 full snapshot 门槛保留。两子任务会话错误后已恢复原任务，文件和原失败记录保留。

Owner新账号 `jimmasta` 已记录，目标仓库和 CLI 认证尚未核实。继续当前修复，新的云端同来源验收与推送尚未进行；没有本轮生产更新、正式发行、密码轮换或客户操作。

## 07:35 接续：当前冻结与新验收补充

主控两Python已冻结：产品`d382eb54142d5d2d2d6341d17b10bb1ad59ee909a918a85e55d2d10630acd17b`、测试`a4a2f012bf09176ee31b3f60b3355c523d5a48f146b0f0d087624272dad81749`。本机Windows132项自然0，其中90通过／42明确Linux-root skip。原Linux`security-controller3274-result.log`132项中131通过／1失败，精修仅默认journal路径的测试adapter后，`security-controller3277-result.log`对原失败的1test／4故障cases自然0，原机器、backend unit状态和共享PG88982保持。准确范围是原131与新目标1覆盖闭合，不写整轮132自然0；真实libc／Node安装中断、PG配套包策略和Debian内核实际boot仍待。

宿主实际冻结为packages`e31761dcbf3ad90410c31c0fa2cfad0444dfd5706398e5716e1578124278d960`、musl`073a6394a7db13be9bf817e583ce9263a25bcf414693a0a9835b596c8d8a3013`、test`645424dbbe66596743b2c993a2ba1ce6b7948049803001295d5f5ca9ef73eb55`。独立DebianARM旧r2底盘使用经终审的真实pivot-root／独立mount+PID runtime，`security-musl-pivot-arm3272-result.log`原生`TestNativeMuslInterruptedOfflineReplay`193.72秒自然0：实际签名APK、文件与数据库两种提交顺序、原cache离线payload修复、完整plan/world、重复不变、维护先于工具修复均通过；原Debian快照不变。原chroot3271失败证据保留；该结果不证明AMD新原生、guest新kernelboot或生产更新。

来源工具旧静态7/7自然0（3275／ef21与48c237输入）；3276单独核官方Go1.27.3 ARMarchive及43份精确signed-index Debian包下载，未执行archive／安装系统包。当前新channels入口`2fb164ebac9e91c2a916bbf9ea27e7e2ff2b6b5dc2f6496df5ca07ebecf8dfc7`、tests`2eedba44dc6f79e2e29e7b62b5d11cf0f8c824aacebff582b8c934fd3d900f38`、plan`3b427d81c16ea1e2c5de06abd13d3b0010a7a3266d36cc0abbf56f60bcc855de`仅独立终审，11组新static/native与逐字节ELF重建仍待。旧Gitproof匹配旧commit的89文件，不能替代最新上传／全Git历史秘密扫描。

kernel产品与plan/native原冻结保持，新增`logs/security-kernel-native3273-*`三份工具仍为draft：继续修真实virtio-serial sysfs路径、核原ESP保留，GUEST_SHA最终冻结及独立终审前不可执行。双架构实际boot／回退／丢回复／后续patch仍未过，生产permit空。

owner已亲自确认GitHub账户停用，主智能体核最后成功push是04:17:50、94de16db；[最后推送与申诉事实](github-account-suspension-2026-11-25.md)单列。新的云端同来源验证／推送／发行受阻，本机代码与证据保留；已授权本地安全余项继续，不操作GitHub反复盲试，不将账号限制当历史CI失败根因。文档记录更新已过仓库来源守卫和diff-check，没有生产热更新或正式发行。

## 最终冻结接线与实际复验（2026-11-25）

继续使用原三个子智能体，分别独占主控两份 Python、宿主维护源码及备份来源独立终审；主智能体统一实际 Linux／PG、Git 与部署。最新 kernel 模板 `e811a024225360b5c67892e5dc70eee63e1c07158ae2ab575b1d37b34de184ee`、Python test `1d747cecf750a303f4bb8e2665132929d2c7de05cf984b4a1eb1dcfb6451c2ba`、计划入口 `d054fe1ce700553ca098194ea22e3fae2460cb0726d004fb7f58736be3908212`、native 入口 `7dec23708800347724dcdf3e3d913087212078c9bdbd6ba0014d3ca76782b3a3` 均冻结并经独立静态终审。模板 89200 字节，仅固定 kernel 模块明确支持 96KiB，不放宽其它原模块限制。

网关分别在两个非 `__main__` namespace 内编译固定源码、双向注入只读 guard，不从宿主 import、不运行第二个 main 或另取维护锁。旧 AppArmor helper `c5ae7cac509221ccc40dcc0c37e333aeae0526475dc1d6b8353e9dcafe9649c4` 只认 lstat 的 FileNotFoundError 为缺失，核完整原 schema 和精确 prepareHash；falsey／重复字段／bool version／dangling symlink／I/O 拒绝均不误判空闲。历史终态只核共同 nodeId／identityHash／architecture，不以旧客户、boot 或旧任务永久阻止之后的正常维护。

最终强类型旧 intent 与新 kernel fixture `058e924e67a80745e3b2dcc837212e8e41aa2192f44f6719348c4f7b43f8a1e9` 已在原本机 PG 数据目录、同专用库顺序复验：kernel、security-hardening-queue、gateway-dns-channel、host-security-maintenance 全部自然 exit 0，分别见 `logs/security-all-projects3220-20261124T214241541Z-*.log`；未删除历史库或改变客户。最终 server type-check 自然 exit 0，四对应守卫 `logs/test-run-20261125-054553` 全部通过，清单完整有效、232 项；该清单验证不是全量运行。

保持 B 原 SSH pin、PG PID 88982 与 nft 出站 drop，在新私有目录核输入 SHA 后实际 Linux kernel 35/35、旧 AppArmor 25/25、网关 9/9、刷新 8/8 无 skip 已自然通过。额外完整 onboarding 回归完成前 13 项后，千台逐项登记压力项耗尽整段 180 秒；整组退出非零，原失败日志 `logs/security-kernel3260-unit-result.log` 保留，不记整组／后续 Go 已通过。已独立核原机器、backend unit 状态、PG PID 与出站规则不变；定位到该测试逐次登记和回读千台记录的压力范围，在新日志中对未完成目标及之后两类回归做有限 900 秒独立观察，不重复已完成 13 项、不改产品门槛。不将这些夹具称真实 kernel 启动验收，双架构磁盘 boot／回退／丢回复／后续 patch 仍待，许可表为空。旧 Alpine VM 是外部固定内核加只读 ISO、进程已结束；不重建旧 pin 或把它原样重启称 guest kernel 已升级。

ARM 官方 Alpine 3.24.0／musl r2／APK 3.0.6-r0 实际 no-install fetch 复现 `logs/security-apk3257-arm-result.log` 自然 exit 0：旧精确 fetch 返回 package-constraints；recursive 精确 fetch 唯一候选、同 FD 验签与 loader 全通过，r999 零候选和额外候选拒绝。原 world／DB／loader／keys／inode／时间戳保持。此结果不是实际安装中断／离线重装验收；原 3255 提前版本格式断言失败材料保留。Go 最新三文件 SHA 为 packages `e31761dcbf3ad90410c31c0fa2cfad0444dfd5706398e5716e1578124278d960`、musl `073a6394a7db13be9bf817e583ce9263a25bcf414693a0a9835b596c8d8a3013`、test `17d4444e6195de905a925140934267968d9521c3c1f498186366530eff9bb36e`。

主控两 Python 的跨 boot／原认证 Node archive／原 dump 续接仍由子任务精修，最新草稿 Windows 111 项自然通过、30 项明确 Linux/root skip，最终冻结与真实 Linux／libc／Node 中断尚待。GitHub suspended／403 仍为已取接口事实，不能把它当历史 CI cancelled 的原因或全绿。没有本轮生产更新、发行或密码轮换；最终同来源完整验证后才原 worker 热更新、新真实主控备份本机隔离恢复与条件式发行。

## 94de16db 终态、失败与继续精修

阶段 `94de16db4b4d8e328f761c62fd04d621cd534d6e` 已推。完整无 tag 预览 `45480088932` 终态 success：双构建、候选 Agent、双首装／原 root worker 恢复、六旧 worker 升级／迁移留库／后半程回滚共 13 项成功，Release 预期 skipped。Agent `45479320541`、SSH `45479320786`、内存 `45479321082`、sysinfo 构建 `45479320535` 成功。主 CI `45479320637` 终态 cancelled（29 success，pool shard 4 job `138747887273` cancelled）。取该 job 日志时 GitHub REST 返回 suspended／403，job log 返回 404；尚未取得取消根因，不把接口拒绝直接当作 job 的原因，也不原样重跑。

原生 `45479320534` 为 failure（12/14）：AMD job `138749699177`、ARM job `138749699269` 完整日志分别保留于 `logs/security-native3249-amd-failure.log` 与 `logs/security-native3249-arm-failure.log`。真正 r2 与 bootstrap 后完整组保持已经通过，中断测试仍在 installer 前 candidate-fetch 返回 exit 1／unknown。独立复审定位 APK 3.0.6 将 `musl=版本` 整串作为 MATCH_EXACT 包名比较，且报错为单数；runner 此调用未丢 stderr。只改精确 atom 的 recursive fetch 与固定诊断，保单候选、同 FD APK 验签、Expected／architecture／origin／loader／原缓存。新 native 负例包含不可用版本、零候选与额外候选；新实际双架构中断仍未通过。独立 ARM 无安装 fetch 复现 3255 在版本格式断言提前失败，真实版本为 `apk-tools 3.0.6-r0,`，原系统前后完全保持；修正验收脚本后待新复验，不记已经安装成功。

内核旧冻结 `cb5e001f…`／Python `73327b00…` 在原 B pin 真实 Linux 25/25 无 skip，日志 `logs/security-kernel3254-unit-result.log`。3252 初次启动器要求 incudal.service 有 PID 而实际读到 0，在 Python 测试前退出；只修启动器并保留原服务状态，原 PG PID 88982 保持，不用该读取推断其它运行服务的健康。PG fixture 先后因非法 checkout source 与小写 StorageType 被真实约束拒绝；只修为实际 `direct`／`FTP`，冻结 `124d5313…` 完整内核 PG 守卫自然 exit 0，日志 `logs/security-all-projects3220-20261124T210924866Z-host-kernel-maintenance.log`。新 kernel 只读终态 guard／强类型 fixture 仍待终审与新 Linux 验证。

主控局部 `bc428209…`／test `d0dc4fa5…` 的真实 Debian 六组 dpkg conffile 自然 exit 0（一个 unittest 内六个 subcase）。完整 Linux 98 仍 2 failures／1 error，日志 `logs/security-controller3255-full-result.log`：主智能体漏上传原 worker example 辅助输入，已补；锁 fixture 未将 os.open 映射至临时 dpkg lock、新 payload proof 提前拒绝旧安装状态 fixture，子任务继续精修。新 boot／认证 Node archive／真实 libc 与原 dump 续接未冻结，不记完整通过。

主智能体接线继续：严格 kernel intent 与对应 resumer、claim／receipt 保留独立 kernel 摘要、健康宿主独立核验、固定双 namespace 网关 stdin 包装、仅 kernel 96KiB 上限及依赖先／entrypoint 最后发布。复审发现旧 AppArmor falsey／duplicate／version=True／dangling symlink／Python3.14存在性隐藏IO错误均可误判 journal，已最小收紧、只认 lstat 的 FileNotFoundError 为缺失，并补保留原证据及未知拒绝测试。Windows旧模板24项（1 Linux skip）、网关9项、刷新8项通过；新真实 Linux 接线／双架构 boot／回退／丢回复／后续 patch 仍待，许可表为空，不部署草稿或提前发行。

## 1ba6cd39 终态与本轮精修

已阶段提交推送 `1ba6cd397b13591b7c1bff05d069a1117c66f969`。完整无 tag 预览 `45468824080` 已终态 success：两架构构建、候选 Agent、两首装／原 root worker 备份恢复及六旧包升级／回滚，共 13 项成功，Release 预期 skipped。Agent `45468787172`、SSH `45468787002`、内存 `45468786936`、sysinfo 构建 `45468786871` 均终态 success。

同来源主 CI `45468786976` 为 **failure（29/30）**：job `138710747881` 的购买交付 fixture 只接受旧 operations 地址，新增所有项目缓存核验第一次请求便失败。完整日志保留于 `logs/security-ci3235-pool3-failure.log`。仅修精确 fixture 响应，补其他项目 pending、异常对象／状态与删除前新任务到达的真实 PostgreSQL 回归；`review-pool-provision` 已自然 exit 0。没有将外项目忙检查加入目标专属到期停删／续费查询。

同来源原生 `45468787284` 为 **failure（12/14）**：AMD job `138714321144`、ARM job `138714321204` 的 musl 回放在 installer 之前返回裸 exit 1，原完整日志保持。原 11/17 cloud root 的 musl 已为 r3，提前安装 Go 又引入 musl-dev r3，不能覆盖真正旧版升级中断；不能据此推断裸 exit 1 的实际 APK 阶段。两个子任务独立核验官方 Alpine 3.24.0 minirootfs：musl／musl-utils 均 r2、apk-tools 3.0.6-r0，无 Go／musl-dev。AMD SHA256 `de9a11c0e0e7e9c94db3ed8af7b450eafc0b13687bd7e9199d55050f20aa0a89`，ARM `4b8cd66a6688b2a87276c39843ed89c3a06d9534fc6a5823c586aff2696c1f2a`。新版固定该来源、明确断言 r2、保 bootstrap 后完整组不变，empty-pool 不安装 Go；cloud Python split 的原起点保持。

APK 准备、确认、原缓存和重装补固定阶段／枚举诊断并保原 error cause，不输出原 stderr／URL／argv。三 Go 文件最新冻结 SHA256：packages `5f942f8032f902341ae9c74366dd3086e1961694f857ecd99d9b7dbfeccf1c53`、musl `df5e1fe53430e9448fa5db5e7aac482f4d99831e6fc3effa3056eeb897202b3c`、test `b2912c2f5408f94d3e40d0cb425e0b2adb51a44752abf99f15eb2d29c1d96f47`。双 Linux 测试编译、AMD vet、server 类型、四守卫 `logs/test-run-20261125-040007`、YAML／两工作流 shell／原生 shell 语法通过；固定 pin 的 Linux 诊断回归 `3240` 自然 exit 0（实际测试 ELF SHA `d73707964c61edbce50e57a4da16821318c505420111be595365b249f8f6da48`）。新的实际 APK 原生中断尚待，不能记 musl 安装回放已通过。

内核八文件仍为独占草稿。B 上首轮 Python 20 项仅 9 通过，10 errors／1 failure 被真实控制节点哨兵先拒；产品保护正确，fixture 未隔离 B 的 `/opt`。仅修私有 fixture 映射、新增五种控制节点哨兵拒绝，新 21 项待验。内核 PG 首轮在种子创建触发 `HOST_CUSTOMER_CPU_EXCEEDED`，未到维护路径；仅按真实 E2／ARM1C 限额修 fixture、将准备阶段纳入精确 finally，新候选待验。保留原失败与历史 DB，不放宽业务触发器。Python test 新 SHA `a8d85a43fe3b4039335915d6897aab2ae8d7fc70445d123baccf951085e35800`，PG test `7b921618b1e193fd511abfb9f6b54f053f22a793aea964475d0bc1a58cef5a27`。模板 83579 字节超过旧单模块 65536 限制，需对固定内核模块明确有界支持，不能截断或冒称已经网关接线。

主控仅两 Python 草稿继续：完整 Before／Expected payload+control、原 fresh 签名 Expected 完整私有缓存及仅原 remaining 本地 deb 离线续接、conffile 预先固定原 Before／认证 vendor 过渡和原子恢复、持久安装意图中原程序文件缺失的有限同版本重装，以及新 boot 派生 nonce／追加 dump／共享 PG 原 PID。Before-only snapshot 仅定位原版本、固定 Debian13 keyring 签名链、规范单次同域跳转和原采集时 expiry；不安装 Before、不从历史 snapshot 获取 Expected、不重签原 proof。尚未冻结，真实 dpkg／libc、Alpine 双架构 boot／回退／丢回复、旧 ELF 字节来源和最终主控新备份隔离恢复仍未通过。

新 Debian 13 ARM 源盘／seed／instance-id 保持。QEMU 9.2 两次 Windows ntdll `0xc00000ff` 事件已核，不能归为 SSH 凭据问题；使用已有 11.1.3 后先因缺 PXE ROM 在启动前退出。只修隔离 VM 输入，不重建原 seed、磁盘或旧 pin。新 VM 首次身份核验尚未成功，Ubuntu B unit 不代替 Debian libc 或 Alpine boot。

## 03:15 接续：原来源终态与已验证阶段

来源 `259e5e64244bb8d785d8593f05d231bdc2b18641` 的主 CI `45455837072` 为 success（30/30）；Agent `45455837626`、sysinfo `45455837142`、SSH `45455837121`、原生 `45455837366`（14 项）及内存 `45455837481`（6 项）均终态 success。

完整无 tag 预览 `45455825327` 为 **failure**：AMD 首装含实际 PostgreSQL 18 接入通过，ARM PostgreSQL 16 接入也通过，六个真实旧 worker 场景成功；ARM 首装 job `138671699430` 在原 root worker 恢复演练失败。18:23:57.019 UTC 的 preview 成功后，观察器恰在 180 秒终止 launcher；原后端在同一时段正常完成受保护启动。这是 CI 恢复观察预算未与已修服务预算对齐，不能记作数据库接入失败，也不能把整轮预览写成通过。完整失败日志保持于本机 ignored 目录。

`smoke-platform-backup.mjs` 将同一原 worker 的单次观察与恢复续接观察设为有限 15 分钟，CI 外层总预算保持。观察失败只报告固定状态／错误码；加入 `protected_start`，状态读取失败明确为 `held=unknown`，不暴露系统命令或私密日志。实际 launcher 边界回归覆盖四分钟正常结束、恰一次终止、失败结果、不可读状态与秘密不输出；相关七项守卫全部自然 exit 0（`logs/test-run-20261125-030501`）。首轮回归曾因新测试漏闭合对象失败，已修并保留失败日志，未放宽产品断言。

整宿主维护、兼容、回池、磁盘准备／镜像卷清理及恢复清单改查 `all-projects=true` 的 operations；对操作对象和终态严格解析，不以 malformed 数据为空闲。未修改目标专属到期停删／续费操作查询。独立 PostgreSQL 的维护、客户恢复、回池、换机和清理均通过；末次维护复验另覆盖非 default project 的 pending image 操作及错误状态类型，全程零远端准备／重启。保留原本机 PG 数据目录和全部历史数据库，未代删客户。

宿主五个 Go 文件已冻结并通过独立补审；Windows Go 全套、双架构 Linux 测试编译与 vet 已通过。新版原生 CI 固定旧两架构 Alpine rootfs，检查 bootstrap 不提前升级 musl，再执行原签名缓存的中断离线重放与 LXCFS 激活；这批新原生运行仍待，不能以交叉编译当实际安装通过。

主控两个 Python 文件和宿主内核八个新文件继续实施／复审，尚未冻结。主控半安装跨 boot 按原完整签名计划、全 payload Before/Expected、旧拒绝事实保留和派生本 boot 权限继续收紧；内核自动 recipe 在双架构实际 boot／回退／丢回复通过前保持禁用。阶段提交只包含上述已验证批次，不收录草稿、不部署或正式发行。

## 首装验收的 PostgreSQL 服务选择

完整来源 `7f9dd2bbbcc5e7b6c43fa176cd62a57c8c5b47e8` 的预览 `45447982666` 在 AMD 首装 job `138642035662` 失败。ARM 首装和六个原旧 worker 升级／回滚场景成功；整个预览为 failure，Release 按无 tag 预期跳过。失败日志已保存，不把这些分项成功当完整通过。

精确失败点为数据库只读接入原生验收。该 AMD runner 的固定镜像为 `ubuntu-26.04`／`ubuntu26/20261116.202`，公开软件清单明确预装 PostgreSQL 18.7；现有安装器按原规则保留已安装的 16 及以上版本，而验收脚本写死 `postgresql@16-main`。因此实际后端健康时仍会读到不相干服务的零 PID，在真正连接超时测试之前失败。没有用更换数据库版本或强启额外集群掩盖失败。

`scripts/test-startup-database-admission.mjs` 改为先从原本机数据库执行只读 `SHOW server_version_num`，选择对应的受支持 `postgresql@16/17/18-main`，再指纹核验原数据库与唯一后端。两个真实 TCP 接入超时、错误密码恰一次拒绝、原身份／财务／配置哈希和进程保持条件均保留；新增失败阶段和固定错误码，原详细材料仍私密保存。

已通过 JS 语法及启动数据库安全守卫。原固定 SSH pin 的隔离 Linux unit `payincus-database-admission3217` 自然 exit 0：真实 PostgreSQL 16 两次超时后第三次成功、错误密码一次拒绝，原 Node／PG 和全部受保护文件保持。其实际源码 SHA 为 `7c0df4bf214822fcd47a8ef91764018bcdd4008f0e54e15f73489c0563760a29`，原生测试 SHA 为 `b154bd4ae9c2b18c719b4d6f9ee6a70cd9d34f5324f70b5b3847b88c97a882e6`。PostgreSQL 18 的完整首装复验仍须在新来源预览完成。

## 主控系统库与内核

独立下载并验证 Debian 官方 archive 公钥的固定指纹、InRelease 三份签名、AMD／ARM Packages.xz 的 SHA256 和六个实际 deb 的 SHA／size，取得 `libc6`／`libc-bin 2.41-12+deb13u5` 与 `systemd 257.13-1~deb13u1`。材料仅在本机 ignored 目录，没有生产安装，也不把受过篡改主控的包数据库当独立来源证明。

主控子任务正在实现仅作用于 APT／dpkg 子进程 PATH 的有限包装、原精确计划中断续接和受管服务库激活。未知 systemctl 请求即使被官方脚本的 `|| true` 吞掉，也必须留下拒绝事实；原共享 PG 不重启。已发现并继续精修 systemd 触发待处理状态、缓存丢失和错误后的原业务恢复。该部分未冻结／未验收，不能部署草稿。

Debian 内核另核实际 meta/image 包与运行 kernel 的 Debian package revision，避免同 ABI 更新漏报；不能把安装成功当新内核已启动。Ubuntu 不套用 Debian 专有版本标识。完整自动内核维护另按独立 recipe、原许可和实际双架构 boot 验收推进。

## 宿主基础库与并发审查

宿主子任务实现完整 musl 组、经过真实 APK 验签的 loader 摘要、原签名索引／完整软件包缓存和离线续接。Windows Go 全套、双架构测试编译、Linux vet 与相关守卫已过；原生中断回放尚未验收。

独立第三方代码审视又发现：APK 可以先替换 loader、后写包数据库；以及非 default project 的 operations 未被原空机核验涵盖。均已交回宿主子任务精修，暂不提交这份未闭环代码。完成必须核原计划内部分安装、精确原版本重装、所有项目实例及 operations；第三种 loader 字节或不安全权限不放行。

原生 CI 正在加入固定旧 Alpine 两架构源、真实安装中断和离线原缓存重放，随后仍核真实 LXCFS 更新。不能以交叉编译、测试被跳过或新 minirootfs 已更新代替旧宿主实际升级。

## 备份恢复与旧程序来源

备份验收工具回归 10/10、旧 channels 安全预检回归 5/5；进一步收紧逐表正常恢复效果、原身份文件 hash／权限、认证重签时间窗口和实际业务门禁。原归档全部 89 个文件已对照独立 Git 对象。旧 ELF 的实际原生逐字节重建仍未执行，源码一致不等于 ELF 已可信。

待最终完整候选热更新后，生成该版本真实主控备份、私密保存本机，在独立 B 的原受信身份和出站阻断内执行完整原 worker 模拟恢复。Owner 已明确本阶段没有配置云 OSS；真实 OSS 传输、公网整机失联和完整网关灾备另列未验，不混称通过。

## 接续纪律

每份子任务按文件独占；主智能体只将已验证阶段精确提交推送并跟进对应 Actions 至终态。先闭环本批 loader／全项目操作／libc 恢复，再推进内核接线和完整候选。局部安全清理与密码更换不等于失陷主机的整机信任恢复或所有秘密轮换完成。
