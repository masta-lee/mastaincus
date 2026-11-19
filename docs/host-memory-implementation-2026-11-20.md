# 机器池宿主内存自动优化实施方案

Owner要求再次测试彻查原因、给出优化建议和实施方案、实现持久化自动优化。本轮保留客户768MiB配额、原实例/磁盘/密码/网络/账期及所有原签名和身份保护；当前生产仅只读，不在客户机器压测、不清缓存、不重启Incus或客户。实现不能以数字变小或增加swap替代实际RSS/PSS与稳定性证据。

## 根因与选择

前轮现场：Agent每30秒完整解压约61.6MiB内置Incus并整文件读取已安装程序，产生大量暂时Go堆；Agent匿名RSS约192–323MiB，THP巨大页占约180–294MiB。Incus另外占约145–236MiB。128空闲E2中72台实时available<256MiB。四运行客户当时仅68–185MiB，已有宿主swap160–229MiB但OOM0，不能作为客户满768MiB成功证据。

本轮本地同编译器/同64MiB输入对照：旧解压路径每次TotalAlloc165527826字节（约158MiB），流式78594字节（约76.8KiB），吞吐未变差。此项为分配基准，不等于线上AgentRSS已降低。

## 已实现的源码

1. Agent启动首次以流式验证immutable嵌入payload完整大小、架构、固定来源和SHA，内存仅保留小manifest；之后周期检查每次流式校验已安装Incus完整内容，保留漂移检查。缓冲32KiB，避免重复解压或把64MiB文件读进Go堆。
2. 真正安装/替换时以同样流式解压写入临时文件、校验、fsync及原子替换；原程序备份和恢复也用流式拷贝，核原SHA、读前后size/mtime/ctime、root属主/权限、不可软/硬链接、原进程与客户记录保护。失败不留下可作为完成证据的半份备份。
3. Agent每次启动自动按min(物理内存, cgroup-v2祖先限制)的1/16设Go软内存预算，32–256MiB；E2约60MiB。明确GOMEMLIMIT优先，不覆盖管理员设置。仅Agent的Go堆GC/回收，不修改内核THP、宿主swap、客户cgroup或服务硬MemoryMax。目标预算不是RSS硬上限，ELF文件映射等仍需实测。
4. 修改编译后的同架构Agent后，新安装/重启/升级均自然执行预算；无需每台手工填写参数。正常检查仍有界持续运行，失联不停止安全自修。

Incus高占用后续按原生堆/压力证据判断，当前不盲目重启、强制GC、改内核或调整客户配额。UI加固页现是历史采样，实时值沿已有Agent资源；本轮优化真实资源，不先改UI掩盖。

## 验收与状态

本地manifest/损坏gzip/超长与短数据/校验值/双ELF架构/取消/多gzip成员拒绝以及小缓冲分配测试通过。Windows的Go不能运行现有Linux-only完整Agent，使用双架构Linux编译检查；root文件/安装/回滚及持续RSS需原生Linux证据。host-provisioning-tools、pool-disk-isolation、customer-isolation三相关守卫已通过。

新增双架构原生Incus验收：原旧daemon到修复daemon、正常/已有准备/回滚再试/空池/重装/前代回滚保留全部；空池再跑实际已verified状态20轮分配守卫，以及相同真实payload的旧/新路径20轮RSS/heap/GC对照、预算连续临时分配测试。需要核所有job自然终态和实际日志后才说原生通过。

本地一次性QEMU在执行测试前退出（无产品日志，退出码3221225727）；旧测试VM未启动，未因此访问生产写入或DD已删资料。改用CI一次性原生AMD/ARM验收，不把本地模拟绿当现场生效。

当前还需原生/完整Agent检查和专用满768MiB压力验收；生产新Agent未部署、未发布新版本。实际自动升级的候选部署与全部宿主验收按本轮授权明确推进，不用旧v1.0.15运行态声称修复已生效。

## 双架构原生阶段结果

源码97ae0734的Alpine运行44561714405全部14job自然success，含两构建与两架构各6场景。Agent运行44561714476全部7job success（PR，不公开发行）；SSH运行44561714588全部9job success。完整CI44561714849尚在运行，不提前记通过。

| 实际同payload工作负载（20轮） | AMD64 | ARM64 |
|---|---:|---:|
| 原已verified状态分配/次 | 36,377 B | 36,298 B |
| 旧工作负载累计分配 | 9,726,874,832 B | 7,980,281,376 B |
| 新流式累计分配 | 676,336 B | 675,352 B |
| 旧采样RSS峰值 | 323,196 KiB | 233,508 KiB |
| 新采样RSS峰值 | 30,012 KiB | 27,776 KiB |

这是独立核验测试进程的结果，不是完整Agent或线上全池结果。自动GC持续分配测试实际runner预算256MiB，通过；其不能代替E2约60MiB验收。

补只读线上同一时点Incus /1.0/metrics与smaps：135/136/56/21的活跃Go堆约6–13MiB，Go保留Sys约56–63MiB，但RSS约150–241MiB，匿名THP约68–130MiB；ARM53的Go活跃堆约8MiB而RSS325MiB、匿名THP162MiB。文件映射、Go及C/SQLite/LXC等匿名内存共同构成RSS，尚不具备逐C分配归因，不将其一概称Go泄漏。证据为仓库外compat-host-memory-20261120-incus.json。

新增隔离压力工作流host-memory-native.yml：实际完整Agent、原固定来源Incus、aggregate cgroup memory.max=966MiB及宿主swap=1GiB，真实客户容器仍768MiB且swap禁止，持续至少752MiB charge三分钟；校验签名心跳/完整compat核验/原UUID/PID/磁盘/无OOM及停启重启重装删除。它使用共享runner内核，不是原生1GiB OCI整机；真实物理E2的内核余量/长期满载验收仍需后续专用机器。两个既有专用SSH入口本轮未通过原pin连接，未绕过身份。新增测试尚未运行，生产未更新。
