# 空闲机器池宿主可用内存调查

2026-11-19，主控正式v1.8.13/source629dca1f，宿主Agent v1.0.15。Owner指出seoul-amd-8/#136显示270 MiB、phx-amd-2/#56显示172 MiB，其他宿主也偏低。此次只读核主控、宿主/proc与cgroup，不重启、清缓存、修改参数、加载分析器或对客户做内存压测；没有修改产品代码。

## 结论

确有高占用问题，不能只解释为Linux文件缓存正常。E2实际MemTotal约966 MiB，客户配额768 MiB，配置中宿主余量约198 MiB；实际Agent与Incus常驻占用明显超过该余量。配额是客户的上限，不是提前给客户锁住768 MiB物理内存；未开客户时已高占用，客户满载需要与宿主竞争回收／swap，不能据目前没有OOM宣称全额稳定。

原截图来源是加固详情的检查快照，并非每分钟刷新的内存。#136快照2026-11-19 21:48约270 MiB，#56快照2026-11-19 00:40约172 MiB；但对照最新签名心跳与SSH读取后，数值虽变化，偏低情况仍真实存在。

## 实际证据

| 宿主 | 客户数量 | 30秒采样可用内存 | Agent RSS | Incus RSS |
|---|---:|---:|---:|---:|
| seoul-amd-7/#135 | 0 | 312–337 MiB | 309–324 MiB | 148 MiB |
| seoul-amd-8/#136 | 0 | 316–425 MiB | 218–309 MiB | 151 MiB |
| phx-amd-2/#56 | 0 | 186–284 MiB | 250–349 MiB | 224 MiB |
| sydney-amd-1/#21（另一次采样） | 0 | 约239 MiB | 306 MiB | 236 MiB |

三台周期采样每3秒一份，共11份；前置抽样另核MemTotal、MemAvailable、RSS匿名/文件、PSS、swap、内核Slab、cgroup及OOM计数。Agent大多数占用是匿名内存，不能归为可直接回收的文件缓存。#136在一次采样中Agent从218升至308 MiB，可用从425降到343 MiB；#56Agent峰值349 MiB同时可用降至186 MiB。

全池只读快照：134台一机一卖宿主，其中128台空闲E2、4台承载客户E2、2台ARM。128台空闲E2的78台加固快照低于256 MiB；2026-11-19 22:05最新签名心跳资源中72台低于256 MiB。最新#56约196 MiB、#136约323 MiB、#135约335 MiB。统计是该时点观测，不能推广为每台永久固定值。

## 已定位的主要分配来源

`agent/internal/provisioning/tools.go:67`约每30秒调用`incusCompatibilityStatus`，即使compat journal已verified仍执行。

`incus_compat_linux.go:93`调用`compatibilityBinary()`，后者读取内置gzip并经`io.ReadAll`解压完整64552560字节（约61.6 MiB）的Incus程序。随后`incusCompatibilityStatus`又用`os.ReadFile`完整读取/usr/sbin/incusd，比较两份内容hash。`compatibilityBinary`已经核完整清单和SHA，状态路径仍重复对解压结果计算hash。它不是必要的持续业务工作集，却按周期产生大块分配；已修复完成的宿主也不例外。

发布时`prepare-incus-compat.mjs`把对应架构gzip嵌入Agent，Agent现场文件约26.6 MiB；现场Agent匿名RSS达到192–323 MiB，明显大于嵌入文件本身。并非“程序包只有26MiB所以内存应只有26MiB”，也不能把这些匿名页称为普通文件缓存。

三台宿主THP均为`[always] madvise never`，Agent匿名巨大页位于Go堆映射，#135约270–280 MiB、#136约180–266 MiB、#56约200–294 MiB。大块临时Go堆分配、回收后驻留与THP膨胀是需重点验证的组合。现场无GOMEMLIMIT/GOGC/GODEBUG配置。未采集Go heap profile、未修改GC，因而不能声称已精确证明每一匿名页归属或持续泄漏；已确定的是周期状态检查存在不必要的整文件解压与读取，且Agent实际高RSS周期变化。

Incus本身另占约145–236 MiB，运行较久的宿主更高；未取Incus堆剖析，不直接断言Incus泄漏。LXCFS约1MiB、网关DNS Python约5–13MiB，均不是此次数百MiB高占用的主体。

## 客户与swap的实际影响

四台承载客户宿主65/23/97/63全部running；客户cgroup memory.max=805306368（768 MiB），memory.swap.max=0，客户配额没有被更改。

| 宿主 | 客户实际cgroup占用 | 宿主swap使用 | 宿主/客户OOM计数 |
|---|---:|---:|---:|
| osaka-amd-2/#65 | 约76 MiB | 约160 MiB | 0 |
| seoul-amd-1/#23 | 约185 MiB | 约199 MiB | 0 |
| cardiff-amd-1/#97 | 约68 MiB | 约229 MiB | 0 |
| singapore-amd-1/#63 | 约148 MiB | 约177 MiB | 0 |

Incus及其它宿主页已换出，Agent匿名RSS仍大；客户未接近768 MiB。当前无OOM仅证明本次运行态未出现OOM，不证明全额客户用量可以稳定交付。禁止以真实客户压测来验证这一点。需在专用空闲测试机上覆盖满额内存、持续Agent检查、实际创建/重装、swap与OOM及延迟后才给结论。

所有抽样机均有约1GiB磁盘swap。swap可缓解内存不足，但不能代替客户RAM，增大swap不解决Agent临时堆/THP高占用。`/proc/pressure/memory`在抽样机不存在，页面“内存压力 —”表示没有PSI数据，不是压力为零。

## 后续修复方向（尚未执行）

1. 周期状态检查读取一次已验证的嵌入清单/摘要；已安装Incus使用有界流式hash核内容，持续检查篡改而不整文件解压/读入内存。真正需要安装/替换时才解压payload，保留完整SHA、架构、原进程/客机/权限和回滚保护。
2. 把安装／替换分配也改为受限流式写入与校验，避免为了校验同时保留多份完整64MiB内容。不要通过取消校验减少内存。
3. 先核优化后的RSS/PSS与堆、THP、GC回收；仍需参数时仅针对平台Agent设计适合小内存机器的预算，不修改客户内存限制或全局关闭宿主/客机功能。GC软预算不等于RSS硬上限。
4. 详情明确显示加固采样时间，实时资源沿已有Agent resources使用正确口径；界面修改不能代替实际内存优化。
5. 真正验收E2满额768MiB时的宿主剩余、管理/Agent/创建/重装/停启、swap/OOM与性能，覆盖新接入和全部已有宿主自动升级；不得只重启一台或清缓存后短时截图当修好。

完整只读数据保存在仓库外私有证据目录，ignored本地调查脚本没有注入生产服务。此次未改Agent/服务/宿主/客户配置，未commit/push/发行/OTA。需owner明确开始修复后按上述范围验证。
