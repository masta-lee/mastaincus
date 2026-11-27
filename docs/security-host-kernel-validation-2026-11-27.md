# 宿主内核更新：包格式、空间与固定传输验收

日期：2026-11-27。本文记录本轮源码和隔离验证；真实双架构启动、回滚及生产自动启用仍需后续验收。

本批源码 `287c8527ce525be5d05b33d11f54c81a3c37d0e6` 已推 main 与工作分支。普通 CI `45990216078` 最终 30 项全部成功，独立 SSH 安全 `45990216229` 最终 9 项全部成功，完整预览 `45990416441` 最终 17 项必需任务全部成功，Release 预期 skipped。两个实际包独立下载／核心核验／完整归档复核均自然退出 0：AMD64 221404411 字节、SHA256 `380b705455cf49da04a16cf596b905b306043485483ee8c2eaa7eaec65335224`；ARM64 220466278 字节、SHA256 `677f89f23b65ec08036898ae26af6bcb8b716ed9bbe426a8119145d3debe8bff`。原 Ed25519、四类拒绝对照、321 份完整源码、root 权限、全部链接／祖先、ZIP CRC 与 gzip 尾块通过；6f32／6188／a101 在两包精确匹配，每架构仅下载一次。报告 `logs/mastaincus-preview-287c8527-artifacts/AUDIT_SUMMARY.md`。

## 修复

已认证的 Alpine LTS APK 还包含 `/boot/config-<release>`、`/boot/System.map-<release>` 与 `/usr/share/kernel/<flavor>/kernel.release`。旧解析器拒绝这些成员。新解析器只接受同一内核 flavor/release 的三条固定路径；`kernel.release` 的大小、完整 SHA256 和内容必须对应候选 release 加换行。原 APK 签名、datahash、路径、属主、权限和其它成员检查保持。

新事务保存三项原 metadata 的证明或明确缺失，先私有备份，再执行原已认证 APK。中断重入分别核对原值、已登记候选值和缺失状态；安装、启动准备、回滚、再次激活和终态归档均复核。未知修改阻止写入。旧 journal 未包含该字段时保持原结构及 plan hash。

空间判断同时计算旧文件、新候选及原子复制的临时占用，在首次备份和执行 APK 前分别核对根目录与 `/boot`。原 64/16 MiB 与 256/32 MiB 余量保留。新增负例覆盖旧 metadata 全部缺失、两个候选各 40 MiB、根目录或 `/boot` 空间不足，以及首次备份和 APK 前两个阶段；不足时原文件、包库、journal 与库存保持。

内核模板现为 108363 字节，超出原 96 KiB 传输边界。只将该固定模块的控制器、网关升级、网关读取及 native loader 边界统一为 128 KiB；AppArmor 的 64 KiB、其它 helper 的 131072 字节和 base64 的 174764 字符上限保持。维护执行完整读取两个固定模块，合法分片继续读取，提前 EOF 在宿主探测前拒绝。原 Web 鉴权、SSH pin、WireGuard 身份、锁、publish-last 和完整 hash 回读保持。

## 本轮证据

| 检查 | 结果与范围 |
|---|---|
| 最终内核源码 | SHA256 `6f32f757243c92080cf90e0a3860ec99780442b1fcd472d6cd78b863fee7b1de`，108363 字节 |
| 最终内核守卫 | SHA256 `e8cde413afe12e3cf63eed5830df25b935b6b64e4ccbe27d6c3aac28896e204e`，143449 字节 |
| Linux 内核守卫 | r6 的 `84ce968c…` 完整 84 项，308.611 秒自然退出 0，无跳过、无失败 |
| 最后特异性精修 | r7 单项的四个子例通过，7.467 秒；仅 APK 前根目录空间改为 300 MiB，使旧 256 MiB 判断可以通过而新版约 416 MiB 判断拒绝，其余 83 方法 AST 不变；原完整 84 项来源保留 |
| Linux 固定通道／升级 | r5 6 项通道与 13 项升级守卫，自然退出 0，无跳过 |
| Linux 实际 FD／发布 | 98305 与 131072 字节完整发布、回读和 SHA256 均通过；131073 字节在写入前拒绝；仅新临时目录中的测试身份 |
| 本机相关守卫 | security-hardening 与 host-kernel-maintenance-plan 通过；完整读取和升级子套已接入原 security-hardening 守卫 |
| 类型与编译 | server type-check、server build 通过；Python/Bash 相关语法与 diff 检查通过 |
| Windows 内核测试 | 84 项中 55 项要求 Linux 而明确跳过，单独记录，不作为文件系统验收 |

Linux r6 和最终通道 r5 均在原隔离 B 的具名临时目录运行，原 PG PID88982、真实 `incudal-backend.service` 的 PID93844／启动 ticks／InvocationID／NRestarts、boot、系统身份、包库、防火墙和所有测试输入前后保持。此前观察器采集的 `incudal.service` 实际未安装；真实后台保护从新 r6／r5 开始，不追认旧观察器已覆盖该后台。

完整日志及输入位于 `logs/kernel-package-metadata-20261127-r6-*`、`logs/kernel-package-metadata-20261127-r7-*`、`logs/kernel-module-128k-20261127-r5-*`；其中未脱敏材料不提交或上传。

## 保留的失败及后续门槛

- 原 82 项内核测试触及 270 秒外层观察超时，旧失败保留。新具名运行的 600 秒仅是测试观察预算，实际完成耗时 308.611 秒；产品命令、请求过期和清理预算不变。
- 网关完整 38 项的 r3 触及 90 秒外层超时，最后停在千宿主登记测试。r5 验证的是受影响的 6 项通道和 13 项升级，不声称完成这轮 38 项；同提交 CI 的完整网关测试仍需核终态。
- Windows 直接运行完整网关测试缺少 Linux `O_DIRECTORY`，其失败记录保留；Linux 通道／升级及实际受保护文件读写分别提供证据。
- 原真实 LTS 包解析的 3797 个成员通过，只证明该已认证包格式。新的 AMD64／ARM64 实际启动、回滚、旧内核保留和自动许可尚需完成。
- 双 PostgreSQL 实际 worker 矩阵、真实 Debian 13/glibc 2.41 系统资格和新的主控备份本机完整模拟恢复仍需完成。最后才按原可信 worker 热更新主控、验证并正式发版。
- PG 两次实际启动已分别暴露旧 QEMU `-drive serial` 参数和测试 runtime 缺少 `bios-256k.bin`。参数已修，固件依赖仍在准备可信来源及严格派生预检；两轮均确认只停止本次 QEMU，原盘、seed、B 和本机 PG 保护保持，未完成矩阵。

真实 H/D 首轮在测试 wrapper 的二次 100 KiB 输入绑定处拒绝，尚未启动 QEMU。新 wrapper 仅对该固定 kernel 核完整 SHA／108363 字节，执行原 main 的全部绑定阶段后在 QEMU 创建前停止的四组 old/new 对照通过。沿用两份未启动的 overlay 后，原 6.18.58 内核与原 SSH pin 实际启动成功；第二轮在测试 helper 的 `plan.sources` 循环再次使用默认 100 KiB 而拒绝，未确认任何 APK／GRUB／候选内核操作成功。两轮失败、停机和原 prepared 证据保留；接续已启动的数据不得再标成未启动或重跑旧 prepare。

复审漏点是只核了带 kernel 字面量的读取，未覆盖通用循环和 launcher/helper 二次读取。后续先枚举 prepare→wrapper→guest/helper→flow 全部受限读者，对固定路径、SHA 与完整字节用同一受限规则；测试完整安全 module-load 与所有 `plan.sources`，在 APK／GRUB 写入前确认实际新源通过，再进入真实启动。新增 pending guard 的可执行源码须来自已核 bytes／FD，不能先核路径再重开执行。该测试工具问题与已经通过的产品源码／CI／包分别记录。

备份版本只读审查确认 `manifest.version` 取实际 `version.json`，候选版要求完全同版；最后保存的生产证据是 `test.a241daf`，`test.994fff2` 只是历史。旧原备份只能先在同版原签名包恢复并核身份／财务／保护，再实测原 worker 升级到新签名候选。验证新恢复代码需从这个隔离升级后数据集生成真正同候选备份，再同源恢复；不改原备份 manifest，不把这份派生备份称新生产快照。最终候选可用 branch 的 `workflow_dispatch tag=v1.8.14-test.<7hex>` 生成测试资产，Release 仅在 `refs/tags/v` 时发布；不必提前发行或操作生产以绕过版本门禁。

最新已完成的前一批 `eca80074366852a5113752989cabf4077dbf3902`：普通 CI 45967552390 的 30 项与完整双架构预览 45968108311 的 17 项必需任务均最终成功，Release 预期 skipped。两实际包独立签名、321 份固定源码、权限、全部链接、ZIP CRC 与 gzip 尾块通过；包内为该提交的 `21a349…` 模板，不能把本轮尚未发行的 metadata 修复归入旧包。
