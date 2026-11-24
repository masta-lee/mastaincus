# 安全剩余工作：并行精修与实际验证

本记录区分源码、工具回归、真实 Linux、完整发行预览及生产部署。Owner 已授权三个子智能体并行工作；主智能体统一整合和操作测试环境、Git、主控热更新。生产程序仍为完整 `v1.8.14-test.a241daf`，本批尚未热更新或正式发行。

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
