# 悉尼／圣地亚哥宿主接入只读调查

调查日期：2026-11-16，以下人工时间均为北京时间。Owner要求本次只查因和写报告，不修改产品代码，不执行校时、重启、维护或接入重试。后续Owner自行放开悉尼所在VCN出站规则，要求观察程序是否自动恢复；这项变更由Owner执行，agent仅查询。

## 已确认结论

两台悉尼在主控v1.8.13/source629dca1f的接入准备阶段被拦。不是主控界面漏显示内网IP：`hostId`、`managementIp`和资源检测结果确实均为空。程序在校时／准备密钥完成之后才向网关申请管理IP，因此此时尚未创建管理隧道或安装Agent。

两台真实系统均为Alpine3.24.4，chronyd4.8运行，ntpd已正常停止，crond运行，DNS能够解析pool.ntp.org和ipinfo.io。chrony配置只有发行版的`pool pool.ntp.org iburst`，没有OCI内部NTP源。

02:00前的真实证据：`chronyc tracking`的Reference ID=00000000、Stratum=0、参考时间1970、Leap status=Not synchronised；sources中8个公网源全部`^?`、Reach=0、没有任何样本。宿主日志分别在01:25:41／01:27:09明确写`Can't synchronise: no selectable sources (8 unreachable sources)`。同接入脚本的只读`chronyc waitsync 6 1 0 2`连续6次refid=00000000后exit1，直接复现当前阻断条件，不执行调时。

网络查询对照：公网162.159.200.1、203.14.0.251、168.138.12.93的UDP123均4秒超时；OCI内部169.254.169.254均约1毫秒收到48字节mode4、stratum3、leap0正常NTP回包。ipinfo.io的IPv4HTTPS连接也超时；IPv6查询无AAAA响应。宿主无已安装nft／iptables-save，无法据此单独判断云安全列表；Owner随后确认VCN未放开出站。这是现场已确认的直接原因，不是DNS、缺chrony包、服务没启动或时区导致NTP失败。

Owner放开出站后约02:03再次只读测试：上述三个公网NTP在1–13毫秒正常回包，两台ipinfo.io均HTTP200、timezone=Australia/Sydney；网络恢复已有实证。此时chrony仍未拿到新的自主样本，需等待其下一次poll与平台自动重试，不能将查询收到NTP回包当成chrony已经同步／接入已完成。

## 自动重试是否在工作

01:46左右两台attempt=8，01:50左右=9，01:56左右=10，02:01左右=11，持续queued→running→queued且同一任务、同一SSH指纹保留。不是任务停止或旧租约死锁。代码退避从15秒增至最大300秒；每次重新执行同一校时准备，并不替换不可达的时间源或强制让已经启动的chrony立即burst。公网源不可达时，同样输入的重试不可能自行成功。

两台临时接入凭据均有效至11月17日01:22左右，取证时未到期；无需以重复创建任务解决本次网络问题。观察期间等待自然重试，不点击重试或重启服务。

## 圣地亚哥等待的具体原因与时间线

`santiago-amd-2`为宿主74，01:26:02排队，01:28完成安装，AppArmor内核支持存在但未激活，需要固定安全维护方案及重启。程序的维护并发是全平台单台：所有其他宿主未完成的维护记录都阻止启动下一台维护，不仅限同接入批次。

实际等待日志18293／18304／18327分别在01:31:16、01:33:41、01:35:46。与真实维护历史逐项对齐：

| 74被阻断时刻 | 正在维护的宿主 | 该维护实际完成 |
|---|---|---|
| 01:31:16 | santiago-amd-1／73，01:29:16开始 | 01:32:49 |
| 01:33:41 | stockholm-amd-1／75，01:33:37开始 | 01:35:32 |
| 01:35:46 | stockholm-amd-2／76，01:35:43开始 | 01:37:35 |

74随后01:37:49开始自身维护，01:38:53持久记录reboot-intent，01:39等待重连时一次暂未取得远端结果，01:40:13进入恢复核验、01:40:32维护verified。01:40:43隔离及SSH加固通过，之后等待Agent有效网络防护回执，01:43:05接入succeeded/done。02:03只读确认online、Agent1.0.15、防护/工具回执有效、无隔离、真实库存查询可售。Owner报其已恢复，与实际记录一致。

这次没有永久维护死锁；等待主要是已有多台的单台重启队列及自身重启／回执核验。页面仅显示“已有未完成维护”缺少阻塞宿主／阶段，难以分辨正常排队和异常；日志和当前UI不直接记录阻塞目标。现有查询按created_at优先，在另一维护刚结束后新登记机器也可能先开始；74这次被后登记的75/76先处理，需要在后续修复阶段评估公平排队，不直接削弱单台维护保护。

## 源码审查与待改进项（本次未修改）

1. `server/src/services/onboarding-scripts.ts:55`至66将时区助手失败、NTP服务启动失败和waitsync超时都归为HOST_TIME_SYNC_PENDING。主控只保存同一码，无法在页面区分实际步骤。
2. `server/src/services/onboarding-ssh.ts:50`丢弃远端stderr；waitsync stdout/stderr又被重定向至/dev/null；`hostOnboardingWorker.ts:347`只给hardening阶段持久记等待日志，tunnel阶段失败只更新node错误码。本次后台日志按两悉尼名字只找到创建记录，缺少每轮失败诊断。
3. 新接入仅用发行版默认公网pool；已有OCI内部NTP可达时仍不采用，应后续考虑识别OCI并查询验证内部源、保留原配置、记录源可达性与时间质量，再自动续接。出站不通时也应指出实际NTP/HTTPS连通问题；不能用跳过同步验收冒充成功。
4. NTP和时区是不同事情。ipinfo.io失败按当前助手设计非阻断，保留定时重试；本次HTTPS不可达解释了时区receipt缺失，但直接阻断经只读waitsync复现为NTP没有样本。
5. 开放出站后，chrony先前退避的轮询可仍延迟恢复。后续可以评估在已确认网络恢复的原daemon上安全触发采样的自动路径；本次不触发burst、makestep、restart或任何写入。

另发现主控独立校时观测异常：incudal-clock服务active，系统timedatectl报告NTPSynchronized=yes，但程序status.json持续synchronizing；chronyc查询exit1，journal记录chrony.drift.tmp Permission denied。此项是额外待查，不是本次悉尼NTP全部不可达的原因；本次未修复或重启主控。

## 恢复观察

Owner放开VCN出站后，agent持续只读观察，未点击重试、安装或维护按钮。两台均在原任务第12次尝试自动越过校时，后续接入终态如下：

| 宿主 | 主控编号 | 分配的管理IP | 完成接入 | 最终状态 |
|---|---|---|---|---|
| sydney-amd-4 | 79 | 10.253.240.67 | 02:12:43 | succeeded/done、online、可售 |
| sydney-amd-3 | 80 | 10.253.240.68 | 02:17:02 | succeeded/done、online、可售 |

第4台先于02:09:30开始自身AppArmor维护，02:10:46记录重启意图、02:12:29维护核验通过；第3台按全局单台维护保护等它完成，于02:12:43开始自身维护，02:14:00记录重启意图、02:15:43维护核验通过，最后等有效Agent回执于02:17:02接入完成。每台仅有一次reboot-intent，没有反复重启或失联后新建任务。

02:17:26主控只读确认两台的Agent1.0.15心跳、防护和交付工具回执有效，poolFaulted=false、publicIpSyncBlocked=false、空闲库存查询通过。02:18:11经原登记SSH指纹与原管理公钥回读宿主：两台timezone均Australia/Sydney、时区receipt已正常创建，AppArmor enabled=Y、Agent服务started、Incus list为空。第3台chrony Leap=Normal、Stratum4、偏移0.000023748秒；第4台Leap=Normal、Stratum3、偏移0.000069207秒，均已选中实际公网NTP源并有连续样本。

因此这次出站规则放开后，原代码完成了自动恢复；两台悉尼的校时卡点与缺内网IP均已解决，圣地亚哥也保持已接入。该结论指接入与空闲可售门槛，没有购买客户实例或用此观察代替客户业务测试。保存的完整JSON/私有诊断位于仓库外`C:/Users/adminuser/.codex/private/payincus/hardening29/`，报告不含密码/token/密钥。

产品源码与Git状态未改；本次仅新增本报告和ignored本地只读调查脚本，未commit/push/tag/OTA，也未代改云安全规则。
