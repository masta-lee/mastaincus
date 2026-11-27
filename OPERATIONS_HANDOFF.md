# MastaIncus 操作与发行手册

先读 [OWNER_REQUIREMENTS.md](OWNER_REQUIREMENTS.md)，再读 [AGENTS.md](AGENTS.md) 与 [HANDOFF.md](HANDOFF.md)。当前状态集中在HANDOFF；本文件只保留操作入口、边界和流程。原完整阶段记录保存于[历史操作台账](docs/archive/handoffs/OPERATIONS-through-2a0309c0.md)。

## 维护来源与正式资产

唯一仓库：[masta-lee/mastaincus](https://github.com/masta-lee/mastaincus)，PUBLIC，默认main。原正式v1.8.14、配套Agent v1.0.16及原签名/校验/tag保持；开发源码的后续安全修复尚未正式发行。新仓库延续原分批提交、CI、候选测试、正式发行流程。

匿名首装：

```bash
curl -fsSL https://raw.githubusercontent.com/masta-lee/mastaincus/main/scripts/install-panel.sh -o install-panel.sh
sudo bash install-panel.sh
```

新脚本支持精确识别并迁移已安装旧官方仓库值，保留自定义仓库与原凭据。用于匹配退役值的历史代码不是当前下载入口；禁止机械替换匹配值、重打旧包或重新seal使不可信内容通过。

原官方安装的更新来源配置：

```dotenv
SYSTEM_UPDATE_RELEASE_REPOSITORY=masta-lee/mastaincus
INCUDAL_AGENT_RELEASE_REPOSITORY=masta-lee/mastaincus
```

## 部署与更新

- 私有业务后端只能有一个Node进程，监听127.0.0.1:3001；用户端与管理端独立源和cookie域。
- 安装根为/opt/incudal，原子OTA使用releases与current软链。原程序/服务/平台/WireGuard/SSH身份保持。
- 已有原子布局使用管理员“版本更新”及原OTA worker；install-panel.sh --upgrade仅供旧式非原子布局。
- Node24 LTS / pnpm9.14.2 / PostgreSQL16；运行版本与已加载库须实证，不按安装版本推断全部生效。
- 安装/OTA/签名组件或发行前必读[v1.8.7事故复盘](docs/postmortem-v1.8.7-upgrade-2026-11-12.md)，保留双架构原旧worker正常升级、已迁移状态、后半程故障回退再升级和实际tar完整核验。

当前授权为源码精修、阶段提交推送、对应隔离/指定测试账户验收，验证后的完整可信主控热更新及条件式发版。主控现场源码/配置补丁、人工清故障标绿、放宽未知身份、生产还原/DNS/客户数据操作不在此次继续范围。RUN_DB_CHECKS=0只能在owner明确批准时使用。

## Private Backend Must Run As A Single Instance

The private backend at `127.0.0.1:3001` must run as exactly one Node.js process. Treat a second backend replica as an unsupported deployment. Before enabling multiple processes, move the process-local locks, nonce replay protection, delivery finalization and configuration cache to shared storage with coordinated invalidation.

## 测试与发行顺序

1. 先读受影响代码与守卫，只改必要问题；同批源码冻结后运行对应类型/守卫和可执行实机验证。
2. 验证通过的实质批次提交推送main及工作分支，核完整远端SHA。
3. 跟进同提交CI，读取失败日志并修根因；完整双架构预览的必需job全部成功后，独立核实际包签名、SHA、来源、权限、链接与完整尾块。
4. 全部本轮相关项通过后，原worker热更新完整包并验证原钱/权限/身份/客户与指定账户流程；发现问题精修复验。
5. 最后正式tag/发行并核公开资产。Release预期skipped、台账提交、静态测试或候选包不代表正式发行或生产生效。

测试窗口须先备好可执行修复/继续入口，再启动。原失败/旧窗口保留；不要因观察超时就重复启动或用新测试预算放宽产品限制。

## 连接、备份与资料

- 主控/测试机的完整资料保存在 C:/Users/adminuser/.codex/private/payincus/TEST_MACHINES.md 和 ssh-connections.private.json；先复用原身份，不打印/提交密码、token、cookie、私钥或原始数据库。
- Owner已自行轮换主控SSH密码；不使用旧聊天密码或添加新公钥。此前DD机器的IP/密码已按要求删除，不复用。
- 本阶段恢复验收使用真实主控备份保存本机后的隔离模拟，生产未配置阿里OSS；网络隔离先于解密和恢复，保留recoveryHeld。
- 原3116备份应用版本为1.8.14-test.a241daf，先用完全同版原签名包首装/恢复/核账目身份，再另验原worker升新候选；不得改旧manifest/version/tag、重seal或先生产热更绕版本门禁。
- 平台备份不含客户VPS磁盘；恢复面板不能重建客户磁盘、重置密码、账期或网络。

## 当前未闭环

原安全20项中17项已有源码及对应验证，S11/E03/E04仍有完整恢复、系统自动生效与内核实启回滚缺口。具体结果、CI运行和下一步以[HANDOFF](HANDOFF.md)及[当前实机进度](docs/security-validation-progress-2026-11-27.md)为准；不从旧历史“在途/待审”字样推断现在状态。

历史操作台账原文SHA256：82aabc8ca80d73a372275c2f48b34122d2b25fac8d40e1f8197b5a5c597180a0。
