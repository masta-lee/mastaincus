# 注册、管理员删除账户、通知与密码刷新

本批源码与候选包、双架构升级、主控候选与现场流程已完成验收，正式 v1.8.12 发行待。前一版 v1.8.11 的发行与实测记录保持独立。

## 主控只读发现

Owner 提供的 IP 在 2026-11-13 21:17 至23:32北京时间有11条成功注册记录，其中7条在约4秒内。所涉账户当前全部封禁，无实例。注册开放、邀请码关闭、Turnstile关闭、SMTP开启。仅查日志和配置，未代删或修改这些账户。

短时防护失效来自路由限流配置安装顺序：限流插件的 onRoute 已读取默认配置之后才写入接口策略。现将策略钩子放在插件之前，查询参数归一，保留代理受信边界；真实 Fastify 插件验证同IP注册3次/分钟、验证码5次/小时及伪造转发头、查询参数不能绕过。

## 最终实现范围

- 按受信 request.ip 限制滚动24小时成功注册3个，可在后台调整。IPv4映射IPv6归一；IPv6同/64计为同源。事务锁、成功创建与计数同事务，删除账户不重置计数。升级SQL从过去24小时有效注册日志回填，旧/无效地址安全排除。启用但配置不完整的注册验证不再默默降级。
- 仅管理员有删除入口，桌面和手机均有浏览器原生最终确认。禁止自删及删除管理员；拥有宿主/套餐等运营服务者提示先转交。接纳后封禁与撤会话，取消未付订单及转让，原付款人转让手续费只退一次。逐实例沿原受信身份执行停止、删除、卷/快照/转发不存在核验，再确认回池；未完成保留账户、账目和资源占用。历史快照/普通反代意图交由完整删除续接，正在运行的资源任务保留门禁。所有实例均继续检查，单台失败不阻断其他实例。
- 清零余额并删除目标账单、订单和账户。已确认付款和迟到付款仅保留不可逆流水摘要防重复入账。其他付款人的账务保持；必要的已删除实例历史记录归当前管理员，密码清除，无运行容器。注销或管理员权限变化时暂停破坏动作，可由有效管理员重新确认续接，原UUID/删除步骤保持。
- 普通用户TG、站内信与个人webhook剥离宿主/OCI/内网元数据和原始运维错误；托管收入、流量、全局资源通知单独补边界。管理员告警只选当前管理员所属渠道，保留详细分行HTML。Telegram同时核HTTP与body.ok，转义后的负载有界，避免截断转义/Unicode；受控测试不向真实用户发消息。
- 重装密码以加密凭据版本失效缓存，可见密码自动重新读取；旧路由/会话/请求不覆盖新密码。手动重置同样失效旧读取；明文密码接口no-store，仅实例所有者/管理员能读凭据版本。

## 已取得的证据

最终 `logs/account-full-tests-final.log` 225/225成功。随后小补充把PENDING任务取消移至同一个管理员权限事务及实例锁中，列表使用deletionMap避免逐用户搜索；`account-admin-admission-final.log`真PG/mTLS/JWT/迁移与 `account-authority-types.log`通过。产品候选版本号准备1.8.12，尚未tag/发布/主控部署；新同来源原生/包预览仍须通过。

- `logs/account-guard-fixes-final.log`：注册源/实际限流、通知内容、前端路由/i18n、分页及配置守卫8项通过；原管理员/用户TG守卫也通过。
- `logs/account-cleanup-final-r10.log`、`account-cleanup-stuck-final2.log`、`account-remaining-acceptance-final.log`：真实PostgreSQL并发源限额、实际JWT/角色/输入拒绝；HTTPS双向证书替身运行/旧deleted/creating实例、删除503保留库存、恢复续接、转让rename恢复、其他付款人账单保留通过。它们不是原生Incus容器验收。
- `logs/account-finance-final-r9.log`：旧流水实际充值重放拒绝、checkout会话锁竞争、19种转让续接与签名迟到付款回归通过。
- `logs/account-registration-http-r6.log`：实际注册路由、关闭/邀请码/SMTP、错误与消费过验证码、成功会话和来源计数通过。升级SQL隔离命名空间回填通过。
- `logs/account-telegram-delivery-r7.log`及`account-remaining-acceptance-final.log`：实际发送函数的客户/站点/托管/流量/资源渠道负载脱敏、管理员详情、错误渠道归属及HTTP失败回执通过；外部Telegram transport拦截。
- `logs/account-transport-r4.log`、`account-last-live-r11.log`：真实本地HTTP超时、body取消、每路失败回执、重试与零悬挂日志通过。Turnstile八种配置组合与五原验证器通过。
- `logs/account-password-browser-final3.log`、`account-delete-browser-final2.log`：真实Chrome源组件、原生确认取消无POST/确认精确目标/重复点击拒绝、旧回执/会话/路由、重装新密码和手动重置不被旧读取覆盖、手机/桌面通过。
- 后端最终类型/构建及前端最终双构建已通过：`account-final-types-r12.log`、`account-server-build-final.log`、`account-final-client-build.log`。双端包边界通过。

## 失败与剩余门槛

进一步真实机器池creating测试发现：原开通补偿已成功删远端及释放分配后，账户删除再次把历史deleted记录设deletionBillingPending会触发数据库HOST_POOL_FAULTED。源码改沿原poolProvision failed清理实证继续核absence/回池，不重开库存；真实mTLS503保分配→恢复补偿→原池可售→删除账户通过（account-pool-creation-delete3.log）。普通旧deleted无原清理证据仍走完整授权删除，不放宽数据库池门禁。

首轮完整224项221过/3失败（`account-full-tests-r5.log`）：分页、配置守卫仍匹配新增字段前文本，已修并定向通过；Windows十场景安装夹具60秒总时限失败，改外层180秒且产品内部限时保持，`account-agent-installer-final.log`十场景通过。新增快照续接曾使用数据库不允许的superseded，改合法cancelled并保留实例删除核验，已重新通过。浏览器早轮受编辑引起Vite reload及新增成功toast未清夹具影响，日志保留；稳定源码最后两轮通过。

上述为过程中的失败与等待记录，最终结果见下。

## 最终候选与主控验收

产品来源 `8cd82d858791ac78e60664ef5aa290104ea3bd01`，本地225全套通过后最后creating补修对应mTLS/类型/补偿/到期守卫通过。最后同来源完整CI43666672521（原仓库 Actions 运行 #43666672521；未迁移）29/29成功，实际Incus job132667469473与全部本批注册/清理/TG步骤通过；Alpine43666672557（原仓库 Actions 运行 #43666672557；未迁移）成功。

无tag预览43666670130（原仓库 Actions 运行 #43666670130；未迁移）双构建、双首装、六种真实v1.8.11原worker升级全部success，Release预期skipped。两实际tar均独立原pin、签名、完整source、244迁移、新模块和用户无删账户/改价入口通过。证据`account-final-arm-verification2.log`与`account-final-amd-verification.log`。

主控候选任务54于2026-11-15 10:43:25北京时间success：`preview-8cd82d8`，备份`/opt/incudal.bak.20261115024109`；原worker/平台签名身份、DB支付就绪、唯一backend、双前端/API/WS、日志凭据扫描通过，244迁移。Owner自行此前更新了正式1.8.11，故此热更起点实际v1.8.11。更新前后#49–52原UUID、密码摘要、价格10/无改价、账期及镜像库完整清单保持。34host online/poolFaulted=false。

实际Chrome加载主控发布的双端页面：管理员桌面/390手机删除入口正确；普通测试用户调用管理员删账户API403。通过正常管理员API新建专用#20测试账户、33测试余额、11元真实池购买#53于原host48；成功运行。页面原生确认取消不删，确认后真实stop/delete，容器/卷/forward不存在，账户/余额流水/实例账单/checkout全消失，资源0、host48实际allocator重新可售。不是删除恶意账户；恶意账户仅只读调查。证据`account-delete-live-browser2.log`和仓库外`compat-account-deletion-confirmed2.json`。

原测试账户#49实际停止、重装Alpine3.21 TinyCloud完成，原页面未reload、可见新SSH密码自动显示；通过认证Incus读取客机SSH公钥后公网登录新密码成功。#50–52均Incus Running，价格/账期/密码摘要保持。`account-live-browser2.log`及仓库外`compat-account-final-live3.json`。测试账号余额及新临时账号清理分别记录；没有重跑全镜像。

TG真外部群/用户未额外发测试消息，客户/管理员所有发送管道的真实payload＋本地HTTP超时及平台API回执已有专项与最终CI；此范围明确。正式发行后仅需验证公开资产，无需再次OTA相同产品代码。

来源3ad63ecde847204fa1942472e819bc505de311de已推草稿PR16（原仓库 PR #16；未迁移）。CI43664559570实际Incus job132660955563已success，真实Running客机/快照/LVM卷/forward删除→可售→余额账单账户删除日志完整；本批PG/注册HTTP/TG集成步骤132660955628也success，其余分片仍运行。预览43664562150双构建成功，两实际tar独立原签名、完整source、244迁移、新模块及用户无删除/改价入口通过。六旧worker在升级动作前失败：仍固定断言v1.8.10，而工作流已下载真实v1.8.11；修演练脚本从已校验旧包读取baseline版本、回滚同一baseline，不跳守卫。新预览待。主控未部署，正式未发行。
