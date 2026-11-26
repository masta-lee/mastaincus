# 到期封停后手动续费自动开机

Owner截图实测qa1811-resale-arm-01/#51续费成功后只有已停止，要求自动恢复运行。主控只读核2026-11-15 12:27:13到期封停、12:27:58到账续费10元、无自动开机task，12:31:14另手动创建普通start任务后才恢复。到期封停和扣款正常；原代码只有automatic参数存在才queueRenewalResume，单台/批量手动路线不排队。

源码已统一单台、批量、公共API与自动续费：只有原状态确为系统到期封停（expired、suspendedBy=null）时，扣费/新账期/解除封停/一次受保护开机task同事务提交。真实Incus Running核验后才写运行状态，不直接改显示数字。不产生重复收费；同请求重放不重排。

追加已付款月数更新同一当前原实例待开机intent，避免第二次续费使旧paidUntil失效；后续停止/取消/删除/转让或身份变化不能被旧intent覆盖。原本普通stopped实例续费保持关机，不把用户主动停止当到期封停。autostart仅恢复到期保存的原策略，无论远端Stopped还是因停止未确认仍Running；原账号/客机UUID/创建时间/TLS/隔离/设备配置/原账单核验保持。

本地真实PG+受信HTTPS测试（非原生Incus）覆盖AMD/ARM元数据、单台/批量/PAT实际路由、重复请求、连续不同续费、取消保持、autostart恢复、六次暂时故障恢复/丢回执只核验、离线、restore hold、实际行锁竞争/手动封禁、后续停止/删除/转移/身份/安全配置，以及账务整事务回滚。日志`manual-renewal-autostart-integration.log`、`manual-renewal-resume-final-verification.log`。对应types/build、6相关到期/改价/路由守卫通过。

新增CI双架构原生Incus流程：真实Running容器自然到期→Stopped→关闭autoRenew情况下手动续费→正常轻任务claim/worker→原UUID Running且单扣一次→正常删除回池。独立busybox镜像原生/sbin/init启动，无raw.lxc覆盖；原身份/隔离守卫完整。43679907784（原仓库 Actions 运行 #43679907784；未迁移）来源98b7a3ad的AMD job132708067750、ARM job132708067915均success；ARM日志`manual-renew-native-arm-final.log`明确包含上述闭环及原systemd/Agent重连。该运行其余集成分片尚待终态，不能把局部job成功作为完整CI通过。

ARM前两次原生CI分别因夹具宿主仍登记E2、实例仍使用200CPU而失败，尚未执行续费专项；已按真实ARM1C规格修正夹具，没有放宽生产容量/隔离保护。失败日志已核，旧轮43679492768/43679818814定向取消，最新轮继续核。后续发行预览改用当前公开v1.8.12双包的原worker作六升级场景，旧包动态版本解析保持。此流程修改的repository/system-update守卫已过，实际升级尚待新预览。

本地全量`renewal-full-tests.log`自然exit0，225/225通过；删除图标/列表闪烁补充后的相关前端守卫与types单独再核，不能据此前全量声称后续界面未测。

前项IPv6/移除建站ae7f552b保留同分支；云端旧quota browser仍要求sites tab导致失败，已更新为所有quota下入口不再出现，本地真实浏览器通过，未放回功能。旧付费period fixture用90天过期被正确保留期守卫拒，改为当前宽限期内测试、保留逾期拒绝规则。

当前源码尚未部署主控、未发布新版；#51目前只读核已被owner后续手动启动，未重复停止/续费。

候选533ff125双包已独立验签及本批修复/244迁移/用户边界核过；预览43682328472双首装/六v1.8.12旧worker升级与回滚再升级终态success，未公开发行。准备现场时发现详情续费按钮沿用isOperationDisabled，系统到期封停下也被禁止，列表路线可用。继续局部补修独立续费禁用条件：仅系统expired、无封停操作者可续费，停启操作仍禁用、手动封禁/在途/转让保持。`expired-detail-renewal-browser-verified.log`真实桌面/手机RenewModal预览点击与原密码/请求/生命周期浏览器回归自然exit0，types/route/i18n与最终双build通过。补充后的新来源需重新预览，不使用533包做最终部署。
