# v1.8.13 同批修复及发行验收

产品源码`629dca1f6c70c9c9b497f36b8862b15bea0610c3`，PR17精确快进合入main，注释tag v1.8.13指向同源码。正式[43688994863](https://github.com/mastalee928/payincus/actions/runs/43688994863)已启动，公开Release及资产尚待核验；main重复CI43688988825待终态。

本批包含手动单台/批量/PAT/自动续费恢复原到期封停客机、连续付款延长同一意图、详情页系统到期仍可续费；用户和管理员IPv4/IPv6同款排版、移除建站；管理员删除用户图标与悬停“删除用户”、后台列表刷新避免骨架闪烁，末页删除/旧会话回执保护。Agent保持v1.0.15，没有新增Agent发行。

本地225全量自然exit0；后续新增UI与详情入口的相关types/route/i18n和最终双build/产物边界均过。18组Chrome图标/慢刷新原行保持/原生确认/错误重试/末页修正/旧回执与完整余额登录弹窗、详情密码和生命周期均过。最终完整CI[43684128355](https://github.com/mastalee928/payincus/actions/runs/43684128355)全部30job success、Alpine43684128416 success；原生AMD/ARM实际Incus到期Stopped→手动付款→同UUID Running/一笔扣款→删除回池通过。最终预览[43684126456](https://github.com/mastalee928/payincus/actions/runs/43684126456)双首装/六v1.8.12原worker正常/已迁移/故障回滚再升级全部success，Release预期skipped。两实际候选tar原pin签名/来源/244迁移/对应编译模块/无内置镜像库/用户边界已独立核过。

主控原worker热更新任务56于2026-11-15 14:41:36北京时间success，当前`preview-629dca1`同源码，备份`/opt/incudal.bak.20261115063950`，原签名/DB支付检查和自动回滚保持。最后/api/health HTTP200。升级前后原49–52四实例UUID相关规格hash/密码hash/账期/价格/IPv4/IPv6/账目及所有13账户余额摘要一致，34host在线无隔离。原#51/#52被owner手动启动及改价/续费的变化保留。

现场新建专用账户#21，正常管理员创建/测试余额66、实际购买两台E2的54/55订单22元，主控正常管理员expiry API触发到期，autoRenew=false；核实际Incus均Stopped及系统expired。用户详情单台与列表批量各付10元，正常任务1190/1191均COMPLETED，两台同原UUID实际Running，各一续费账单、余额24，未手动start或直接改运行状态。两台ARM宿主53/54仍被原51/52占用、可售ARM库存零，本轮现场不更改原ARM已付账期；ARM范围以最终原生CI闭环为证，不能宣称新增线上ARM购买实测。

用户/管理员桌面/手机4组现场IPv4/IPv6计算字体、字号、颜色、行高与padding相等，无溢出/建站入口，4截图全部查看。管理员原生取消保留专用账户，确认后删除#21及两台54/55，真实MutationObserver证明其它用户行未卸载/不闪烁；最终核账户/实例/全账单与订单不存在、两原Incus客机及卷/转发无、host48/49可售，原13账户和四实例保持。日志`renewal-live-network-final.log`与`renewal-live-delete-browser.log`实际exit0；资金/远端终态私有脱敏回执保存在仓库外。

正式公开包尚需继续下载/核API size/digest、SHA/checksum、OTA清单及原pin签名/来源。正式包与已实测候选同产品，不重复主控OTA和专用销毁。长期真实OSS公网DNS切换/整机失联灾备等原未验目标保持独立。
