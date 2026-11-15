# 实例网络地址样式与建站入口移除

Owner要求两端实例详情IPv6与IPv4字体、颜色、大小、位置一致，并删除“建站”。本次仅修改前端显示与入口，不执行主控更新、网络配置或实例操作。

共享实例页移除建站tab类型、tab配置和InstanceSitesTab import/渲染；用户和管理员两个产物不包含该组件或proxy-sites请求代码。后端原资源清理与权限保持，避免既有站点残留影响实例删除。

PublicIpv6Addresses仅在实例网络页启用network外观，原订单结果/宿主信息页显示保持。IPv4/IPv6网络地址统一14px JetBrains Mono、400字重、20px行高，同前景/背景/padding；标签左缘、地址和16px复制图标右缘一致。长地址完整换行，多地址逐条复制，待配置/失败/未分配仍可见。旧NAT带重新分配按钮时地址与复制图标一起换行。

验证：实际Vue/Chrome，两种入口、深浅色及1440/768/390共12组合计算样式逐项相等、复制完整地址、无横向溢出。另验多IPv6、pending/failed/none与五旧网络模式。全部12截图人工审阅；审查记录`logs/network-cleanup-browser/REVIEW.md`和`results.json`。完整页面审查的原有页头/间距警告与本次地址卡分开记录。

最终双端types/build通过`logs/network-cleanup-shipped-build.log`，边界/路由/i18n/公网IPv6相关守卫通过；实例页密码和旧请求/路由生命周期回归通过`network-cleanup-detail-regression.log`。初次自加守卫缺读入变量、浏览器fixture未等Vite预构建/异步回执，以及编辑期间一次构建读取未完成写入导致失败已修/稳定来源复验，失败日志保留。ESLint无error，剩两条原页头插值spacing warning未扩 scope。

本次源码和本地双端验证完成，尚未主控热更新、未新增正式版本。
