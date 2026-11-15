# v1.8.12 发行和现场验收

正式[v1.8.12](https://github.com/mastalee928/payincus/releases/tag/v1.8.12)于2026-11-15 11:14:33北京时间公开，tag/source `fc284676c570f88a532cc05018ad43e7f2996a31`。PR16合入，产品代码与验收来源`8cd82d858791ac78e60664ef5aa290104ea3bd01`完全一致；合入后仅台账/Release notes新增。

完整产品CI[43666672521](https://github.com/mastalee928/payincus/actions/runs/43666672521)29/29 success，原生Incus账户删除及本批注册HTTP/PG/TG集成通过，Alpine43666672557 success；本地225/225及最后creating/账务/权限专项已通过。正式tag重复[43670232244](https://github.com/mastalee928/payincus/actions/runs/43670232244)双构建、双首装及六v1.8.11原worker正常/已迁移/后半程回滚再升级全部success，正式Release成功；preview-agent预期skipped不替代正式Agent下载。Agent仍原v1.0.15，没有新增Agent发行。

六个公开资产已重新下载，全部API digest/size/SHA、双checksum与OTA两个清单一致。两个实际公开tar原固定组件公钥/签名、完整source、244迁移、新模块/权限、用户包无删号/修改续费价入口核过；与正式build artifact完全一致。AMD64 214613716 bytes / `8b7714bf1a6498fa9fae3d5dfc39cb63eba193df9892151d998f00c44d9a9875`；ARM64 213839523 bytes / `b56df7d939fff2fa66586190de758785102a6d57e3a527b9f727a8ed9cc07918`。证据`logs/account-public-assets-verified.json`、`account-public-package-verified.log`。

主控已在正式发行之前通过原worker热更新候选任务54，10:43:25北京时间success，运行`preview-8cd82d8`；原签名/DB支付/日志安全/双前端/API/WS/唯一后端通过，备份`/opt/incudal.bak.20261115024109`。原49–52 UUID/密码hash/价格账期/镜像库完整清单升级保持，34host online/poolFaulted=false。正式包产品代码相同，不重复OTA。

实际页面和流程：管理员桌面/390手机显示删除入口，原生cancel无副作用/confirm只指定目标；正常管理员创建临时#20账户33测试余额，11元实购#53/host48成功交付后网页删除，账户、余额流水、全部账单/checkout消失，原Incus容器/磁盘/forward不存在、host48实际可售且资源0。原测试#49停止和重装后同页面自动显示新SSH密码，无reload；从认证Incus读取客机host key后公网新密码SSH认证通过。其余#50–52运行/密码/价格账期保持。

Owner在正式发行核验完成后追加授权删除指定恶意IP注册账户的1–2个。只读选定#9 testu1和#10 testu2，均匹配原149.112.84.133成功注册日志、banned/普通角色/无实例无余额账单。通过实际管理员页面原生确认分别删除，数据库核两个账户及相关实例/账单/余额流水/checkout均无，另外九个原账户保留封禁。34host仍online无隔离。证据`account-malicious-delete-browser.log`及仓库外`compat-account-malicious-deletion.json`。

TG未额外发送测试消息到真实外部用户/群；全部发送函数客户/admin payload、错误归属过滤、实际本地HTTP超时/重试和持久错误回执已验证。公开资产、生产候选部署和外部transport替身范围分别记录，不混为全网TG送达测试。完整问题和失败过程见[检查记录](account-notification-reinstall-review-2026-11-15.md)。长期OSS灾备/网关完整目标不由本版替代。

main同产品源码重复CI43670183718仍在运行，无失败；最终结果继续记录，不以正式发行success代替其终态。
