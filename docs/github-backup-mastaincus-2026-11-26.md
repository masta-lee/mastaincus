# mastaincus 仓库替代与原正式资产迁移

Owner确认原仓库已退出，masta-lee/mastaincus 是今后唯一维护、安装和发行仓库。2026-11-27 owner明确批准公开，沿用无需token的安装和更新；源代码／历史候选复核、主分支同步及实际公开回读分别记录，不把批准当成已完成。

原源码备份 d6c0a04d675af0061d21276b947e3638e116346c 已推送并回读：22分支、206原标签共228 refs与本机一致；本轮另迁移配套 agent-v1.0.16 标签至原来源 ced7c10cd17de34107b7281f8846702609ab4f32。当前迁移补丁待阶段提交，原Git历史和v1.8.14 tag提交不变。

原正式 [v1.8.14](https://github.com/masta-lee/mastaincus/releases/tag/v1.8.14) 已在新仓库正式/latest。两架构安装包和两份SHA256校验文件保持原字节；两份OTA清单仅改 artifacts.url，完整版本、来源、大小和包hash保持。新清单SHA256为605ec85f3329ced07a8c5ea1e7a790043a1d8eb074e57c2d9678274a11a323cd。原包没有重建、重新seal或加入未发布修复。

配套 [Agent v1.0.16](https://github.com/masta-lee/mastaincus/releases/tag/agent-v1.0.16) 已迁移。原两架构二进制与LICENSE字节一致；新增publisher-manifest.json由保留发行身份为原文件签发，明确是本次新元数据，未伪称原发行已有该签名。Agent不是面板latest。

迁移代码涵盖安装／OTA／Git源回退、Agent、环境初始化、原子布局、历史worker桥接、文档与当前Git远端。runtime精确映射退役默认，custom alias-only不会被primary补值遮盖；env修改同目录原子替换、前后核原内容和文件身份，失败保留原凭据。可信原包部署helper只生成新的仓库常量，原tar及运行模板不修改；旧backup安装钩子再次复制helper后也处理同一常量。旧worker在备份前迁移退役源，因此回滚后的旧代码继续请求新仓库，其他配置逐字节和属主模式保持。Git核唯一raw origin和effective值，拒URL重写；origin只在成功worker的正常postflight更新，不在工作期间破坏旧seal。

实际新私有仓库测试（公开前）：生产OTA代码先复现网页404，再修为有token且metadata绑定时单向转官方资产API；API404仍永久失败。通过同一生产代码完整下载原AMD64/ARM64包，214617555／213831970B和完整SHA全部一致，真实CDN请求未携带凭据。Agent实际公共下载路由分别取原manifest及两架构完整二进制／Ed25519校验自然0；独立临时Fastify inject，无数据库、主控或客户操作。此处token只在本机测试进程内使用，未写主控或源码。

本机仓库选择器、相关3守卫、前端route/i18n、双端构建／dist边界、后端构建、文档检查／构建、Bash安装守卫自然0。Bash首次新fixture缺少set_env_value第三个label导致nounset，修正fixture后r4完整通过；旧失败与脱敏诊断保留。当前233全量仍运行；新仓库双架构真实首装／升级预览待运行。原6个历史worker clean／migrated-atomic／rollback保留，新增4个新installer安装原包后clean／rollback场景，覆盖两架构，不删除旧门槛。

历史Actions／PR／issue运行没有迁移，保留无链接原编号；旧版资产未迁移的链接改为已复制源码tag并明确范围。原版权保留。公开前源码与已知历史候选复核继续，泛化匹配数不冒充凭据泄漏数或绝对无泄漏证明。

原安全余项仍保留：双架构内核实际启动／回退及后续补丁、旧组件可信来源、多版本真实PostgreSQL恢复矩阵、当前完整包／主控新备份本机完整模拟恢复，随后才可原流程可信热更新／目标主控测试和条件式新版本发行。当前迁移未部署生产、操作客户或更换SSH密码。旧源码R5全量233、当前Python f2693318／b43922f6的Linux206及本机206证据分别保留，不覆盖新增迁移验证。
