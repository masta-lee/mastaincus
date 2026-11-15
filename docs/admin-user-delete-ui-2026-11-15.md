# 管理员删除用户图标及列表闪烁修复

Owner截图要求将用户管理操作栏的“删除用户”文字换成与同栏一致的图标，悬停仍显示“删除用户”；随后实测删除时页面闪烁，要求查因修复。

`UsersView.vue`桌面及移动卡片采用相同16px、2px描边、圆角端点的垃圾桶图标，按钮继续使用原btn-ghost/btn-sm。原生title和aria-label沿用三语删除名称，处理中沙漏/aria-busy及读屏status保留，手机点击范围至少44px。管理员行继续没有删除入口，原生window.confirm、后台cleanup、重复提交保护和失败重试保持。

闪烁根因为删除受理/最终完成调用普通loadUsers时先令usersLoading=true，v-if切整页骨架，表格/移动卡片与头像被卸载后重建。现仅删除相关列表刷新使用background模式，保留已加载的用户行、位置和滚动，收到当前正确结果后更新同key行；实际完成后才移除目标。最后一页删除导致页码超界时后台读取有效页。当前会话/页码/搜索/读序号保护保留，异步初次状态回执另重查会话。普通初次加载与用户搜索分页行为保持。

浏览器专项`delete-user-flicker-edges-final.log`实际exit0：三语×深浅×1440/768/390共18组，16px与相邻图标相等、title/aria正确、键盘Tab焦点及44px手机点击范围通过；模拟慢列表刷新时原行、布局和滚动保持，同key行回执完成不卸载。真实原生Enter取消零请求，鼠标确认精确目标、禁用/aria-busy/沙漏、重复点击、错误可重试，正常轮询done后仅目标移除；MutationObserver确认其它用户行贯穿流程未卸载。末页修正、失败列表保留、旧回执拒绝另通过。

最终完整原余额/登录弹窗回归`delete-user-flicker-dialogs-final.log`已自然exit0。对应client类型、路由/i18n守卫通过，最终双前端构建与dist边界`delete-user-flicker-final-build.log`已自然exit0。本地此前225全量已exit0。未部署主控、未公开新版本，不把本地模拟cleanup API说成线上实际账户删除；真实后端删除/远端回池证据沿用v1.8.12，新增UI候选上线还需现场核验。
