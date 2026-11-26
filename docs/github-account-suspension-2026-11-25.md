# GitHub 账户停用与最后推送事实

2026-11-25，owner亲自登录GitHub后确认提示账户因违反规定被停用。此前读取API已有`suspended`／HTTP403，但尚未取得具体条款、违规行为或申诉回复，不能据此确定原因。本记录不包含登录资料、凭据或私有备份。

随后owner回复未看到停用通知邮件，只看到几条CI fail邮件。这只能作为看到验证失败通知的事实，不能当GitHub指出违规条款或判定封号原因；具体邮件正文和运行编号未提供，不擅自与已知某次失败绑定，也不因没有邮件否定已确认的账户停用。

## 最后一次成功推送

- 北京时间：**2026-11-25 04:17:50（UTC+08:00）**。
- 分支：`codex/financial-integrity-audit`。
- 提交：`94de16db4b4d8e328f761c62fd04d621cd534d6e`。
- 标题：`fix: diagnose APK failures and exercise original musl recovery`。
- 依据：本机`git reflog show refs/remotes/origin/codex/financial-integrity-audit --date=iso-strict`中的`update by push`。提交生成时间为04:17:14，与推送时间分别记录。

该提交共9文件、142行新增、25行删除：三个宿主Go实现／测试文件、Alpine原生工作流与测试入口、机器池PostgreSQL回归fixture、三份脱敏交接文档。实际用途为APK失败的固定阶段诊断、旧Alpine／musl原恢复验证及跨项目operations测试修正。

已逐份核该提交diff，未发现挖矿程序、用于攻击外部目标的载荷或真实凭据；测试中的虚构secret用于验证不向日志输出。此结论只覆盖最后该提交内容，不能代替全Git历史、GitHub账户访问及其他仓库行为审计，也不能代GitHub判定违规条款。

## 上传与发行范围

同来源完整无tag预览`45480088932`已保存双架构构建、候选Agent、首装／原worker恢复和六旧worker升级／回滚验证，13项成功；正式Release按无tag条件跳过。工作流只上传指定的完整程序tar、签名及候选Agent目录，不将本机私有目录或真实主控备份作为上传输入。此次没有正式发布新版本。

主CI`45479320637`为cancelled（29 success／1 cancelled），原生`45479320534`为failure（12 success／2 failure），不能将完整预览成功等同全部CI成功。原生失败已定位APK3.0.6精确fetch语义并在本机继续修复；取消job的完整日志因API受限未取得，不能断言取消由账户停用导致。详细记录在[并行安全审查](security-parallel-review-2026-11-25.md)。

近期确有较多与本项目有关的双架构构建和原生测试；尚无官方证据表明测试频率、产物大小、某次源码推送或生产安全事件是账户停用原因。

## 有界补查结果

独立子任务已审本分支`origin/main..94de16db`的150提交、1062个新blob版本和当前8个Actions配置，主智能体另用`git rev-list --count`复核150提交范围。该范围包含随后删除／替换的新对象；最大单blob为HANDOFF.md约1.36MiB，全部新blob未压缩字节和不是一次push的传输量。本次未fetch／调用受限GitHub接口。

强格式完整私钥、GitHub／云AccessKey／Telegram／service token／JWT没有新增命中；17组弱候选仍按路径与上下文继续核查，不能仅因处于测试文件便判虚构，也不打印值或原行。本次有限检查未发现已确认的真实凭据。origin/main旧内容、编码／拼接值、账户及其它仓库不在该结论的覆盖内。

8工作流配置与已推HEAD相同，作用对应本项目的构建、交付／资源／身份／网络／财务测试、文档与签名发行；有限入口引用核查覆盖当前工作区92个脚本，该部分不能冒充全部已推源代码的递归审计。未发现明显与项目无关的矿工、攻击外部目标、批量注册或常驻服务内容。上传配置限定程序包／签名／候选Agent、兼容组件output和文档dist，未见整个workspace、logs或本机私有备份目录的上传配置；实际云端tar内部内容与账户行为仍需独立证据。

完整脱敏补查报告位于本机ignored的`logs/github-last-push-audit-20261125.md`，未随本次推送或公开上传；结论仍不能解释GitHub停用原因。

## 官方申诉入口与所需事实

GitHub官方[申诉与恢复政策](https://docs.github.com/en/site-policy/acceptable-use-policies/github-appeal-and-reinstatement)于本次HTTP200复核，页面指向[账户恢复申诉入口](https://support.github.com/contact/reinstatement)。owner可在原账户提交申诉，说明该仓库用于Incus实例管理软件开发，近期运行的是该软件的双架构构建、安装、升级及恢复测试，并请求告知具体违规行为／条款和可采取的整改措施。

具体通知文字、账号相关行为及其他仓库仍待核实；没有GitHub回复前，不保证停用为误判、不编造被封原因，也不代owner发送申诉。

## 当前工作边界

本机源码、未提交更改、原Git对象和测试证据保留；已授权本地安全修复继续。新的远端推送、Actions同来源验证和正式发行受账户停用阻碍。生产最后已证完整候选仍为`v1.8.14-test.a241daf`／Agent security.10，不能把本机草稿、较早成功包或账户恢复当本轮全部修复已部署／验收。当前安全余项及真实备份模拟恢复继续按原台账推进。
