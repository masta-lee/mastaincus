<h1 align="center"><img src="./client/public/incudal_logo.webp" width="96" align="absmiddle" alt="MastaIncus logo"> MastaIncus</h1>

<p align="center">面向 Incus 的 VPS 销售、实例交付、支付账务与运营平台。</p>

<p align="center">
  <a href="https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/deployment/one-click-install.md">安装说明</a>
  ·
  <a href="https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/guide/ota-update.md">在线更新</a>
  ·
  <a href="https://github.com/masta-lee/mastaincus/releases">发行下载</a>
  ·
  <a href="https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/guide/introduction.md">项目文档</a>
  ·
  <a href="https://github.com/masta-lee/mastaincus/issues">问题反馈</a>
</p>

MastaIncus 将机器池定价、用户购买与续费、Incus 实例管理、IPv4 / IPv6 网络、宿主机 Agent、工单通知、Public API 和后台 OTA 放在同一套交付流程中。用户端与管理端分离，支持 Linux AMD64 / ARM64。

本项目统一维护于 [masta-lee/mastaincus](https://github.com/masta-lee/mastaincus)。最新正式版为 [v1.8.14](https://github.com/masta-lee/mastaincus/releases/tag/v1.8.14)，配套 [Agent v1.0.16](https://github.com/masta-lee/mastaincus/releases/tag/agent-v1.0.16)。原发行包、签名和校验值保持；开发分支中的后续安全修复尚未正式发行。

## 安装

在干净的 Debian / Ubuntu 服务器上执行：

```bash
curl -fsSL https://raw.githubusercontent.com/masta-lee/mastaincus/main/scripts/install-panel.sh -o install-panel.sh
sudo bash install-panel.sh
```

仓库和正式发行资产已公开，无需 GitHub token。安装器会选择对应架构的正式包，校验后安装依赖、数据库、用户端、管理端和后台服务。详细的系统要求、域名、Cloudflare Tunnel 与检查步骤见 [一键安装](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/deployment/one-click-install.md)。

## 更新

已有主控使用 **管理后台 → 版本更新**：检查正式版本、下载并校验包、执行更新、查看结果。更新前完成备份，保留上一版回滚目录。

安装目录继续使用 `/opt/incudal`，原子部署通过 `/opt/incudal/current` 指向当前 release。原有服务名、平台与宿主管理身份保持。`install-panel.sh --upgrade` 仅适用于旧式非原子布局；已有 `current` 布局使用后台 OTA。

更新来源统一为 `masta-lee/mastaincus`。详细流程与回滚说明见 [在线更新](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/guide/ota-update.md)，已发布的安装包见 [Releases](https://github.com/masta-lee/mastaincus/releases)。

## 部署配置

两个前端分别提供静态文件，并通过各自同源的 `/api`、`/api/ws` 访问唯一后端。跨机部署的内网示例：

```text
用户浏览器 -> https://panel.example.com -> Nginx: /opt/incudal/current/client/dist/user
           -> /api, /api/ws -> http://10.0.0.12:3001
管理员浏览器 -> https://admin.example.com -> Nginx: /opt/incudal/current/client/dist/admin
             -> /api, /api/ws -> http://10.0.0.12:3001
后端服务 -> /opt/incudal/current/server/dist/app.js -> 单个 Node.js 进程
```

安装器负责初始化环境；手工部署按 [.env.example](.env.example) 配置数据库，并为 `JWT_SECRET`、`COOKIE_SECRET`、`ENCRYPTION_KEY` 分别生成独立、至少 32 字符的随机值。配置中的占位文字必须替换。跨机示例的 `/opt/incudal/.env`：

```dotenv
NODE_ENV=production
HOST=10.0.0.12
PORT=3001
SERVE_STATIC_CLIENT=false
COOKIE_DOMAIN=
FRONTEND_URL=https://panel.example.com
ADMIN_FRONTEND_URL=https://admin.example.com
SITE_URL=https://panel.example.com
PAYMENT_CALLBACK_BASE_URL=https://panel.example.com
SYSTEM_UPDATE_RELEASE_REPOSITORY=masta-lee/mastaincus
INCUDAL_AGENT_RELEASE_REPOSITORY=masta-lee/mastaincus
```

`COOKIE_DOMAIN` 必须保持空值。单机安装保持 `HOST=127.0.0.1`，两端 Nginx 代理和验收的 `BACKEND_URL` 使用 `http://127.0.0.1:3001`；跨机后端只向前端代理开放内网访问。模板见 [Nginx](deploy/nginx-split-intranet.conf.example) 与 [systemd](deploy/incudal-backend.service.example)。

从源码构建时设置两端链接地址：

```bash
VITE_API_BASE_URL=/api VITE_CUSTOMER_BASE_URL=https://panel.example.com VITE_ADMIN_BASE_URL=https://admin.example.com pnpm build
```

手工部署且尚未配置 systemd 时，从程序目录启动唯一后端；已安装的服务由 systemd 管理：

```bash
ENV_FILE=/opt/incudal/.env NODE_ENV=production HOST=10.0.0.12 PORT=3001 SERVE_STATIC_CLIENT=false node server/dist/app.js
```

## 使用文档

| 任务 | 入口 |
| --- | --- |
| 了解系统与部署结构 | [项目介绍](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/guide/introduction.md) · [部署文档](https://github.com/masta-lee/mastaincus/tree/main/docs-site/docs/deployment) |
| 接入宿主与管理机器池 | [机器池说明](https://github.com/masta-lee/mastaincus/blob/main/docs/host-pool.md) |
| 平台备份与恢复 | [OSS 备份说明](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/deployment/oss-backup.md) |
| 对接 API | [API 文档](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/api/overview.md) · [TypeScript SDK](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/public/sdk/payincus-public-api.ts) |
| 查看版本与提交记录 | [版本日志](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/release/version-log.md) |
| 维护与发行 | [发行说明](https://github.com/masta-lee/mastaincus/blob/main/docs/fork-release.md) |

平台备份保存数据库、配置与受管身份，不包含客户 VPS 磁盘。完整灾备接管的未完成验收与实际部署证据见 [HANDOFF.md](https://github.com/masta-lee/mastaincus/blob/main/HANDOFF.md)。

## 部署验收

从程序目录运行以下命令，并将示例域名、内网地址替换为实际配置：

```bash
RUN_LIVE_CHECKS=0 pnpm verify:production

export ENV_FILE=/opt/incudal/.env
export FRONTEND_URL=https://panel.example.com
export ADMIN_FRONTEND_URL=https://admin.example.com
export BACKEND_URL=http://10.0.0.12:3001
pnpm verify:production
pnpm verify:split:host

REQUIRE_LIVE_PROOF_REFS=1 \
LIVE_PAYMENT_PROOF_REF=pay_provider_order_xxx \
LIVE_LOG_HEADER_PROOF_REF=nginx_access_redacted_xxx \
pnpm verify:final-acceptance
```

`pnpm verify:production` 会强制开启生产预检；`RUN_LIVE_CHECKS=0 pnpm verify:production` 仅检查配置和构建前置条件。`pnpm verify:split:host` 检查双端入口、API 代理和登录/权限 smoke。最终验收需要真实付款与日志头验证证据，`LIVE_PAYMENT_PROOF_REF`、`LIVE_LOG_HEADER_PROOF_REF` 的占位文字必须替换为可追溯记录；完整步骤见 [部署验证](https://github.com/masta-lee/mastaincus/blob/main/docs-site/docs/deployment/manual-install.md#验证)。

## 开发

```text
client/       Vue 3 + Vite，用户端与管理端
server/       Fastify + Prisma + PostgreSQL
agent/        Go 宿主机 Agent
scripts/      安装、构建、验证与 OTA
deploy/      systemd 与 Nginx 模板
docs-site/   双语文档站
```

使用 Node.js 24 LTS、pnpm 9.14.2 和 PostgreSQL：

```bash
pnpm install --frozen-lockfile
pnpm dev
pnpm test
pnpm build
```

私有业务后端必须只运行一个 Node.js 进程。用户端与管理端使用独立域名，`COOKIE_DOMAIN` 必须保持空值，确保 refresh cookie 不共享域。开发和变更纪律见 [AGENTS.md](https://github.com/masta-lee/mastaincus/blob/main/AGENTS.md)。

## 许可证

本项目按 [BSD 3-Clause](https://github.com/masta-lee/mastaincus/blob/main/LICENSE) 发布，保留原许可证与版权声明。
