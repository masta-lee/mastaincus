#!/usr/bin/env bash
# ============================================================================
# PayIncus 本地 .env 初始化脚本
#
# 用法：
#   bash scripts/init-env.sh
#
# 行为：
#   - 如果 .env 不存在，创建 .env
#   - 如果 .env 已存在，只补齐缺失或空值的关键变量
#   - 保留已有配置；仅将退役的默认 Release 仓库迁至当前仓库
# ============================================================================
set -euo pipefail
umask 077

ENV_FILE="${ENV_FILE:-.env}"
readonly GITHUB_REPO="masta-lee/mastaincus"

log() {
    echo "[✓] $1" >&2
}

info() {
    echo "[i] $1" >&2
}

gen_password() {
    openssl rand -hex 64 | cut -c "1-${1:-24}"
}

gen_secret() {
    printf 'A1!%s' "$(openssl rand -hex 64)" | cut -c "1-${1:-48}"
}

get_env_value() {
    local key="$1"
    if [[ ! -f "$ENV_FILE" ]]; then
        return 0
    fi
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d'=' -f2- || true
}

env_file_identity() {
    local metadata digest
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || return 1
    metadata="$(stat -c '%d:%i:%u:%g:%a:%h' "$ENV_FILE")" || return 1
    [[ "${metadata##*:}" == 1 ]] || return 1
    digest="$(sha256sum "$ENV_FILE" | awk '{print $1}')" || return 1
    [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s:%s' "$metadata" "$digest"
}

write_env_atomically() {
    local candidate="$1" expected="$2"
    if [[ "$(env_file_identity)" != "$expected" ]] ||
        ! chown --reference="$ENV_FILE" "$candidate" ||
        ! chmod --reference="$ENV_FILE" "$candidate" ||
        { [[ "$(uname -s)" == Linux ]] && ! sync -f "$candidate"; } ||
        [[ "$(env_file_identity)" != "$expected" ]] ||
        ! mv -T -- "$candidate" "$ENV_FILE"; then
        rm -f -- "$candidate"
        printf 'Environment update failed; original configuration retained.\n' >&2
        return 1
    fi
}

set_env_if_missing() {
    local key="$1"
    local value="$2"
    local label="$3"
    local current
    current="$(get_env_value "$key")"

    if [[ -n "$current" ]]; then
        return 0
    fi

    local tmp_file original_state
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
        if ! awk -v key="$key" -v value="$value" '
            BEGIN { replaced = 0 }
            $0 ~ "^" key "=" {
                if (replaced == 0) print key "=" value
                replaced = 1
                next
            }
            { print }
        ' "$ENV_FILE" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    else
        if ! { cat "$ENV_FILE" && printf '\n%s=%s\n' "$key" "$value"; } > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    fi
    write_env_atomically "$tmp_file" "$original_state" || return 1

    log "已自动补充 ${label}: ${key}"
}

get_release_repository_default() {
    get_env_value "$1" | awk -v fallback="$GITHUB_REPO" '
        { value = $0 }
        END {
            sub(/#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            quote = substr(value, 1, 1)
            if ((quote == "\"" || quote == "\047") && substr(value, length(value), 1) == quote)
                value = substr(value, 2, length(value) - 2)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value == "") print fallback
            else if (value ~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/) print value
        }
    '
}

migrate_release_repository() {
    local key="$1" tmp_file original_state
    [[ -f "$ENV_FILE" ]] || return 0
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    # Read dotenv values as data; retain custom sources and every credential.
    if ! awk -v key="$key" -v repository="$GITHUB_REPO" '
        index($0, key "=") == 1 {
            value = substr($0, length(key) + 2)
            sub(/#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            quote = substr(value, 1, 1)
            if ((quote == "\"" || quote == "\047") && substr(value, length(value), 1) == quote)
                value = substr(value, 2, length(value) - 2)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (tolower(value) == "mastalee928/payincus") {
                print key "=" repository
                next
            }
        }
        { print }
    ' "$ENV_FILE" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    if ! cmp -s "$ENV_FILE" "$tmp_file"; then
        write_env_atomically "$tmp_file" "$original_state" || return 1
        log "已迁移退役的 Release 仓库: ${key}"
    fi
    rm -f "$tmp_file"
}

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<EOF_ENV
# ============================================================================
# PayIncus 主机进程部署环境配置
# 由 scripts/init-env.sh 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================
EOF_ENV
    info "已创建 ${ENV_FILE}"
fi

db_password="$(gen_password 24)"
redis_password="$(gen_password 24)"

set_env_if_missing "NODE_ENV" "production" "运行环境"
set_env_if_missing "HOST" "127.0.0.1" "后端监听地址"
set_env_if_missing "PORT" "3001" "后端监听端口"
set_env_if_missing "TRUST_PROXY" "true" "信任本机 Nginx 代理头"
set_env_if_missing "DATABASE_URL" "postgresql://incudal:${db_password}@127.0.0.1:5432/incudal" "PostgreSQL 连接地址"
set_env_if_missing "REDIS_URL" "redis://:${redis_password}@127.0.0.1:6379" "Redis 连接地址"
set_env_if_missing "JWT_SECRET" "$(gen_secret 48)" "JWT 密钥"
set_env_if_missing "COOKIE_SECRET" "$(gen_secret 48)" "Cookie 密钥"
set_env_if_missing "ENCRYPTION_KEY" "$(openssl rand -base64 32)" "敏感数据加密密钥"
set_env_if_missing "ADMIN_EMAIL" "admin@payincus.local" "管理员初始邮箱"
set_env_if_missing "ADMIN_PASSWORD" "$(gen_password 16)" "管理员初始密码"
set_env_if_missing "SERVE_STATIC_CLIENT" "false" "后端静态文件服务开关"
set_env_if_missing "VITE_API_BASE_URL" "/api" "前端 API 基础路径"
set_env_if_missing "VITE_CUSTOMER_BASE_URL" "" "管理后台生成客户链接的前端地址"
set_env_if_missing "VITE_ADMIN_BASE_URL" "" "客户前端管理后台地址"
set_env_if_missing "SYSTEM_UPDATE_RELEASE_REPOSITORY" "$(get_release_repository_default GITHUB_REPO)" "在线更新 GitHub Release 仓库"
set_env_if_missing "INCUDAL_AGENT_RELEASE_REPOSITORY" "$(get_release_repository_default GITHUB_REPOSITORY)" "Agent GitHub Release 仓库"
for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do
    migrate_release_repository "$repository_key"
done
set_env_if_missing "INCUDAL_AGENT_RELEASE_TOKEN" "${INCUDAL_AGENT_RELEASE_TOKEN:-}" "Agent GitHub Release Token"
set_env_if_missing "INCUDAL_AGENT_RELEASE_DIR" "" "Agent 本地 Release 目录"
set_env_if_missing "INCUDAL_AGENT_BINARY_URL" "" "Agent 自定义二进制地址"
set_env_if_missing "INCUDAL_AGENT_BINARY_SHA256" "" "Agent 自定义二进制 SHA256"
set_env_if_missing "LOG_LEVEL" "info" "日志级别"
set_env_if_missing "DISABLE_REQUEST_LOG" "true" "请求日志开关"

chmod 600 "$ENV_FILE"
log "环境配置已就绪: ${ENV_FILE}"
info "请备份 ${ENV_FILE}，尤其是 ENCRYPTION_KEY，生产环境不能随意更换。"
