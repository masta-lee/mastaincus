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

env_dotenv_data() {
    local operation="$1" key="$2" value="${3-}" last_byte
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || return 1
    last_byte="$(tail -c 1 -- "$ENV_FILE" | od -An -tu1)" || return 1
    last_byte="${last_byte//[[:space:]]/}"
    # Parse data with the base-system tools available before Node installation.
    # Values are never shell code or command arguments. Keep the original bytes,
    # including CRLF/no final LF, and skip complete quoted credential blocks.
    cat -- "$ENV_FILE" | INCUDAL_ENV_WRITE_VALUE="$value" LC_ALL=C awk -v BINMODE=3 \
        -v operation="$operation" -v key="$key" -v final_byte="$last_byte" '
        function fail() {
            print "Environment data parsing failed; original configuration retained." > "/dev/stderr"
            exit 65
        }
        function ws(s, p, c, b) {
            c = substr(s, p, 1)
            if (c != "" && c ~ /[[:space:]]/) return 1
            if (substr(s, p, 2) == "\302\240") return 2
            b = substr(s, p, 3)
            if (b == "\357\273\277" || b == "\341\232\200" ||
                b == "\342\200\250" || b == "\342\200\251" || b == "\342\200\257" ||
                b == "\342\201\237" || b == "\343\200\200" ||
                (substr(b, 1, 2) == "\342\200" && substr(b, 3, 1) ~ /^[\200-\212]$/)) return 3
            return 0
        }
        function skip_space(s, p, n) { while ((n = ws(s, p)) > 0) p += n; return p }
        function trim_end(s, end, start, n) {
            while (end >= start) {
                if (ws(s, end) == 1) end--
                else if (end - 1 >= start && ws(s, end - 1) == 2) end -= 2
                else if (end - 2 >= start && ws(s, end - 2) == 3) end -= 3
                else break
            }
            return end
        }
        function trim(s, start, end) { start = skip_space(s, 1); end = trim_end(s, length(s), start); return substr(s, start, end - start + 1) }
        function line_end(s, p, c) { while (p <= length(s)) { c = substr(s, p, 1); if (c == "\r" || c == "\n") break; p++ } return p }
        function next_line(s, p) { p = line_end(s, p); if (substr(s, p, 2) == "\r\n") return p + 2; return p + 1 }
        function record_end(s, p, c, b) {
            while (p <= length(s)) {
                c = substr(s, p, 1); b = substr(s, p, 3)
                if (c == "\r" || c == "\n" || b == "\342\200\250" || b == "\342\200\251") break
                p++
            }
            return p
        }
        function next_record(s, p, b) {
            p = record_end(s, p); b = substr(s, p, 3)
            if (b == "\342\200\250" || b == "\342\200\251") return p + 3
            if (substr(s, p, 2) == "\r\n") return p + 2
            return p + 1
        }
        function quote_end(s, p, q, j, fallback) {
            # dotenv may backtrack an escaped quote at a valid record tail
            # into the closing quote. A non-escaped quote cannot be body data.
            for (j = p + 1; j <= length(s); j++) if (substr(s, j, 1) == q) {
                if (substr(s, j - 1, 1) != "\\") return quote_tail(s, j + 1) ? j : fallback
                if (quote_tail(s, j + 1)) fallback = j
            }
            return fallback
        }
        function quote_tail(s, p, n, c) {
            while ((n = ws(s, p)) > 0 && record_end(s, p) != p) p += n
            c = substr(s, p, 1); return c == "" || c == "#" || record_end(s, p) == p
        }
        function decoded(s, q) {
            s = trim(s); q = substr(s, 1, 1)
            gsub(/\r\n?/, "\n", s)
            if (length(s) >= 2 && (q == single || q == "\"" || q == "`") && substr(s, length(s), 1) == q) {
                s = substr(s, 2, length(s) - 2)
            }
            # dotenv expands these escapes whenever the value starts with a
            # double quote, including its legal unquoted-fallback form.
            if (q == "\"") { gsub(/\\n/, "\n", s); gsub(/\\r/, "\r", s) }
            return s
        }
        function encoded(s, preferred, q) {
            if (index(s, "\r")) fail()
            if (preferred != "" && !index(s, preferred) &&
                (preferred != "\"" || (!index(s, "\\n") && !index(s, "\\r")))) return preferred s preferred
            q = substr(s, 1, 1)
            if (trim(s) == s && !index(s, "#") && !index(s, "\n") && q != single && q != "\"" && q != "`") return s
            if (!index(s, single)) return single s single
            if (!index(s, "`")) return "`" s "`"
            if (!index(s, "\"") && !index(s, "\\n") && !index(s, "\\r")) return "\"" s "\""
            fail()
        }
        { raw = raw $0 "\n"; records++ }
        END {
            single = sprintf("%c", 39)
            if (records && final_byte != 10) raw = substr(raw, 1, length(raw) - 1)
            if (key !~ /^[A-Za-z0-9_.-]+$/ || operation !~ /^(read|repository|presence|set|migrate|needs-migration)$/) fail()
            cursor = 1
            while (cursor <= length(raw)) {
                line = cursor; p = skip_space(raw, cursor)
                if (substr(raw, p, 1) == "#") { cursor = next_record(raw, p); continue }
                if (substr(raw, p, 6) == "export" && ws(raw, p + 6)) p = skip_space(raw, p + 6)
                if (!match(substr(raw, p), /^[A-Za-z0-9_.-]+/)) { cursor = next_record(raw, line); continue }
                name = substr(raw, p, RLENGTH); p = skip_space(raw, p + RLENGTH)
                separator = substr(raw, p, 1)
                if (separator != "=" && !(separator == ":" && ws(raw, p + 1))) { cursor = next_record(raw, line); continue }
                p++
                # The colon branch consumes at least one whitespace character.
                # dotenv normalizes CRLF into one LF before this step.
                if (separator == ":") p += substr(raw, p, 2) == "\r\n" ? 2 : ws(raw, p)
                while (ws(raw, p) && substr(raw, p, 1) != "\r" && substr(raw, p, 1) != "\n") p += ws(raw, p)
                begin = p; look = skip_space(raw, p); q = substr(raw, look, 1); closing = 0; bounded_record = 0
                if (q == single || q == "\"" || q == "`") closing = quote_end(raw, look, q)
                if (closing && quote_tail(raw, closing + 1)) { begin = look; finish = closing + 1; bounded_record = 1 }
                else {
                    finish = line_end(raw, p)
                    for (j = p; j < finish; j++) if (substr(raw, j, 1) == "#") { finish = j; bounded_record = 1; break }
                    finish = trim_end(raw, finish - 1, begin) + 1
                }
                count++; names[count] = name; starts[count] = begin; ends[count] = finish
                values[count] = decoded(substr(raw, begin, finish - begin)); last[name] = count
                cursor = bounded_record ? next_record(raw, finish) : next_line(raw, finish)
            }
            if (operation == "presence") {
                printf "%d\n", (length(values[last[key]]) > 0)
            } else if (operation == "read" || operation == "repository") {
                result = values[last[key]]
                if (operation == "repository") {
                    result = trim(result)
                    if (result != "" && result !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/) fail()
                }
                printf "%s\n", result
            } else if (operation == "needs-migration") {
                found = 0
                for (i = 1; i <= count; i++) if (names[i] == key && tolower(trim(values[i])) == "mastalee928/payincus") found = 1
                printf "%d\n", found
            } else if (operation == "migrate") {
                result = ""; previous = 1
                for (i = 1; i <= count; i++) if (names[i] == key && tolower(trim(values[i])) == "mastalee928/payincus") {
                    piece = substr(raw, starts[i], ends[i] - starts[i])
                    if (!match(tolower(piece), /mastalee928\/payincus/)) fail()
                    result = result substr(raw, previous, starts[i] - previous) substr(piece, 1, RSTART - 1) \
                        "masta-lee/mastaincus" substr(piece, RSTART + RLENGTH)
                    previous = ends[i]
                }
                printf "%s", result substr(raw, previous)
            } else {
                i = last[key]; preferred = ""
                if (i) {
                    piece = substr(raw, starts[i], ends[i] - starts[i]); q = substr(piece, 1, 1)
                    if (length(piece) >= 2 && (q == single || q == "\"" || q == "`") && substr(piece, length(piece), 1) == q) preferred = q
                    printf "%s%s%s", substr(raw, 1, starts[i] - 1), encoded(ENVIRON["INCUDAL_ENV_WRITE_VALUE"], preferred), substr(raw, ends[i])
                } else {
                    eol = "\n"; p = line_end(raw, 1)
                    if (substr(raw, p, 2) == "\r\n") eol = "\r\n"
                    else if (substr(raw, p, 1) == "\r") eol = "\r"
                    delimiter = raw != "" && substr(raw, length(raw), 1) != "\n" && substr(raw, length(raw), 1) != "\r" ? eol : ""
                    printf "%s%s%s=%s%s", raw, delimiter, key, encoded(ENVIRON["INCUDAL_ENV_WRITE_VALUE"], ""), eol
                }
            }
        }
    '
}

get_env_value() {
    local key="$1"
    [[ -f "$ENV_FILE" ]] || return 0
    env_dotenv_data read "$key"
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
    if [[ "$key" == SYSTEM_UPDATE_RELEASE_REPOSITORY || "$key" == INCUDAL_AGENT_RELEASE_REPOSITORY ]]; then
        current="$(env_dotenv_data repository "$key")" || return 1
    else
        current="$(env_dotenv_data presence "$key")" || return 1
        [[ "$current" != 1 ]] || return 0
        [[ "$current" == 0 ]] || return 1
        current=""
    fi
    if [[ -n "$current" ]]; then
        return 0
    fi

    local tmp_file original_state
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    if ! env_dotenv_data set "$key" "$value" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    write_env_atomically "$tmp_file" "$original_state" || return 1

    log "已自动补充 ${label}: ${key}"
}

get_release_repository_default() {
    local alias="$1" primary="${2-}" configured
    # Respect the effective last primary before inspecting an alias.
    if [[ -n "$primary" ]]; then
        configured="$(env_dotenv_data repository "$primary")" || return 1
        if [[ -n "$configured" ]]; then printf '%s\n' "$configured"; return 0; fi
    fi
    configured="$(env_dotenv_data repository "$alias")" || return 1
    printf '%s\n' "${configured:-$GITHUB_REPO}"
}
migrate_release_repository() {
    local key="$1" tmp_file original_state migration_needed
    [[ -f "$ENV_FILE" ]] || return 0
    migration_needed="$(env_dotenv_data needs-migration "$key")" || return 1
    [[ "$migration_needed" != 0 ]] || return 0
    [[ "$migration_needed" == 1 ]] || return 1
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    # Replace only actual retired values, retaining quoting and every other
    # byte. Unmatched files never change identity or announce a migration.
    if ! env_dotenv_data migrate "$key" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
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

system_repository="$(get_release_repository_default GITHUB_REPO SYSTEM_UPDATE_RELEASE_REPOSITORY)" || exit 1
agent_repository="$(get_release_repository_default GITHUB_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY)" || exit 1
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
set_env_if_missing "SYSTEM_UPDATE_RELEASE_REPOSITORY" "$system_repository" "在线更新 GitHub Release 仓库"
set_env_if_missing "INCUDAL_AGENT_RELEASE_REPOSITORY" "$agent_repository" "Agent GitHub Release 仓库"
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
