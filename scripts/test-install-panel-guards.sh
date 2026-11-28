#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "INSTALL_GUARD_FAILED line=%s\n" "$LINENO" >&2' ERR

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=install-panel.sh
source "$REPO_ROOT/scripts/install-panel.sh"

WORK_DIR="$(mktemp -d)"

cat > "$WORK_DIR/legacy-helper-original" <<'LEGACY_HELPER'
#!/usr/bin/env bash
[[ "${1:-}" == "https://github.com/mastalee928/payincus.git" ]] || exit 1
[[ "${2:-}" == fixed-identity ]] || exit 1
LEGACY_HELPER
cp "$WORK_DIR/legacy-helper-original" "$WORK_DIR/legacy-helper"
normalize_legacy_online_task_helper "$WORK_DIR/legacy-helper"
bash "$WORK_DIR/legacy-helper" https://github.com/masta-lee/mastaincus.git fixed-identity
if bash "$WORK_DIR/legacy-helper" https://github.com/mastalee928/payincus.git fixed-identity ||
    bash "$WORK_DIR/legacy-helper" https://untrusted.invalid/repository.git fixed-identity ||
    bash "$WORK_DIR/legacy-helper" https://github.com/masta-lee/mastaincus.git wrong-identity; then
    echo 'legacy deployment helper lost its exact repository or identity gate' >&2; exit 1
fi
cp "$REPO_ROOT/deploy/incudal-online-task.sh.example" "$WORK_DIR/current-helper"
normalize_legacy_online_task_helper "$WORK_DIR/current-helper"
cmp "$REPO_ROOT/deploy/incudal-online-task.sh.example" "$WORK_DIR/current-helper"
# Exercise the unchanged Git gate with real local Git configuration. This
# fixture isolates URL handling; native root ownership is verified separately.
sed -n '/^verify_git_control() {/,/^}/p' "$REPO_ROOT/deploy/incudal-online-task.sh.example" |
    sed 's#/usr/bin/git#git#g' > "$WORK_DIR/git-origin-gate.sh"
bash -s -- "$WORK_DIR" <<'GIT_ORIGIN_GUARD'
    set -euo pipefail
    test_work="$1"
    export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$test_work/isolated-git-config"
    : > "$GIT_CONFIG_GLOBAL"
    source "$test_work/git-origin-gate.sh"
    INSTALL_DIR="$test_work/git-origin-fixture"
    git init --quiet "$INSTALL_DIR"
    fail() { printf '%s\n' "$*" >&2; exit 1; }
    find() { :; }
    current_origin=https://github.com/masta-lee/mastaincus.git
    retired_origin=https://github.com/mastalee928/payincus.git
    git -C "$INSTALL_DIR" remote add origin "$current_origin"
    verify_git_control
    git -C "$INSTALL_DIR" remote set-url origin "$retired_origin"
    verify_git_control
    [[ "$(git -C "$INSTALL_DIR" config --local --get remote.origin.url)" == "$retired_origin" ]]
    verify_git_control migrate-retired-origin
    [[ "$(git -C "$INSTALL_DIR" config --local --get remote.origin.url)" == "$current_origin" ]]
    git -C "$INSTALL_DIR" remote set-url origin https://untrusted.invalid/project.git
    git -C "$INSTALL_DIR" config "url.${retired_origin}.insteadOf" https://untrusted.invalid/project.git
    [[ "$(git -C "$INSTALL_DIR" remote get-url origin)" == "$retired_origin" ]]
    if (verify_git_control migrate-retired-origin) > /dev/null 2>&1; then echo 'rewritten custom raw origin accepted' >&2; exit 1; fi
    [[ "$(git -C "$INSTALL_DIR" config --local --get remote.origin.url)" == https://untrusted.invalid/project.git ]]
    git -C "$INSTALL_DIR" config --unset "url.${retired_origin}.insteadOf"
    git -C "$INSTALL_DIR" remote set-url origin "$current_origin"
    git -C "$INSTALL_DIR" config --add remote.origin.url https://untrusted.invalid/second.git
    if (verify_git_control) > /dev/null 2>&1; then echo 'multiple raw origin URLs accepted' >&2; exit 1; fi
    git -C "$INSTALL_DIR" config --unset-all remote.origin.url
    git -C "$INSTALL_DIR" config remote.origin.url "$retired_origin"
    git -C "$INSTALL_DIR" config 'url.https://untrusted.invalid/source.git.insteadOf' "$current_origin"
    if (verify_git_control) > /dev/null 2>&1; then echo 'source fetch URL rewrite accepted' >&2; exit 1; fi
    git -C "$INSTALL_DIR" config --unset "url.https://untrusted.invalid/source.git.insteadOf"
    : > "$test_work/forbidden-config"
    for forbidden_key in core.hooksPath core.fsmonitor filter.fixture.clean filter.fixture.smudge filter.fixture.process diff.fixture.command include.path 'includeIf.gitdir:/fixture/.path'; do
        git -C "$INSTALL_DIR" config "$forbidden_key" "$test_work/forbidden-config"
        if (verify_git_control) > /dev/null 2>&1; then echo 'executable or untracked repository configuration accepted' >&2; exit 1; fi
        git -C "$INSTALL_DIR" config --unset "$forbidden_key"
    done
GIT_ORIGIN_GUARD
if declare -f start_service | grep -q 'journalctl'; then
    echo 'startup diagnostics cannot publish raw secret-bearing journal output' >&2; exit 1
fi
declare -f start_service > "$WORK_DIR/start-service.sh"
bash -s -- "$WORK_DIR" <<'STARTUP_DIAGNOSTIC_GUARD'
    source "$1/start-service.sh"
    SERVICE_NAME=incudal-backend
    step() { :; }; log() { :; }; error() { :; }; sleep() { :; }
    systemctl() {
        case "$1" in
            start) return 0 ;;
            is-active) return 1 ;;
            show) printf '%s\n' 'ActiveState=failed' 'Result=exit-code' 'ExecMainStatus=1' 'SubState=guard-secret-value' 'Unexpected=guard-secret' ;;
        esac
    }
    journalctl() { printf 'guard-secret'; }
    if (start_service) > "$1/startup-output"; then exit 1; fi
    grep -Fxq 'ActiveState=failed' "$1/startup-output"
    grep -Fxq 'Result=exit-code' "$1/startup-output"
    ! grep -Fq 'Unexpected=' "$1/startup-output"
    ! grep -Fq 'guard-secret' "$1/startup-output"
STARTUP_DIAGNOSTIC_GUARD
HTTP_FIXTURE_PID=""
trap '[[ -z "$HTTP_FIXTURE_PID" ]] || kill "$HTTP_FIXTURE_PID" 2>/dev/null || true; rm -rf "$WORK_DIR"' EXIT

# The signature verifier is needed even on a minimal machine with Node and
# PostgreSQL already installed and recommended APT packages disabled.
(
    apt-get() { printf '%s\n' "$@" > "$WORK_DIR/system-packages"; }
    command() {
        if [[ "$1" == -v ]]; then
            printf '%s\n' "$2" >> "$WORK_DIR/checked-system-tools"
            [[ "$2" != gpgv || "$have_gpgv" == yes ]]
        else
            builtin command "$@"
        fi
    }
    have_gpgv=yes
    install_system_tools > "$WORK_DIR/tools-ok" 2>&1
    grep -Fxq 'gpgv' "$WORK_DIR/system-packages"
    grep -Fxq 'gpgv' "$WORK_DIR/checked-system-tools"
    have_gpgv=no
    if (install_system_tools) > "$WORK_DIR/tools-missing" 2>&1; then
        printf 'install_system_tools accepted a missing gpgv executable\n' >&2
        exit 1
    fi
    grep -Fq 'gpgv' "$WORK_DIR/tools-missing"
)

# Real Bash readonly assignment semantics differ from an ordinary fixture
# variable. Pass the fixed path only to the two children, never reassign it.
declare -f database_migration_mode run_migrations > "$WORK_DIR/migration-function.sh"
mkdir "$WORK_DIR/migration-bin"
mkdir -p "$WORK_DIR/install/server" "$WORK_DIR/install/scripts"
: > "$WORK_DIR/install/scripts/harden-database.py"
: > "$WORK_DIR/install/scripts/migrate-database.sh"
for migration_program in python3 bash; do
    cat > "$WORK_DIR/migration-bin/$migration_program" <<'MIGRATION_PROGRAM'
#!/bin/sh
printf '%s|%s\n' "$ENV_FILE" "$1" >> "$MIGRATION_CALLS"
MIGRATION_PROGRAM
    chmod 0755 "$WORK_DIR/migration-bin/$migration_program"
done
bash -s -- "$WORK_DIR" <<'MIGRATION_ENV_GUARD'
    set -euo pipefail
    migration_work="$1"
    source "$migration_work/migration-function.sh"
    readonly ENV_FILE="$migration_work/retained.env"
    readonly INSTALL_DIR="$migration_work/install"
    export MIGRATION_CALLS="$migration_work/migration-calls"
    export PATH="$migration_work/migration-bin:$PATH"
    RELEASE_VERIFIED_THIS_RUN=true
    VERIFIED_LEGACY_DATABASE_PACKAGE=""
    step() { :; }; log() { :; }; error() { printf '%s\n' "$*" >&2; }
    run_migrations
    [[ "$(wc -l < "$MIGRATION_CALLS")" == 2 ]]
    grep -Fxq "$ENV_FILE|$INSTALL_DIR/scripts/harden-database.py" "$MIGRATION_CALLS"
    grep -Fxq "$ENV_FILE|$INSTALL_DIR/scripts/migrate-database.sh" "$MIGRATION_CALLS"
    [[ "$(database_migration_mode "$INSTALL_DIR")" == modern ]]
    RELEASE_VERIFIED_THIS_RUN=false
    if (database_migration_mode "$INSTALL_DIR") > /dev/null 2>&1; then echo 'unverified migrations accepted' >&2; exit 1; fi
    RELEASE_VERIFIED_THIS_RUN=true
    VERIFIED_LEGACY_DATABASE_PACKAGE=v1.8.14
    if (database_migration_mode "$INSTALL_DIR") > /dev/null 2>&1; then echo 'extra legacy migration tools accepted' >&2; exit 1; fi
    rm -f "$INSTALL_DIR/scripts/harden-database.py"
    VERIFIED_LEGACY_DATABASE_PACKAGE=""
    if (database_migration_mode "$INSTALL_DIR") > /dev/null 2>&1; then echo 'partial modern migration tools accepted' >&2; exit 1; fi
    rm -f "$INSTALL_DIR/scripts/migrate-database.sh"
    VERIFIED_LEGACY_DATABASE_PACKAGE=v1.8.14
    [[ "$(database_migration_mode "$INSTALL_DIR")" == legacy ]]
    VERIFIED_LEGACY_DATABASE_PACKAGE=v1.8.13
    [[ "$(database_migration_mode "$INSTALL_DIR")" == legacy ]]
    VERIFIED_LEGACY_DATABASE_PACKAGE=""
    if (database_migration_mode "$INSTALL_DIR") > /dev/null 2>&1; then echo 'missing modern tools treated as legacy' >&2; exit 1; fi
MIGRATION_ENV_GUARD

if [[ "$(uname -s)" == Linux ]]; then
  python3 "$REPO_ROOT/scripts/test-platform-recovery-lock.py"
fi

# Token-bearing script downloads retain forwarding but no proxy request logs.
write_nginx_split_server_block panel.example.invalid /fixture/user > "$WORK_DIR/nginx-script-token.conf"
sed -n '/location \^~ \/api\/hosts\/caddy-script\//,/^    }/p' "$WORK_DIR/nginx-script-token.conf" > "$WORK_DIR/nginx-script-token-location.conf"
grep -Fq 'access_log off;' "$WORK_DIR/nginx-script-token-location.conf"
grep -Fq 'error_log /dev/null;' "$WORK_DIR/nginx-script-token-location.conf"
grep -Fq "proxy_pass http://127.0.0.1:${DEFAULT_PORT};" "$WORK_DIR/nginx-script-token-location.conf"
grep -Fq 'proxy_set_header X-Forwarded-Host $incudal_forwarded_host;' "$WORK_DIR/nginx-script-token-location.conf"
# A fresh file used to discard the supplied token even though upgrades populated
# empty values. Exercise both paths without real credentials or system ownership.
declare -f generate_env ensure_env_keys env_dotenv_data get_env_value env_file_identity write_env_atomically set_env_if_missing set_env_value set_env_if_value get_release_repository_default migrate_release_repository gen_secret gen_password > "$WORK_DIR/env-functions.sh"
# Installer paths are intentionally readonly. Run the unchanged functions in a
# separate shell so test paths cannot weaken those production constants.
bash -s -- "$WORK_DIR" "$WORK_DIR/env-functions.sh" <<'ENV_GUARD'
    set -Eeuo pipefail
    trap 'printf "INSTALL_ENV_GUARD_FAILED line=%s\n" "$LINENO" >&2' ERR
    token_work="$1"
    source "$2"
    DEFAULT_PORT=3001
    INSTALL_DIR=/opt/incudal
    GITHUB_REPO=masta-lee/mastaincus
    RUN_USER=incudal
    log() { printf '%s\n' "$*"; }
    info() { printf '%s\n' "$*"; }
    step() { printf '%s\n' "$*"; }
    ENV_FILE="$token_work/fresh-agent-token.env"
    INCUDAL_AGENT_RELEASE_TOKEN=guard_agent_token_not_a_credential
    chown() { :; }
    generate_env guard_db guard_redis guard_admin installer@example.invalid > "$token_work/agent-token-output" 2>&1
    [[ "$(get_env_value INCUDAL_AGENT_RELEASE_TOKEN)" == "$INCUDAL_AGENT_RELEASE_TOKEN" ]]
    [[ "$(grep -c '^INCUDAL_AGENT_RELEASE_TOKEN=' "$ENV_FILE")" == 1 ]]
    chmod_mode=$(stat -c %a "$ENV_FILE")
    # Windows file modes are not Linux deployment evidence.
    [[ "$(uname -s)" != Linux || "$chmod_mode" == 640 ]]
    if grep -Fq "$INCUDAL_AGENT_RELEASE_TOKEN" "$token_work/agent-token-output"; then
        echo 'installer exposed the supplied Agent token' >&2; exit 1
    fi
    INCUDAL_AGENT_RELEASE_TOKEN=guard_different_agent_token
    generate_env guard_db guard_redis guard_admin installer@example.invalid >> "$token_work/agent-token-output" 2>&1
    [[ "$(get_env_value INCUDAL_AGENT_RELEASE_TOKEN)" == guard_agent_token_not_a_credential ]]
    sed -i 's/^INCUDAL_AGENT_RELEASE_TOKEN=.*/INCUDAL_AGENT_RELEASE_TOKEN=/' "$ENV_FILE"
    ensure_env_keys >> "$token_work/agent-token-output" 2>&1
    [[ "$(get_env_value INCUDAL_AGENT_RELEASE_TOKEN)" == "$INCUDAL_AGENT_RELEASE_TOKEN" ]]
    if grep -Fq "$INCUDAL_AGENT_RELEASE_TOKEN" "$token_work/agent-token-output"; then
        echo 'installer exposed the supplied Agent token' >&2; exit 1
    fi
    ENV_FILE="$token_work/no-agent-token.env"
    unset INCUDAL_AGENT_RELEASE_TOKEN
    chown() { :; }
    generate_env guard_db guard_redis guard_admin installer@example.invalid > /dev/null 2>&1
    [[ -z "$(get_env_value INCUDAL_AGENT_RELEASE_TOKEN)" ]]
    ENV_FILE="$token_work/retired-repositories.env"
    cat > "$ENV_FILE" <<'RETIRED_ENV'
SYSTEM_UPDATE_RELEASE_REPOSITORY="mastalee928/payincus" # retired default
INCUDAL_AGENT_RELEASE_REPOSITORY='  MASTALEE928/PAYINCUS  '
GITHUB_REPO=  mastalee928/payincus
GITHUB_REPOSITORY=custom/agent-source
SYSTEM_UPDATE_RELEASE_TOKEN=guard-retained-update-token
INCUDAL_AGENT_RELEASE_TOKEN=guard-retained-agent-token
ENCRYPTION_KEY=guard-retained-key
OTHER_SOURCE=mastalee928/payincus
RETIRED_ENV
    cp "$ENV_FILE" "$ENV_FILE.before"
    for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do
        migrate_release_repository "$repository_key" > /dev/null
    done
    for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO; do
        [[ "$(env_dotenv_data repository "$repository_key")" == masta-lee/mastaincus ]]
    done
    [[ "$(get_env_value GITHUB_REPOSITORY)" == custom/agent-source ]]
    cmp <(grep -Ev '^(SYSTEM_UPDATE_RELEASE_REPOSITORY|INCUDAL_AGENT_RELEASE_REPOSITORY|GITHUB_REPO)=' "$ENV_FILE.before") \
        <(grep -Ev '^(SYSTEM_UPDATE_RELEASE_REPOSITORY|INCUDAL_AGENT_RELEASE_REPOSITORY|GITHUB_REPO)=' "$ENV_FILE")
    cp "$ENV_FILE" "$ENV_FILE.expected"
    migrate_release_repository SYSTEM_UPDATE_RELEASE_REPOSITORY > /dev/null
    cmp "$ENV_FILE" "$ENV_FILE.expected"
    for custom_source in custom/panel-source mastalee928/payincus-other mastalee928/payincus/extra; do
        printf 'SYSTEM_UPDATE_RELEASE_REPOSITORY=%s\n' "$custom_source" > "$ENV_FILE"
        cp "$ENV_FILE" "$ENV_FILE.expected"
        migrate_release_repository SYSTEM_UPDATE_RELEASE_REPOSITORY > /dev/null
        cmp "$ENV_FILE" "$ENV_FILE.expected"
    done
    ENV_FILE="$token_work/custom-alias-only.env"
    printf '%s\n' 'GITHUB_REPO="custom/panel"' "GITHUB_REPOSITORY='custom/agent'" 'JWT_SECRET=guard-retained-jwt' 'COOKIE_SECRET=guard-retained-cookie' 'ENCRYPTION_KEY=guard-retained-encryption' > "$ENV_FILE"
    ensure_env_keys > /dev/null
    [[ "$(get_env_value SYSTEM_UPDATE_RELEASE_REPOSITORY)" == custom/panel ]]
    [[ "$(get_env_value INCUDAL_AGENT_RELEASE_REPOSITORY)" == custom/agent ]]
    grep -Fxq 'GITHUB_REPO="custom/panel"' "$ENV_FILE"
    grep -Fxq "GITHUB_REPOSITORY='custom/agent'" "$ENV_FILE"
    ENV_FILE="$token_work/exported-alias-and-multiline.env"
    cat > "$ENV_FILE" <<'EXPORTED_ALIAS_ENV'
export GITHUB_REPO = "custom/panel"
export GITHUB_REPOSITORY = 'custom/agent'
JWT_SECRET="fixture-first
GITHUB_REPO=mastalee928/payincus
fixture-last"
COOKIE_SECRET=guard-retained-cookie
ENCRYPTION_KEY=guard-retained-encryption
EXPORTED_ALIAS_ENV
    ensure_env_keys > /dev/null
    [[ "$(get_env_value SYSTEM_UPDATE_RELEASE_REPOSITORY)" == custom/panel ]]
    [[ "$(get_env_value INCUDAL_AGENT_RELEASE_REPOSITORY)" == custom/agent ]]
    [[ "$(get_env_value JWT_SECRET)" == $'fixture-first\nGITHUB_REPO=mastalee928/payincus\nfixture-last' ]]
    grep -Fxq 'export GITHUB_REPO = "custom/panel"' "$ENV_FILE"
    grep -Fxq "export GITHUB_REPOSITORY = 'custom/agent'" "$ENV_FILE"
    # A real trailing LF is credential data. Shell substitution must not turn
    # newline-only secrets into missing values or a suffixed password/port into
    # an exact insecure/default value during the full installer repair path.
    set_env_value JWT_SECRET $'\n' fixture > /dev/null
    set_env_value ADMIN_PASSWORD $'admin123\n' fixture > /dev/null
    set_env_value PORT $'3000\n' fixture > /dev/null
    cp "$ENV_FILE" "$ENV_FILE.expected"
    ensure_env_keys > /dev/null
    cmp "$ENV_FILE" "$ENV_FILE.expected"
    [[ "$(get_env_value JWT_SECRET && printf '\037')" == $'\n\n\037' ]]
    [[ "$(get_env_value ADMIN_PASSWORD && printf '\037')" == $'admin123\n\n\037' ]]
    [[ "$(get_env_value PORT && printf '\037')" == $'3000\n\n\037' ]]
    set_env_value ADMIN_PASSWORD admin123 fixture > /dev/null
    ensure_env_keys > /dev/null
    [[ "$(get_env_value ADMIN_PASSWORD)" != admin123 ]]
    for failed_command in awk cat chmod mv; do
        ENV_FILE="$token_work/atomic-failure-${failed_command}.env"
        printf '%s\n' 'JWT_SECRET=guard-retained-atomic-key' 'SYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus' > "$ENV_FILE"
        cp "$ENV_FILE" "$ENV_FILE.expected"
        (
            case "$failed_command" in
                awk) awk() { if [[ ${1:-} == -v ]]; then printf 'partial edit\n'; return 71; else command awk "$@"; fi; } ;;
                cat) cat() { printf 'partial read\n'; return 72; } ;;
                chmod) chmod() { return 73; } ;;
                mv) mv() { return 74; } ;;
            esac
            if [[ "$failed_command" == cat ]]; then
                if set_env_value NEW_SETTING fixture 'fixture setting' > /dev/null 2>&1; then echo 'partial environment copy was accepted' >&2; exit 1; fi
            elif migrate_release_repository SYSTEM_UPDATE_RELEASE_REPOSITORY > /dev/null 2>&1; then
                echo 'failed environment replacement was accepted' >&2; exit 1
            fi
        )
        cmp "$ENV_FILE" "$ENV_FILE.expected"
        [[ -z "$(find "$token_work" -maxdepth 1 -name "$(basename "$ENV_FILE").incudal-env.*" -print -quit)" ]]
    done
ENV_GUARD

# The standalone initializer must migrate existing defaults too, not only the
# full installer. Keep credentials and custom sources, then verify idempotency.
cat > "$WORK_DIR/init-repositories.env" <<'INIT_ENV'
SYSTEM_UPDATE_RELEASE_REPOSITORY=mastalee928/payincus
INCUDAL_AGENT_RELEASE_REPOSITORY="MASTALEE928/PAYINCUS"
GITHUB_REPOSITORY=custom/agent-source
JWT_SECRET=guard-retained-jwt
COOKIE_SECRET=guard-retained-cookie
ENCRYPTION_KEY=guard-retained-encryption
INIT_ENV
env ENV_FILE="$WORK_DIR/init-repositories.env" bash "$REPO_ROOT/scripts/init-env.sh" > "$WORK_DIR/init-repositories.log" 2>&1
grep -Fxq 'SYSTEM_UPDATE_RELEASE_REPOSITORY=masta-lee/mastaincus' "$WORK_DIR/init-repositories.env"
grep -Fxq 'INCUDAL_AGENT_RELEASE_REPOSITORY="masta-lee/mastaincus"' "$WORK_DIR/init-repositories.env"
for retained in 'GITHUB_REPOSITORY=custom/agent-source' 'JWT_SECRET=guard-retained-jwt' 'COOKIE_SECRET=guard-retained-cookie' 'ENCRYPTION_KEY=guard-retained-encryption'; do
    grep -Fxq "$retained" "$WORK_DIR/init-repositories.env"
done
cp "$WORK_DIR/init-repositories.env" "$WORK_DIR/init-repositories.expected"
env ENV_FILE="$WORK_DIR/init-repositories.env" bash "$REPO_ROOT/scripts/init-env.sh" >> "$WORK_DIR/init-repositories.log" 2>&1
cmp "$WORK_DIR/init-repositories.env" "$WORK_DIR/init-repositories.expected"
! grep -Fq guard-retained "$WORK_DIR/init-repositories.log"
printf '%s\n' 'GITHUB_REPO="custom/panel"' "GITHUB_REPOSITORY='custom/agent'" > "$WORK_DIR/init-alias-only.env"
env ENV_FILE="$WORK_DIR/init-alias-only.env" bash "$REPO_ROOT/scripts/init-env.sh" > "$WORK_DIR/init-alias-only.log" 2>&1
grep -Fxq 'SYSTEM_UPDATE_RELEASE_REPOSITORY=custom/panel' "$WORK_DIR/init-alias-only.env"
grep -Fxq 'INCUDAL_AGENT_RELEASE_REPOSITORY=custom/agent' "$WORK_DIR/init-alias-only.env"
grep -Fxq 'GITHUB_REPO="custom/panel"' "$WORK_DIR/init-alias-only.env"
grep -Fxq "GITHUB_REPOSITORY='custom/agent'" "$WORK_DIR/init-alias-only.env"

# Invalid existing credentials must fail before package/service changes and keep
# every byte of the existing configuration. Run only unchanged installer code.
printf '%s\n' "${INSTALLATION_IDENTITY_PATHS[@]}" | grep -Fxq /var/lib/incudal-gateway-controller/signing.pem
[[ "$INSTALLATION_GATEWAY_STATE_DIR" == /var/lib/incudal-management-gateway ]]
declare -f do_install env_file_identity has_existing_installation_identity database_migration_mode get_env_value env_dotenv_data > "$WORK_DIR/install-function.sh"
declare -f do_upgrade > "$WORK_DIR/upgrade-function.sh"
bash -s -- "$WORK_DIR" <<'EXISTING_ENV_GUARD'
    set -euo pipefail
    test_work="$1"
    source "$test_work/install-function.sh"
    INSTALL_DIR="$test_work/install"
    ENV_FILE="$test_work/existing.env"
    printf 'DATABASE_URL=invalid\nJWT_SECRET=fixture-identity\n' > "$ENV_FILE"
    cp "$ENV_FILE" "$test_work/expected.env"
    show_banner() { :; }; check_os() { :; }; check_existing() { return 0; }
    warn() { :; }; info() { :; }; error() { :; }
    do_upgrade() { echo 'invalid credentials must not reach a successful upgrade' >&2; return 0; }
    gen_password() { echo 'installer must not generate replacement credentials' >&2; exit 99; }
    if do_install > /dev/null; then echo 'installer accepted invalid existing credentials' >&2; exit 1; fi
    cmp "$ENV_FILE" "$test_work/expected.env"
EXISTING_ENV_GUARD

# Run the original installer functions in separate processes with isolated paths.
# Dependency and package callbacks are controls; real checksum/archive checks
# remain below and native signed-package installation is verified independently.
resume_cases=(
    configured configured-single-quoted configured-double-quoted configured-space-record configured-failed configured-checksum-failed configured-invalid configured-duplicate-invalid configured-env-read-failed atomic
    fresh partial partial-env partial-env-single-quoted partial-env-double-quoted partial-env-spaced partial-certs partial-empty-certs partial-env-checksum-failed
    download-failed checksum-failed publisher-failed archive-failed helpers-failed
    lost-managed-service lost-legacy-service lost-enrollment lost-controller
    lost-controller-signing lost-controller-signing-no-app
    lost-private-key lost-public-key lost-wireguard lost-recovery
    lost-gateway-identity lost-gateway-bootstrap lost-gateway-owner lost-gateway-transport-identity lost-gateway-auth env-directory env-hardlink env-symlink
    fresh-os-failed fresh-db-password-failed fresh-redis-password-failed fresh-admin-password-failed fresh-admin-prompt-failed
    fresh-apt-failed fresh-dependency-tools-failed fresh-dependency-node-failed fresh-dependency-pnpm-failed
    fresh-dependency-postgres-failed fresh-dependency-redis-failed fresh-dependency-user-failed
    fresh-git-failed fresh-certificate-failed fresh-database-failed fresh-redis-failed fresh-env-failed
    fresh-controller-failed fresh-service-failed fresh-root-unit-failed fresh-migration-failed
    fresh-network-read-failed fresh-nginx-failed fresh-cf-failed fresh-gateway-failed fresh-start-failed fresh-result-failed
)
resume_executed=0
resume_native_pending=0
for resume_case in "${resume_cases[@]}"; do
    resume_root="$WORK_DIR/install-resume-$resume_case"
    mkdir -p "$resume_root/install/server" "$resume_root/control" "$resume_root/gateway-state"
    case "$resume_case" in
        fresh|fresh-*) ;;
        partial-empty-certs) mkdir "$resume_root/install/server/certs" ;;
        *)
            mkdir "$resume_root/install/server/certs"
            printf 'original certificate\n' > "$resume_root/install/server/certs/client.crt"
            ;;
    esac
    if [[ -d "$resume_root/install/server/certs" ]]; then
        cp -a "$resume_root/install/server/certs" "$resume_root/expected-certs"
    fi
    printf 'DATABASE_URL=postgresql://incudal:fixture-db-password@127.0.0.1:5432/incudal\nJWT_SECRET=fixture-retained-identity\n' > "$resume_root/original.env"
    case "$resume_case" in
        configured|configured-*|atomic|env-*)
            mkdir -p "$resume_root/install/server/dist"
            printf 'original app\n' > "$resume_root/install/server/dist/app.js"
            cp "$resume_root/original.env" "$resume_root/install/.env"
            ;;
        fresh-*) ;;
        lost-controller-signing-no-app) ;;
        partial-env*) cp "$resume_root/original.env" "$resume_root/install/.env" ;;
        partial-certs|partial-empty-certs) ;;
        partial|*-failed|lost-*)
            mkdir -p "$resume_root/install/server/dist"
            printf 'original app\n' > "$resume_root/install/server/dist/app.js"
            ;;
    esac
    case "$resume_case" in
        configured-invalid) printf 'DATABASE_URL=invalid\nJWT_SECRET=fixture-retained-identity\n' > "$resume_root/install/.env" ;;
        configured-duplicate-invalid) printf 'DATABASE_URL=invalid\n' >> "$resume_root/install/.env" ;;
        configured-single-quoted|partial-env-single-quoted)
            printf '%s\n' "DATABASE_URL='postgresql://incudal:fixture-db-password@127.0.0.1:5432/incudal'" 'JWT_SECRET=fixture-retained-identity' > "$resume_root/install/.env"
            ;;
        configured-double-quoted|partial-env-double-quoted)
            printf '%s\n' 'DATABASE_URL="postgresql://incudal:fixture-db-password@127.0.0.1:5432/incudal" # original comment' 'JWT_SECRET=fixture-retained-identity' > "$resume_root/install/.env"
            ;;
        configured-space-record|partial-env-spaced)
            printf '%s\n' '  export DATABASE_URL = "postgresql://incudal:fixture-db-password@127.0.0.1:5432/incudal"  # original spacing' 'JWT_SECRET=fixture-retained-identity' > "$resume_root/install/.env"
            ;;
        env-directory) rm "$resume_root/install/.env"; mkdir "$resume_root/install/.env" ;;
        env-hardlink) rm "$resume_root/install/.env"; ln "$resume_root/original.env" "$resume_root/install/.env" ;;
        env-symlink)
            rm "$resume_root/install/.env"
            if MSYS=winsymlinks:nativestrict ln -s "../original.env" "$resume_root/install/.env" 2> "$resume_root/symlink.log" &&
                [[ -L "$resume_root/install/.env" ]]; then
                :
            elif [[ "$(uname -s)" != Linux ]]; then
                printf 'NATIVE_ENV_SYMLINK_CASE_PENDING: this Windows toolchain cannot create a real symlink; Linux CI must run the refusal case.\n'
                resume_native_pending=$((resume_native_pending + 1))
                continue
            else
                echo 'the Linux symlink refusal fixture requires real symlink semantics' >&2
                exit 1
            fi
            ;;
        lost-managed-service) : > "$resume_root/control/managed.service" ;;
        lost-legacy-service) : > "$resume_root/control/legacy.service" ;;
        lost-enrollment) : > "$resume_root/control/enrollment.json" ;;
        lost-controller) : > "$resume_root/control/identity.json" ;;
        lost-controller-signing|lost-controller-signing-no-app) : > "$resume_root/control/signing.pem" ;;
        lost-private-key) : > "$resume_root/control/management-key" ;;
        lost-public-key) : > "$resume_root/control/management-key.pub" ;;
        lost-wireguard) : > "$resume_root/control/wireguard.conf" ;;
        lost-recovery) : > "$resume_root/control/recovery-hold.json" ;;
        lost-gateway-identity|lost-gateway-bootstrap)
            mkdir "$resume_root/gateway-state/gateway-a"
            if [[ "$resume_case" == lost-gateway-identity ]]; then
                : > "$resume_root/gateway-state/gateway-a/identity.json"
            else
                : > "$resume_root/gateway-state/gateway-a/bootstrap.json"
            fi
            ;;
        lost-gateway-owner) : > "$resume_root/gateway-state/owner.json" ;;
        lost-gateway-transport-identity)
            mkdir -p "$resume_root/gateway-state/gateway-a/transport"
            : > "$resume_root/gateway-state/gateway-a/transport/gateway-identity.json"
            ;;
        lost-gateway-auth)
            mkdir -p "$resume_root/gateway-state/gateway-a/auth"
            : > "$resume_root/gateway-state/gateway-a/auth/gateway-auth.json"
            ;;
    esac
    if [[ -f "$resume_root/install/.env" && ! -L "$resume_root/install/.env" ]]; then
        cp "$resume_root/install/.env" "$resume_root/expected.env"
    fi
    : > "$resume_root/trace"
    printf '3\n' > "$resume_root/network-answer"
    case "$resume_case" in
        fresh-network-read-failed) : > "$resume_root/network-answer" ;;
        fresh-nginx-failed) printf '1\n' > "$resume_root/network-answer" ;;
        fresh-cf-failed) printf '2\n' > "$resume_root/network-answer" ;;
        fresh-controller-failed)
            mkdir -p "$resume_root/install/vendor/gateway" "$resume_root/install/scripts"
            : > "$resume_root/install/vendor/gateway/catalog.json"
            printf '#!/usr/bin/env bash\nexit 42\n' > "$resume_root/install/scripts/install-gateway-controller.sh"
            ;;
    esac
    if bash -s -- "$WORK_DIR" "$resume_root" "$resume_case" > "$resume_root/output.log" 2>&1 <<'INSTALL_RESUME_GUARD'
    set -euo pipefail
    guard_work="$1"
    guard_root="$2"
    guard_case="$3"
    source "$guard_work/install-function.sh"
    readonly INSTALL_DIR="$guard_root/install" ENV_FILE="$guard_root/install/.env"
    readonly SERVICE_NAME=incudal-backend SERVICE_FILE="$guard_root/control/managed.service"
    readonly INSTALLATION_IDENTITY_PATHS=(
        "$SERVICE_FILE" "$guard_root/control/legacy.service" "$guard_root/control/enrollment.json"
        "$guard_root/control/identity.json" "$guard_root/control/signing.pem" "$guard_root/control/management-key"
        "$guard_root/control/management-key.pub" "$guard_root/control/wireguard.conf" "$guard_root/control/recovery-hold.json"
    )
    readonly INSTALLATION_GATEWAY_STATE_DIR="$guard_root/gateway-state"
    RELEASE_VERIFIED_THIS_RUN=false
    VERIFIED_LEGACY_DATABASE_PACKAGE=""
    CF_TUNNEL_SELECTED=false
    DEFAULT_PORT=3001
    CYAN="" YELLOW="" DIM="" BOLD="" NC=""
    record() { printf '%s\n' "$*" >> "$guard_root/trace"; }
    show_banner() { :; }; check_os() { [[ "$guard_case" != fresh-os-failed ]] || { record failed:os; return 42; }; }; warn() { :; }; info() { :; }; log() { :; }; step() { :; }; divider() { :; }
    error() { printf '%s\n' "$*" >&2; }
    check_existing() { [[ -f "$INSTALL_DIR/server/dist/app.js" ]]; }
    gen_password() {
        local count=0
        [[ ! -f "$guard_root/password-calls" ]] || read -r count < "$guard_root/password-calls"
        count=$((count + 1)); printf '%s\n' "$count" > "$guard_root/password-calls"
        record generated-password
        if [[ ( "$count" == 1 && "$guard_case" == fresh-db-password-failed ) || ( "$count" == 2 && "$guard_case" == fresh-redis-password-failed ) || ( "$count" == 3 && "$guard_case" == fresh-admin-password-failed ) ]]; then record failed:password; return 42; fi
        printf 'fixture-generated-password'
    }
    prompt_initial_admin_email() { record administrator-prompt; [[ "$guard_case" != fresh-admin-prompt-failed ]] || { record failed:administrator; return 42; }; printf 'fixture@example.invalid'; }
    if [[ "$guard_case" == configured-env-read-failed ]]; then
        get_env_value() { return 42; }
    fi
    set_env_value() { [[ "$RELEASE_VERIFIED_THIS_RUN" == true ]] || return 96; record configuration:edit; }
    dependency() { record "dependency:$1"; [[ "$guard_case" != "fresh-dependency-$1-failed" ]] || { record "failed:dependency-$1"; return 42; }; }
    apt-get() { record dependency:apt; [[ "$guard_case" != fresh-apt-failed ]] || { record failed:apt; return 42; }; }
    install_system_tools() { dependency tools; }
    install_nodejs() { dependency node; }
    install_pnpm() { dependency pnpm; }
    install_postgresql() { dependency postgres; }
    install_redis() { dependency redis; }
    create_user() { dependency user; }
    do_upgrade() { record delegated-upgrade; [[ "$guard_case" != configured-failed ]] || return 41; return 0; }
    if [[ "$guard_case" == atomic || "$guard_case" == configured-checksum-failed ]]; then
        source "$guard_work/upgrade-function.sh"
        is_atomic_layout() { [[ "$guard_case" == atomic ]]; }
        systemctl() { record service-control; }
    fi
    obtain_release() { record obtain-release; [[ "$guard_case" != download-failed ]] || return 43; printf '%s' "$guard_root/controlled-archive"; }
    install_release() {
        record "install-release:$2"
        RELEASE_VERIFIED_THIS_RUN=false
        local phase
        for phase in checksum publisher archive helpers; do
            record "verify:$phase"
            [[ "$guard_case" != "$phase-failed" && "$guard_case" != "configured-$phase-failed" && "$guard_case" != "partial-env-$phase-failed" ]] || return 42
        done
        record authenticated-package
        RELEASE_VERIFIED_THIS_RUN=true
        mkdir -p "$INSTALL_DIR/scripts"
        : > "$INSTALL_DIR/scripts/harden-database.py"
        : > "$INSTALL_DIR/scripts/migrate-database.sh"
    }
    configured_action() {
        [[ "$RELEASE_VERIFIED_THIS_RUN" == true ]] || return 92
        [[ "$(database_migration_mode "$INSTALL_DIR")" == modern ]] || return 93
        record "configuration:$1"
        [[ "$guard_case" != "fresh-$1-failed" ]] || { record "failed:$1"; return 42; }
    }
    configure_git_metadata() { configured_action git; }
    generate_panel_cert() { configured_action certificate; }
    setup_database() {
        configured_action database || return "$?"
        case "$guard_case" in
            partial-env*) [[ "$1" == fixture-db-password ]] || return 94; record retained-db-password ;;
        esac
    }
    setup_redis() { configured_action redis; }
    generate_env() { configured_action env || return "$?"; [[ -f "$ENV_FILE" ]] || cp "$guard_root/original.env" "$ENV_FILE"; }
    create_service() { configured_action service; }
    create_online_update_service() { configured_action root-unit; }
    run_migrations() { configured_action migration; }
    configure_host_pool_gateway() { configured_action gateway; }
    start_service() { configured_action start; }
    show_result() { configured_action result; }
    setup_nginx_certbot() { record failed:nginx; return 42; }
    setup_cf_tunnel() { record failed:cf; return 42; }
    if [[ "$guard_case" == configured-checksum-failed || "$guard_case" == configured-env-read-failed || "$guard_case" == partial-env-checksum-failed || "$guard_case" == fresh-* ]]; then
        # A calling condition disables Bash errexit inside functions. Package
        # refusal must still return its failure without reaching configuration.
        if do_install < "$guard_root/network-answer"; then exit 0; else exit "$?"; fi
    fi
    do_install < "$guard_root/network-answer"
INSTALL_RESUME_GUARD
    then
        resume_status=0
    else
        resume_status=$?
    fi
    resume_expected=1
    case "$resume_case" in
        configured|configured-single-quoted|configured-double-quoted|configured-space-record|fresh|partial|partial-env|partial-env-single-quoted|partial-env-double-quoted|partial-env-spaced|partial-certs|partial-empty-certs) resume_expected=0 ;;
        configured-failed) resume_expected=41 ;;
        configured-checksum-failed|configured-env-read-failed) resume_expected=42 ;;
    esac
    if [[ "$resume_case" == fresh-* && "$resume_case" != fresh-network-read-failed ]]; then resume_expected=42; fi
    [[ "$resume_status" -eq "$resume_expected" ]] || {
        printf 'installer resume case %s returned %s instead of %s\n' "$resume_case" "$resume_status" "$resume_expected" >&2
        cat "$resume_root/output.log" >&2
        exit 1
    }
    if [[ -d "$resume_root/expected-certs" ]]; then
        diff -r "$resume_root/expected-certs" "$resume_root/install/server/certs"
    fi
    if [[ -f "$resume_root/expected.env" ]]; then
        cmp "$resume_root/expected.env" "$resume_root/install/.env"
    fi
    case "$resume_case" in
        configured|configured-single-quoted|configured-double-quoted|configured-space-record|configured-failed)
            [[ "$(cat "$resume_root/trace")" == delegated-upgrade ]]
            ;;
        configured-checksum-failed)
            grep -Fxq verify:checksum "$resume_root/trace"
            ! grep -q '^configuration:' "$resume_root/trace"
            ! grep -Fxq authenticated-package "$resume_root/trace"
            ! grep -Fxq generated-password "$resume_root/trace"
            ! grep -Fxq administrator-prompt "$resume_root/trace"
            ;;
        fresh|partial|partial-env|partial-env-single-quoted|partial-env-double-quoted|partial-env-spaced|partial-certs|partial-empty-certs)
            grep -Fxq obtain-release "$resume_root/trace"
            if [[ "$resume_case" == partial* ]]; then
                grep -Fxq install-release:true "$resume_root/trace"
            else
                grep -Fxq install-release:false "$resume_root/trace"
            fi
            verified_line=$(grep -nFx authenticated-package "$resume_root/trace" | cut -d: -f1)
            first_config=$(grep -n '^configuration:' "$resume_root/trace" | head -n 1 | cut -d: -f1)
            [[ "$verified_line" -lt "$first_config" ]]
            grep -Fxq configuration:result "$resume_root/trace"
            if [[ "$resume_case" == partial-env* ]]; then grep -Fxq retained-db-password "$resume_root/trace"; fi
            ;;
        partial-env-checksum-failed)
            grep -Fxq install-release:true "$resume_root/trace"
            grep -Fxq verify:checksum "$resume_root/trace"
            ! grep -q '^configuration:' "$resume_root/trace"
            ! grep -Fxq authenticated-package "$resume_root/trace"
            ;;
        download-failed|checksum-failed|publisher-failed|archive-failed|helpers-failed)
            ! grep -q '^configuration:' "$resume_root/trace"
            ! grep -Fxq authenticated-package "$resume_root/trace"
            [[ ! -e "$resume_root/install/.env" ]]
            ;;
        fresh-*)
            ! grep -Fxq configuration:result "$resume_root/trace" || [[ "$resume_case" == fresh-result-failed ]]
            if [[ "$resume_case" != fresh-controller-failed && "$resume_case" != fresh-network-read-failed ]]; then
                [[ "$(tail -n 1 "$resume_root/trace")" == failed:* ]]
            fi
            if [[ "$resume_case" == fresh-migration-failed ]]; then
                ! grep -Fxq configuration:gateway "$resume_root/trace"
                ! grep -Fxq configuration:start "$resume_root/trace"
            fi
            ;;
        *)
            [[ ! -s "$resume_root/trace" ]]
            ;;
    esac
    if [[ "$resume_case" == atomic ]]; then grep -Fq '检测到原子 OTA 布局' "$resume_root/output.log"; fi
    resume_executed=$((resume_executed + 1))
done
printf 'PASS installer resume subprocess controls: %s configured/partial/refusal cases; native_symlink_pending=%s\n' "$resume_executed" "$resume_native_pending"

declare -f install_release do_upgrade > "$WORK_DIR/install-release-functions.sh"
release_failure_cases=(
    success empty-certs root-mkdir front-harden date backup-copy
    env-backup-temp cert-backup-temp env-backup-copy cert-backup-copy
    tree-cleanup archive-extract env-restore-temp env-restore-copy env-restore-move
    cert-restore-temp cert-restore-copy cert-retained-temp cert-retained-rmdir
    cert-retain-move cert-publish-move cert-cleanup download-cleanup final-cert-mkdir post-harden
)
for release_failure_case in "${release_failure_cases[@]}"; do
    release_guard_root="$WORK_DIR/release-command-$release_failure_case"
    mkdir -p "$release_guard_root/install/server/certs" "$release_guard_root/payload/server/dist" "$release_guard_root/tmp"
    printf 'paid-expiry=2030-01-01\nidentity=fixture-original\n' > "$release_guard_root/install/.env"
    cp "$release_guard_root/install/.env" "$release_guard_root/original.env"
    if [[ "$release_failure_case" != empty-certs ]]; then
        printf 'fixture original client identity\n' > "$release_guard_root/install/server/certs/client.key"
        printf 'fixture hidden identity\n' > "$release_guard_root/install/server/certs/.hidden"
        mkdir "$release_guard_root/install/server/certs/empty"
    fi
    cp -a "$release_guard_root/install/server/certs" "$release_guard_root/original-certs"
    printf 'fixture new app\n' > "$release_guard_root/payload/server/dist/app.js"
    tar -czf "$release_guard_root/archive.tar.gz" -C "$release_guard_root/payload" .
    bash -s -- "$WORK_DIR" "$release_guard_root" "$release_failure_case" <<'ORIGINAL_RELEASE_COMMAND_GUARD'
    set -euo pipefail
    guard_work="$1"; guard_root="$2"; guard_case="$3"
    source "$guard_work/install-release-functions.sh"
    readonly INSTALL_DIR="$guard_root/install"
    RELEASE_VERIFIED_THIS_RUN=false; VERIFIED_LEGACY_DATABASE_PACKAGE=""
    record() { printf '%s\n' "$*" >> "$guard_root/actions"; }
    error() { record "error:$*"; }; info() { :; }; step() { :; }
    log() { record "success:$*"; }
    verify_release_checksum() { record checksum; }
    verify_release_publisher() { record publisher; }
    validate_release_archive() { record archive-validation; }
    install_verified_root_helpers_from_archive() { record verified-helpers; }
    function /usr/local/libexec/incudal/incudal-online-task {
        [[ "$1" == harden ]] || return 91
        [[ "$RELEASE_VERIFIED_THIS_RUN" == false ]] || return 92
        local count=0
        [[ ! -f "$guard_root/hardens" ]] || read -r count < "$guard_root/hardens"
        count=$((count + 1)); printf '%s\n' "$count" > "$guard_root/hardens"
        record "harden:$count"
        if [[ "${guard_probe:-false}" != true && ( ( "$count" == 1 && "$guard_case" == front-harden ) || ( "$count" == 2 && "$guard_case" == post-harden ) ) ]]; then return 42; fi
    }
    # Prove the absolute helper is controlled before calling the untouched
    # original function; no host root helper or service is executed.
    guard_probe=true
    /usr/local/libexec/incudal/incudal-online-task harden
    guard_probe=false
    rm "$guard_root/hardens"
    : > "$guard_root/actions"
    fs_command() {
        local program="$1"; shift
        local operation="" count=0
        case "$program" in
            mkdir)
                [[ "$*" != "-p $INSTALL_DIR" ]] || operation=root-mkdir
                [[ "$*" != "-p $INSTALL_DIR/server/certs" ]] || operation=final-cert-mkdir
                ;;
            date) operation=date ;;
            cp)
                [[ "$1" != -r || "$2" != "$INSTALL_DIR" ]] || operation=backup-copy
                [[ "$1" != -a || "$2" != "$INSTALL_DIR/.env" ]] || operation=env-backup-copy
                [[ "$1" != -a || "$2" != "$INSTALL_DIR/server/certs" ]] || operation=cert-backup-copy
                [[ "$3" != "$INSTALL_DIR"/.env.restore.* ]] || operation=env-restore-copy
                [[ "$3" != "$INSTALL_DIR"/server/.certs.restore.* ]] || operation=cert-restore-copy
                ;;
            rm)
                [[ "$*" != "-rf $INSTALL_DIR/client "* ]] || operation=tree-cleanup
                [[ "$*" != "-f $guard_root/archive.tar.gz "* ]] || operation=download-cleanup
                [[ "$*" != "-rf $INSTALL_DIR/server/.certs.retained."* ]] || operation=cert-cleanup
                ;;
            tar) operation=archive-extract ;;
            mv)
                local move_source="$2"
                [[ "$2" != -- ]] || move_source="$3"
                [[ "$move_source" != "$INSTALL_DIR"/.env.restore.* ]] || operation=env-restore-move
                [[ "$move_source" != "$INSTALL_DIR/server/certs" ]] || operation=cert-retain-move
                [[ "$move_source" != "$INSTALL_DIR"/server/.certs.restore.* ]] || operation=cert-publish-move
                ;;
            rmdir) operation=cert-retained-rmdir ;;
            mktemp)
                [[ ! -f "$guard_root/temps" ]] || read -r count < "$guard_root/temps"
                count=$((count + 1)); printf '%s\n' "$count" > "$guard_root/temps"
                case "$count" in 1) operation=env-backup-temp ;; 2) operation=cert-backup-temp ;; 3) operation=env-restore-temp ;; 4) operation=cert-restore-temp ;; 5) operation=cert-retained-temp ;; esac
                ;;
        esac
        record "command:$program:$operation"
        if [[ "$operation" == "$guard_case" ]]; then
            if [[ "$operation" == env-restore-copy ]]; then printf 'partial invalid identity' > "$3"; fi
            if [[ "$operation" == cert-restore-copy ]]; then printf 'partial invalid identity' > "$3/client.key"; fi
            return 42
        fi
        if [[ "$program" == mktemp && "$#" -eq 0 ]]; then
            command mktemp "$guard_root/tmp/file.XXXXXXXX"
        elif [[ "$program" == mktemp && "$*" == -d ]]; then
            command mktemp -d "$guard_root/tmp/dir.XXXXXXXX"
        else
            command "$program" "$@"
        fi
    }
    mkdir() { fs_command mkdir "$@"; }; date() { fs_command date "$@"; }
    cp() { fs_command cp "$@"; }; rm() { fs_command rm "$@"; }
    tar() { fs_command tar "$@"; }; mv() { fs_command mv "$@"; }
    rmdir() { fs_command rmdir "$@"; }; mktemp() { fs_command mktemp "$@"; }
    if install_release "$guard_root/archive.tar.gz" true; then result=0; else result=$?; fi
    if [[ "$guard_case" == success || "$guard_case" == empty-certs ]]; then
        [[ "$result" -eq 0 && "$RELEASE_VERIFIED_THIS_RUN" == true ]]
        grep -Fq 'success:产物包安装完成' "$guard_root/actions"
        [[ "$(cat "$guard_root/hardens")" -eq 2 ]]
    else
        [[ "$result" -eq 42 && "$RELEASE_VERIFIED_THIS_RUN" == false ]] || { printf 'original install_release failure case %s returned %s/receipt=%s\n' "$guard_case" "$result" "$RELEASE_VERIFIED_THIS_RUN" >&2; exit 1; }
        ! grep -Fq 'success:产物包安装完成' "$guard_root/actions"
        [[ "$(tail -n 1 "$guard_root/actions")" == "command:"*":$guard_case" || "$guard_case" == front-harden || "$guard_case" == post-harden || "$guard_case" == cert-publish-move ]]
    fi
    command cmp "$guard_root/original.env" "$INSTALL_DIR/.env"
    command diff -r "$guard_root/original-certs" "$INSTALL_DIR/server/certs"
    record checked-original-identity-and-paid-expiry
ORIGINAL_RELEASE_COMMAND_GUARD
done
printf 'PASS original install_release command controls: %s cases; partial restore writes, empty/hidden certificates and paid identity retained\n' "${#release_failure_cases[@]}"

upgrade_failure_cases=(success config-git config-keys config-service config-root-unit migration start)
for upgrade_failure_case in "${upgrade_failure_cases[@]}"; do
    upgrade_guard_root="$WORK_DIR/upgrade-command-$upgrade_failure_case"
    mkdir -p "$upgrade_guard_root/install"
    printf 'paid-expiry=2030-01-01\nidentity=fixture-original\n' > "$upgrade_guard_root/install/.env"
    cp "$upgrade_guard_root/install/.env" "$upgrade_guard_root/original.env"
    bash -s -- "$WORK_DIR" "$upgrade_guard_root" "$upgrade_failure_case" <<'ORIGINAL_UPGRADE_COMMAND_GUARD'
    set -euo pipefail
    guard_work="$1"; guard_root="$2"; guard_case="$3"
    source "$guard_work/install-release-functions.sh"
    readonly INSTALL_DIR="$guard_root/install" ENV_FILE="$guard_root/install/.env" RUN_USER=fixture
    readonly SERVICE_NAME=incudal-backend
    GITHUB_REPO=masta-lee/mastaincus; CYAN="" GREEN="" BOLD="" NC=""
    record() { printf '%s\n' "$*" >> "$guard_root/actions"; }
    show_banner() { :; }; check_os() { :; }; check_existing() { return 0; }; is_atomic_layout() { return 1; }
    error() { record error; }; info() { :; }; divider() { :; }
    apt-get() { :; }; install_system_tools() { :; }; systemctl() { :; }
    obtain_release() { printf 'controlled-archive'; }
    install_release() { record validated-package; RELEASE_VERIFIED_THIS_RUN=true; }
    chmod() { :; }; chown() { :; }
    action() { record "$1"; [[ "$1" != "$guard_case" ]] || return 42; }
    configure_git_metadata() { action config-git; }; ensure_env_keys() { action config-keys; }
    create_service() { action config-service; }; create_online_update_service() { action config-root-unit; }
    run_migrations() { action migration; }; start_service() { action start; }
    if do_upgrade > "$guard_root/output.log" 2>&1; then result=0; else result=$?; fi
    if [[ "$guard_case" == success ]]; then
        [[ "$result" -eq 0 ]]
        grep -Fq '升级到 unknown 完成' "$guard_root/output.log"
    else
        [[ "$result" -eq 42 ]]
        [[ "$(tail -n 1 "$guard_root/actions")" == "$guard_case" ]]
        ! grep -Fq '升级到 unknown 完成' "$guard_root/output.log"
    fi
    cmp "$guard_root/original.env" "$ENV_FILE"
ORIGINAL_UPGRADE_COMMAND_GUARD
done
printf 'PASS original do_upgrade configuration controls: %s conditional-call cases; failures propagate without later actions or success text\n' "${#upgrade_failure_cases[@]}"

mkdir -p "$WORK_DIR/payload"
printf 'payincus installer guard\n' > "$WORK_DIR/payload/version.txt"

SAFE_ARCHIVE="$WORK_DIR/incudal-v0.0.0-linux-amd64.tar.gz"
tar -czf "$SAFE_ARCHIVE" -C "$WORK_DIR/payload" .
sha256sum "$SAFE_ARCHIVE" > "${SAFE_ARCHIVE}.sha256"

verify_release_checksum "$SAFE_ARCHIVE"
validate_release_archive "$SAFE_ARCHIVE"

printf '%064d  %s\n' 0 "$(basename "$SAFE_ARCHIVE")" > "${SAFE_ARCHIVE}.sha256"
if verify_release_checksum "$SAFE_ARCHIVE"; then
    echo "checksum guard accepted a mismatched archive" >&2
    exit 1
fi

UNSAFE_ARCHIVE="$WORK_DIR/unsafe.tar.gz"
tar -czf "$UNSAFE_ARCHIVE" --transform='s#^#../#' -C "$WORK_DIR/payload" .
if validate_release_archive "$UNSAFE_ARCHIVE"; then
    echo "archive guard accepted a parent traversal path" >&2
    exit 1
fi

grep -Fq -- '-f "${INSTALL_DIR}/current/server/dist/app.js"' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq '检测到原子 OTA 布局' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'ExecStart=/usr/local/libexec/incudal/incudal-online-task update %i' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'ExecStart=/usr/local/libexec/incudal/incudal-online-task rollback %i' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'chown "root:${RUN_USER}" "$ENV_FILE"' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'Defaults:${RUN_USER} secure_path=/usr/local/libexec/incudal:' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'if [[ -x /usr/bin/node ]]; then' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'current_ver=$(/usr/bin/node -v' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq -- '--configure-gateway-controller)' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq -- '"$action" == --initialize' "$REPO_ROOT/scripts/install-gateway-controller.sh"
grep -Fq '/usr/bin/python3 -I -B "$tool" "$action"' "$REPO_ROOT/scripts/install-gateway-controller.sh"
grep -Fq '"$INSTALL_DIR/scripts/install-gateway-controller.sh" --initialize-release' "$REPO_ROOT/scripts/install-panel.sh"
grep -Fq 'chmod go-w /opt' "$REPO_ROOT/scripts/smoke-fresh-install.sh"
grep -Fq 'provision_action=--refresh' "$REPO_ROOT/scripts/install-gateway-controller.sh"
bash -n "$REPO_ROOT/scripts/install-gateway-controller.sh"
if [[ "$(uname -s)" == Linux ]]; then
    if [[ $EUID -eq 0 ]]; then
        python3 "$REPO_ROOT/scripts/test-gateway-controller-directory.py"
    else
        sudo -n python3 "$REPO_ROOT/scripts/test-gateway-controller-directory.py"
    fi
fi
grep -Fq 'NOPASSWD: /usr/local/libexec/incudal/systemctl' "$REPO_ROOT/scripts/install-gateway-controller.sh"
if grep -Fq 'NOPASSWD: /usr/local/libexec/incudal/systemctl start' "$REPO_ROOT/scripts/install-gateway-controller.sh"; then
    echo 'gateway sudo rule must use the argument-validating wrapper, without parser-dependent wildcard arguments' >&2
    exit 1
fi
for sudo_source in install-panel.sh install-platform-backup.sh migrate-ota-atomic-layout.sh; do
    grep -Fq 'NOPASSWD: /usr/local/libexec/incudal/systemctl' "$REPO_ROOT/scripts/$sudo_source"
    if grep -Fq 'NOPASSWD: /usr/local/libexec/incudal/systemctl start' "$REPO_ROOT/scripts/$sudo_source"; then
        echo 'managed worker sudo rules must avoid parser-dependent wildcard arguments' >&2
        exit 1
    fi
    if grep -Fq 'requiretty' "$REPO_ROOT/scripts/$sudo_source"; then
        echo 'managed worker sudo rules must not require parser-specific requiretty settings' >&2
        exit 1
    fi
done
grep -Fq 'cmp -s "$wrapper" "$root/deploy/incudal-systemctl-wrapper.sh.example"' "$REPO_ROOT/scripts/install-gateway-controller.sh"
for rejected in \
    'start --no-block ssh.service' \
    'restart --no-block incudal-gateway-task@11111111-1111-4111-8111-111111111111.service' \
    'start --no-block incudal-gateway-task@*.service' \
    'start --no-block incudal-gateway-task@11111111-1111-4111-8111-111111111111.service extra'; do
    read -r -a rejected_args <<< "$rejected"
    if bash "$REPO_ROOT/deploy/incudal-systemctl-wrapper.sh.example" "${rejected_args[@]}" >/dev/null 2>&1; then
        echo 'systemctl wrapper accepted an unsupported gateway invocation' >&2
        exit 1
    fi
done

for helper in \
    incudal-online-task.sh.example \
    incudal-systemctl-wrapper.sh.example \
    incudal-ota-chown-wrapper.sh.example; do
    bash -n "$REPO_ROOT/deploy/$helper"
done

# A restrictive caller umask must not prevent APT from reading its public key.
postgresql_function=$(declare -f install_postgresql)
postgresql_function=${postgresql_function//\/etc\/apt\/keyrings\/postgresql.gpg/$WORK_DIR\/postgresql-public.gpg}
postgresql_function=${postgresql_function//\/etc\/apt\/sources.list.d\/pgdg.list/$WORK_DIR\/pgdg.list}
postgresql_fixture_hash=$(printf 'public-key-fixture\n' | sha256sum | awk '{print $1}')
postgresql_function=${postgresql_function//0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76/$postgresql_fixture_hash}
printf '%s\n' "$postgresql_function" > "$WORK_DIR/postgresql-functions.sh"
bash -s -- "$WORK_DIR" <<'PG_KEY_GUARD'
    set -euo pipefail
    key_work="$1"
    source "$key_work/postgresql-functions.sh"
    PG_VERSION=16
    OS_CODENAME=guard
    umask 077
    psql() { printf 'psql (PostgreSQL) 0.1\n'; }
    step() { :; }
    info() { :; }
    log() { :; }
    error() { :; }
    install() { :; }
    curl() {
        local destination=""
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == -o ]]; then destination="$2"; shift 2; else shift; fi
        done
        printf 'public-key-fixture\n' > "$destination"
    }
    gpg() {
        local destination=""
        while [[ $# -gt 1 ]]; do
            if [[ "$1" == -o ]]; then destination="$2"; shift 2; else shift; fi
        done
        cat "$1" > "$destination"
    }
    apt-get() {
        if [[ "$1" == update && "$(uname -s)" == Linux ]]; then
            [[ "$(stat -c %a "$key_work/postgresql-public.gpg")" == 644 ]] || {
                echo 'strict umask left the public PostgreSQL signing key unreadable by APT' >&2
                return 1
            }
        fi
    }
    ensure_postgresql_running() { :; }
    install_postgresql
    rm -f "$key_work/postgresql-public.gpg"
    curl() {
        local destination=""
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == -o ]]; then destination="$2"; shift 2; else shift; fi
        done
        printf 'different-public-key\n' > "$destination"
    }
    if install_postgresql; then echo 'untrusted PGDG identity accepted' >&2; exit 1; fi
    [[ ! -e "$key_work/postgresql-public.gpg" ]]
PG_KEY_GUARD

# Preinstalled PostgreSQL can be stopped (for example, on a fresh CI image).
# Skipping the package install must still start it before database creation.
(
    psql() { printf 'psql (PostgreSQL) 16.4\n'; }
    systemctl() { printf '%s\n' "$*" >> "$WORK_DIR/postgresql-service-calls"; }
    pg_isready() { grep -Fxq 'start postgresql' "$WORK_DIR/postgresql-service-calls"; }
    install_postgresql
    grep -Fxq 'enable postgresql' "$WORK_DIR/postgresql-service-calls"
    grep -Fxq 'start postgresql' "$WORK_DIR/postgresql-service-calls"
)

if grep -Fq 'ExecStart=/usr/bin/node /opt/incudal/current/server/dist/scripts/' \
    "$REPO_ROOT/deploy/incudal-online-update@.service.example" \
    "$REPO_ROOT/deploy/incudal-online-rollback@.service.example"; then
    echo "root unit still executes a worker from current directly" >&2
    exit 1
fi

# Windows Git Bash can provide Python as python.exe rather than python3.
PYTHON_BIN="$(command -v python3 || command -v python)"
if ! command -v python3 >/dev/null && command -v python >/dev/null; then
    python3() { python "$@"; }
fi

# Verify that listing errors after valid members and non-unique root helpers
# cannot install a partial set. These fixtures never touch system destinations.
helper_work="$WORK_DIR/root-helper-archive"
mkdir -p "$helper_work/output"
"$PYTHON_BIN" -I -B - "$helper_work" <<'HELPER_ARCHIVE_FIXTURES'
import io, pathlib, sys, tarfile

root = pathlib.Path(sys.argv[1])
names = ("incudal-online-task.sh.example", "incudal-systemctl-wrapper.sh.example", "incudal-ota-chown-wrapper.sh.example")
for case in ("valid", "duplicate", "missing", "linked", "empty", "oversized"):
    with tarfile.open(root / (case + ".tar.gz"), "w:gz") as archive:
        for index, name in enumerate(names):
            if index == 2 and case == "missing":
                continue
            data = ("#!/bin/bash\n# " + name + "\n").encode()
            if index == 2 and case == "empty":
                data = b""
            if index == 2 and case == "oversized":
                data += b"x" * (1024 * 1024)
            member = tarfile.TarInfo(("./" if index % 2 else "") + "deploy/" + name)
            if index == 2 and case == "linked":
                member.type = tarfile.SYMTYPE
                member.linkname = names[0]
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
                if index == 2 and case == "duplicate":
                    archive.addfile(member, io.BytesIO(data))
(root / "truncated.tar.gz").write_bytes((root / "valid.tar.gz").read_bytes()[:-8])
HELPER_ARCHIVE_FIXTURES
stage_release_root_helpers "$helper_work/valid.tar.gz" "$helper_work/output"
for helper in incudal-online-task.sh.example incudal-systemctl-wrapper.sh.example incudal-ota-chown-wrapper.sh.example; do
    printf '#!/bin/bash\n# %s\n' "$helper" | cmp - "$helper_work/output/$helper"
done
for variant in duplicate missing linked empty oversized; do
    mkdir "$helper_work/$variant"
    if stage_release_root_helpers "$helper_work/$variant.tar.gz" "$helper_work/$variant" ||
        [[ -n "$(ls -A "$helper_work/$variant")" ]]; then
        echo "Invalid $variant helper set was accepted or partially staged" >&2; exit 1
    fi
done
if validate_release_archive "$helper_work/truncated.tar.gz"; then
    echo 'Archive with a truncated gzip trailer passed validation' >&2; exit 1
fi

for domain in panel.example.com admin.example.com PANEL.example.com xn--fiqs8s.example.com; do
    is_valid_cf_domain "$domain" || { echo "valid CF domain rejected" >&2; exit 1; }
done
for domain in '' localhost 127.0.0.1 https://panel.example.com panel.example.com/ \
    panel.example.com:80 'panel.example.com injected' '-panel.example.com' \
    'panel-.example.com' 'panel..example.com' '.panel.example.com' 'panel.example.com.'; do
    if is_valid_cf_domain "$domain"; then
        echo "invalid CF domain accepted" >&2
        exit 1
    fi
done
[[ "$(printf 'https://panel.example.com\nPANEL.example.com\n' | prompt_cf_domain 客户 panel.example.com 2>/dev/null)" == panel.example.com ]]
show_cf_tunnel_guide > "$WORK_DIR/cf-guide" 2>&1
grep -Fq '内网 Service URL' "$WORK_DIR/cf-guide"
grep -Fq 'http://127.0.0.1:80' "$WORK_DIR/cf-guide"
(
    DOMAIN=customer.sub.example.com
    ADMIN_DOMAIN=control.sub.example.com
    show_cf_route_summary > "$WORK_DIR/cf-routes" 2>&1
    grep -Eq 'customer\.sub\.example\.com +http://127\.0\.0\.1:80' "$WORK_DIR/cf-routes"
    grep -Eq 'control\.sub\.example\.com +http://127\.0\.0\.1:80' "$WORK_DIR/cf-routes"
)

# Invalid tokens and CLI output must not leak, and a failed install must stay failed.
(
    cloudflared() { printf 'Provided Tunnel token is not valid: %s\n' "$3"; return 1; }
    if install_cf_service <<< 'installer-guard-placeholder' > "$WORK_DIR/cf-token-output" 2>&1; then
        echo "failed cloudflared install accepted" >&2
        exit 1
    fi
    ! grep -Fq 'installer-guard-placeholder' "$WORK_DIR/cf-token-output"
    grep -Fq 'Token 无效' "$WORK_DIR/cf-token-output"
    cloudflared() { printf 'unsafe successful output: %s\n' "$3"; }
    install_cf_service <<< 'installer-guard-placeholder' > "$WORK_DIR/cf-token-output" 2>&1
    ! grep -Fq 'installer-guard-placeholder' "$WORK_DIR/cf-token-output"
    cloudflared() { echo 'unexpected invocation' >> "$WORK_DIR/cf-invalid-token-call"; }
    if install_cf_service <<< 'cloudflared service install placeholder' >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$WORK_DIR/cf-invalid-token-call" ]]
)

mkdir -p "$WORK_DIR/cf-user" "$WORK_DIR/cf-admin"
printf '<html>customer frontend</html>\n' > "$WORK_DIR/cf-user/index.html"
printf '<html>admin frontend</html>\n' > "$WORK_DIR/cf-admin/index.html"

# systemctl may return 1 for not-found. Local unit files can still exist on a
# live test host; neither situation is an inability to query systemd (status 2).
(
    systemctl() { printf 'not-found\n'; return 1; }
    status=0
    cf_service_exists || status=$?
    [[ "$status" -ne 2 ]]
    systemctl() { return 1; }
    status=0
    cf_service_exists || status=$?
    [[ "$status" -eq 2 ]]
)

# Exercise setup without touching /etc, starting services or contacting Cloudflare.
(
    # Ignore a real host's existing unit files when exercising installation.
    cf_service_exists() { [[ "${CF_GUARD_LOAD:-not-found}" != not-found ]]; }
    resolve_static_dist_dir() {
        if [[ "$1" == client/dist/user ]]; then printf '%s' "$WORK_DIR/cf-user";
        else printf '%s' "$WORK_DIR/cf-admin"; fi
    }
    check_cf_prerequisites() { return 0; }
    configure_cf_nginx() { echo nginx >> "$WORK_DIR/cf-actions"; }
    set_env_value() { printf 'env:%s\n' "$1" >> "$WORK_DIR/cf-actions"; }
    systemctl() {
        printf '%s\n' "$*" >> "$WORK_DIR/cf-service-calls"
        case "$1" in
            show) printf '%s\n' "${CF_GUARD_LOAD:-not-found}" ;;
            is-active) [[ "${CF_GUARD_ACTIVE:-yes}" == yes ]] ;;
            enable|start) [[ "${CF_GUARD_START:-yes}" == yes ]] ;;
        esac
    }
    cloudflared() { [[ "${CF_GUARD_INSTALL:-yes}" == yes ]]; }
    CF_GUARD_INSTALL=no
    if setup_cf_tunnel <<< $'panel.example.com\nadmin.example.com\ninstaller-guard-placeholder' >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$WORK_DIR/cf-actions" && "$CF_TUNNEL_SELECTED" == false ]]
    CF_GUARD_INSTALL=yes
    CF_GUARD_START=no
    if setup_cf_tunnel <<< $'panel.example.com\nadmin.example.com\ninstaller-guard-placeholder' >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$WORK_DIR/cf-actions" ]]
    CF_GUARD_START=yes
    setup_cf_tunnel <<< $'panel.example.com\nadmin.example.com\ninstaller-guard-placeholder' >/dev/null 2>&1
    [[ "$CF_TUNNEL_SELECTED" == true && "$CF_TUNNEL_VERIFIED" == false ]]
    grep -Fxq nginx "$WORK_DIR/cf-actions"
    [[ "$(grep -c '^env:' "$WORK_DIR/cf-actions")" -eq 6 ]]

    : > "$WORK_DIR/cf-actions"
    configure_cf_nginx() { return 1; }
    CF_TUNNEL_SELECTED=false
    if setup_cf_tunnel <<< $'panel.example.com\nadmin.example.com\ninstaller-guard-placeholder' >/dev/null 2>&1; then exit 1; fi
    [[ ! -s "$WORK_DIR/cf-actions" && "$CF_TUNNEL_SELECTED" == false ]]
    configure_cf_nginx() { echo nginx >> "$WORK_DIR/cf-actions"; }

    # Existing tunnels require explicit reuse and must never be installed/restarted.
    : > "$WORK_DIR/cf-actions"
    : > "$WORK_DIR/cf-service-calls"
    CF_GUARD_LOAD=loaded
    CF_TUNNEL_SELECTED=false
    if setup_cf_tunnel <<< '' >/dev/null 2>&1; then exit 1; fi
    [[ ! -s "$WORK_DIR/cf-actions" && "$CF_TUNNEL_SELECTED" == false ]]
    cloudflared() { echo 'overwrote existing tunnel' >> "$WORK_DIR/cf-actions"; return 1; }
    CF_GUARD_ACTIVE=no
    if setup_cf_tunnel <<< $'reuse\npanel.example.com\nadmin.example.com' >/dev/null 2>&1; then exit 1; fi
    [[ ! -s "$WORK_DIR/cf-actions" ]]
    CF_GUARD_ACTIVE=yes
    setup_cf_tunnel <<< $'reuse\npanel.example.com\nadmin.example.com' >/dev/null 2>&1
    ! grep -Eq '^(enable|start|restart)' "$WORK_DIR/cf-service-calls"
    ! grep -Fq 'overwrote' "$WORK_DIR/cf-actions"
    if setup_cf_tunnel <<< $'reuse\npanel.example.com\nPANEL.example.com' >/dev/null 2>&1; then exit 1; fi
)

# Stored URLs are read as data, and invalid URL fields cannot enter diagnostics.
(
    get_env_value() {
        if [[ "$1" == FRONTEND_URL ]]; then echo "${CF_GUARD_USER_URL:-https://panel.example.com/}";
        else echo "${CF_GUARD_ADMIN_URL:-https://admin.example.com}"; fi
    }
    load_cf_domains
    [[ "$DOMAIN" == panel.example.com && "$ADMIN_DOMAIN" == admin.example.com ]]
    CF_GUARD_ADMIN_URL=https://PANEL.example.com
    if load_cf_domains; then exit 1; fi
    CF_GUARD_ADMIN_URL=https://admin.example.com/path
    if load_cf_domains; then exit 1; fi
    CF_GUARD_USER_URL=http://panel.example.com
    if load_cf_domains >/dev/null 2>&1; then exit 1; fi
)

# A non-Nginx listener on port 80 must fail preflight without killing it.
(
    ss() { echo 'LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("other-server",pid=42,fd=5))'; }
    systemctl() { return 0; }
    if check_cf_prerequisites > "$WORK_DIR/cf-preflight" 2>&1; then exit 1; fi
    grep -Fq '80 端口被其他程序占用' "$WORK_DIR/cf-preflight"
    ss() { return 0; }
    nginx() { return 1; }
    if check_cf_prerequisites > "$WORK_DIR/cf-preflight" 2>&1; then exit 1; fi
    grep -Fq '现有 Nginx 配置未通过' "$WORK_DIR/cf-preflight"
)

# Only live connection metrics from this service invocation can prove readiness.
(
    systemctl() { [[ "$1" != show ]] || echo 0123456789abcdef0123456789abcdef; }
    journalctl() {
        [[ "$1" == _SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef ]] || return 1
        echo 'Starting metrics server on 127.0.0.1:20241/metrics'
    }
    curl() { echo "cloudflared_tunnel_ha_connections ${CF_GUARD_CONNECTIONS:-4}"; }
    cf_connection_ready
    journalctl() { echo 'Starting metrics server on [::1]:20241/metrics'; }
    curl() {
        [[ "${*: -1}" == 'http://[::1]:20241/metrics' ]] || return 1
        echo "cloudflared_tunnel_ha_connections ${CF_GUARD_CONNECTIONS:-4}"
    }
    cf_connection_ready
    CF_GUARD_CONNECTIONS=0
    status=0; cf_connection_ready || status=$?
    [[ "$status" -eq 1 ]]
    curl() { echo '# unrelated metrics'; }
    status=0; cf_connection_ready || status=$?
    [[ "$status" -eq 2 ]]
    journalctl() { echo 'Starting metrics server on 0.0.0.0:20241/metrics'; }
    status=0; cf_connection_ready || status=$?
    [[ "$status" -eq 2 ]]
)

# Real local HTTP responses: 200 alone is insufficient, and roles must not swap.
cat > "$WORK_DIR/cf-http-fixture.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        code = {'/502': 502, '/530': 530, '/access': 302}.get(self.path, 200)
        if self.path == '/api/health':
            body = b'{"status":"ok"}'
        elif self.path == '/bad-health':
            body = b'{"status":"failed"}'
        else:
            role = 'cf-admin' if self.headers.get('Host') == 'admin.example.com' else 'cf-user'
            body = (Path(sys.argv[2]) / role / 'index.html').read_bytes()
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
Path(sys.argv[1]).write_text(str(server.server_port), encoding='utf-8')
server.serve_forever()
PY
"$PYTHON_BIN" "$WORK_DIR/cf-http-fixture.py" "$WORK_DIR/cf-http-port" "$WORK_DIR" &
HTTP_FIXTURE_PID=$!
for attempt in {1..50}; do
    [[ ! -s "$WORK_DIR/cf-http-port" ]] || break
    sleep 0.1
done
[[ -s "$WORK_DIR/cf-http-port" ]]
CF_HTTP_URL="http://127.0.0.1:$(cat "$WORK_DIR/cf-http-port")"
cf_probe_http 用户端 "$CF_HTTP_URL/" "$WORK_DIR/cf-user/index.html" panel.example.com
cf_probe_http 管理端 "$CF_HTTP_URL/" "$WORK_DIR/cf-admin/index.html" admin.example.com
cf_probe_http 健康检查 "$CF_HTTP_URL/api/health" health
if cf_probe_http 错误页面 "$CF_HTTP_URL/" "$WORK_DIR/cf-admin/index.html" panel.example.com > "$WORK_DIR/cf-probe" 2>&1; then exit 1; fi
grep -Fq '内容不符' "$WORK_DIR/cf-probe"
if cf_probe_http 错误健康状态 "$CF_HTTP_URL/bad-health" health >/dev/null 2>&1; then exit 1; fi
for route in 502 530 access; do
    if cf_probe_http 公网 "$CF_HTTP_URL/$route" health > "$WORK_DIR/cf-probe" 2>&1; then exit 1; fi
    case "$route" in
        502) grep -Fq 'Type=HTTP、URL=127.0.0.1:80' "$WORK_DIR/cf-probe" ;;
        530) grep -Fq '1033' "$WORK_DIR/cf-probe" ;;
        access) grep -Fq 'Access' "$WORK_DIR/cf-probe" ;;
    esac
done
(
    curl() { return 6; }
    sleep() { return 0; }
    if cf_probe_http 公网 https://panel.example.com/ health > "$WORK_DIR/cf-probe" 2>&1; then exit 1; fi
    grep -Fq 'DNS 解析失败' "$WORK_DIR/cf-probe"
    grep -Fq 'DNS 缓存或传播延迟' "$WORK_DIR/cf-probe"
    grep -Fq '无需重装面板' "$WORK_DIR/cf-probe"
)

# Recover transient public failures using the same resolver and verified response.
# Persistent failures are bounded; local, HTTP, content and TLS failures do not retry.
(
    sleep() { echo "$1" >> "$WORK_DIR/cf-retry-sleeps"; }
    curl() {
        local call_count=0 arg
        [[ ! -f "$WORK_DIR/cf-retry-count" ]] || call_count="$(cat "$WORK_DIR/cf-retry-count")"
        call_count=$((call_count+1))
        printf '%s' "$call_count" > "$WORK_DIR/cf-retry-count"
        for arg in "$@"; do
            [[ "$arg" != https://panel.example.com/* ]] || {
                if [[ "$CF_GUARD_RETRY_CODE" -ne 0 ]] &&
                    [[ "$CF_GUARD_RETRY_ALWAYS" == yes || "$call_count" -eq 1 ]]; then
                    return "$CF_GUARD_RETRY_CODE"
                fi
                # Use the real local HTTP fixture for the successful response.
                set -- "${@:1:$#-1}" "$CF_HTTP_URL/${arg#https://panel.example.com/}"
                break
            }
        done
        command curl "$@"
    }
    CF_GUARD_RETRY_ALWAYS=no
    for CF_GUARD_RETRY_CODE in 6 7 28; do
        rm -f "$WORK_DIR/cf-retry-count" "$WORK_DIR/cf-retry-sleeps"
        cf_probe_http 公网 https://panel.example.com/api/health health > "$WORK_DIR/cf-probe" 2>&1
        [[ "$(cat "$WORK_DIR/cf-retry-count")" == 2 ]]
        [[ "$(cat "$WORK_DIR/cf-retry-sleeps")" == 3 ]]
        grep -Fq 'API status=ok' "$WORK_DIR/cf-probe"
    done
    CF_GUARD_RETRY_ALWAYS=yes
    CF_GUARD_RETRY_CODE=6
    rm -f "$WORK_DIR/cf-retry-count" "$WORK_DIR/cf-retry-sleeps"
    if cf_probe_http 公网 https://panel.example.com/api/health health > "$WORK_DIR/cf-probe" 2>&1; then exit 1; fi
    [[ "$(cat "$WORK_DIR/cf-retry-count")" == 3 ]]
    [[ "$(wc -l < "$WORK_DIR/cf-retry-sleeps")" -eq 2 ]]
    ! grep -Fq '通过' "$WORK_DIR/cf-probe"
    CF_GUARD_RETRY_CODE=60
    rm -f "$WORK_DIR/cf-retry-count" "$WORK_DIR/cf-retry-sleeps"
    if cf_probe_http 公网 https://panel.example.com/api/health health >/dev/null 2>&1; then exit 1; fi
    [[ "$(cat "$WORK_DIR/cf-retry-count")" == 1 && ! -e "$WORK_DIR/cf-retry-sleeps" ]]
    CF_GUARD_RETRY_ALWAYS=no
    CF_GUARD_RETRY_CODE=0
    for route in 502 bad-health; do
        rm -f "$WORK_DIR/cf-retry-count" "$WORK_DIR/cf-retry-sleeps"
        if cf_probe_http 公网 "https://panel.example.com/$route" health >/dev/null 2>&1; then exit 1; fi
        [[ "$(cat "$WORK_DIR/cf-retry-count")" == 1 && ! -e "$WORK_DIR/cf-retry-sleeps" ]]
    done
    curl() { echo call >> "$WORK_DIR/cf-local-count"; return 6; }
    if cf_probe_http 本机 "$CF_HTTP_URL/api/health" health >/dev/null 2>&1; then exit 1; fi
    [[ "$(wc -l < "$WORK_DIR/cf-local-count")" -eq 1 && ! -e "$WORK_DIR/cf-retry-sleeps" ]]
)

# Diagnostics collect all layers, and no failure/unknown state can announce success.
(
    DOMAIN=panel.example.com
    ADMIN_DOMAIN=admin.example.com
    nginx() { return 0; }
    systemctl() { return 0; }
    journalctl() { return 0; }
    curl() { return 0; }
    sleep() { return 0; }
    resolve_static_dist_dir() { echo "$WORK_DIR/cf-user"; }
    cf_connection_ready() { return "${CF_GUARD_READY:-0}"; }
    cf_probe_http() {
        echo "$1" >> "$WORK_DIR/cf-diagnostic-calls"
        [[ "$1" != "${CF_GUARD_FAIL:-none}" ]]
    }
    diagnose_cf_tunnel >/dev/null 2>&1
    [[ "$CF_TUNNEL_VERIFIED" == true ]]
    CF_GUARD_FAIL=用户端公网页面
    if diagnose_cf_tunnel >/dev/null 2>&1; then exit 1; fi
    [[ "$CF_TUNNEL_VERIFIED" == false ]]
    grep -Fxq '管理端公网 API' "$WORK_DIR/cf-diagnostic-calls"
    CF_GUARD_FAIL=none
    CF_GUARD_READY=2
    if diagnose_cf_tunnel > "$WORK_DIR/cf-diagnostic" 2>&1; then exit 1; fi
    grep -Fq '尚未验证' "$WORK_DIR/cf-diagnostic"
    CF_TUNNEL_SELECTED=true
    get_env_value() { return 0; }
    show_result > "$WORK_DIR/cf-result" 2>&1
    ! grep -Fq '部署成功' "$WORK_DIR/cf-result"
    grep -Fq '尚未全部验证通过' "$WORK_DIR/cf-result"
)

echo "install-panel guards passed (including CF setup, secret handling and layered diagnostics)"
