#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/incudal}"
SERVICE_NAME="${SERVICE_NAME:-incudal-backend}"
RUN_USER="${RUN_USER:-incudal}"
GITHUB_REPO="${GITHUB_REPO:-masta-lee/mastaincus}"
if [[ "${GITHUB_REPO,,}" == mastalee928/payincus ]]; then GITHUB_REPO=masta-lee/mastaincus; fi
VERIFIED_RELEASE_ARCHIVE="${VERIFIED_RELEASE_ARCHIVE:-}"

log() {
  printf '[migrate-ota-atomic] %s\n' "$*"
}

fail() {
  printf '[migrate-ota-atomic] ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || fail "must run as root"
}

verify_release_archive() {
  [[ -n "$VERIFIED_RELEASE_ARCHIVE" ]] || fail "VERIFIED_RELEASE_ARCHIVE is required"
  [[ -f "$VERIFIED_RELEASE_ARCHIVE" && ! -L "$VERIFIED_RELEASE_ARCHIVE" ]] || fail "verified release archive must be a regular file"
  [[ -f "${VERIFIED_RELEASE_ARCHIVE}.sha256" && ! -L "${VERIFIED_RELEASE_ARCHIVE}.sha256" ]] || fail "verified release checksum file is missing"
  [[ "$(stat -c '%u' "$VERIFIED_RELEASE_ARCHIVE")" == "0" && "$(stat -c '%u' "${VERIFIED_RELEASE_ARCHIVE}.sha256")" == "0" ]] || fail "release archive and checksum must be root-owned"
  if find "$VERIFIED_RELEASE_ARCHIVE" "${VERIFIED_RELEASE_ARCHIVE}.sha256" -perm /022 -print -quit | grep -q .; then
    fail "release archive and checksum must not be writable by group/other"
  fi
  (cd "$(dirname "$VERIFIED_RELEASE_ARCHIVE")" && sha256sum -c "$(basename "${VERIFIED_RELEASE_ARCHIVE}.sha256")") >/dev/null || fail "release archive checksum verification failed"
  tar -tzf "$VERIFIED_RELEASE_ARCHIVE" >/dev/null 2>&1 || fail "release archive is not a valid tar.gz"
  while IFS= read -r entry; do
    entry="${entry#./}"
    [[ "$entry" != /* && "$entry" != ".." && "$entry" != ../* && "$entry" != */../* && "$entry" != */.. ]] || fail "release archive contains an unsafe path"
  done < <(tar -tzf "$VERIFIED_RELEASE_ARCHIVE")
}

install_root_helpers_from_archive() {
  local helper entry tmp normalized
  install -d -o root -g root -m 0755 /usr/local/libexec/incudal /usr/local/libexec/incudal/ota-path
  for helper in incudal-online-task.sh.example incudal-systemctl-wrapper.sh.example incudal-ota-chown-wrapper.sh.example; do
    entry="$(tar -tzf "$VERIFIED_RELEASE_ARCHIVE" | grep -E "^(\./)?deploy/${helper}$" || true)"
    [[ "$(printf '%s\n' "$entry" | sed '/^$/d' | wc -l)" -eq 1 ]] || fail "verified release is missing a unique root helper: deploy/$helper"
    tmp="$(mktemp)"
    tar -xOzf "$VERIFIED_RELEASE_ARCHIVE" "$entry" > "$tmp" || fail "verified root helper extraction failed"
    if [[ "$helper" == incudal-online-task.sh.example ]] &&
        grep -Fq 'https://github.com/mastalee928/payincus.git' "$tmp" &&
        ! grep -Fq 'https://github.com/masta-lee/mastaincus.git' "$tmp"; then
      normalized="$(mktemp)"
      sed 's#https://github[.]com/mastalee928/payincus[.]git#https://github.com/masta-lee/mastaincus.git#g' "$tmp" > "$normalized"
      bash -n "$normalized" || fail "legacy root helper repository migration is invalid"
      mv -f -- "$normalized" "$tmp"
    fi
    [[ -s "$tmp" ]] && bash -n "$tmp" || fail "verified root helper is invalid: deploy/$helper"
    case "$helper" in
      incudal-online-task.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/incudal-online-task ;;
      incudal-systemctl-wrapper.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/systemctl ;;
      incudal-ota-chown-wrapper.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/ota-path/chown ;;
    esac
    rm -f "$tmp"
  done
  install -d -o root -g root -m 0755 /var/cache/incudal-ota /var/lib/incudal-ota/manifests
}

migrate_repository_settings() {
  local raw_origins=() raw_origin target_origin
  target_origin=https://github.com/masta-lee/mastaincus.git
  [[ -d "$INSTALL_DIR/.git" ]] || fail "trusted Git metadata is missing"
  mapfile -t raw_origins < <(git -C "$INSTALL_DIR" config --local --get-all remote.origin.url)
  [[ ${#raw_origins[@]} -eq 1 ]] || fail "Git origin must have exactly one configured URL"
  raw_origin="${raw_origins[0]}"
  [[ "$raw_origin" == https://github.com/mastalee928/payincus.git || "$raw_origin" == "$target_origin" ]] || fail "Git origin is not the trusted repository"
  [[ "$(git -C "$INSTALL_DIR" remote get-url origin)" == "$raw_origin" && "$(git -C "$INSTALL_DIR" ls-remote --get-url "$target_origin")" == "$target_origin" ]] || fail "Git URL rewriting is forbidden"
  git -C "$INSTALL_DIR" remote set-url origin "$target_origin"
  [[ "$(git -C "$INSTALL_DIR" remote get-url origin)" == "$target_origin" ]] || fail "Git origin migration failed"
  /usr/bin/python3 -I -B - "$INSTALL_DIR/.env" <<'REPOSITORY_ENV'
import os,re,stat,sys,tempfile
path=sys.argv[1];before=os.lstat(path)
assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
original=open(path,'rb').read()
def migrate(match):
    value=match[2].split(b'#')[0].strip()
    if len(value)>=2 and value[:1] in [b'"',b"'"] and value[-1:]==value[:1]:value=value[1:-1].strip()
    return match[1]+b'=masta-lee/mastaincus' if value.lower()==b'mastalee928/payincus' else match[0]
changed=re.sub(rb'^(SYSTEM_UPDATE_RELEASE_REPOSITORY|INCUDAL_AGENT_RELEASE_REPOSITORY|GITHUB_REPO|GITHUB_REPOSITORY)=([^\r\n]*)(\r?)$',migrate,original,flags=re.M)
if changed!=original:
    fd,temporary=tempfile.mkstemp(prefix='.incudal-repository-',dir=os.path.dirname(path))
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(changed);os.fchown(stream.fileno(),before.st_uid,before.st_gid);os.fchmod(stream.fileno(),stat.S_IMODE(before.st_mode));stream.flush();os.fsync(stream.fileno())
        current=os.lstat(path)
        assert (current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode,current.st_nlink)==(before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode,before.st_nlink)
        assert open(path,'rb').read()==original
        os.replace(temporary,path)
        directory=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
REPOSITORY_ENV
}

write_systemd_units() {
  local app_dir="$INSTALL_DIR/current"
  local env_file="$INSTALL_DIR/.env"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=PayIncus backend API
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service
Wants=network.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${app_dir}
EnvironmentFile=${env_file}
Environment=HOME=${INSTALL_DIR}
Environment=PATH=/usr/local/libexec/incudal:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=NPM_CONFIG_CACHE=${INSTALL_DIR}/.npm
Environment=XDG_CACHE_HOME=${INSTALL_DIR}/.cache

ExecStartPre=/usr/bin/bash -lc 'cd ${app_dir}/server && pnpm exec prisma migrate deploy'
ExecStart=/usr/bin/node ${app_dir}/server/dist/app.js

Restart=on-failure
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=35min
TimeoutStartSec=10min
LimitNOFILE=65536

NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR} ${INSTALL_DIR}/current ${INSTALL_DIR}/releases ${INSTALL_DIR}/server/certs ${INSTALL_DIR}/.npm ${INSTALL_DIR}/.cache ${INSTALL_DIR}/.git ${INSTALL_DIR}/update-logs
PrivateTmp=true

StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/incudal-online-update@.service <<EOF
[Unit]
Description=PayIncus online update task %i
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${env_file}
Environment=HOME=/var/cache/incudal-ota
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/libexec/incudal/incudal-online-task update %i
TimeoutStartSec=120min
StandardOutput=journal
StandardError=journal
SyslogIdentifier=incudal-online-update
EOF

  cat > /etc/systemd/system/incudal-online-rollback@.service <<EOF
[Unit]
Description=PayIncus online update rollback task %i
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${env_file}
Environment=HOME=/var/cache/incudal-ota
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/libexec/incudal/incudal-online-task rollback %i
TimeoutStartSec=60min
StandardOutput=journal
StandardError=journal
SyslogIdentifier=incudal-online-rollback
EOF

  local sudoers_tmp
  sudoers_tmp="$(mktemp)"
  cat > "$sudoers_tmp" <<EOF
Defaults:${RUN_USER} secure_path=/usr/local/libexec/incudal:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${RUN_USER} ALL=(root) NOPASSWD: /usr/local/libexec/incudal/systemctl
EOF
  chmod 440 "$sudoers_tmp"
  visudo -cf "$sudoers_tmp" >/dev/null
  install -o root -g root -m 0440 "$sudoers_tmp" /etc/sudoers.d/incudal-online-update
  rm -f "$sudoers_tmp"
}

main() {
  require_root
  [[ -d "$INSTALL_DIR" ]] || fail "install dir does not exist: $INSTALL_DIR"
  verify_release_archive
  install_root_helpers_from_archive
  /usr/local/libexec/incudal/incudal-online-task harden
  migrate_repository_settings

  local version timestamp releases_dir release_dir current_link
  version="$(node -e "try { console.log(require('${INSTALL_DIR}/version.json').version || 'local') } catch { console.log('local') }" 2>/dev/null || echo local)"
  timestamp="$(date +%Y%m%d%H%M%S)"
  releases_dir="$INSTALL_DIR/releases"
  release_dir="$releases_dir/${version}-${timestamp}"
  current_link="$INSTALL_DIR/current"

  log "creating release from checksum-verified artifact: $release_dir"
  mkdir -p "$releases_dir" "$release_dir"
  tar -xzf "$VERIFIED_RELEASE_ARCHIVE" -C "$release_dir" --no-same-owner --no-same-permissions
  if find "$release_dir" -xdev \( -type l -o \! -type f \! -type d \) -print -quit | grep -q .; then
    fail "verified release contains symlinks or special files"
  fi
  chown -R root:root "$release_dir"
  find "$release_dir" -xdev -type d -exec chmod 0755 {} +
  find "$release_dir" -xdev -type f -exec chmod go-w {} +
  local next_link
  next_link="$releases_dir/.next-current-$timestamp"
  rm -f "$next_link"
  ln -s "$release_dir" "$next_link"
  mv -Tf "$next_link" "$current_link"

  mkdir -p "$INSTALL_DIR/update-logs" "$INSTALL_DIR/.npm" "$INSTALL_DIR/.cache"
  [[ -f "$INSTALL_DIR/.env" ]] || fail "install env file is missing"
  chown "root:$RUN_USER" "$INSTALL_DIR/.env"
  chmod 0640 "$INSTALL_DIR/.env"

  write_systemd_units
  /usr/local/libexec/incudal/incudal-online-task seal
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME"

  FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:3000}" \
  ADMIN_FRONTEND_URL="${ADMIN_FRONTEND_URL:-http://127.0.0.1:3002}" \
  BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:3001}" \
    bash "$current_link/scripts/verify-split-host.sh"

  log "atomic OTA layout migration completed"
}

main "$@"
