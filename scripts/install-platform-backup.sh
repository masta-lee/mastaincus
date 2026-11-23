#!/usr/bin/env bash
# Invoked by verified installation/update code, or explicitly by the owner.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[[ "$root" == /opt/incudal || "$root" == /opt/incudal/releases/* ]] || { echo 'Unexpected install directory.' >&2; exit 1; }
for file in "$root/deploy/incudal-online-task.sh.example" "$root/deploy/incudal-systemctl-wrapper.sh.example" "$root/deploy/incudal-platform-backup@.service.example"; do
  [[ -f "$file" && ! -L "$file" && $(stat -c %u "$file") == 0 ]] || { echo 'Untrusted helper source.' >&2; exit 1; }
done
# An unsupported DB/Node patch must fail before any persistent service/helper
# replacement, so an installed old worker can still roll back normally.
if [[ -f "$root/scripts/harden-database.py" && ! -e /var/lib/incudal-backup/recovery-hold.json && -f /opt/incudal/.env ]] && /usr/bin/pg_isready -q -d incudal; then
  INCUDAL_DATABASE_PREFLIGHT=1 /usr/bin/python3 -I -B "$root/scripts/harden-database.py"
fi
install -d -o root -g root -m 0755 /usr/local/libexec/incudal
if [[ -f "$root/scripts/harden-nginx-logging.py" ]] && command -v nginx >/dev/null 2>&1; then
  /usr/bin/python3 -I -B "$root/scripts/harden-nginx-logging.py"
fi
if [[ -f "$root/scripts/system-security-inventory.py" ]]; then
  [[ ! -L "$root/scripts/system-security-inventory.py" && $(stat -c %u "$root/scripts/system-security-inventory.py") == 0 && -z $(find "$root/scripts/system-security-inventory.py" -perm /022 -print -quit) ]] || exit 1
  install -o root -g root -m 0755 "$root/scripts/system-security-inventory.py" /usr/local/libexec/incudal/system-security-inventory.py
  cat > /etc/systemd/system/incudal-system-security.service <<'EOF'
[Unit]
Description=PayIncus installed and running security component inventory
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/local/libexec/incudal/system-security-inventory.py --maintain
TimeoutStartSec=15min
EOF
  cat > /etc/systemd/system/incudal-system-security.timer <<'EOF'
[Unit]
Description=Refresh PayIncus security component inventory
[Timer]
OnBootSec=3min
OnUnitInactiveSec=5min
RandomizedDelaySec=30s
[Install]
WantedBy=timers.target
EOF
  /usr/bin/systemctl daemon-reload
  /usr/bin/systemctl enable --now incudal-system-security.timer
fi
# Keep the verifier outside releases so an old worker can reconcile component
# enrollment after switching back to an older release. Install before replacing
# the root launcher; only the current trusted package supplies these tools.
controller_tools=/usr/local/libexec/incudal/gateway-controller-tools
install -d -o root -g root -m 0755 "$controller_tools"
for name in verify-gateway-component-package.py enroll-gateway-controller.py provision-gateway-controller.py; do
  source="$root/scripts/$name"
  [[ -f "$source" && ! -L "$source" && $(stat -c %u "$source") == 0 && -z $(find "$source" -perm /022 -print -quit) ]] || exit 1
  install -o root -g root -m 0644 "$source" "$controller_tools/$name"
done
# Old OTA workers already invoke this installer from the newly verified
# package. Schedule clock upkeep here so the first upgrade gains the fix.
if ! python3 "$root/scripts/ensure-time-sync.py" --install; then
  echo 'TIME_SYNC_INSTALL_PENDING: clock scheduler installation failed; see /var/lib/incudal-time-sync/status.json. Backend startup continues.' >&2
fi
install -d -o root -g incudal -m 0750 /var/lib/incudal-backup
# Independent persistent image data; never lives inside an OTA release tree.
[[ ! -L /var/lib/incudal-images ]] || { echo 'Untrusted persistent image directory.' >&2; exit 1; }
install -d -o incudal -g incudal -m 0750 /var/lib/incudal-images
[[ ! -L /var/lib/incudal-finance ]] || { echo 'Untrusted financial integrity directory.' >&2; exit 1; }
install -d -o incudal -g incudal -m 0700 /var/lib/incudal-finance
install -d -o incudal -g incudal -m 0700 /var/lib/incudal-backup/inbox
install -d -o root -g incudal -m 0750 /var/lib/incudal-backup/results
install -d -o root -g root -m 0700 /var/lib/incudal-backup/private
install -o root -g root -m 0755 "$root/deploy/incudal-online-task.sh.example" /usr/local/libexec/incudal/incudal-online-task
install -o root -g root -m 0755 "$root/deploy/incudal-systemctl-wrapper.sh.example" /usr/local/libexec/incudal/systemctl
install -o root -g root -m 0644 "$root/deploy/incudal-platform-backup@.service.example" /etc/systemd/system/incudal-platform-backup@.service
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
printf '%s\n' 'incudal ALL=(root) NOPASSWD: /usr/local/libexec/incudal/systemctl' > "$temporary"
chmod 0440 "$temporary"
visudo -cf "$temporary" >/dev/null
install -o root -g root -m 0440 "$temporary" /etc/sudoers.d/incudal-platform-backup
install -d -o root -g root -m 0755 /etc/systemd/system/incudal-backend.service.d
work_dir=/opt/incudal
[[ ! -L /opt/incudal/current ]] || work_dir=/opt/incudal/current
cat > /etc/systemd/system/incudal-backend.service.d/platform-backup.conf <<EOF
[Service]
ReadWritePaths=/var/lib/incudal-backup/inbox
ReadWritePaths=/var/lib/incudal-images
ReadWritePaths=/var/lib/incudal-finance
ExecStartPre=
ExecStartPre=+/usr/bin/bash $work_dir/scripts/install-platform-backup.sh
ExecStartPre=+/usr/local/libexec/incudal/incudal-online-task recovery-startup
ExecStartPost=+/usr/local/libexec/incudal/incudal-online-task recovery-ready
ExecStartPre=+/usr/bin/bash -lc 'if [ ! -e /var/lib/incudal-backup/recovery-hold.json ]; then /usr/bin/bash $work_dir/scripts/migrate-database.sh; fi'
EOF
chmod 0644 /etc/systemd/system/incudal-backend.service.d/platform-backup.conf
if [[ -f "$root/scripts/migrate-database.sh" && -f "$root/scripts/harden-database.py" ]]; then
  # Preserve this verified security runtime across physical/atomic rollback.
  # Copy code and dependencies only; never copy .env, certs or user uploads.
  compatibility=/usr/local/libexec/incudal/database-compat-runtime
  # Ordinary startup reuses the preserved runtime. Replace it only when the
  # verified source security modules changed, avoiding a large copy each boot.
  source_hash=$(cd "$root"; { find server/dist server/templates -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum package.json pnpm-lock.yaml; } | sha256sum | awk '{print $1}')
  if [[ ! -f "$compatibility/source.hash" || $(cat "$compatibility/source.hash") != "$source_hash" ]]; then
    stage=$(mktemp -d /usr/local/libexec/incudal/.database-compat-XXXXXX)
    trap 'if [[ -n "${stage:-}" && "$stage" == /usr/local/libexec/incudal/.database-compat-* && -d "$stage" && ! -L "$stage" ]]; then rm -rf -- "$stage"; fi' EXIT
    install -d -m 0755 "$stage/server"
    cp -a "$root/server/dist" "$root/server/templates" "$root/server/node_modules" "$root/server/package.json" "$stage/server/"
    cp -a "$root/node_modules" "$root/package.json" "$stage/"
    # Old workers prepend their strictly scoped chown wrapper to PATH. This
    # retained root runtime is outside /opt/incudal, so use the real utility.
    /usr/bin/chown -R root:root "$stage"
    chmod -R go-w "$stage"
    chmod 0755 "$stage"
    python3 -I -B - "$stage" <<'PY'
import pathlib,hashlib,json,sys
root=pathlib.Path(sys.argv[1])
files={};links={}
for path in sorted(root.rglob('*')):
    if path.is_symlink():
        if not path.resolve().is_relative_to(root):raise ValueError('Database compatibility link escapes retained runtime')
        links[str(path.relative_to(root))]=str(path.readlink())
    elif path.is_file():files[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
(root/'manifest.json').write_text(json.dumps({'version':1,'files':files,'links':links},separators=(',',':')))
PY
    chmod 0644 "$stage/manifest.json"
    printf '%s\n' "$source_hash" > "$stage/source.hash"
    if [[ -e "$compatibility" ]]; then
      [[ -d "$compatibility" && ! -L "$compatibility" ]] || exit 1
      previous="$compatibility.before"
      [[ ! -e "$previous" ]] || { [[ -d "$previous" && ! -L "$previous" ]] || exit 1; rm -rf -- "$previous"; }
      mv "$compatibility" "$previous"
    fi
    mv "$stage" "$compatibility"
    stage=""
    trap - EXIT
  fi
  install -o root -g root -m 0755 "$root/scripts/migrate-database.sh" /usr/local/libexec/incudal/migrate-database
  install -o root -g root -m 0755 "$root/scripts/harden-database.py" /usr/local/libexec/incudal/harden-database.py
  [[ -f "$root/scripts/legacy-database-startup.mjs" && ! -L "$root/scripts/legacy-database-startup.mjs" && $(stat -c %u "$root/scripts/legacy-database-startup.mjs") == 0 && -z $(find "$root/scripts/legacy-database-startup.mjs" -perm /022 -print -quit) ]] || exit 1
  install -o root -g root -m 0644 "$root/scripts/legacy-database-startup.mjs" /usr/local/libexec/incudal/legacy-database-startup.mjs
  # Old installers replace the ordinary launcher when rolling back. These
  # fixed unit overrides keep the verified security launcher for subsequent
  # updates, while it still verifies and executes the original current worker.
  install -o root -g root -m 0755 "$root/deploy/incudal-online-task.sh.example" /usr/local/libexec/incudal/database-secure-task
  for operation in update rollback; do
    if [[ "$operation" == update ]]; then unit=incudal-online-update@.service; else unit=incudal-online-rollback@.service; fi
    install -d -m 0755 "/etc/systemd/system/$unit.d"
    cat > "/etc/systemd/system/$unit.d/zz-database-security.conf" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/libexec/incudal/database-secure-task $operation %i
EOF
    chmod 0644 "/etc/systemd/system/$unit.d/zz-database-security.conf"
  done
  # Preserve the rollback runtime and shim before revoking legacy DDL authority.
  if [[ ! -e /var/lib/incudal-backup/recovery-hold.json && -f /opt/incudal/.env ]] && /usr/bin/pg_isready -q -d incudal; then
    /usr/bin/python3 -I -B "$root/scripts/harden-database.py"
  fi
  # A rollback's older installer must not restore application-owned migrations.
  # The fixed root helper resolves current on each invocation and remains trusted.
  cat > /etc/systemd/system/incudal-backend.service.d/zz-database-security.conf <<'EOF'
[Service]
ExecStartPre=
ExecStartPre=+/usr/bin/python3 -I -B /usr/local/libexec/incudal/harden-database.py
ExecStartPre=+/usr/local/libexec/incudal/incudal-online-task recovery-startup
ExecStartPre=+/usr/bin/bash -lc 'if [ ! -e /var/lib/incudal-backup/recovery-hold.json ]; then /usr/local/libexec/incudal/migrate-database; fi'
Environment=NODE_OPTIONS=--import=/usr/local/libexec/incudal/legacy-database-startup.mjs
EOF
  chmod 0644 /etc/systemd/system/incudal-backend.service.d/zz-database-security.conf
fi
cat > /etc/systemd/system/incudal-recovery-supervisor.service <<'EOF'
[Unit]
Description=PayIncus interrupted recovery continuation
After=postgresql.service network-online.target
[Service]
Type=oneshot
User=root
Group=incudal
EnvironmentFile=/opt/incudal/.env
Environment=NODE_ENV=production
ExecStart=/usr/local/libexec/incudal/incudal-online-task recovery-supervisor
TimeoutStartSec=10min
KillMode=control-group
UMask=0027
EOF
cat > /etc/systemd/system/incudal-recovery-supervisor.timer <<'EOF'
[Unit]
Description=Continue interrupted PayIncus recovery
[Timer]
OnBootSec=90s
OnUnitInactiveSec=60s
Unit=incudal-recovery-supervisor.service
[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/incudal-recovery-supervisor.{service,timer}
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now incudal-recovery-supervisor.timer
if [[ -f "$root/scripts/install-local-gateway-worker.sh" ]]; then
    [[ ! -L "$root/scripts/install-local-gateway-worker.sh" && $(stat -c %u "$root/scripts/install-local-gateway-worker.sh") == 0 ]] || exit 1
    bash "$root/scripts/install-local-gateway-worker.sh"
fi
if [[ -f "$root/scripts/install-gateway-controller.sh" ]]; then
    [[ ! -L "$root/scripts/install-gateway-controller.sh" && $(stat -c %u "$root/scripts/install-gateway-controller.sh") == 0 ]] || exit 1
    if find "$root/scripts/install-gateway-controller.sh" -perm /022 -print -quit | grep -q .; then exit 1; fi
    bash "$root/scripts/install-gateway-controller.sh"
fi
