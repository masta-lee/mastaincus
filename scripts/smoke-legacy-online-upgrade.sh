#!/usr/bin/env bash
# Destructive only inside a fresh disposable GitHub VM; never production.
set -Eeuo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 && ! -e /opt/incudal ]] || exit 1
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
candidate=$(readlink -f -- "${1:?new release archive required}")
old=$(readlink -f -- "${2:?official baseline archive required}")
scenario=${3:-clean}
installer_source=${UPGRADE_DRILL_INSTALLER_SOURCE:-legacy}
[[ $scenario == clean || $scenario == migrated-atomic || $scenario == rollback ]] || exit 1
[[ $installer_source == legacy || $installer_source == current ]] || exit 1
export UPGRADE_DRILL_SCENARIO="$scenario"
export UPGRADE_DRILL_BASELINE_ARCHIVE="$old"
test -s "$candidate"; test -s "$old"; test -s "$old.sha256"
(cd "$(dirname "$old")"; sha256sum --check "$(basename "$old").sha256")
# This migration uses the unchanged original v1.8.14 packages. Keep their
# independent retained digests, not only a checksum fetched from the same URL.
case "$(basename "$old"):$(sha256sum "$old" | awk '{print $1}')" in
  incudal-v1.8.14-linux-amd64.tar.gz:9cfd05408aa6ddd0ec0d7872099c2a0b550d96bce2beb2a063f220f55dd85ee4|incudal-v1.8.14-linux-arm64.tar.gz:03bfb27d636d628048761a44e3bdca8f5d55b1f33183e2466465dfdd98657eaf) ;;
  *) printf '%s\n' 'Original upgrade baseline identity mismatch.' >&2; exit 1 ;;
esac
UPGRADE_DRILL_BASELINE_VERSION=$(tar -xOf "$old" ./version.json | python3 -c 'import json,sys,re; version=json.load(sys.stdin)["version"]; assert re.fullmatch(r"v\d+\.\d+\.\d+", version); print(version)')
export UPGRADE_DRILL_BASELINE_VERSION
work=$(mktemp -d /root/incudal-upgrade-drill-XXXXXX)
export UPGRADE_DRILL_WORK="$work"
stage=legacy-install
report_failure() {
  echo "Legacy upgrade failed at $stage ($scenario). Sanitized diagnostics follow."
  journalctl -u incudal-backend --no-pager -n 60 > "$work/backend.log" 2>&1 || true
  # Raw logs stay on the disposable runner; redact generated credentials.
  python3 - <<'PY'
import pathlib,re,os,urllib.parse
secrets=[]
env=pathlib.Path('/opt/incudal/.env')
if env.exists():
    for line in env.read_text().splitlines():
        if '=' not in line or line.startswith('#'):continue
        key,value=line.split('=',1);value=value.strip().strip('\"\'')
        if value and re.search(r'PASSWORD|SECRET|TOKEN|ENCRYPTION_KEY|DATABASE_URL',key):
            secrets.append(value)
            try:
                password=urllib.parse.urlsplit(value).password
                if password:secrets.append(password)
            except ValueError:pass
work=pathlib.Path(os.environ['UPGRADE_DRILL_WORK'])
paths=[work/'old-install.log',work/'prior-migration.log',work/'worker.log',work/'retry-worker.log',work/'backend.log',*pathlib.Path('/opt/incudal/update-logs').glob('system-update-*.log')]
for p in paths:
    if not p.exists():continue
    text=p.read_text(errors='replace')
    for secret in sorted(secrets,key=len,reverse=True):text=text.replace(secret,'[redacted]')
    for line in text.splitlines()[-60:]:
        if re.search(r'ERROR|FATAL|Error|error|失败|PROVISIONING_REJECTED|DATABASE_|AUTHENTICATION_|FINANCIAL_|INCUDAL_RETIRED_HELPER|INCUDAL_REPOSITORY_STARTUP|Database security|Auto rollback|System update completed|Production readiness verification passed|Backend health is ready',line):
            print(p.name+': '+line[:500])
PY
}
trap report_failure ERR
reset_healthy_fixture_start_budget() {
  # Warmup and separate root-unit scenarios issue normal, successful restarts.
  # Start counting each independent scenario from its verified healthy baseline;
  # retain the real production limits and every restart within the scenario.
  systemctl is-active --quiet incudal-backend
  local fixture_pid_before fixture_pid_after fixture_limits_before fixture_limits_after
  fixture_pid_before=$(systemctl show incudal-backend.service -p MainPID --value)
  [[ "$fixture_pid_before" =~ ^[1-9][0-9]*$ ]] || exit 1
  fixture_limits_before=$(systemctl show incudal-backend.service --property=StartLimitIntervalUSec,StartLimitBurst,RestartUSec)
  [[ $'\n'"$fixture_limits_before"$'\n' == *$'\nStartLimitBurst=5\n'* && $'\n'"$fixture_limits_before"$'\n' == *$'\nRestartUSec=10s\n'* ]] || exit 1
  [[ $'\n'"$fixture_limits_before"$'\n' == *$'\nStartLimitIntervalUSec=5min\n'* || $'\n'"$fixture_limits_before"$'\n' == *$'\nStartLimitIntervalUSec=300s\n'* ]] || exit 1
  systemctl reset-failed incudal-backend.service
  systemctl is-active --quiet incudal-backend
  fixture_pid_after=$(systemctl show incudal-backend.service -p MainPID --value)
  fixture_limits_after=$(systemctl show incudal-backend.service --property=StartLimitIntervalUSec,StartLimitBurst,RestartUSec)
  [[ "$fixture_pid_after" == "$fixture_pid_before" && "$fixture_limits_after" == "$fixture_limits_before" ]] || exit 1
  printf '%s\n' 'PASS isolated healthy fixture start budget: original PID and production start/restart limits unchanged'
}
[[ -d /opt && ! -L /opt && $(stat -c %u /opt) == 0 ]] || exit 1
chmod go-w /opt
install -d -m 755 /tmp/incudal
cp "$old" "$old.sha256" /tmp/incudal/
if [[ "$installer_source" == current ]]; then
  # Bind the new installer to the actual signed candidate, while installing the
  # unchanged original published baseline package in this disposable runner.
  node --input-type=module - "$candidate" "$repo" <<'SIGNED_INSTALLER'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {execFileSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {pathToFileURL} from 'node:url'
const [archive,repo]=process.argv.slice(2)
const {verifyPanelDigest}=await import(pathToFileURL(repo+'/scripts/panel-package-signature.mjs').href)
const metadata=JSON.parse(execFileSync('tar',['-xOf',archive,'./version.json'],{encoding:'utf8'}))
const arch=process.arch==='arm64'?'arm64':'amd64',hash=createHash('sha256').update(readFileSync(archive)).digest('hex')
assert.ok(verifyPanelDigest(metadata.version,arch,hash,readFileSync(archive+'.sig','utf8').trim()))
console.log('Signed current installer source verified against the actual candidate')
SIGNED_INSTALLER
  tar -xOf "$candidate" ./scripts/install-panel.sh > "$work/old-install.sh"
else
  tar -xOf "$old" ./scripts/install-panel.sh > "$work/old-install.sh"
fi
printf 'installer@example.invalid\n3\n' | ONBOARDING_PUBLIC_HOST=gateway.example.com \
  bash "$work/old-install.sh" > "$work/old-install.log" 2>&1
systemctl is-active --quiet incudal-backend
# The genuine installer has now supplied the fixed system Node used by root
# tasks. Pre-install build fixtures instead select setup-node explicitly.
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/python3 -I -B "$repo/scripts/test-repository-startup-normalizer.py" "$old"
if [[ "$installer_source" == current ]]; then
  # The first real startup has already rerun the old backup hook. Repeat a
  # normal service restart so a one-time post-install correction cannot pass.
  stage=current-installer-restart
  systemctl restart incudal-backend
  systemctl is-active --quiet incudal-backend
fi
python3 "$repo/scripts/test-database-ownership-scope.py"
# Retained test/restore databases are legitimate old-install inputs. The new
# role migration must preserve them instead of requiring deletion or globally
# transferring their owner to the migration role.
runuser -u postgres -- createdb -O incudal incudal_retained_upgrade_test
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d incudal_retained_upgrade_test -c "CREATE TABLE preserved(id int primary key,value text);INSERT INTO preserved VALUES(1,'original');" >/dev/null
if [[ -n "${INCUDAL_PREVIEW_AGENT_DIR:-}" ]]; then
  # Same-source signed binaries are a disposable preview input, exactly as in
  # fresh-install. The installed backend still verifies both hashes/signatures.
  install -d -m 0755 /opt/incudal/agent-release
  cp "$INCUDAL_PREVIEW_AGENT_DIR"/* /opt/incudal/agent-release/
  chown -R root:root /opt/incudal/agent-release
  chmod 0644 /opt/incudal/agent-release/*
  printf '\nINCUDAL_AGENT_RELEASE_DIR=/opt/incudal/agent-release\n' >> /opt/incudal/.env
fi

# Model both an original flat installation and the deployed atomic layout
# after a failed attempt has already committed the additive DB migration.
# All setup is confined to this disposable VM and uses the actual archives.
frontend_root=/opt/incudal
stage=prior-migration-setup
if [[ $scenario == migrated-atomic || $scenario == rollback ]]; then
  baseline_dir="/opt/incudal/releases/$UPGRADE_DRILL_BASELINE_VERSION-baseline"
  install -d -m 755 "$baseline_dir" "$work/candidate"
  tar --no-same-owner -xzf "$old" -C "$baseline_dir"
  cp -a /opt/incudal/server/certs "$baseline_dir/server/"
  ln -s "$baseline_dir" /opt/incudal/current
  frontend_root=/opt/incudal/current
  cat > /etc/systemd/system/incudal-backend.service.d/upgrade-drill.conf <<'EOF'
[Service]
WorkingDirectory=/opt/incudal/current
ExecStart=
ExecStart=/usr/bin/node /opt/incudal/current/server/dist/app.js
EOF
  tar --no-same-owner -xzf "$candidate" -C "$work/candidate"
  node "$repo/scripts/smoke-legacy-online-upgrade.mjs" migrate "$work/candidate" > "$work/prior-migration.log" 2>&1
fi

# Real local HTTPS origins exercise all normal post-OTA checks. Trust is local
# to this disposable runner; no production DNS/certificate is used.
stage=test-origins
apt-get install -y -qq nginx >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=upgrade.test \
  -addext 'subjectAltName=DNS:user.upgrade.test,DNS:admin.upgrade.test' \
  -keyout "$work/site.key" -out /usr/local/share/ca-certificates/incudal-upgrade.crt >/dev/null 2>&1
update-ca-certificates >/dev/null 2>&1
printf '127.0.0.1 user.upgrade.test admin.upgrade.test\n' >> /etc/hosts
cat > /etc/nginx/conf.d/incudal-upgrade-test.conf <<EOF
server {
 listen 127.0.0.1:443 ssl;
 server_name user.upgrade.test admin.upgrade.test;
 ssl_certificate /usr/local/share/ca-certificates/incudal-upgrade.crt;
 ssl_certificate_key $work/site.key;
 set \$frontend_root $frontend_root/client/dist/user;
 if (\$host = admin.upgrade.test) { set \$frontend_root $frontend_root/client/dist/admin; }
 root \$frontend_root;
 add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
 add_header X-Content-Type-Options nosniff always;
 add_header X-Frame-Options DENY always;
 add_header Referrer-Policy strict-origin-when-cross-origin always;
 location /healthz { return 200 'ok'; }
 location / { try_files \$uri \$uri/ /index.html; }
 location /api/ { proxy_pass http://127.0.0.1:3001; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; }
}
EOF
nginx -t
systemctl restart nginx
python3 - <<'PY'
from pathlib import Path
import re
p=Path('/opt/incudal/.env');s=p.read_text()
values={'FRONTEND_URL':'https://user.upgrade.test','ADMIN_FRONTEND_URL':'https://admin.upgrade.test',
        'SITE_URL':'https://user.upgrade.test','PAYMENT_CALLBACK_BASE_URL':'https://user.upgrade.test',
        'PAYMENT_CALLBACK_SKIP_IP_WHITELIST':'false','PAYMENT_CALLBACK_IP_WHITELIST_REQUIRED':'false',
        'BACKEND_URL':'http://127.0.0.1:3001'}
for k,v in values.items():
    if re.search(r'^'+k+'=',s,re.M):s=re.sub(r'^'+k+'=.*$',k+'='+v,s,flags=re.M)
    else:s+='\n'+k+'='+v+'\n'
p.write_text(s)
if Path('/opt/incudal/current').is_symlink():
    import shutil
    shutil.copy2(p, '/opt/incudal/current/.env')
PY
systemctl daemon-reload
# The cloned old release must receive the real installer/OTA ownership before
# its service account reads .env or certs. copy2 preserves modes, not groups.
/usr/local/libexec/incudal/incudal-online-task seal
systemctl restart incudal-backend
curl -fsS --retry 20 --retry-delay 2 --retry-connrefused https://user.upgrade.test/api/health >/dev/null
node "$repo/scripts/smoke-legacy-online-upgrade.mjs" before "$candidate"
reset_healthy_fixture_start_budget
stage=old-worker-upgrade
if [[ $scenario == rollback ]]; then
  # The actual worker reaches its production verification only after installing
  # and registering new components. Fail that check once, leaving every other
  # command, migration, service operation and rollback on the original path.
  install -d -m 755 "$work/path"
  export UPGRADE_DRILL_ORIGINAL_PNPM
  UPGRADE_DRILL_ORIGINAL_PNPM=$(command -v pnpm)
  cat > "$work/path/pnpm" <<'EOF'
#!/usr/bin/env bash
if [[ $* == verify:production && ! -e "$UPGRADE_DRILL_WORK/failure-injected" ]]; then
  touch "$UPGRADE_DRILL_WORK/failure-injected"
  echo 'Injected post-install production-check failure for rollback verification' >&2
  exit 70
fi
exec "$UPGRADE_DRILL_ORIGINAL_PNPM" "$@"
EOF
  chmod 755 "$work/path/pnpm"
  export PATH="$work/path:$PATH"
fi
# Do not bypass the old worker's migration, production DB or health checks.
(
  cd /opt/incudal
  exec 9>/var/lib/incudal-platform-operation.lock
  flock -n 9
  # Refresh deliberately changed only the disposable test origin configuration.
  # Keep the same hardened filesystem and sealed source checks as real OTA.
  /usr/local/libexec/incudal/incudal-online-task seal
  if NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/incudal-upgrade.crt \
    node "$repo/scripts/smoke-legacy-online-upgrade.mjs" worker "$candidate" > "$work/worker.log" 2>&1; then
    [[ $scenario != rollback ]]
  else
    [[ $scenario == rollback && -f "$work/failure-injected" ]]
    node "$repo/scripts/smoke-legacy-online-upgrade.mjs" rolled-back "$candidate"
    UPGRADE_DRILL_RETRY=true node "$repo/scripts/smoke-legacy-online-upgrade.mjs" before "$candidate"
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/incudal-upgrade.crt \
      node "$repo/scripts/smoke-legacy-online-upgrade.mjs" worker "$candidate" > "$work/retry-worker.log" 2>&1
  fi
  /usr/local/libexec/incudal/incudal-online-task seal
)
stage=post-upgrade-verification
systemctl restart incudal-backend
systemctl is-active --quiet incudal-backend
node "$repo/scripts/smoke-legacy-online-upgrade.mjs" after "$candidate"
if tar -xOf "$candidate" ./version.json | python3 -c 'import json,sys,re; sys.exit(0 if re.fullmatch(r"v1\.8\.14-test\.[a-f0-9]{7}",json.load(sys.stdin)["version"]) else 1)'; then
  candidate_version=$(tar -xOf "$candidate" ./version.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
  # Checkout files belong to the GitHub runner. Protect only these reviewed
  # test tools in a separate root directory; never relax production ownership.
  install -d -o root -g root -m700 "$work/owner-candidate-tools"
  for tool in apply-verified-owner-candidate.mjs finalize-verified-owner-candidate.mjs panel-package-signature.mjs agent-package-signature.mjs sealed-runtime-links.mjs drain-legacy-owner-backend.mjs; do
    install -o root -g root -m600 "$repo/scripts/$tool" "$work/owner-candidate-tools/$tool"
  done
  INCUDAL_OWNER_CANDIDATE_DEPLOY=authorized-test node "$work/owner-candidate-tools/apply-verified-owner-candidate.mjs" "$candidate" "$candidate_version" --preflight
  candidate_task=$(python3 -c 'import json; print(json.load(open("/root/incudal-legacy-upgrade.json"))["taskId"])')
  INCUDAL_OWNER_CANDIDATE_DEPLOY=authorized-test node "$work/owner-candidate-tools/finalize-verified-owner-candidate.mjs" "$candidate" "$candidate_version" "$candidate_task"
fi
if [[ $scenario == rollback && $installer_source == current ]]; then
  stage=actual-root-postflight-rollback
  reset_healthy_fixture_start_budget
  node "$repo/scripts/smoke-legacy-online-upgrade.mjs" root-rollback-prepare "$candidate"
  root_rollback_task=$(python3 -c 'import json; print(json.load(open("/root/incudal-legacy-upgrade.json"))["taskId"])')
  # Queue the genuine root unit behind a normal backend startup. Its worker
  # performs another real restart; no candidate HTTP adapter is involved.
  systemctl restart --no-block incudal-backend
  systemctl start "incudal-online-rollback@${root_rollback_task}.service"
  node "$repo/scripts/smoke-legacy-online-upgrade.mjs" root-rollback-wait "$candidate"
  # A completed task is intentionally replayed only to exercise the next real
  # launcher and the old worker's duplicate guard. Do not restart in between.
  systemctl start "incudal-online-update@${root_rollback_task}.service"
  node "$repo/scripts/smoke-legacy-online-upgrade.mjs" root-duplicate-after "$candidate"
fi
test "$(ss -ltnp 'sport = :3001' | tail -n +2 | wc -l)" = 1
test "$(runuser -u postgres -- psql -X -At -d postgres -c "SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname='incudal') FROM pg_database WHERE datname='incudal_retained_upgrade_test'")" = t
test "$(runuser -u postgres -- psql -X -At -d incudal_retained_upgrade_test -c 'SELECT value FROM preserved WHERE id=1')" = original
runuser -u postgres -- dropdb incudal_retained_upgrade_test
echo 'Legacy-to-current online upgrade passed with real old worker, signed archives and preserved controller/network identity.'
