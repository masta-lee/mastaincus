#!/bin/sh
set -eu
test "${INCUDAL_MEMORY_PRESSURE_TEST:-}" = disposable
umount -l /.oldroot
mount -t proc proc /proc
apk add --no-cache incus incus-client incus-openrc openrc apparmor apparmor-utils apparmor-profiles-tunables apparmor-profiles-abstractions iproute2 python3 lxcfs lxcfs-openrc tar gzip xz squashfs-tools rsync util-linux lvm2 lvm2-extra device-mapper btrfs-progs btrfs-progs-extra wireguard-tools
command -v apparmor_parser
test -d /sys/kernel/security/apparmor
test -f /etc/apparmor.d/tunables/global
# Redirect only the disposable OpenRC service cgroup base. Moving a daemon
# later does not migrate its already charged pages; all startup allocations
# must be charged below the aggregate budget from the beginning.
python3 - <<'PY'
from pathlib import Path
p=Path('/usr/libexec/rc/sh/rc-cgroup.sh')
s=p.read_text()
old='unified) printf "/sys/fs/cgroup" ;;'
assert s.count(old)==1
p.write_text(s.replace(old, 'unified) printf "/sys/fs/cgroup/incudal-memory-fixture" ;;'))
s=p.read_text()
old='mountinfo -q "${cgroup_path}"|| return 0'
assert s.count(old)==1
p.write_text(s.replace(old, '[ -f "${cgroup_path}/cgroup.controllers" ] || return 0'))
PY
mkdir -p /etc/network /run/openrc/started /run/dbus /run/incus
# The fixture already mounted and delegated cgroups; record this actual setup
# before OpenRC dependencies, which otherwise mount a fresh cgroup root over it.
touch /run/openrc/started/cgroups
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
touch /run/openrc/softlevel
dbus-daemon --system --fork
case "${INCUDAL_MEMORY_TUNING:-automatic}" in
  automatic) ;;
  explicit-daemon-settings)
    printf '\nexport GOMEMLIMIT=80MiB\nexport GODEBUG=disablethp=0\n' >> /etc/conf.d/incusd
    ;;
  *) echo 'Unknown disposable memory experiment'; exit 1 ;;
esac
/usr/sbin/incusd --group incus >/tmp/incusd-original.log 2>&1 &
echo $! > /run/incus/incusd.pid
incus admin waitready --timeout=60
incus storage create default dir
python3 /out/raft-retention.py seed
/out/provisioning-test -test.run '^TestNativeCompatibilityEmptyPoolReload$' -test.v
/out/provisioning-test -test.run '^TestNativeMemoryReservePersistenceAndOverrides$' -test.v
python3 /out/raft-retention.py verify
# A real service restart reopens the compacted logs. No data files are removed
# by the fixture, and the following pressure test still uses the same DB.
old_pid=$(cat /run/incus/incusd.pid)
old_start=$(python3 -c 'import pathlib,sys; s=pathlib.Path("/proc/"+sys.argv[1]+"/stat").read_text(); print(s[s.rfind(") ")+2:].split()[19])' "$old_pid")
rc-service incusd quit
python3 - "$old_pid" "$old_start" <<'PY'
import pathlib,sys,time
pid,start=sys.argv[1:]
for _ in range(120):
    try:
        text=pathlib.Path('/proc/'+pid+'/stat').read_text()
        fields=text[text.rfind(') ')+2:].split()
        if fields[0]=='Z' or fields[19]!=start:
            break
    except FileNotFoundError:
        break
    time.sleep(.5)
else:
    raise RuntimeError('Original fixture daemon did not finish graceful quit')
PY
rc-service incusd zap
rc-service incusd start
incus admin waitready --timeout=60
python3 /out/raft-recovery.py
python3 /out/pressure.py
