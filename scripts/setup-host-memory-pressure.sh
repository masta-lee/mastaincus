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
PY
mount --bind /sys/fs/cgroup/incudal-memory-fixture /sys/fs/cgroup/incudal-memory-fixture
mkdir -p /etc/network /run/openrc/started /run/dbus /run/incus
# The fixture already mounted and delegated cgroups; record this actual setup
# before OpenRC dependencies, which otherwise mount a fresh cgroup root over it.
touch /run/openrc/started/cgroups
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
touch /run/openrc/softlevel
dbus-daemon --system --fork
/usr/sbin/incusd --group incus >/tmp/incusd-original.log 2>&1 &
echo $! > /run/incus/incusd.pid
incus admin waitready --timeout=60
incus storage create default dir
/out/provisioning-test -test.run '^TestNativeCompatibilityEmptyPoolReload$' -test.v
python3 /out/pressure.py
