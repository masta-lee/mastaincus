#!/bin/sh
set -eu
test "${INCUDAL_MEMORY_PRESSURE_TEST:-}" = disposable
umount -l /.oldroot
mount -t proc proc /proc
umount -l /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup
apk add --no-cache incus incus-client incus-openrc openrc apparmor apparmor-utils apparmor-profiles-tunables apparmor-profiles-abstractions iproute2 python3 lxcfs lxcfs-openrc tar gzip xz squashfs-tools rsync util-linux lvm2 lvm2-extra device-mapper btrfs-progs btrfs-progs-extra wireguard-tools
command -v apparmor_parser
test -d /sys/kernel/security/apparmor
test -f /etc/apparmor.d/tunables/global
mkdir -p /etc/network /run/openrc /run/dbus /run/incus
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
touch /run/openrc/softlevel
dbus-daemon --system --fork
/usr/sbin/incusd --group incus >/tmp/incusd-original.log 2>&1 &
echo $! > /run/incus/incusd.pid
incus admin waitready --timeout=60
incus storage create default dir
/out/provisioning-test -test.run '^TestNativeCompatibilityEmptyPoolReload$' -test.v
python3 /out/pressure.py
