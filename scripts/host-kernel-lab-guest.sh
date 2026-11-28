#!/usr/bin/env bash
# Runs only inside a newly provisioned public Alpine test VM.
set -Eeuo pipefail
umask 077
root=/root/incudal-kernel-lab
state=/var/lib/incudal-kernel-native-evidence
kernel=/boot/vmlinuz-virt
initrd=/boot/initramfs-virt
cd "$root"
[[ $EUID == 0 && $# == 1 && $(cat /var/lib/cloud/data/instance-id) == "kernel-$(cat "$root/id")" ]]
[[ $(cat /sys/class/block/vda/serial) == "e04-$(cut -c1-12 "$root/id")" ]]
[[ $(uname -m) == "$(cat "$root/arch")" && $(cat /etc/alpine-release) == 3.24.3 ]]
[[ ! -e /opt/incudal && ! -e /var/lib/incudal-gateway-controller ]]
export PAYINCUS_HOST_KERNEL_NATIVE=1 PAYINCUS_HOST_KERNEL_DISPOSABLE_VM=1 PAYINCUS_KERNEL_EXPECTED_CANDIDATE=6.18.65-r0
original=6.18.58-0-virt
candidate=6.18.65-0-virt
# Emit only the phase and failing line. The host prints these two safe fields.
requested_phase=$1
trap 'printf "E04_GUEST_FAILURE phase=%s line=%s\n" "$requested_phase" "$LINENO" >&2' ERR
installed_kernel() { apk info -v | grep -Fx "linux-virt-$1" >/dev/null; }
phase() { bash "$root/test-host-kernel-boot-native.sh" "$1" > "$root/phase-$1.out"; }
prepare_grub() {
    [[ $(uname -r) == "$original" && ! -e "$state" && ! -e "$root/original-kernel" ]]
    [[ $(findmnt -n -o FSTYPE /boot) == vfat && $(findmnt -n -o FSTYPE /) == ext4 ]]
    cp "$kernel" "$root/original-kernel"
    cp "$initrd" "$root/original-initrd"
    sha256sum "$root/original-kernel" "$root/original-initrd" > "$root/original.sha256"
    sed -n '/^[^#]/p' /etc/apk/repositories | grep -q '/v3.24/main'
    grep -Eq '^[^#]+/v3.24/community/?$' /etc/apk/repositories ||
        printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' >> /etc/apk/repositories
    apk add --no-cache --no-progress bash python3 grub-efi incus incus-client incus-openrc \
        lxcfs lxcfs-openrc apparmor apparmor-openrc apparmor-utils apparmor-profiles-abstractions \
        apparmor-profiles-tunables dbus dbus-openrc chrony chrony-openrc util-linux openssl \
        kmod wireguard-tools ca-certificates
    installed_kernel 6.18.58-r0
    sha256sum -c "$root/original.sha256"
    cmp "$root/original-kernel" "$kernel"; cmp "$root/original-initrd" "$initrd"
    [[ -x /etc/init.d/incusd && ! -e /etc/init.d/incus ]]
    rc-update add cgroups boot
    rc-update add apparmor boot
    for service in dbus chronyd lxcfs incusd; do rc-update add "$service" default; done
    # Use the distro OpenRC ordering. Incus and LXCFS must be available at
    # the next boot, before any product transaction or customer inventory.
    [[ ! -e /var/lib/incudal-kernel-native.disposable && ! -e /etc/incudal-onboarding-id ]]
    printf 'payincus-disposable-kernel-v1\n' > /var/lib/incudal-kernel-native.disposable
    cat "$root/id" > /etc/incudal-onboarding-id
    mkdir -m 700 "$root/original-boot"
    cp -p "$kernel" "$initrd" /boot/config-"$original" /boot/System.map-"$original" "$root/original-boot/"
    local old_esp modules console efi
    old_esp=$(findmnt -n -o SOURCE /boot)
    modules=$(tr ' ' '\n' < /proc/cmdline | grep -E '^modules=[a-z0-9_,.-]+$')
    [[ $modules == *ext4* && $modules != *$'\n'* ]]
    case $(uname -m) in x86_64) console=ttyS0; efi=x86_64-efi ;; aarch64) console=ttyAMA0; efi=arm64-efi ;; *) return 1 ;; esac
    python3 -I -B - <<'PY'
from pathlib import Path
p=Path('/etc/fstab')
lines=p.read_text().splitlines(); matches=[]
for i,line in enumerate(lines):
    fields=line.split()
    if len(fields)==6 and fields[1]=='/boot' and fields[2]=='vfat':
        fields[1]='/boot/efi'; matches.append(i); lines[i]='\t'.join(fields)
assert len(matches)==1 and sum(r.split()[1]=='/boot/efi' for r in lines if r.strip() and not r.lstrip().startswith('#'))==1
p.write_text('\n'.join(lines)+'\n')
PY
    umount /boot
    [[ -z $(ls -A /boot) ]]
    mkdir /boot/efi /boot/grub; mount /boot/efi
    [[ $(findmnt -n -o SOURCE /boot/efi) == "$old_esp" ]]
    cp -p "$root/original-boot/"* /boot/
    cat > /etc/default/grub <<EOF
GRUB_TIMEOUT=1
GRUB_DISABLE_RECOVERY=true
GRUB_DISABLE_SUBMENU=y
GRUB_DISABLE_OS_PROBER=true
GRUB_CMDLINE_LINUX_DEFAULT="$modules rootfstype=ext4 console=$console apparmor=1 security=apparmor lsm=landlock,yama,apparmor,bpf"
EOF
    chmod 644 /etc/default/grub
    grub-install --target="$efi" --efi-directory=/boot/efi --bootloader-id=incudal-e04 --removable --no-nvram
    grub-mkconfig -o /boot/grub/grub.cfg
    grub-script-check /boot/grub/grub.cfg
    python3 -I -B - <<'PY'
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('kernel',Path.cwd()/'host-kernel-maintenance.py')
kernel=importlib.util.module_from_spec(spec);spec.loader.exec_module(kernel)
args=kernel.linux_arguments(Path('/boot/grub/grub.cfg').read_bytes(),'grub','linux-virt')
assert len([a for a in args if a.startswith('modules=') and 'ext4' in a.split('=',1)[1].split(',')])==1
assert 'rootfstype=ext4' in args
(Path.cwd()/'expected-args').write_text(' '.join(args))
PY
    date -u +%s > "$root/setup-finished"
    sync
}
host_ready() {
    [[ $(findmnt -n -o FSTYPE /boot/efi) == vfat && $(findmnt -n -o FSTYPE /) == ext4 ]]
    [[ $(cat /sys/module/apparmor/parameters/enabled) == Y ]]
    local args
    args=$(cat /proc/cmdline); [[ "${args#BOOT_IMAGE=/boot/vmlinuz-virt }" == "$(cat "$root/expected-args")" ]]
    rc-service incusd status
    rc-service lxcfs status
    [[ -e /var/lib/lxcfs/proc/meminfo && -f /usr/share/lxc/config/common.conf.d/00-lxcfs.conf ]]
    incus query 'local:/1.0/instances?recursion=1&all-projects=true' | python3 -c 'import sys,json; assert json.load(sys.stdin)==[]'
    for round in $(seq 1 45); do
        if chronyc -n tracking | grep -Eq '^Leap status[[:space:]]*:[[:space:]]*Normal'; then return; fi
        sleep 2
    done
    return 1
}
case "$1" in
    setup) prepare_grub ;;
    base)
        [[ $(uname -r) == "$original" ]]
        host_ready
        sha256sum -c "$root/original.sha256";cmp "$root/original-kernel" "$kernel";cmp "$root/original-initrd" "$initrd"
        cat /proc/sys/kernel/random/boot_id > "$root/baseline-boot"
        cat /proc/cmdline > "$root/baseline-cmdline"
        ;;
    pre-rollback)
        host_ready; phase prepare; phase rollback
        cmp "$root/original-kernel" "$kernel";cmp "$root/original-initrd" "$initrd"
        [[ $(cat /proc/sys/kernel/random/boot_id) == "$(cat "$root/baseline-boot")" ]] ;;
    prepare-activation)
        phase prepare
        installed_kernel 6.18.65-r0; [[ $(uname -r) == "$original" ]]
        cmp -s "$root/original-kernel" "$kernel" && exit 1
        touch "$root/reboot-request";sync; phase reboot ;;
    activated)
        [[ $(uname -r) == "$candidate" && -f "$root/reboot-request" ]]
        [[ $(cat /proc/sys/kernel/random/boot_id) != "$(cat "$root/baseline-boot")" ]]
        phase verify; host_ready
        cat /proc/sys/kernel/random/boot_id > "$root/candidate-boot"
        # Boot original bytes on separate read-only FAT media, on the same
        # root disk. GRUB still gives Linux the identical BOOT_IMAGE path.
        args=$(cat "$root/expected-args"); printf 'search --no-floppy --label E04RETURN --set=root\nlinux /boot/vmlinuz-virt %s\ninitrd /boot/initramfs-virt\nboot\n' "$args" > "$root/fallback.cfg"
        grub-script-check "$root/fallback.cfg"
        if [[ $(uname -m) == x86_64 ]]; then platform=x86_64-efi;else platform=arm64-efi;fi
        grub-mkstandalone -O "$platform" -o "$root/fallback.efi" "boot/grub/grub.cfg=$root/fallback.cfg"
        sha256sum "$root/fallback.efi" "$root/original-kernel" "$root/original-initrd" > "$root/fallback.sha256"
        ;;
    post-rollback)
        [[ $(uname -r) == "$original" && $(cat /proc/cmdline) == "$(cat "$root/baseline-cmdline")" ]]
        [[ $(cat /proc/sys/kernel/random/boot_id) != "$(cat "$root/candidate-boot")" ]]
        phase rollback; host_ready;cmp "$root/original-kernel" "$kernel";cmp "$root/original-initrd" "$initrd"
        installed_kernel 6.18.65-r0
        ;;
    *) exit 2 ;;
esac
