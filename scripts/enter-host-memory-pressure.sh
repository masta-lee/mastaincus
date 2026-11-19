#!/bin/bash
# Caller already joined the fixture's cgroup before creating this namespace.
set -euo pipefail
root=$1
group=$2
echo $$ > "$group/host/cgroup.procs"
echo +memory > "$group/cgroup.subtree_control"
mount --rbind "$root" "$root"
cd "$root"
mkdir .oldroot
pivot_root . .oldroot
exec /bin/sh /out/setup.sh
