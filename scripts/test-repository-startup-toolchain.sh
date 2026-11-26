#!/usr/bin/env bash
# Prepare only a disposable CI test tool; never replace an installed Node.
set -Eeuo pipefail
[[ $# -eq 0 && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || exit 1
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
node_source=$(readlink -f -- "$(node -p process.execPath)")
[[ -f "$node_source" && ! -L "$node_source" && -x "$node_source" ]] || exit 1
source_sha=$(sha256sum -- "$node_source" | awk '{print $1}')
[[ "$source_sha" =~ ^[a-f0-9]{64}$ ]] || exit 1
node_dir=$(sudo mktemp -d /root/incudal-startup-node-XXXXXX)
[[ "$node_dir" == /root/incudal-startup-node-* ]] || exit 1
trap 'sudo rm -f -- "$node_dir/node"; sudo rmdir -- "$node_dir"' EXIT
sudo install -o root -g root -m 0755 -- "$node_source" "$node_dir/node"
[[ $(sudo sha256sum -- "$node_dir/node" | awk '{print $1}') == "$source_sha" ]] || exit 1
[[ $(sha256sum -- "$node_source" | awk '{print $1}') == "$source_sha" ]] || exit 1
sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/python3 -I -B \
  "$repo/scripts/test-repository-startup-normalizer.py" --node "$node_dir/node"
