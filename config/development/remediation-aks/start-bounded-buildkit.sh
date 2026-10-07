#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--inside" ]]; then
  if [[ "${ORKA_BUILDKIT_QUALIFICATION:-0}" != "1" ]]; then
    /opt/orka-buildkit/bin/buildkit-preflight.py certified
  fi
  exec unshare --mount --cgroup --propagation private "$0" --inside
fi

# The new cgroup namespace is rooted at the delegated service subgroup. Even an
# explicit LLB cgroup-parent override cannot select an ancestor through this mount.
mount -t cgroup2 -o nosuid,nodev,noexec none /sys/fs/cgroup
mkdir -p /sys/fs/cgroup/daemon /sys/fs/cgroup/workloads
printf '%s\n' "$$" > /sys/fs/cgroup/daemon/cgroup.procs
printf '%s\n' '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
printf '%s\n' '+cpu +memory +pids' > /sys/fs/cgroup/workloads/cgroup.subtree_control

if [[ "${ORKA_BUILDKIT_QUALIFICATION:-0}" == "1" ]]; then
  exec /opt/orka-buildkit/bin/buildkitd \
    --config /etc/orka-buildkit/qualification.toml
fi
exec /opt/orka-buildkit/bin/buildkitd --config /etc/orka-buildkit/buildkitd.toml
