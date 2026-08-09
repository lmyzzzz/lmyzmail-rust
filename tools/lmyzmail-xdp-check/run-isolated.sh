#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECKER=${1:-"${SCRIPT_DIR}/target/x86_64-unknown-linux-gnu/debug/lmyzmail-xdp-check"}
INTERFACE=lmyz-xdp0
PEER_INTERFACE=lmyz-xdp1
PEER_NAMESPACE=lmyz-xdp-peer
PIN_PATH=/sys/fs/bpf/lmyzmail-xdp-check

if [[ ${EUID} -ne 0 ]]; then
    echo "run-isolated.sh must run as root" >&2
    exit 2
fi
if [[ ! -x ${CHECKER} ]]; then
    echo "checker binary is missing or not executable: ${CHECKER}" >&2
    exit 2
fi

if [[ ${LMYZMAIL_XDP_CHECK_ISOLATED:-0} != 1 ]]; then
    exec unshare --mount --net --fork env \
        LMYZMAIL_XDP_CHECK_ISOLATED=1 \
        LMYZMAIL_XDP_CHECK_INTERFACE=${INTERFACE} \
        LMYZMAIL_XDP_CHECK_PEER_NAMESPACE=${PEER_NAMESPACE} \
        LMYZMAIL_XDP_CHECK_PIN_PATH=${PIN_PATH} \
        "${BASH_SOURCE[0]}" "${CHECKER}"
fi

if [[ $(readlink /proc/self/ns/net) == $(readlink /proc/1/ns/net) ]] ||
   [[ $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
    echo "refusing to configure XDP outside isolated network and mount namespaces" >&2
    exit 2
fi

mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs -o mode=0755,size=1m tmpfs /run/netns
mkdir -p /run/lmyzmail
mount -t tmpfs -o mode=0750,size=1m tmpfs /run/lmyzmail
if mountpoint -q /sys/fs/bpf; then
    umount /sys/fs/bpf
fi
mount -t tmpfs -o mode=0700,size=1m tmpfs /sys/fs/bpf
mkdir "${PIN_PATH}" "${PIN_PATH}.rollback"
mount -t bpf -o mode=0700 bpf "${PIN_PATH}"
mount -t bpf -o mode=0700 bpf "${PIN_PATH}.rollback"

ip link set lo up
ip netns add "${PEER_NAMESPACE}"
ip link add "${INTERFACE}" type veth peer name "${PEER_INTERFACE}"
ip link set "${PEER_INTERFACE}" netns "${PEER_NAMESPACE}"
ip addr add 198.51.100.1/30 dev "${INTERFACE}"
ip -6 addr add 2001:db8:1::1/64 dev "${INTERFACE}" nodad
ip link set "${INTERFACE}" up
ip -n "${PEER_NAMESPACE}" link set lo up
ip -n "${PEER_NAMESPACE}" addr add 198.51.100.2/30 dev "${PEER_INTERFACE}"
ip -n "${PEER_NAMESPACE}" -6 addr add 2001:db8:1::2/64 dev "${PEER_INTERFACE}" nodad
ip -n "${PEER_NAMESPACE}" link set "${PEER_INTERFACE}" up

exec "${CHECKER}"
