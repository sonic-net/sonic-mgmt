#!/usr/bin/env bash
# Shared settings for the per-PR KNE T0 gate. Source this, then call `slot_vars <SLOT>`.
#
# One "slot" == one KNE namespace == one TOPO_ID == one mgmt subnet 172.31.<SLOT>.0/24.
# Everything below is derived from the slot number so PRs never collide.

set -euo pipefail

KNE_CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${KNE_CI_DIR}/../.." && pwd)"

# Host-side state (locks + rendered topo files). Lives outside the checkout so a
# re-checkout does not lose track of running namespaces.
KNE_CI_STATE="${KNE_CI_STATE:-/tmp/kne-ci}"

# Slot range scanned by pick_slot.sh. 100-102 are the hand-built long-lived labs.
KNE_SLOT_MIN="${KNE_SLOT_MIN:-103}"
KNE_SLOT_MAX="${KNE_SLOT_MAX:-140}"

# Image used for the throwaway sonic-mgmt container that runs ansible + pytest
# against the PR checkout. Same image as the long-lived kne-sonic-mgmt container.
SONIC_MGMT_IMAGE="${SONIC_MGMT_IMAGE:-sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest}"
KIND_NODE="${KIND_NODE:-kne-control-plane}"

SONIC_USER="admin"
# Inventories read these. The admin password is not stored in the repo.
export SONIC_MGMT_PTF_PASSWORD="${SONIC_MGMT_PTF_PASSWORD:-root}"

# Last octets. DUT SWITCH_ID is 2: .1 is the pod-bridge gateway (PR 7).
DUT_OCT=2
PTF_OCT=200
T1_OCTS=(251 252 253 250)   # t1-1 t1-2 t1-3 t1-4  == VM<SLOT>0..3

log() { printf '\033[0;32m[kne-ci]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[kne-ci]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[0;31m[kne-ci]\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "${SONIC_MGMT_SONIC_PASSWORD:-}" ]] || die "set SONIC_MGMT_SONIC_PASSWORD"
export SONIC_MGMT_SONIC_PASSWORD
SONIC_PASS="$SONIC_MGMT_SONIC_PASSWORD"

slot_vars() {
  SLOT="${1:?slot}"
  [[ "$SLOT" =~ ^[0-9]+$ ]] || die "slot must be numeric, got '$SLOT'"
  NS="$SLOT"                                  # k8s namespace == TOPO_ID (startup.sh needs numeric)
  SUBNET="172.31.${SLOT}.0/24"
  GW="172.31.${SLOT}.1"                       # br<SLOT> inside each pod
  DUT_IP="172.31.${SLOT}.${DUT_OCT}"
  PTF_IP="172.31.${SLOT}.${PTF_OCT}"
  CI_CONTAINER="kne-ci-${SLOT}"
  SLOT_DIR="${KNE_CI_STATE}/${SLOT}"
  TOPO_FILE="${SLOT_DIR}/topo.pb.txt"
  CONSOLE_PORT=$((4321 + SLOT * 256 + DUT_OCT))   # same formula as t0/startup.sh
  mkdir -p "$SLOT_DIR"
  if [[ -n "${2:-}" ]]; then
    TOPO="$2"
  elif [[ -f "${SLOT_DIR}/topo.name" ]]; then
    TOPO="$(cat "${SLOT_DIR}/topo.name")"
  else
    TOPO="t0"
  fi
  case "$TOPO" in
    t0)
      DUT_NAME="vlab-kne-${SLOT}"
      TESTBED="kne-t0-${SLOT}"
      INV="kne_vtb_${SLOT}"
      BASE_ID=100
      BASE_PREFIX="172.31.100."
      SRC_INV="kne_vtb"
      SRC_DUT="vlab-kne-01"
      SRC_PTF="ptf-kne-01"
      SRC_TB="kne-t0"
      SRC_CSV="sonic_kne_vtb"
      SRC_GROUP="vms6-1"
      EXPECTED_BGP=4
      ;;
    t1)
      DUT_NAME="vlab-kne-t1-${SLOT}"
      TESTBED="kne-t1-${SLOT}"
      INV="kne_vtb_t1_${SLOT}"
      BASE_ID=101
      BASE_PREFIX="172.31.101."
      SRC_INV="kne_vtb_t1"
      SRC_DUT="vlab-kne-t1-01"
      SRC_PTF="ptf-kne-t1-01"
      SRC_TB="kne-t1"
      SRC_CSV="sonic_kne_vtb_t1"
      SRC_GROUP="vms6-2"
      EXPECTED_BGP=32
      ;;
    t1-lag)
      DUT_NAME="vlab-kne-t1lag-${SLOT}"
      TESTBED="kne-t1-lag-${SLOT}"
      INV="kne_vtb_t1_lag_${SLOT}"
      BASE_ID=102
      BASE_PREFIX="172.31.102."
      SRC_INV="kne_vtb_t1_lag"
      SRC_DUT="vlab-kne-t1lag-01"
      SRC_PTF="ptf-kne-t1lag-01"
      SRC_TB="kne-t1-lag"
      SRC_CSV="sonic_kne_vtb_t1_lag"
      SRC_GROUP="vms6-3"
      EXPECTED_BGP=24
      ;;
    *) die "unknown topo '$TOPO' (have t0, t1, t1-lag)" ;;
  esac
  if [[ ! -f "${SLOT_DIR}/topo.name" || -n "${2:-}" ]]; then
    echo "$TOPO" > "${SLOT_DIR}/topo.name"
  fi
  export SLOT NS SUBNET GW DUT_IP PTF_IP DUT_NAME TESTBED INV CI_CONTAINER SLOT_DIR TOPO_FILE CONSOLE_PORT \
    TOPO BASE_ID BASE_PREFIX SRC_INV SRC_DUT SRC_PTF SRC_TB SRC_CSV SRC_GROUP EXPECTED_BGP
}

# Management IPs of SONiC nodes in the rendered topology, one per line.
# PTF is not included; setup_ptf_mgmt.sh owns that address.
sonic_mgmt_ips() {
  [[ -f "$TOPO_FILE" ]] || die "no rendered topology at ${TOPO_FILE}"
  python3 - "$TOPO_FILE" "${REPO_ROOT}/ansible/kne/setup_mgmt_routes.py" << 'PY'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("setup_mgmt_routes", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
_, nodes = mod.parse_topology(Path(sys.argv[1]))
for node in nodes:
    if not mod.is_sonic_node(node):
        continue
    print(mod.derive_mgmt(node["topo_id"], node["switch_id"])["mgmt_ip"])
PY
}

# ssh into a SONiC VM (DUT or T1) from inside the per-slot CI container.
# usage: sonic_ssh <ip> <remote command...>
sonic_ssh() {
  local ip="$1"; shift
  docker exec "$CI_CONTAINER" sshpass -p "$SONIC_PASS" \
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=8 "${SONIC_USER}@${ip}" "$@"
}

# copy a local file into a SONiC VM via the CI container.
sonic_scp() {
  local src="$1" ip="$2" dst="$3"
  docker cp "$src" "${CI_CONTAINER}:/tmp/_scp_src"
  docker exec "$CI_CONTAINER" sshpass -p "$SONIC_PASS" \
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        /tmp/_scp_src "${SONIC_USER}@${ip}:${dst}"
}

# wait_for <seconds> <description> <command...>
wait_for() {
  local secs="$1" what="$2"; shift 2
  local end=$((SECONDS + secs))
  until "$@" >/dev/null 2>&1; do
    if (( SECONDS >= end )); then
      die "timed out after ${secs}s waiting for: ${what}"
    fi
    sleep 10
  done
  log "ready: ${what}"
}

kind_gateway() {
  docker inspect "$KIND_NODE" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

# The CI container stays root so it can install the mgmt route. It mounts the
# checkout writable, so pytest and ansible leave root-owned files behind.
# Hand the tree back to the runner user while the container still exists.
restore_checkout_owner() {
  [[ -n "${CI_CONTAINER:-}" ]] || return 0
  docker inspect "$CI_CONTAINER" >/dev/null 2>&1 || return 0
  docker exec -u 0 "$CI_CONTAINER" chown -R "$(id -u):$(id -g)" /data/sonic-mgmt || true
}
