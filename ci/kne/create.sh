#!/usr/bin/env bash
# Bring the slot's topology up and make it reachable from the per-slot CI container.
# usage: create.sh <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"
[[ -f "$TOPO_FILE" ]] || die "run render.sh first (${TOPO_FILE} missing)"

# --- 1. pods ---------------------------------------------------------------------
log "kne create ${TOPO_FILE}"
kne create "$TOPO_FILE"
wait_for 300 "all pods in ns ${NS} Running" \
  bash -c "kubectl get pods -n ${NS} --no-headers | awk '\$3!=\"Running\"{bad=1} END{exit bad}'"
kubectl get pods -n "$NS" -o wide

# --- 2. routes from the PR 7 scripts ----------------------------------------------------
# Kind node gets a /32 per SONiC VM. Each pod bridge br<SLOT> owns the gateway
# .1. setup_mgmt_routes.py also tries a host route with sudo, which this runner
# does not have. Skip that one call; this container is on the kind network and
# gets its own route below. PTF has no startup.sh, so its address is set separately.
log "ptf management ${PTF_IP}"
bash "${REPO_ROOT}/ansible/kne/setup_ptf_mgmt.sh" "$TOPO_FILE"
log "mgmt routes for ${SUBNET}"
python3 - "$TOPO_FILE" "${REPO_ROOT}/ansible/kne/setup_mgmt_routes.py" << 'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("setup_mgmt_routes", sys.argv[2])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
real_add_host_route = mod.add_host_route

def add_host_route(subnet, kind_gw, kind_bridge):
    if os.geteuid() != 0:
        try:
            sudo_ok = mod._run(["sudo", "-n", "true"]).returncode == 0
        except FileNotFoundError:
            sudo_ok = False
        if not sudo_ok:
            mod.log(f"  WARNING: skipping host route {subnet} (no passwordless sudo)")
            return
    return real_add_host_route(subnet, kind_gw, kind_bridge)

mod.add_host_route = add_host_route
sys.argv = [sys.argv[2], sys.argv[1]]
raise SystemExit(mod.main())
PY
mapfile -t SSH_IPS < <(sonic_mgmt_ips)
[[ ${#SSH_IPS[@]} -gt 0 ]] || die "no SONiC nodes in ${TOPO_FILE}"

# --- 3. per-slot sonic-mgmt container with THIS checkout mounted ------------------------
# Root, not the runner uid: `ip route` below needs it, and pytest stays root
# so Ansible can log into the DUT. restore_checkout_owner puts files back.
# One container per slot: three labs run at once and cannot share sonic-mgmt.
docker rm -f "$CI_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CI_CONTAINER" --network kind --cap-add NET_ADMIN \
  -v "${REPO_ROOT}:/data/sonic-mgmt" \
  -e ANSIBLE_HOST_KEY_CHECKING=False \
  -e SONIC_MGMT_SONIC_PASSWORD \
  -e SONIC_MGMT_PTF_PASSWORD \
  -w /data/sonic-mgmt/ansible \
  "$SONIC_MGMT_IMAGE" sleep infinity >/dev/null
docker exec "$CI_CONTAINER" ip route replace "$SUBNET" via "$(kind_gateway)" dev eth0
log "container ${CI_CONTAINER} up, route ${SUBNET} via $(kind_gateway)"

# --- 4. wait for the SONiC VMs to boot -------------------------------------------------
pids=()
for ip in "${SSH_IPS[@]}"; do
  wait_for 900 "ssh ${ip}" sonic_ssh "$ip" true &
  pids+=("$!")
done
ssh_fail=0
for pid in "${pids[@]}"; do
  wait "$pid" || ssh_fail=1
done
[[ "$ssh_fail" -eq 0 ]] || die "a switch in slot ${SLOT} (${TOPO}) did not answer ssh"
log "slot ${SLOT} (${TOPO}) up, dut ${DUT_IP}, ${#SSH_IPS[@]} switches"
