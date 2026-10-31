#!/usr/bin/env bash
# Install this lab's SSH key on every SONiC node, then configure neighbors.
# t0 and t1 use the scripts under ansible/kne. t1-lag has neighbors.json there
# but no script, so it uses ci/kne/apply_neighbors.py.
# usage: config_neighbors.sh <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"

docker exec "$CI_CONTAINER" bash -c '
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  if [[ ! -f /root/.ssh/id_ed25519 ]]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
  fi
  cat > /root/.ssh/config << EOF
Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
  chmod 600 /root/.ssh/config
'

mapfile -t SSH_IPS < <(sonic_mgmt_ips)
[[ ${#SSH_IPS[@]} -gt 0 ]] || die "no SONiC management IPs in ${TOPO_FILE}"
pub="$(docker exec "$CI_CONTAINER" cat /root/.ssh/id_ed25519.pub)"
for ip in "${SSH_IPS[@]}"; do
  log "ssh key -> ${ip}"
  sonic_ssh "$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && grep -qxF '${pub}' ~/.ssh/authorized_keys || echo '${pub}' >> ~/.ssh/authorized_keys"
done

# SSH accepts a login before config-setup finishes. t1-1 (SWITCH_ID 251) is
# the last VM to boot, and configure_neighbors.sh then sees default INTERFACE
# rows it just failed to clear. Wait until systemd has left "starting".
# "degraded" is a finished boot on SONiC VS (NTP and similar units fail).
sonic_booted() {
  local ip="$1"
  sonic_ssh "$ip" 's=$(systemctl is-system-running 2>/dev/null || true); case "$s" in running|degraded) exit 0 ;; *) exit 1 ;; esac'
}
boot_pids=()
for ip in "${SSH_IPS[@]}"; do
  wait_for 600 "SONiC boot finished on ${ip}" sonic_booted "$ip" &
  boot_pids+=("$!")
done
boot_fail=0
for pid in "${boot_pids[@]}"; do
  wait "$pid" || boot_fail=1
done
[[ "$boot_fail" -eq 0 ]] || die "a switch in slot ${SLOT} did not finish booting"

case "$TOPO" in
  t0)
    TOPO_ID="$SLOT" SONIC_MGMT_CONTAINER="$CI_CONTAINER" DUT_NAME="$DUT_NAME" \
      bash "${REPO_ROOT}/ansible/kne/topologies/t0/configure_neighbors.sh"
    ;;
  t1)
    SONIC_MGMT_CONTAINER="$CI_CONTAINER" \
      python3 "${REPO_ROOT}/ansible/kne/topologies/t1/configure_neighbors.py" "$TOPO_FILE"
    ;;
  t1-lag)
    # ansible/kne has no t1-lag configure script. apply_neighbors.py reads
    # ci/kne/topos/t1-lag.neighbors.json and rewrites each neighbor's config_db.
    TOPO="$TOPO" SLOT="$SLOT" BASE_PREFIX="$BASE_PREFIX" CI_CONTAINER="$CI_CONTAINER" \
      DUT_NAME="$DUT_NAME" DUT_IP="$DUT_IP" SONIC_PASS="$SONIC_PASS" \
      python3 "${KNE_CI_DIR}/apply_neighbors.py"
    ;;
  *) die "unknown topo ${TOPO}" ;;
esac
