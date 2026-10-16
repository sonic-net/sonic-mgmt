#!/usr/bin/env bash
# Push the minigraph to the DUT, then wait until EXPECTED_BGP IPv4 sessions are up.
# usage: deploy_dut.sh <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"

log "ansible-playbook config_sonic_basedon_testbed.yml -> ${DUT_NAME}"
docker exec \
  -e SONIC_MGMT_SONIC_PASSWORD -e SONIC_MGMT_PTF_PASSWORD \
  "$CI_CONTAINER" timeout 30m ansible-playbook -i "$INV" config_sonic_basedon_testbed.yml \
  -l "$DUT_NAME" -e testbed_name="$TESTBED" -e testbed_file=kne_testbed.yaml -e vm_file="$INV" \
  -e deploy=true -e save=true

wait_for 300 "ssh ${DUT_IP} after minigraph" sonic_ssh "$DUT_IP" true

bgp_up() {
  local n
  n="$(sonic_ssh "$DUT_IP" 'show ip bgp summary' | awk '$1 ~ /^[0-9]+\./ && $(NF-1) ~ /^[0-9]+$/ {c++} END {print c+0}')"
  [[ "$n" -ge "$EXPECTED_BGP" ]]
}
wait_for 600 "${EXPECTED_BGP} IPv4 BGP sessions Established on ${DUT_NAME} (${TOPO})" bgp_up
sonic_ssh "$DUT_IP" 'show ip bgp summary'
restore_checkout_owner
log "DUT ${DUT_NAME} deployed"
