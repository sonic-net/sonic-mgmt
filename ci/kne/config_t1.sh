#!/usr/bin/env bash
# Configure the four SONiC T1 neighbors to match ansible/vars/topo_t0.yml:
# AS 64600, PortChannel1 (LACP, member Ethernet0), v4+v6 peering to the DUT (AS 65100).
# Done by rewriting /etc/sonic/config_db.json and `config reload` (bgpcfgd regenerates FRR).
# usage: config_t1.sh <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"

#            oct  hostname    lo4            lo6               pc4          pc6           peer4      peer6
T1_ROWS=(
  "251 ARISTA01T1 100.1.0.29/32 2064:100::1d/128 10.0.0.57/31 fc00::72/126 10.0.0.56 fc00::71"
  "252 ARISTA02T1 100.1.0.30/32 2064:100::1e/128 10.0.0.59/31 fc00::76/126 10.0.0.58 fc00::75"
  "253 ARISTA03T1 100.1.0.31/32 2064:100::1f/128 10.0.0.61/31 fc00::7a/126 10.0.0.60 fc00::79"
  "250 ARISTA04T1 100.1.0.32/32 2064:100::20/128 10.0.0.63/31 fc00::7e/126 10.0.0.62 fc00::7d"
)

for row in "${T1_ROWS[@]}"; do
  read -r oct host lo4 lo6 pc4 pc6 peer4 peer6 <<<"$row"
  ip="172.31.${SLOT}.${oct}"
  log "T1 ${host} @ ${ip}"
  sonic_scp "${KNE_CI_DIR}/t1_configdb.py" "$ip" /tmp/t1_configdb.py
  sonic_ssh "$ip" "sudo python3 /tmp/t1_configdb.py ${host} ${lo4} ${lo6} ${pc4} ${pc6} ${peer4} ${peer6} ${DUT_NAME} ${DUT_IP} \
                   && (sudo config reload -y -f >/dev/null 2>&1 &) && echo RELOAD_KICKED"
done

# config reload takes ~1-2 min; wait until the PortChannel exists on each T1.
t1_has_pc() { sonic_ssh "$1" 'show interfaces portchannel' | grep -q PortChannel1; }
for row in "${T1_ROWS[@]}"; do
  read -r oct _ <<<"$row"
  ip="172.31.${SLOT}.${oct}"
  wait_for 300 "PortChannel1 on ${ip}" t1_has_pc "$ip"
done
log "T1s configured for slot ${SLOT}"
