#!/usr/bin/env bash
# Render one slot from the PR 7 template of the same shape (t0=100, t1=101, t1-lag=102).
# usage: render.sh <t0|t1|t1-lag> <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
TOPO_ARG="${1:?topo}"
slot_vars "${2:?slot}" "$TOPO_ARG"

ANS="${REPO_ROOT}/ansible"
case "$TOPO" in
  t0)     SRC_PB="${ANS}/kne/topologies/t0/t0.pb.txt" ;;
  t1)     SRC_PB="${ANS}/kne/topologies/t1/t1.pb.txt" ;;
  t1-lag) SRC_PB="${ANS}/kne/topologies/t1-lag/t1-lag.pb.txt" ;;
  *) die "no topology template for ${TOPO}" ;;
esac
[[ -f "$SRC_PB" ]] || die "missing topology template $SRC_PB"

sed -e "s/^name: \"${BASE_ID}\"/name: \"${NS}\"/" \
    -e "s/\(key: \"TOPO_ID\"[[:space:]]*value: \)\"${BASE_ID}\"/\1\"${SLOT}\"/" \
    "$SRC_PB" > "$TOPO_FILE"
grep -q "^name: \"${NS}\"" "$TOPO_FILE" || die "topology name not rendered"
[[ "$(grep -c "TOPO_ID\"[[:space:]]*value: \"${SLOT}\"" "$TOPO_FILE")" -eq "$(grep -c 'key: "TOPO_ID"' "$SRC_PB")" ]] \
  || die "TOPO_ID not rendered on all nodes"

render() {
  sed -e "s/${BASE_PREFIX}/172.31.${SLOT}./g" \
      -e "s/${SRC_DUT}/${DUT_NAME}/g" \
      -e "s/${SRC_PTF}/ptf-kne-${SLOT}/g" \
      -e "s/KNE-VSERV-01/KNE-VSERV-${SLOT}/g" \
      -e "s/VM01/VM${SLOT}/g" \
      -e "s/^- conf-name: ${SRC_TB}$/- conf-name: ${TESTBED}/" \
      -e "s/group-name: ${SRC_GROUP}$/group-name: vms6-${SLOT}/" \
      -e "s/inv_name: ${SRC_INV}$/inv_name: ${INV}/" \
      "$1"
}

render "${ANS}/${SRC_INV}" > "${ANS}/${INV}"

cat > "${ANS}/host_vars/KNE-VSERV-${SLOT}.yml" << EOF
mgmt_bridge: br${SLOT}
mgmt_gw: ${GW}
EOF

render "${ANS}/files/${SRC_CSV}_devices.csv" > "${ANS}/files/sonic_${INV}_devices.csv"
render "${ANS}/files/${SRC_CSV}_links.csv"   > "${ANS}/files/sonic_${INV}_links.csv"

awk -v name="$SRC_TB" '
  $0 == "- conf-name: " name { p=1 }
  p && /^- conf-name:/ && $0 != "- conf-name: " name { exit }
  p
' "${ANS}/kne_testbed.yaml" | render /dev/stdin >> "${ANS}/kne_testbed.yaml"
grep -q "conf-name: ${TESTBED}$" "${ANS}/kne_testbed.yaml" || die "testbed entry not appended"
grep -qx "  - ${INV}" "${ANS}/files/graph_groups.yml" || echo "  - ${INV}" >> "${ANS}/files/graph_groups.yml"

log "rendered ${TOPO} slot ${SLOT}: ${DUT_NAME} @ ${DUT_IP}, testbed ${TESTBED}"
