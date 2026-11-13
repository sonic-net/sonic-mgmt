#!/bin/bash
# =============================================================================
# Configure the four T1 neighbors of the KNE T0 topology.
#
# Each neighbor boots SONiC VS's default configuration, which uses the same
# BGP AS as the DUT and puts an IP on every port. For each neighbor, this:
#   1. Removes the default interface IPs, loopback IPs, and BGP neighbors.
#   2. Creates PortChannel1 on Ethernet0 (the link to the DUT).
#   3. Assigns the PortChannel and loopback addresses from sonic-mgmt's T0
#      topology (ansible/vars/topo_t0.yml).
#   4. Sets BGP AS 64600 and peers with the DUT (AS 65100) over IPv4 and IPv6.
#   5. Saves the configuration and restarts BGP.
#
# Usage:
#   TOPO_ID=100 ./configure_neighbors.sh
#
# Runs its SSH commands through the sonic-mgmt container, which needs SSH key
# access to each neighbor as admin.
# =============================================================================
set -uo pipefail

TOPO_ID=${TOPO_ID:?set TOPO_ID to the topology ID}
CONTAINER=${SONIC_MGMT_CONTAINER:-sonic-mgmt}
NEIGHBOR_ASN=64600
DUT_ASN=65100
DUT_NAME=vlab-kne-01

#  SWITCH_ID  Loopback        PortChannel1 IPv4  PortChannel1 IPv6  DUT IPv4    DUT IPv6
NEIGHBORS=(
  "251        100.1.0.29/32   10.0.0.57/31       fc00::72/126       10.0.0.56   fc00::71"
  "252        100.1.0.30/32   10.0.0.59/31       fc00::76/126       10.0.0.58   fc00::75"
  "253        100.1.0.31/32   10.0.0.61/31       fc00::7a/126       10.0.0.60   fc00::79"
  "250        100.1.0.32/32   10.0.0.63/31       fc00::7e/126       10.0.0.62   fc00::7d"
)

# Runs on each neighbor. Arguments: LO V4 V6 PEER4 PEER6 ASN PEER_ASN PEER_NAME
REMOTE_SCRIPT=$(cat <<'EOF'
# Wrapped in a function and run with stdin from /dev/null: bash reads the
# whole function before running it, so commands inside (sudo, config, ...)
# can't consume the rest of this script from SSH's stdin.
main() {
LO=$1; V4=$2; V6=$3; PEER4=$4; PEER6=$5; ASN=$6; PEER_ASN=$7; PEER_NAME=$8

remove_ips() {   # $1 = CONFIG_DB table, e.g. INTERFACE or LOOPBACK_INTERFACE
    for key in $(sonic-db-cli CONFIG_DB keys "$1|*|*"); do
        intf=$(echo "$key" | cut -d'|' -f2)
        prefix=$(echo "$key" | cut -d'|' -f3)
        sudo config interface ip remove "$intf" "$prefix" >/dev/null 2>&1
    done
}

echo "  [1/5] Removing default interface IPs, loopback IPs, and BGP neighbors"
remove_ips INTERFACE
remove_ips LOOPBACK_INTERFACE
for key in $(sonic-db-cli CONFIG_DB keys 'BGP_NEIGHBOR|*'); do
    sudo sonic-db-cli CONFIG_DB DEL "$key" >/dev/null
done

echo "  [2/5] Creating PortChannel1 on Ethernet0"
sudo config portchannel add PortChannel1 2>/dev/null
# Skip if Ethernet0 is already a member, so rerunning the script is clean
[ -n "$(sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_MEMBER|PortChannel1|Ethernet0')" ] || \
    sudo config portchannel member add PortChannel1 Ethernet0

echo "  [3/5] Assigning $V4, $V6, and loopback $LO"
sudo config interface ip add PortChannel1 "$V4"
sudo config interface ip add PortChannel1 "$V6"
sudo config interface ip add Loopback0 "$LO"

echo "  [4/5] Setting BGP AS $ASN, peering with $PEER_NAME (AS $PEER_ASN)"
sudo sonic-db-cli CONFIG_DB HSET 'DEVICE_METADATA|localhost' bgp_asn "$ASN" >/dev/null
sudo sonic-db-cli CONFIG_DB HSET "BGP_NEIGHBOR|$PEER4" asn "$PEER_ASN" name "$PEER_NAME" \
    local_addr "${V4%/*}" admin_status up holdtime 180 keepalive 60 nhopself 0 rrclient 0 >/dev/null
sudo sonic-db-cli CONFIG_DB HSET "BGP_NEIGHBOR|$PEER6" asn "$PEER_ASN" name "$PEER_NAME" \
    local_addr "${V6%/*}" admin_status up holdtime 180 keepalive 60 nhopself 0 rrclient 0 >/dev/null

echo "  [5/5] Saving the configuration and restarting BGP"
sudo config save -y >/dev/null
sudo systemctl restart bgp

# Verify the configuration database matches what was intended
# Count non-empty lines: sonic-db-cli prints an empty line when no keys match.
problems=""
[ "$(sonic-db-cli CONFIG_DB keys 'INTERFACE|*|*' | grep -c .)" -eq 0 ] || problems="$problems default-IPs-remain"
[ -n "$(sonic-db-cli CONFIG_DB keys "PORTCHANNEL_MEMBER|PortChannel1|Ethernet0")" ] || problems="$problems no-member"
[ -n "$(sonic-db-cli CONFIG_DB keys "PORTCHANNEL_INTERFACE|PortChannel1|$V4")" ] || problems="$problems no-ipv4"
[ -n "$(sonic-db-cli CONFIG_DB keys "PORTCHANNEL_INTERFACE|PortChannel1|$V6")" ] || problems="$problems no-ipv6"
[ "$(sonic-db-cli CONFIG_DB HGET 'DEVICE_METADATA|localhost' bgp_asn)" = "$ASN" ] || problems="$problems wrong-asn"
[ "$(sonic-db-cli CONFIG_DB keys 'BGP_NEIGHBOR|*' | grep -c .)" -eq 2 ] || problems="$problems bgp-neighbors"
if [ -z "$problems" ]; then echo "CONFIGURED"; else echo "FAILED:$problems"; fi
}
main "$@" </dev/null
EOF
)

ok=0; fail=0
for entry in "${NEIGHBORS[@]}"; do
    read -r sid lo v4 v6 peer4 peer6 <<< "$entry"
    ip="172.31.${TOPO_ID}.${sid}"
    echo "=== Neighbor ${ip} (SWITCH_ID ${sid})"
    out=$(echo "$REMOTE_SCRIPT" | docker exec -i "$CONTAINER" \
        ssh -o BatchMode=yes -o ConnectTimeout=30 "admin@${ip}" \
        bash -s -- "$lo" "$v4" "$v6" "$peer4" "$peer6" "$NEIGHBOR_ASN" "$DUT_ASN" "$DUT_NAME" 2>&1)
    echo "$out" | grep -v '^Debian GNU/Linux'
    if echo "$out" | grep -q '^CONFIGURED$'; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
done

echo ""
echo "DONE ok=${ok} fail=${fail}"
[ "$fail" -eq 0 ]
