#!/bin/bash
# =============================================================================
# Set up management access to the PTF container in a KNE SONiC topology.
#
# PTF doesn't run startup.sh, so it has no management bridge or DHCP. This
# script gives it a management IP on the topology's management subnet:
#
#   1. Assigns 172.31.<TOPO_ID>.<SWITCH_ID>/32 to the PTF pod's eth0.
#   2. Routes that IP from the kind node to the PTF pod.
#
# The host's route for the whole management subnet comes from
# setup_mgmt_routes.py. Run both scripts before reaching PTF from the host.
#
# Usage:
#   ./setup_ptf_mgmt.sh <rendered-topology-file> [ptf-node-name]
#
#   <rendered-topology-file>  The rendered file passed to `kne create`,
#                             not the template.
#   [ptf-node-name]           PTF node name in the topology (default: ptf).
#
# Environment:
#   KIND_NODE                 kind node container (default: kne-control-plane)
#
# Rerun after the PTF pod restarts: its pod IP changes, and the address
# assigned inside the pod is lost.
# =============================================================================
set -euo pipefail

TOPO_FILE=${1:-}
PTF_NODE=${2:-ptf}
KIND_NODE=${KIND_NODE:-kne-control-plane}

if [ -z "$TOPO_FILE" ]; then
    echo "Usage: $0 <rendered-topology-file> [ptf-node-name]" >&2
    exit 1
fi
if [ ! -f "$TOPO_FILE" ]; then
    echo "ERROR: $TOPO_FILE not found" >&2
    exit 1
fi
for cmd in kubectl docker awk; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd not found" >&2; exit 1; }
done

# -----------------------------------------------------------------------------
# Read the namespace (topology name = TOPO_ID) and PTF's SWITCH_ID
# -----------------------------------------------------------------------------
TOPO_ID=$(awk -F'"' '/^name:/ {print $2; exit}' "$TOPO_FILE")
if ! [[ "$TOPO_ID" =~ ^[0-9]+$ ]] || [ "$TOPO_ID" -lt 1 ] || [ "$TOPO_ID" -gt 234 ]; then
    echo "ERROR: topology name '$TOPO_ID' is not a valid TOPO_ID (1-234)" >&2
    exit 1
fi

SWITCH_ID=$(awk -v want="$PTF_NODE" '
    /^nodes:/                     { in_node = 1; node = ""; sid = ""; next }
    in_node && node == "" && /name:/ {
        if (match($0, /"[^"]+"/)) node = substr($0, RSTART + 1, RLENGTH - 2)
    }
    in_node && /"SWITCH_ID"/      {
        if (match($0, /value: *"[0-9]+"/)) {
            v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v); sid = v
        }
    }
    in_node && /^}/               {
        if (node == want && sid != "") { print sid; exit }
        in_node = 0
    }
' "$TOPO_FILE")
if ! [[ "$SWITCH_ID" =~ ^[0-9]+$ ]] || [ "$SWITCH_ID" -lt 2 ] || [ "$SWITCH_ID" -gt 254 ]; then
    echo "ERROR: no valid SWITCH_ID (2-254) found for node '$PTF_NODE' in $TOPO_FILE" >&2
    exit 1
fi

NS="$TOPO_ID"
MGMT_IP="172.31.${TOPO_ID}.${SWITCH_ID}"

echo "PTF management setup"
echo "  Topology file : $TOPO_FILE"
echo "  Namespace     : $NS"
echo "  PTF node      : $PTF_NODE"
echo "  Mgmt IP       : $MGMT_IP"

# -----------------------------------------------------------------------------
# 1. Assign the management IP inside the PTF pod
# -----------------------------------------------------------------------------
echo "[1/3] Waiting for pod $PTF_NODE to be ready..."
kubectl wait --for=condition=Ready "pod/$PTF_NODE" -n "$NS" --timeout=300s >/dev/null

echo "[2/3] Assigning ${MGMT_IP}/32 to eth0 in pod $PTF_NODE..."
# /32 so PTF keeps using its default route for the rest of the subnet.
# 'replace' makes this safe to rerun.
kubectl exec -n "$NS" "$PTF_NODE" -c "$PTF_NODE" -- ip addr replace "${MGMT_IP}/32" dev eth0

# -----------------------------------------------------------------------------
# 2. Route the management IP from the kind node to the PTF pod
# -----------------------------------------------------------------------------
echo "[3/3] Routing ${MGMT_IP} to the PTF pod on ${KIND_NODE}..."
PTF_POD_IP=$(kubectl get pod -n "$NS" "$PTF_NODE" -o jsonpath='{.status.podIP}')
if [ -z "$PTF_POD_IP" ]; then
    echo "ERROR: could not determine pod IP for $PTF_NODE" >&2
    exit 1
fi

# "ip route get" works whether the CNI gives each pod its own route or one
# subnet route via a bridge (as KNE's kind-bridge setup does).
PTF_DEV=$(docker exec "$KIND_NODE" ip route get "$PTF_POD_IP" | awk '/dev/ {for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
if [ -z "$PTF_DEV" ]; then
    echo "ERROR: could not find the interface for pod IP $PTF_POD_IP on $KIND_NODE" >&2
    exit 1
fi

docker exec "$KIND_NODE" ip route replace "${MGMT_IP}/32" via "$PTF_POD_IP" dev "$PTF_DEV" onlink

# -----------------------------------------------------------------------------
# Verify
# -----------------------------------------------------------------------------
if ! kubectl exec -n "$NS" "$PTF_NODE" -c "$PTF_NODE" -- ip -4 addr show dev eth0 | grep -q "inet ${MGMT_IP}/32"; then
    echo "ERROR: ${MGMT_IP}/32 is not on eth0 in pod $PTF_NODE" >&2
    exit 1
fi
if ! docker exec "$KIND_NODE" ip route show "${MGMT_IP}/32" | grep -q "via ${PTF_POD_IP}"; then
    echo "ERROR: route for ${MGMT_IP} on $KIND_NODE is missing" >&2
    exit 1
fi

echo ""
echo "Done: ${MGMT_IP} is assigned in pod ${PTF_NODE} (pod IP ${PTF_POD_IP}, via ${PTF_DEV})."
echo "Once setup_mgmt_routes.py has also run, check it from the host with:"
echo "  ping -c 3 ${MGMT_IP}"
