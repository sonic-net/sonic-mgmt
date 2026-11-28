#!/bin/bash
set -uo pipefail

# =============================================================================
# SONiC Virtual Switch — KNE Pod Startup Script
#
# Launches a QEMU-based SONiC VS inside a KNE pod with:
#   - Management bridge + DHCP for QEMU VM management interface
#   - TC-based data plane wiring (ethN <-> tapN redirect)
#   - Optional TC mirror on uplink ports for PTF injected-port sniffing
#
# Environment Variables:
#   SWITCH_ID       — Unique switch identifier (default: 0)
#   TOPO_ID         — Topology/namespace identifier (default: 20)
#   QEMU_RAM        — Guest RAM allocation (default: 4G)
#   QEMU_SMP        — Guest CPU count (default: 2)
#   SERVER_PORTS    — Number of server-facing ports (default: 28)
#   UPLINK_PORTS    — Number of uplink ports to T1 neighbors (default: 4)
#   MIRROR_ENABLED  — Enable TC mirror on uplinks for PTF sniffing (default: 0)
#
# Port Layout (default T0 with 32 data ports):
#   eth1  – eth28  : Server-facing ports (direct to PTF)
#   eth29 – eth32  : Uplink ports (to T1 neighbor VMs)
#   eth33 – eth36  : Mirror ports (copies of uplink traffic to PTF)
#                    Only created when MIRROR_ENABLED=1
#
# The QEMU VM sees only tap0 (mgmt) + tap1–tapN (data ports).
# Mirror ports exist at the pod level only — the VM is unaware of them.
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TOPO_ID=${TOPO_ID:-20}
SID=${SWITCH_ID:-0}
NODE_NAME=$(hostname)
CONSOLE_PORT=$(( 4321 + (TOPO_ID * 256) + SID ))
INTERACT_PORT=$(( 5321 + (TOPO_ID * 256) + SID ))
MTU_VALUE=9100

SERVER_PORTS=${SERVER_PORTS:-28}
UPLINK_PORTS=${UPLINK_PORTS:-4}
MIRROR_ENABLED=${MIRROR_ENABLED:-0}
TOTAL_DATA_PORTS=$(( SERVER_PORTS + UPLINK_PORTS ))
FIRST_UPLINK=$(( SERVER_PORTS + 1 ))
LAST_UPLINK=$(( SERVER_PORTS + UPLINK_PORTS ))
FIRST_MIRROR=$(( TOTAL_DATA_PORTS + 1 ))

# Management network
MGMT_GW="172.31.${TOPO_ID}.1"
MGMT_SUBNET="172.31.${TOPO_ID}.0/24"
MGMT_IP="172.31.${TOPO_ID}.${SID}"
MGMT_MAC=$(printf '52:54:00:00:%02x:%02x' "$TOPO_ID" "$SID")

# Bridge name — unique per pod (pod has its own network namespace)
BR="br${TOPO_ID}"

echo "======================================================="
echo " SONiC Virtual Switch — KNE Startup"
echo "   Node          : $NODE_NAME"
echo "   SWITCH_ID     : $SID"
echo "   TOPO_ID       : $TOPO_ID"
echo "   Console port  : localhost:$CONSOLE_PORT"
echo "   Interact port : localhost:$INTERACT_PORT"
echo "   Mgmt IP       : ${MGMT_IP}/24"
echo "   Mgmt MAC      : ${MGMT_MAC}"
echo "   Bridge        : ${BR}"
echo "   Server ports  : eth1 – eth${SERVER_PORTS}"
echo "   Uplink ports  : eth${FIRST_UPLINK} – eth${LAST_UPLINK}"
echo "   Mirror enabled: ${MIRROR_ENABLED}"
if [ "$MIRROR_ENABLED" = "1" ]; then
echo "   Mirror ports  : eth${FIRST_MIRROR} – eth$(( FIRST_MIRROR + UPLINK_PORTS - 1 ))"
fi
echo "   RAM           : ${QEMU_RAM:-4G}"
echo "======================================================="

# =============================================================================
# 1. Disable bridge filtering
# =============================================================================
sysctl -w net.bridge.bridge-nf-call-iptables=0  2>/dev/null || true
sysctl -w net.bridge.bridge-nf-call-arptables=0 2>/dev/null || true
sysctl -w net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true

# =============================================================================
# 2. Management bridge: eth0 → br<TOPO_ID> → tap0 → QEMU
# =============================================================================
echo "[1/4] Configuring management bridge..."

ip link show "$BR"  &>/dev/null || ip link add "$BR" type bridge || { echo "ERROR: failed to create $BR"; exit 1; }
ip link show tap0   &>/dev/null || ip tuntap add tap0 mode tap   || { echo "ERROR: failed to create tap0"; exit 1; }

ip link set tap0 mtu "$MTU_VALUE"
ip link set "$BR" mtu "$MTU_VALUE"
ip link set tap0 up
ip link set tap0 master "$BR" 2>/dev/null || true
ip link set "$BR" up

# Gateway IP on bridge
ip addr add "${MGMT_GW}/24" dev "$BR" 2>/dev/null || true

# NAT and forwarding for VM internet access via pod's eth0
iptables -t nat -A POSTROUTING -s "${MGMT_SUBNET}" -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i eth0 -o "$BR" -j ACCEPT
iptables -A FORWARD -i "$BR" -o eth0 -j ACCEPT

# Block rogue DHCP from k8s network reaching the VM
iptables -I FORWARD -i eth0 -o "$BR" -p udp --sport 67 --dport 68 -j DROP

# Static ARP for the QEMU VM's management MAC
ip neigh add "${MGMT_IP}" lladdr "${MGMT_MAC}" dev "$BR" 2>/dev/null || true

echo "      ${BR} UP, tap0 enslaved, gateway ${MGMT_GW}"

# =============================================================================
# 3. DHCP server for QEMU VM management interface
# =============================================================================
echo "[2/4] Starting DHCP server on ${BR}..."

DNSMASQ_CONF="/tmp/dnsmasq_${TOPO_ID}_${SID}.conf"
cat > "$DNSMASQ_CONF" <<EOF
interface=${BR}
bind-interfaces
dhcp-range=${MGMT_IP},${MGMT_IP},255.255.255.0,12h
dhcp-host=${MGMT_MAC},${MGMT_IP}
dhcp-option=3,${MGMT_GW}
EOF

dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file="/tmp/dnsmasq_${TOPO_ID}_${SID}.pid"
if ! pgrep -f "dnsmasq.*dnsmasq_${TOPO_ID}_${SID}" >/dev/null 2>&1; then
    echo "ERROR: dnsmasq failed to start" >&2
    exit 1
fi
echo "      dnsmasq started for ${MGMT_IP} on ${BR}"

# =============================================================================
# 4. Data plane: TC redirect (ethN <-> tapN) + optional mirror
# =============================================================================
echo "[3/4] Configuring data plane..."

# Discover data plane interfaces (eth1, eth2, ..., ethN)
# Excludes mirror interfaces if present — those are handled separately
DATA_INTERFACES=""
for i in $(seq 1 "$TOTAL_DATA_PORTS"); do
    if ip link show "eth${i}" &>/dev/null; then
        DATA_INTERFACES="$DATA_INTERFACES eth${i}"
    fi
done

# Build QEMU network arguments starting with management
QEMU_NET_ARGS="\
-netdev tap,id=mgmt,ifname=tap0,script=no,downscript=no \
-device virtio-net-pci,netdev=mgmt,mac=${MGMT_MAC},bus=pcie.0,addr=0x2.0x0,multifunction=on"

for INTF in $DATA_INTERFACES; do
    NUM=${INTF#eth}
    TAP="tap${NUM}"

    # Create tap interface for QEMU
    ip link show "$TAP" &>/dev/null || ip tuntap add "$TAP" mode tap

    ip link set "$INTF" mtu "$MTU_VALUE"
    ip link set "$TAP"  mtu "$MTU_VALUE"
    ip link set "$INTF" up
    ip link set "$TAP"  up

    # --- TC redirect: wire meshnet interface to QEMU tap ---
    tc qdisc add dev "$INTF" clsact 2>/dev/null || true
    tc qdisc add dev "$TAP"  clsact 2>/dev/null || true
    tc filter del dev "$INTF" ingress 2>/dev/null || true
    tc filter del dev "$TAP"  ingress 2>/dev/null || true

    # Determine if this is an uplink port that needs mirroring
    MIRROR_INTF=""
    if [ "$MIRROR_ENABLED" = "1" ] && [ "$NUM" -ge "$FIRST_UPLINK" ] && [ "$NUM" -le "$LAST_UPLINK" ]; then
        MIRROR_NUM=$(( FIRST_MIRROR + (NUM - FIRST_UPLINK) ))
        MIRROR_INTF="eth${MIRROR_NUM}"

        if ip link show "$MIRROR_INTF" &>/dev/null; then
            ip link set "$MIRROR_INTF" mtu "$MTU_VALUE"
            ip link set "$MIRROR_INTF" up

            tc qdisc add dev "$MIRROR_INTF" clsact 2>/dev/null || true
            tc filter del dev "$MIRROR_INTF" ingress 2>/dev/null || true
        else
            echo "      WARNING: Mirror interface ${MIRROR_INTF} not found — skipping mirror for ${INTF}"
            MIRROR_INTF=""
        fi
    fi

    if [ -n "$MIRROR_INTF" ]; then
        # --- Uplink port with mirror ---
        # T1 → DUT: redirect to QEMU + mirror copy to PTF
        tc filter add dev "$INTF" ingress protocol all u32 match u32 0 0 \
            action mirred egress redirect dev "$TAP" \
            action mirred egress mirror dev "$MIRROR_INTF"

        # DUT → T1: redirect to meshnet + mirror copy to PTF
        tc filter add dev "$TAP" ingress protocol all u32 match u32 0 0 \
            action mirred egress redirect dev "$INTF" \
            action mirred egress mirror dev "$MIRROR_INTF"

        # PTF → DUT: allow injection from mirror interface into QEMU
        tc filter add dev "$MIRROR_INTF" ingress protocol all u32 match u32 0 0 \
            action mirred egress redirect dev "$TAP"

        echo "      ${INTF} <-> ${TAP} (uplink, mirror -> ${MIRROR_INTF})"
    else
        # --- Standard port (server-facing or uplink without mirror) ---
        tc filter add dev "$INTF" ingress protocol all u32 match u32 0 0 \
            action mirred egress redirect dev "$TAP"
        tc filter add dev "$TAP" ingress protocol all u32 match u32 0 0 \
            action mirred egress redirect dev "$INTF"

        echo "      ${INTF} <-> ${TAP}"
    fi

    # QEMU PCI addressing
    SLOT=$(( ((NUM - 1) / 8) + 3 ))
    FUNC=$(( (NUM - 1) % 8 ))
    PCI_ADDR=$(printf '0x%x.0x%x' "$SLOT" "$FUNC")
    MAC_ADDR=$(printf '52:54:00:%02x:%02x:%02x' "$TOPO_ID" "$SID" "$NUM")

    QEMU_NET_ARGS="$QEMU_NET_ARGS \
-netdev tap,id=n${NUM},ifname=${TAP},script=no,downscript=no \
-device virtio-net-pci,netdev=n${NUM},mac=${MAC_ADDR},bus=pcie.0,addr=${PCI_ADDR},multifunction=on"
done

# =============================================================================
# 5. Stagger boot to avoid resource contention
# =============================================================================
STAGGER=$(( (SID % 14) * 20 ))
if [ "$STAGGER" -gt 0 ]; then
    echo "      Staggering boot by ${STAGGER}s (SWITCH_ID=${SID})..."
    sleep "$STAGGER"
fi

# =============================================================================
# 6. Launch QEMU
# =============================================================================
# Boot from a copy-on-write overlay. QEMU only reads /sonic.qcow2, so the
# multi-gigabyte base image is never copied into this container's writable
# layer; the overlay holds just this VM's own changes.
OVERLAY=/tmp/sonic-overlay.qcow2
rm -f "$OVERLAY"
qemu-img create -f qcow2 -b /sonic.qcow2 -F qcow2 "$OVERLAY" >/dev/null \
    || { echo "ERROR: failed to create disk overlay $OVERLAY"; exit 1; }

echo "[4/4] Launching QEMU..."

if [ ! -e /dev/kvm ]; then
    echo "WARNING: /dev/kvm not found — QEMU will run without KVM (very slow)"
    KVM_FLAG=""
else
    KVM_FLAG="-enable-kvm"
fi

qemu-system-x86_64 \
    -m "${QEMU_RAM:-4G}" \
    -smp "${QEMU_SMP:-2}" \
    -cpu host \
    $KVM_FLAG \
    -machine q35 \
    -device virtio-blk-pci,drive=drive0,bus=pcie.0,addr=0x2.0x1 \
    -drive file=$OVERLAY,format=qcow2,if=none,id=drive0 \
    -nographic \
    -serial telnet:0.0.0.0:${CONSOLE_PORT},server,nowait \
    -serial telnet:0.0.0.0:${INTERACT_PORT},server,nowait \
    $QEMU_NET_ARGS &

QEMU_PID=$!
echo "      QEMU started (PID=${QEMU_PID})"
echo "      Console: telnet localhost ${CONSOLE_PORT}"

# =============================================================================
# 7. Wait for serial port
# =============================================================================
echo "      Waiting for QEMU serial port..."
for i in $(seq 1 30); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU process died. Exiting."
        exit 1
    fi
    if socat /dev/null "TCP:localhost:${CONSOLE_PORT},connect-timeout=2" 2>/dev/null; then
        echo "      Serial port open after ${i} attempts."
        break
    fi
    echo "      Attempt ${i}/30 — waiting for serial port..."
    sleep 5
done

echo "======================================================="
echo " SONiC Node $NODE_NAME is booting."
echo "   Console : kubectl exec -it -n <ns> <pod> -- telnet localhost ${CONSOLE_PORT}"
echo "   SSH     : ssh admin@${MGMT_IP}  (after SONiC acquires DHCP lease)"
echo "======================================================="

# =============================================================================
# Keep container alive — exit when QEMU exits
# =============================================================================
wait "$QEMU_PID"
exit $?
