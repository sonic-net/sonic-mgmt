#!/bin/bash
#
# Run this script directly ON a SONiC DUT to upgrade its image.
#
# Usage:
#   sudo ./upgrade_on_dut.sh --url <.tar.gz URL>
#   sudo ./upgrade_on_dut.sh --url <.tar.gz URL> --no-reboot
#   sudo ./upgrade_on_dut.sh --url <.tar.gz URL> --dns "8.8.8.8"
#
# Examples:
#   sudo ./upgrade_on_dut.sh \
#     --url https://engci-maven-master.cisco.com/.../sonic-buildimage-cisco.202511.signed-periodic-36861.tar.gz
#
# What it does:
#   1. Configures DNS (so the DUT can resolve the URL hostname)
#   2. Downloads the .tar.gz and extracts the .bin image
#   3. Runs sonic-installer install -y <.bin>
#   4. Sets next boot to the new image
#   5. Restores DNS
#   6. Reboots (unless --no-reboot)
#

set -euo pipefail

# --- Defaults ---
IMAGE_URL=""
DNS_SERVERS="171.70.168.183 171.68.226.120"  # Cisco DNS
NO_REBOOT=false

# --- Color helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    echo "Usage: sudo $0 --url <.tar.gz URL> [--dns <servers>] [--no-reboot]"
    echo ""
    echo "Options:"
    echo "  --url         URL to a .tar.gz SONiC build artifact"
    echo "  --dns         DNS servers, space-separated (default: '$DNS_SERVERS')"
    echo "  --no-reboot   Install only, skip reboot"
    echo "  -h, --help    Show this help"
    exit 1
}

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)        IMAGE_URL="$2"; shift 2 ;;
        --dns)        DNS_SERVERS="$2"; shift 2 ;;
        --no-reboot)  NO_REBOOT=true; shift ;;
        -h|--help)    usage ;;
        *)            log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$IMAGE_URL" ]]; then
    log_error "--url is required"
    usage
fi

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# --- Step 1: Show current state ---
log_info "Current image info:"
sonic-installer list
echo ""

CURRENT_IMAGE=$(sonic-installer list | grep '^Current:' | awk '{print $2}')
log_info "Current image: $CURRENT_IMAGE"

# --- Step 2: Verify network and configure DNS ---
HOSTNAME=$(echo "$IMAGE_URL" | sed -n 's|^https\?://\([^/]*\).*|\1|p')

# Detect management VRF
VRF_CMD=""
if ip link show dev mgmt 2>/dev/null | grep -q 'UP'; then
    VRF_CMD="ip vrf exec mgmt"
    log_info "Management VRF detected — using mgmt VRF for network commands"
fi

# Check eth0 is up with an IP
ETH0_IP=$(ip -4 addr show dev eth0 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
if [[ -z "$ETH0_IP" ]]; then
    log_error "eth0 has no IPv4 address — cannot reach download server"
    exit 1
fi
log_info "eth0 IP: $ETH0_IP"

# Find the default gateway
GW_IP=$(ip route show default dev eth0 2>/dev/null | awk '{print $3}' | head -1)
if [[ -z "$GW_IP" ]]; then
    GW_IP=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
fi
if [[ -z "$GW_IP" ]]; then
    # No default route — derive gateway from eth0 subnet (assume .1)
    GW_IP=$(echo "$ETH0_IP" | sed 's/\.[0-9]*$/.1/')
    log_warn "No default route found — guessing gateway $GW_IP from eth0 subnet"
fi
log_info "Default gateway: $GW_IP"

# Verify gateway is reachable
if ! $VRF_CMD ping -c 2 -W 2 "$GW_IP" > /dev/null 2>&1; then
    log_warn "Gateway $GW_IP not responding to ping (may still route traffic)"
fi

# Configure DNS — try candidates until one can resolve the target hostname
cp /etc/resolv.conf /etc/resolv.conf.bak.upgrade 2>/dev/null || true

# Build candidate list: user-provided DNS, gateway, Google DNS
DNS_CANDIDATES="$DNS_SERVERS $GW_IP 8.8.8.8 8.8.4.4"
WORKING_DNS=""

log_info "Testing DNS candidates: $DNS_CANDIDATES"
for ns in $DNS_CANDIDATES; do
    # Write this single nameserver and test
    echo "nameserver $ns" > /etc/resolv.conf
    if [[ -n "$HOSTNAME" ]] && $VRF_CMD nslookup "$HOSTNAME" "$ns" > /dev/null 2>&1; then
        WORKING_DNS="$ns"
        log_info "DNS server $ns can resolve $HOSTNAME ✓"
        break
    elif $VRF_CMD ping -c 1 -W 2 "$ns" > /dev/null 2>&1; then
        # Server is reachable but maybe can't resolve our host — keep as fallback
        if [[ -z "$WORKING_DNS" ]]; then
            WORKING_DNS="$ns"
            log_info "DNS server $ns is reachable (could not verify hostname resolution)"
        fi
    else
        log_info "DNS server $ns not reachable, skipping"
    fi
done

if [[ -z "$WORKING_DNS" ]]; then
    log_error "No working DNS server found. Tried: $DNS_CANDIDATES"
    log_error "Verify that eth0 ($ETH0_IP) has external network connectivity"
    cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
    exit 1
fi

echo "nameserver $WORKING_DNS" > /etc/resolv.conf
log_info "Using DNS server: $WORKING_DNS"

# --- Step 3: Download, extract, and install image ---
if [[ "$IMAGE_URL" != *.tar.gz ]]; then
    log_error "URL must end in .tar.gz"
    cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
    exit 1
fi

WORK_DIR=$(mktemp -d /tmp/sonic_upgrade.XXXXXX)
TARBALL="${WORK_DIR}/image.tar.gz"

cleanup_work_dir() {
    log_info "Cleaning up $WORK_DIR ..."
    rm -rf "$WORK_DIR"
}

log_info "Downloading $IMAGE_URL ..."
log_info "(This may take a few minutes)"
if ! $VRF_CMD curl -fSL -o "$TARBALL" "$IMAGE_URL"; then
    log_error "Download failed"
    cleanup_work_dir
    cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
    exit 1
fi
log_info "Download complete: $(du -h "$TARBALL" | awk '{print $1}')"

log_info "Extracting tarball ..."
if ! tar xzf "$TARBALL" -C "$WORK_DIR"; then
    log_error "Extraction failed"
    cleanup_work_dir
    cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
    exit 1
fi
rm -f "$TARBALL"

BIN_FILE=$(find "$WORK_DIR" -maxdepth 2 -name '*.bin' -type f | head -1)
if [[ -z "$BIN_FILE" ]]; then
    log_error "No .bin file found in tarball"
    log_error "Contents of $WORK_DIR:"
    find "$WORK_DIR" -type f | head -20
    cleanup_work_dir
    cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
    exit 1
fi
log_info "Found image: $(basename "$BIN_FILE")"

log_info "Installing image ..."
INSTALL_RC=0
sonic-installer install -y "$BIN_FILE" || INSTALL_RC=$?
if [[ $INSTALL_RC -ne 0 ]]; then
    log_warn "sonic-installer exited with code $INSTALL_RC"
    # Check if the image was actually installed despite the error
    # (known issue: umount cleanup failure causes non-zero exit even on success)
    BIN_BASENAME=$(basename "$BIN_FILE" .bin)
    if sonic-installer list 2>/dev/null | grep -q "$BIN_BASENAME"; then
        log_warn "Image appears installed despite exit code — continuing"
    else
        log_error "sonic-installer install failed and image not found"
        cleanup_work_dir
        cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
        exit 1
    fi
fi
cleanup_work_dir
log_info "Image installed successfully"

# --- Step 4: Restore DNS ---
cp /etc/resolv.conf.bak.upgrade /etc/resolv.conf 2>/dev/null || true
log_info "DNS restored"

# --- Step 5: Verify and set next boot ---
log_info "Post-install image info:"
sonic-installer list
echo ""

NEW_IMAGE=$(sonic-installer list | grep -E '^IMAGE-' | grep -v "^${CURRENT_IMAGE}$" | head -1 || true)
NEXT_IMAGE=$(sonic-installer list | grep '^Next:' | awk '{print $2}')

if [[ -n "$NEW_IMAGE" && "$NEW_IMAGE" != "$NEXT_IMAGE" ]]; then
    log_info "Setting next boot to: $NEW_IMAGE"
    sonic-installer set-next-boot "$NEW_IMAGE"
else
    log_info "Next boot already set to: ${NEW_IMAGE:-$NEXT_IMAGE}"
fi

# --- Step 6: Reboot ---
if [[ "$NO_REBOOT" == "false" ]]; then
    log_info "Rebooting in 3 seconds ..."
    sleep 3
    reboot
else
    log_info "Skipping reboot (--no-reboot). Run 'sudo reboot' when ready."
fi
