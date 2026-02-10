#!/bin/bash
#
# setup-ntp-server.sh - Set up a local NTP server for SONiC virtual testbed
#
# This script deploys a Chrony NTP server in a Docker container connected
# to the management bridge (br1) for providing time synchronization to
# SONiC DUTs, especially in IPv6-only management network scenarios.
#
# Usage:
#   ./setup-ntp-server.sh [start|stop|status|restart]
#
# The NTP server will be accessible at:
#   IPv4: 10.250.0.2
#   IPv6: fec0::ffff:afa:2
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="${SCRIPT_DIR}/files/docker-chrony"

# Configuration
CONTAINER_NAME="sonic-mgmt-ntp"
IMAGE_NAME="sonic-mgmt-ntp:latest"
MGMT_BRIDGE="br1"
NTP_IPV4="10.250.0.2"
NTP_IPV4_PREFIX="24"
NTP_IPV6="fec0::ffff:afa:2"
NTP_IPV6_PREFIX="64"
NETWORK_NAME="sonic-mgmt-ntp-net"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check if bridge exists
    if ! ip link show "${MGMT_BRIDGE}" &> /dev/null; then
        log_error "Management bridge '${MGMT_BRIDGE}' does not exist."
        log_error "Please run 'add-topo' first to create the testbed infrastructure."
        exit 1
    fi

    # Check if Dockerfile exists
    if [[ ! -f "${DOCKER_DIR}/Dockerfile" ]]; then
        log_error "Dockerfile not found at ${DOCKER_DIR}/Dockerfile"
        exit 1
    fi

    log_info "Prerequisites check passed."
}

build_image() {
    log_info "Building NTP server Docker image..."

    docker build -t "${IMAGE_NAME}" "${DOCKER_DIR}"

    log_info "Docker image '${IMAGE_NAME}' built successfully."
}

create_network() {
    log_info "Setting up Docker network connected to ${MGMT_BRIDGE}..."

    # Check if network already exists
    if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
        log_info "Network '${NETWORK_NAME}' already exists."
        return 0
    fi

    # Create a macvlan network attached to br1
    # This allows the container to have its own IP on the bridge network
    docker network create \
        --driver=macvlan \
        --subnet=10.250.0.0/24 \
        --gateway=10.250.0.1 \
        --ipv6 \
        --subnet=fec0::/64 \
        --gateway=fec0::1 \
        -o parent="${MGMT_BRIDGE}" \
        "${NETWORK_NAME}"

    log_info "Network '${NETWORK_NAME}' created successfully."
}

start_container() {
    log_info "Starting NTP server container..."

    # Check if container already exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            log_warn "Container '${CONTAINER_NAME}' is already running."
            return 0
        else
            log_info "Removing stopped container '${CONTAINER_NAME}'..."
            docker rm "${CONTAINER_NAME}"
        fi
    fi

    # Run the container with both IPv4 and IPv6 addresses
    # Capabilities needed:
    #   SYS_TIME: to set system time
    #   NET_BIND_SERVICE: to bind to privileged NTP port 123
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --network "${NETWORK_NAME}" \
        --ip "${NTP_IPV4}" \
        --ip6 "${NTP_IPV6}" \
        --cap-add SYS_TIME \
        --cap-add NET_BIND_SERVICE \
        --restart unless-stopped \
        "${IMAGE_NAME}"

    log_info "NTP server container started."
    log_info "  IPv4 address: ${NTP_IPV4}"
    log_info "  IPv6 address: ${NTP_IPV6}"
}

stop_container() {
    log_info "Stopping NTP server container..."

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "${CONTAINER_NAME}"
        docker rm "${CONTAINER_NAME}"
        log_info "Container '${CONTAINER_NAME}' stopped and removed."
    else
        log_warn "Container '${CONTAINER_NAME}' is not running."
    fi
}

remove_network() {
    log_info "Removing Docker network..."

    if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
        docker network rm "${NETWORK_NAME}" 2>/dev/null || true
        log_info "Network '${NETWORK_NAME}' removed."
    else
        log_info "Network '${NETWORK_NAME}' does not exist."
    fi
}

show_status() {
    echo ""
    echo "=== NTP Server Status ==="
    echo ""

    # Check if container exists and is running
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "Container: ${GREEN}Running${NC}"
        echo "  Name: ${CONTAINER_NAME}"
        echo "  IPv4: ${NTP_IPV4}"
        echo "  IPv6: ${NTP_IPV6}"
        echo ""

        # Show chrony status
        echo "Chrony Status:"
        docker exec "${CONTAINER_NAME}" chronyc tracking 2>/dev/null || echo "  Unable to get chrony status"
        echo ""

        # Show connected clients
        echo "Connected Clients:"
        docker exec "${CONTAINER_NAME}" chronyc clients 2>/dev/null || echo "  Unable to get client list"
    elif docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "Container: ${YELLOW}Stopped${NC}"
    else
        echo -e "Container: ${RED}Not created${NC}"
    fi

    # Check network
    echo ""
    if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
        echo -e "Network: ${GREEN}Created${NC} (${NETWORK_NAME})"
    else
        echo -e "Network: ${RED}Not created${NC}"
    fi

    # Check if image exists
    echo ""
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
        echo -e "Image: ${GREEN}Built${NC} (${IMAGE_NAME})"
    else
        echo -e "Image: ${RED}Not built${NC}"
    fi

    echo ""
}

test_ntp() {
    log_info "Testing NTP server connectivity..."

    # First check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "NTP server container is not running. Start it with: $0 start"
        return 1
    fi

    # Show chrony status from inside the container
    echo ""
    echo "=== NTP Server Internal Status ==="
    docker exec "${CONTAINER_NAME}" chronyc tracking 2>/dev/null || log_warn "Could not get chrony tracking info"
    echo ""

    # Test IPv4 connectivity
    echo "=== Testing IPv4 Connectivity (${NTP_IPV4}) ==="
    if ping -c 1 -W 2 "${NTP_IPV4}" &> /dev/null; then
        echo "  Ping: successful"
    else
        log_warn "  Ping: failed (macvlan network may not be reachable from host)"
    fi

    # Try various NTP test methods
    if command -v ntpdate &> /dev/null; then
        echo "  NTP query (ntpdate):"
        ntpdate -q "${NTP_IPV4}" 2>&1 | sed 's/^/    /' || true
    elif command -v sntp &> /dev/null; then
        echo "  NTP query (sntp):"
        sntp "${NTP_IPV4}" 2>&1 | sed 's/^/    /' || true
    elif command -v ntpq &> /dev/null; then
        echo "  NTP query (ntpq):"
        timeout 5 ntpq -p "${NTP_IPV4}" 2>&1 | sed 's/^/    /' || echo "    Query timed out or failed"
    else
        echo "  No NTP client tools found (ntpdate, sntp, ntpq)"
        echo "  Install with: sudo apt-get install ntpdate"
    fi

    # Test IPv6 connectivity
    echo ""
    echo "=== Testing IPv6 Connectivity (${NTP_IPV6}) ==="
    if ping6 -c 1 -W 2 "${NTP_IPV6}" &> /dev/null; then
        echo "  Ping: successful"
    else
        log_warn "  Ping: failed (macvlan network may not be reachable from host)"
    fi

    # Note about macvlan limitation
    echo ""
    echo "=== Notes ==="
    echo "  - Macvlan networks are not directly reachable from the host by design"
    echo "  - The NTP server IS reachable from VMs/containers on the br1 network"
    echo "  - To test from a DUT: ping6 ${NTP_IPV6} && chronyc sources"
}

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start     Build image and start NTP server container"
    echo "  stop      Stop and remove NTP server container"
    echo "  restart   Restart NTP server container"
    echo "  status    Show NTP server status"
    echo "  test      Test NTP server connectivity"
    echo "  clean     Stop container, remove network and image"
    echo "  help      Show this help message"
    echo ""
    echo "NTP Server Configuration:"
    echo "  IPv4: ${NTP_IPV4}/${NTP_IPV4_PREFIX}"
    echo "  IPv6: ${NTP_IPV6}/${NTP_IPV6_PREFIX}"
    echo "  Bridge: ${MGMT_BRIDGE}"
    echo ""
}

# Main
case "${1:-}" in
    start)
        check_prerequisites
        build_image
        create_network
        start_container
        echo ""
        show_status
        echo ""
        log_info "NTP server is ready. DUTs can sync time using:"
        log_info "  IPv4: ${NTP_IPV4}"
        log_info "  IPv6: ${NTP_IPV6}"
        ;;
    stop)
        stop_container
        ;;
    restart)
        stop_container
        start_container
        ;;
    status)
        show_status
        ;;
    test)
        test_ntp
        ;;
    clean)
        stop_container
        remove_network
        log_info "Removing Docker image..."
        docker rmi "${IMAGE_NAME}" 2>/dev/null || true
        log_info "Cleanup complete."
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        if [[ -n "${1:-}" ]]; then
            log_error "Unknown command: $1"
            echo ""
        fi
        usage
        exit 1
        ;;
esac
