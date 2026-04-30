#!/bin/bash

# Unified QoS Test Runner
# Location: /ws/shbhatna-rtp/public/run_test.sh
#
# Usage:
#   ./run_test.sh --platform <name> --yaml <path> <test_file>  # Run specific test
#   ./run_test.sh --platform <name> --yaml <path> full         # Run all QoS tests
#   ./run_test.sh --platform <name> --yaml <path> --env KEY=VAL <test_file>
#
# Container auto-setup: if the container for the user is not running,
# the script loads the docker image (if needed) and starts the container.

set -euo pipefail

# ── Platform registry ─────────────────────────────────────────────────────
# Each platform defines: docker image, tar path, container name, test base path
declare -A PLAT_IMAGE PLAT_TAR PLAT_CONTAINER PLAT_TEST_PATH

_USER="${USER:-$(whoami)}"

PLAT_IMAGE[tortuga]="docker.io/library/ixia-container.10.25:latest"
PLAT_TAR[tortuga]="/ws/shbhatna-rtp/public/ixia-container.10.25.tar.gz"
PLAT_CONTAINER[tortuga]="ixia_10.25_${_USER}"
PLAT_TEST_PATH[tortuga]="/data/tests/cisco/tortuga/qos"

PLAT_IMAGE[gamut]="localhost/spytest/keysight-u18:11.00"
PLAT_TAR[gamut]="/ws/shbhatna-rtp/public/keysight_11.00.tar.gz"
PLAT_CONTAINER[gamut]="keysight_11.00_${_USER}"
PLAT_TEST_PATH[gamut]="/data/tests/cisco/tortuga/qos"

PLAT_IMAGE[oci]="localhost/ixia_11.10_rev2:latest"
PLAT_TAR[oci]="/ws/shbhatna-rtp/public/ixia-11.10-rev2.tar.gz"
PLAT_CONTAINER[oci]="ixia_11.10_${_USER}"
PLAT_TEST_PATH[oci]="/data/tests/cisco/qos"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────

is_inside_container() {
    [ -f "/.dockerenv" ] || [ -f "/run/.containerenv" ]
}

check_container_environment() {
    if [ ! -d "$TEST_PATH" ]; then
        echo -e "${RED}Error: /data not properly mounted or test path missing: $TEST_PATH${NC}"
        exit 1
    fi
    [[ "$PWD" != "/data" ]] && cd /data
}

check_spytest_directory() {
    if [ ! -d "bin" ] || [ ! -d "tests" ]; then
        echo -e "${RED}Error: Not in a spytest directory (missing bin/ or tests/)${NC}"
        echo "Run this from your sonic-mgmt/spytest or oci-sonic-mgmt/spytest directory."
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 --platform <name> --yaml <path> <command> [args]"
    echo ""
    echo "Platforms: tortuga, gamut, oci"
    echo ""
    echo "Commands:"
    echo "  <test_file>     Run specific test (e.g., test_ecn.py, test_dwrr.py)"
    echo "  full            Run all QoS tests"
    echo ""
    echo "Options:"
    echo "  --platform <name>   Platform name (required)"
    echo "  --yaml <path>       Testbed YAML file (required)"
    echo "  --env KEY=VAL       Pass environment variable to container (repeatable)
  --logs-dir <path>   Custom directory for run logs (default: auto-generated)"
    echo ""
    echo "Container is auto-started if not running."
    echo ""
    echo "NOTE: Run this script from the spytest directory of your repo, e.g.:"
    echo "  cd /path/to/sonic-test/sonic-mgmt/spytest && run_test.sh ..."
    echo ""
    echo "Examples:"
    echo "  $0 --platform tortuga --yaml /path/to/tb.yaml test_dwrr.py"
    echo "  $0 --platform gamut --yaml /path/to/tb.yaml full"
    echo "  $0 --platform oci --yaml /path/to/tb.yaml full"
    echo "  $0 --platform oci --yaml /path/to/tb.yaml --env input_file=/data/tests/cisco/input_file/rocev2_input_file.yaml test_ecn.py
  $0 --platform tortuga --yaml /path/to/tb.yaml --logs-dir /data/my_logs test_dwrr.py"
}

do_setup() {
    check_spytest_directory

    echo -e "${GREEN}Auto-setup: ensuring container for platform: $PLATFORM${NC}"
    echo "  Image:     $DOCKER_IMAGE"
    echo "  Container: $CONTAINER_NAME"

    # Copy this script into spytest dir so it's available at /data inside container
    SCRIPT_SOURCE="/ws/shbhatna-rtp/public/run_test.sh"
    if [ -f "$SCRIPT_SOURCE" ]; then
        cp "$SCRIPT_SOURCE" ./run_test.sh
        chmod +x ./run_test.sh
    fi

    # Copy testbed YAML into spytest dir
    if [ -n "$TESTBED_YAML" ]; then
        local YAML_FULL=$(realpath "$TESTBED_YAML" 2>/dev/null || echo "$TESTBED_YAML")
        if [ -f "$YAML_FULL" ]; then
            local YAML_BASE=$(basename "$YAML_FULL")
            cp "$YAML_FULL" "./$YAML_BASE"
            echo "Copied $YAML_BASE to spytest directory"
        fi
    fi

    # Load docker image if needed
    if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
        if [ ! -f "$DOCKER_IMAGE_TAR" ]; then
            echo -e "${RED}Error: Docker tar not found: $DOCKER_IMAGE_TAR${NC}"
            exit 1
        fi
        echo "Loading docker image from $DOCKER_IMAGE_TAR..."
        TMPDIR="${TMPDIR:-/tmp}" docker load -i "$DOCKER_IMAGE_TAR"
        [[ $? -ne 0 ]] && { echo -e "${RED}Failed to load docker image${NC}"; exit 1; }
        echo -e "${GREEN}Image loaded successfully${NC}"
    else
        echo "Docker image already loaded: $DOCKER_IMAGE"
    fi

    # Start container if not running
    # Check if existing container has the correct mount point
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        local MOUNTED_SRC
        MOUNTED_SRC=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
        if [[ "$MOUNTED_SRC" != "$PWD" ]]; then
            echo -e "${RED}ERROR: Container '$CONTAINER_NAME' is mounted to a different directory${NC}"
            echo -e "  Container mount: $MOUNTED_SRC"
            echo -e "  Current dir:     $PWD"
            echo ""
            echo "Either run from the correct directory:"
            echo "  cd $MOUNTED_SRC"
            echo "Or remove the container and re-run:"
            echo "  docker rm -f $CONTAINER_NAME"
            exit 1
        else
            echo "Container '$CONTAINER_NAME' is already running (mount OK)."
        fi
    elif docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        local MOUNTED_SRC
        MOUNTED_SRC=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
        if [[ "$MOUNTED_SRC" != "$PWD" ]]; then
            echo -e "${RED}ERROR: Stopped container '$CONTAINER_NAME' is mounted to a different directory${NC}"
            echo -e "  Container mount: $MOUNTED_SRC"
            echo -e "  Current dir:     $PWD"
            echo ""
            echo "Either run from the correct directory:"
            echo "  cd $MOUNTED_SRC"
            echo "Or remove the container and re-run:"
            echo "  docker rm -f $CONTAINER_NAME"
            exit 1
        else
            echo "Starting stopped container '$CONTAINER_NAME'..."
            docker start "$CONTAINER_NAME"
        fi
    else
        echo "Creating and starting new container..."
        docker run -v "$PWD:/data" --name "$CONTAINER_NAME" -id "$DOCKER_IMAGE" /bin/bash
        [[ $? -ne 0 ]] && { echo -e "${RED}Failed to start container${NC}"; exit 1; }
        echo -e "${GREEN}Container started successfully${NC}"
    fi
}

run_tests() {
    local RUN_TEST_PATH="$1"

    # If outside container, auto-setup and exec into it
    if ! is_inside_container; then
        # Ensure container is running (auto-setup)
        if ! docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
            echo -e "${YELLOW}Container '$CONTAINER_NAME' not running — auto-starting...${NC}"
            do_setup
        fi

        # Verify mount point matches current directory
        local MOUNTED_SRC
        MOUNTED_SRC=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
        if [[ "$MOUNTED_SRC" != "$PWD" ]]; then
            echo -e "${RED}ERROR: Container '$CONTAINER_NAME' is mounted to a different directory${NC}"
            echo -e "  Container mount: $MOUNTED_SRC"
            echo -e "  Current dir:     $PWD"
            echo ""
            echo "Either run from the correct directory:"
            echo "  cd $MOUNTED_SRC"
            echo "Or remove the container and re-run:"
            echo "  docker rm -f $CONTAINER_NAME"
            exit 1
        fi

        echo "Executing test inside container '$CONTAINER_NAME'..."

        # Always copy run_test.sh into the container
        docker cp /ws/shbhatna-rtp/public/run_test.sh "$CONTAINER_NAME:/data/run_test.sh"

        # Copy testbed YAML into container
            local TB_BASE=$(basename "$TESTBED_YAML")
            local TB_FULL=$(realpath "$TESTBED_YAML" 2>/dev/null || echo "$TESTBED_YAML")
            if [ -f "$TB_FULL" ]; then
                docker cp "$TB_FULL" "$CONTAINER_NAME:/data/$TB_BASE"
            else
                echo -e "${RED}Error: Testbed YAML not found: $TESTBED_YAML${NC}"
                exit 1
            fi

            local LOGS_DIR_ARG=""
            [[ -n "$LOGS_DIR" ]] && LOGS_DIR_ARG="--logs-dir $LOGS_DIR"

            docker exec -i "${ENV_ARGS[@]}" "$CONTAINER_NAME" \
                bash /data/run_test.sh --platform "$PLATFORM" --yaml "/data/$TB_BASE" $LOGS_DIR_ARG "$COMMAND"
            return $?
    fi

    # Inside container
    check_container_environment

    # Resolve testbed YAML inside container
    if [ -f "$TESTBED_YAML" ]; then
        local TB_BASE=$(basename "$TESTBED_YAML")
        local TB_DEST="/data/$TB_BASE"
        if [[ "$(realpath "$TESTBED_YAML" 2>/dev/null)" != "$(realpath "$TB_DEST" 2>/dev/null)" ]]; then
            cp "$TESTBED_YAML" "$TB_DEST"
        fi
        TESTBED_YAML="$TB_DEST"
    elif [ -f "/data/$TESTBED_YAML" ]; then
        TESTBED_YAML="/data/$TESTBED_YAML"
    elif [ -f "/data/$(basename "$TESTBED_YAML")" ]; then
        TESTBED_YAML="/data/$(basename "$TESTBED_YAML")"
    else
        echo -e "${RED}Error: Testbed YAML not found: $TESTBED_YAML${NC}"
        exit 1
    fi

    # Build extra --env args for OCI
    local SPYTEST_EXTRA_ARGS=()
    if [[ "$PLATFORM" == "oci" ]]; then
        # OCI needs input_file and tb_cfg_file if not already passed via --env
        local HAS_INPUT_FILE=false
        for arg in "${ENV_ARGS[@]:-}"; do
            [[ "$arg" == *"input_file="* ]] && HAS_INPUT_FILE=true
        done
        if [[ "$HAS_INPUT_FILE" == "false" && -f "/data/tests/cisco/input_file/rocev2_input_file.yaml" ]]; then
            SPYTEST_EXTRA_ARGS+=(--env "input_file=/data/tests/cisco/input_file/rocev2_input_file.yaml")
            SPYTEST_EXTRA_ARGS+=(--env "tb_cfg_file=/data/tests/cisco/input_file/rocev2_input_file.yaml")
        fi
    fi

    local RUN_LOGS_DIR
    if [[ -n "$LOGS_DIR" ]]; then
        RUN_LOGS_DIR="$LOGS_DIR"
    else
        RUN_LOGS_DIR="/data/run_logs_${PLATFORM}_$(date '+%Y%m%d_%H%M%S')"
    fi
    mkdir -p "$RUN_LOGS_DIR"

    echo ""
    echo "Starting test run: $RUN_TEST_PATH"
    echo "Platform:  $PLATFORM"
    echo "Testbed:   $TESTBED_YAML"
    echo "Logs:      $RUN_LOGS_DIR"
    echo "========================================"

    bin/spytest \
        --testbed "$TESTBED_YAML" \
        --device-feature-group master \
        --module-init-max-timeout=99000 \
        --tc-max-timeout=99000 \
        "$RUN_TEST_PATH" \
        --skip-init-checks \
        --skip-init-config \
        --logs-path "$RUN_LOGS_DIR" \
        --port-init-wait 10 \
        "${SPYTEST_EXTRA_ARGS[@]}"
}

# ── Parse args ────────────────────────────────────────────────────────────
PLATFORM=""
TESTBED_YAML=""
LOGS_DIR=""
ENV_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --yaml)     TESTBED_YAML="$2"; shift 2 ;;
        --logs-dir) LOGS_DIR="$2"; shift 2 ;;
        --env)      ENV_ARGS+=(-e "$2"); export "$2"; shift 2 ;;
        -h|--help)  show_usage; exit 0 ;;
        *)          break ;;
    esac
done

[[ -z "$PLATFORM" ]] && { show_usage; echo -e "\n${RED}Error: --platform is required${NC}"; exit 1; }
[[ -z "${PLAT_IMAGE[$PLATFORM]:-}" ]] && { echo -e "${RED}Unknown platform: $PLATFORM (valid: tortuga gamut oci)${NC}"; exit 1; }

# Resolve platform config
DOCKER_IMAGE="${PLAT_IMAGE[$PLATFORM]}"
DOCKER_IMAGE_TAR="${PLAT_TAR[$PLATFORM]}"
CONTAINER_NAME="${PLAT_CONTAINER[$PLATFORM]}"
TEST_PATH="${PLAT_TEST_PATH[$PLATFORM]}"

[[ $# -lt 1 ]] && { show_usage; exit 0; }
COMMAND="$1"

case "$COMMAND" in
    full)
        [[ -z "$TESTBED_YAML" ]] && { echo -e "${RED}Error: --yaml is required${NC}"; exit 1; }
        run_tests "$TEST_PATH/"
        ;;
    -h|--help|help)
        show_usage
        ;;
    *)
        [[ -z "$TESTBED_YAML" ]] && { echo -e "${RED}Error: --yaml is required${NC}"; exit 1; }
        run_tests "$TEST_PATH/$COMMAND"
        ;;
esac
