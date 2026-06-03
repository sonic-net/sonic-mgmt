#!/bin/bash

# Unified QoS Test Runner
#
# Usage:
#   ./run_test.sh --testbed <ID> <test_file>         # Run specific test
#   ./run_test.sh --testbed <ID> full                 # Run all QoS tests
#   ./run_test.sh --testbed <ID> --env KEY=VAL <test_file>
#
# Container auto-setup: if the container for the user is not running,
# the script loads the docker image (if needed) and starts the container.
#
# All testbed-specific config (docker image, test path, etc.) is looked up
# from testbed_config.py using the YAML filename.

set -euo pipefail

# Get script directory (works even if script is sourced or symlinked)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_USER="${USER:-$(whoami)}"

# ── Read config from testbed_config.py ─────────────────────────────────────
# Given a YAML filename, prints shell-eval-able variables:
#   TB_DOCKER_IMAGE, TB_DOCKER_TAR, TB_CONTAINER_PREFIX, TB_TEST_PATH,
#   TB_RUNNER_PLATFORM, TB_INPUT_FILE, TB_PROFILE_SUFFIX
read_tb_config() {
    local yaml_file="$1"
    local yaml_basename
    yaml_basename="$(basename "$yaml_file")"
    python3 - "$yaml_basename" "$SCRIPT_DIR" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[2])
from testbed_config import get_config
cfg = get_config(sys.argv[1])
if not cfg:
    print(f"ERROR: Unknown testbed YAML: {sys.argv[1]}", file=sys.stderr)
    sys.exit(1)
for key in ("docker_image", "docker_tar", "container_prefix", "test_path",
            "runner_platform", "input_file", "profile_suffix"):
    print(f"TB_{key.upper()}={cfg[key]}")
PYEOF
}

# Read container server config from testbed_config.py
read_container_server() {
    python3 - "$SCRIPT_DIR" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from testbed_config import CONTAINER_SERVER
for key in ("host", "user", "password", "path"):
    print(f"CS_{key.upper()}={CONTAINER_SERVER[key]}")
PYEOF
}

# Fetch docker tar from container server if not cached locally
# Usage: fetch_docker_tar <tar_filename>
# Sets DOCKER_IMAGE_TAR to the local path
fetch_docker_tar() {
    local tar_name="$1"
    local cache_dir="${PWD}/.containers"
    local local_tar="${cache_dir}/${tar_name}"
    DOCKER_IMAGE_TAR="$local_tar"

    if [ -f "$local_tar" ]; then
        echo "Container tar cached: $local_tar"
        return 0
    fi

    echo "Fetching container tar from server..."
    mkdir -p "$cache_dir"

    # Read server config
    local CS_OUTPUT
    CS_OUTPUT=$(read_container_server) || { echo -e "${RED}Failed to read container server config${NC}"; exit 1; }
    eval "$CS_OUTPUT"

    local remote_path="${CS_PATH}/${tar_name}"
    echo "  SCP: ${CS_USER}@${CS_HOST}:${remote_path} -> ${local_tar}"
    sshpass -p "$CS_PASSWORD" scp -o StrictHostKeyChecking=no \
        "${CS_USER}@${CS_HOST}:${remote_path}" "$local_tar"
    if [[ $? -ne 0 ]]; then
        rm -f "$local_tar"
        echo -e "${RED}Failed to fetch container tar from server${NC}"
        exit 1
    fi
    echo -e "${GREEN}Container tar downloaded to: ${local_tar}${NC}"
}

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
    echo "Usage: $0 --testbed <ID> <command> [args]"
    echo ""
    echo "Commands:"
    echo "  <test_file>     Run specific test (path relative to qos/, e.g., ecn/test_v6_ecn_marking_l2_1node.py)"
    echo "  full            Run all QoS tests"
    echo ""
    echo "Options:"
    echo "  --testbed <ID>      Testbed ID (see below)"
    echo "  --env KEY=VAL       Pass environment variable to container (repeatable)"
    echo "  --logs-dir <path>   Custom directory for run logs (default: auto-generated)"
    echo ""
    echo "Testbed IDs:"
    echo "  10000 = carib/siren (tortuga_2x2_Q200_testbed.yaml)"
    echo "  10001 = laguna     (tortuga_2x2_G200_testbed.yaml)"
    echo "  10002 = gamut      (gamut_2x2_qos.yaml)"
    echo "  10003 = OCI        (rocev2_testbed.yaml)"
    echo ""
    echo "Examples:"
    echo "  $0 --testbed 10002 full"
    echo "  $0 --testbed 10001 scheduler/test_v4_dwrr_1node.py"
    echo "  $0 --testbed 10003 full"
}

do_setup() {
    check_spytest_directory

    echo -e "${GREEN}Auto-setup: ensuring container${NC}"
    echo "  Image:     $DOCKER_IMAGE"
    echo "  Container: $CONTAINER_NAME"

    # Copy this script and testbed_config.py into spytest dir so they're at /data inside container
    SCRIPT_SOURCE="${SCRIPT_DIR}/run_test.sh"
    if [ -f "$SCRIPT_SOURCE" ]; then
        cp "$SCRIPT_SOURCE" ./run_test.sh
        chmod +x ./run_test.sh
    fi
    if [ -f "${SCRIPT_DIR}/testbed_config.py" ]; then
        cp "${SCRIPT_DIR}/testbed_config.py" ./testbed_config.py
    fi

    # Copy testbed YAML into spytest dir so it's visible at /data/ inside container
    if [ -n "$TESTBED_YAML" ]; then
        local YAML_BASE=$(basename "$TESTBED_YAML")
        cp "$TESTBED_YAML" "./$YAML_BASE"
    fi

    # Load docker image if needed
    if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
        # Fetch tar from server if not cached locally
        fetch_docker_tar "$DOCKER_IMAGE_TAR"
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
    local RUN_TEST_PATHS=("$@")

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

        # Always copy run_test.sh and testbed_config.py into the container
        docker cp "${SCRIPT_DIR}/run_test.sh" "$CONTAINER_NAME:/data/run_test.sh"
        docker cp "${SCRIPT_DIR}/testbed_config.py" "$CONTAINER_NAME:/data/testbed_config.py"

        # Copy testbed YAML into container
            local TB_BASE=$(basename "$TESTBED_YAML")
            local TB_FULL=$(realpath "$TESTBED_YAML" 2>/dev/null || echo "$TESTBED_YAML")
            if [ -f "$TB_FULL" ]; then
                docker cp "$TB_FULL" "$CONTAINER_NAME:/data/$TB_BASE"
            else
                echo -e "${RED}Error: Testbed YAML not found: $TESTBED_YAML${NC}"
                exit 1
            fi

            # Pre-create logs directory on host (so it's owned by user, not root)
            local LOGS_DIR_ARG=""
            if [[ -n "$LOGS_DIR" ]]; then
                mkdir -p "$PWD/$LOGS_DIR" 2>/dev/null || mkdir -p "$LOGS_DIR"
                LOGS_DIR_ARG="--logs-dir $LOGS_DIR"
            else
                local AUTO_LOGS_DIR="run_logs_${PROFILE_SUFFIX_LC}_$(date '+%Y%m%d_%H%M%S')"
                mkdir -p "$PWD/$AUTO_LOGS_DIR"
                LOGS_DIR_ARG="--logs-dir /data/$AUTO_LOGS_DIR"
            fi

            docker exec "${ENV_ARGS[@]}" "$CONTAINER_NAME" \
                bash /data/run_test.sh --yaml "/data/$TB_BASE" $LOGS_DIR_ARG "${RUN_TEST_PATHS[@]}" < /dev/null
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

    # Build extra --env args if input_file is configured for this testbed
    local SPYTEST_EXTRA_ARGS=()
    if [[ -n "$INPUT_FILE" ]]; then
        # Check if input_file was already passed via --env
        local HAS_INPUT_FILE=false
        for arg in "${ENV_ARGS[@]:-}"; do
            [[ "$arg" == *"input_file="* ]] && HAS_INPUT_FILE=true
        done
        if [[ "$HAS_INPUT_FILE" == "false" && -f "$INPUT_FILE" ]]; then
            SPYTEST_EXTRA_ARGS+=(--env "input_file=$INPUT_FILE")
            SPYTEST_EXTRA_ARGS+=(--env "tb_cfg_file=$INPUT_FILE")
        fi
    fi

    local RUN_LOGS_DIR
    if [[ -n "$LOGS_DIR" ]]; then
        RUN_LOGS_DIR="$LOGS_DIR"
    else
        RUN_LOGS_DIR="/data/run_logs_${PROFILE_SUFFIX_LC}_$(date '+%Y%m%d_%H%M%S')"
    fi
    mkdir -p "$RUN_LOGS_DIR"
    # Make logs directory writable for non-root users (container runs as root)
    chmod 777 "$RUN_LOGS_DIR"

    echo ""
    echo "Starting test run: ${RUN_TEST_PATHS[*]}"
    echo "Testbed:   $TESTBED_YAML"
    echo "Logs:      $RUN_LOGS_DIR"
    echo "========================================"

    bin/spytest \
        --testbed "$TESTBED_YAML" \
        --device-feature-group master \
        --module-init-max-timeout=99000 \
        --tc-max-timeout=99000 \
        "${RUN_TEST_PATHS[@]}" \
        --skip-init-checks \
        --skip-init-config \
        --logs-path "$RUN_LOGS_DIR" \
        --port-init-wait 10 \
        "${SPYTEST_EXTRA_ARGS[@]}" || spytest_rc=$?

    # Make all log files accessible outside the container (spytest runs as root)
    chmod -R 777 "$RUN_LOGS_DIR" 2>/dev/null || true

    exit ${spytest_rc:-0}
}

# ── Parse args ────────────────────────────────────────────────────────────
TESTBED_YAML=""
LOGS_DIR=""
ENV_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --testbed)
            # Resolve integer ID to YAML path
            case "$2" in
                10000) TESTBED_YAML="tortuga_2x2_Q200_testbed.yaml" ;;
                10001) TESTBED_YAML="tortuga_2x2_G200_testbed.yaml" ;;
                10002) TESTBED_YAML="gamut_2x2_qos.yaml" ;;
                10003) TESTBED_YAML="rocev2_testbed.yaml" ;;
                *) echo -e "${RED}Unknown testbed ID: $2${NC}"
                   echo "Valid IDs: 10000=carib/siren, 10001=laguna, 10002=gamut, 10003=OCI"
                   exit 1 ;;
            esac
            # Always copy from the canonical source: <repo_root>/spytest_tb_files/
            _REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
            _TB_DIR="${_REPO_ROOT}/spytest_tb_files"
            if [[ ! -f "$_TB_DIR/$TESTBED_YAML" ]]; then
                echo -e "${RED}Cannot find $TESTBED_YAML in $_TB_DIR${NC}"
                exit 1
            fi
            TESTBED_YAML="$(realpath "$_TB_DIR/$TESTBED_YAML")"
            shift 2 ;;
        --yaml)     TESTBED_YAML="$2"; shift 2 ;;
        --logs-dir) LOGS_DIR="$2"; shift 2 ;;
        --env)      ENV_ARGS+=(-e "$2"); export "$2"; shift 2 ;;
        -h|--help)  show_usage; exit 0 ;;
        *)          break ;;
    esac
done

[[ -z "$TESTBED_YAML" ]] && { show_usage; echo -e "\n${RED}Error: --testbed is required${NC}"; exit 1; }

# Look up testbed config from YAML filename
TB_CONFIG_OUTPUT=$(read_tb_config "$TESTBED_YAML") || exit 1
eval "$TB_CONFIG_OUTPUT"

# Set runtime variables from config
DOCKER_IMAGE="$TB_DOCKER_IMAGE"
DOCKER_IMAGE_TAR="$TB_DOCKER_TAR"
CONTAINER_NAME="${TB_CONTAINER_PREFIX}_${_USER}"
TEST_PATH="$TB_TEST_PATH"
INPUT_FILE="$TB_INPUT_FILE"
PROFILE_SUFFIX_LC=$(echo "$TB_PROFILE_SUFFIX" | tr '[:upper:]' '[:lower:]')

# ── Testbed reservation check ──
# Only check outside container (inside = already verified)
if ! is_inside_container 2>/dev/null; then
    YAML_BASE=$(basename "$TESTBED_YAML")
    if ! LOCK_MSG=$(python3 "$SCRIPT_DIR/testbed.py" --yaml "$YAML_BASE" --check 2>&1); then
        echo -e "${RED}✗  No valid reservation for $YAML_BASE${NC}"
        echo -e "${RED}   $LOCK_MSG${NC}"
        echo -e "${RED}   Reserve first: ./testbed.py --testbed <ID> --reserve <HOURS> --note '...'${NC}"
        exit 1
    fi
fi

[[ $# -lt 1 ]] && { show_usage; exit 0; }

# Collect all remaining args as test files
COMMAND="$1"
shift

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
        # Build test paths: handle space-separated tests in COMMAND plus any additional args.
        # Once we encounter a flag (arg starting with '-'), forward it AND all remaining args
        # verbatim to spytest/pytest (handles things like: -k "expr", -m mark, --collect-only).
        TEST_FILES=()
        EXTRA_ARGS=()
        passthrough=0
        for t in $COMMAND "$@"; do
            [[ -z "$t" ]] && continue
            if [[ "$passthrough" -eq 1 ]]; then
                EXTRA_ARGS+=("$t")
                continue
            fi
            if [[ "$t" == -* ]]; then
                passthrough=1
                EXTRA_ARGS+=("$t")
            elif [[ "$t" == /* ]]; then
                TEST_FILES+=("$t")
            elif [[ "$t" == */* ]]; then
                # Relative path with directory (e.g., pfc/test_v4_pfc_4stream_2x2.py)
                TEST_FILES+=("$TEST_PATH/$t")
            else
                echo -e "${RED}Error: '$t' is a bare filename.${NC}"
                echo -e "${RED}Specify path relative to qos/, e.g.: pfc/$t${NC}"
                exit 1
            fi
        done
        run_tests "${TEST_FILES[@]}" "${EXTRA_ARGS[@]}"
        ;;
esac
