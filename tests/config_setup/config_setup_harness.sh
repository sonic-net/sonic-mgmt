!/bin/bash
set -e

HARNESS_DIR="/tmp/config_setup_test"
ACTION_LOG="${HARNESS_DIR}/actions.log"
> "${ACTION_LOG}"

# Parse test parameters
TEST_FUNC="$1"
FAKE_CONFIG_DB_EXISTS="$2"
FAKE_MINIGRAPH_EXISTS="$3"
FAKE_ZTP_ENABLED="$4"
FAKE_WARM_BOOT="$5"
FAKE_PENDING_MIGRATION="$6"

# Set up fake filesystem paths
FAKE_ROOT="${HARNESS_DIR}/fake_root"
rm -rf "${FAKE_ROOT}"
mkdir -p "${FAKE_ROOT}/etc/sonic"
mkdir -p "${FAKE_ROOT}/tmp"

# --- Step 1: Extract functions from the DUT's actual config-setup script ---
# We cannot source config-setup directly because it has an execution block
# at the bottom. Instead, extract everything up to "### Execution starts
# here ###" (or the first non-function line after all function defs).
EXTRACTED="${HARNESS_DIR}/config_setup_functions.sh"
sed -n '1,/^### Execution starts here ###/p' \
    /usr/bin/config-setup | head -n -1 > "${EXTRACTED}"

# Detect where the DUT's config-setup stores pending_config_migration.
# Older builds use /tmp/pending_config_migration; newer builds (after
# sonic-buildimage PR #25215, fixing issue #25202) use
# /etc/sonic/pending_config_migration to survive reboots.
if grep -q '/etc/sonic/pending_config_migration' "${EXTRACTED}"; then
    PENDING_DIR="/etc/sonic"
else
    PENDING_DIR="/tmp"
fi
echo "Detected pending_config dir: ${PENDING_DIR}"

# Create fake files based on test parameters
if [ "$FAKE_CONFIG_DB_EXISTS" = "true" ]; then
    echo '{}' > "${FAKE_ROOT}/etc/sonic/config_db.json"
fi
if [ "$FAKE_MINIGRAPH_EXISTS" = "true" ]; then
    echo '<fake/>' > "${FAKE_ROOT}/etc/sonic/minigraph.xml"
fi
if [ "$FAKE_PENDING_MIGRATION" = "true" ]; then
    touch "${FAKE_ROOT}${PENDING_DIR}/pending_config_migration"
fi

# Rewrite hardcoded paths in the extracted script to use our fake root.
# Handle both /tmp/ and /etc/sonic/ locations — only the matching sed
# will have effect; the other is a harmless no-op.
sed -i "s|/etc/sonic/pending_config_migration|${FAKE_ROOT}${PENDING_DIR}/pending_config_migration|g" \
    "${EXTRACTED}"
sed -i "s|/etc/sonic/pending_config_initialization|${FAKE_ROOT}${PENDING_DIR}/pending_config_initialization|g" \
    "${EXTRACTED}"
sed -i "s|/tmp/pending_config_migration|${FAKE_ROOT}${PENDING_DIR}/pending_config_migration|g" \
    "${EXTRACTED}"
sed -i "s|/tmp/pending_config_initialization|${FAKE_ROOT}${PENDING_DIR}/pending_config_initialization|g" \
    "${EXTRACTED}"
sed -i "s|/tmp/pending_ztp_restart|${FAKE_ROOT}/tmp/pending_ztp_restart|g" \
    "${EXTRACTED}"

# Source the extracted functions — this gives us the DUT's real
# do_config_initialization(), boot_config(), check_system_warm_boot(),
# do_config_migration(), and all other functions as installed on the DUT.
source "${EXTRACTED}"

# --- Step 2: Override constants to use fake paths ---
# These must come AFTER sourcing so they replace the real paths.
CONFIG_DB_JSON="${FAKE_ROOT}/etc/sonic/config_db.json"
# config-setup uses MINGRAPH_FILE (legacy spelling); set both for safety.
MINGRAPH_FILE="${FAKE_ROOT}/etc/sonic/minigraph.xml"
MINIGRAPH_FILE="${FAKE_ROOT}/etc/sonic/minigraph.xml"
TMP_ZTP_CONFIG_DB_JSON="${FAKE_ROOT}/tmp/ztp_config_db.json"
CONFIG_SETUP_VAR_DIR="${FAKE_ROOT}/var/lib/config-setup"
CONFIG_SETUP_POST_MIGRATION_FLAG="${CONFIG_SETUP_VAR_DIR}/pending_post_migration"
CONFIG_SETUP_INITIALIZATION_FLAG="${CONFIG_SETUP_VAR_DIR}/pending_initialization"
CONFIG_POST_MIGRATION_HOOKS="${FAKE_ROOT}/etc/config-setup/config-migration-post-hooks.d"
FACTORY_DEFAULT_HOOKS="${FAKE_ROOT}/etc/config-setup/factory-default-hooks.d"
NUM_ASIC=1
CMD="boot"

# --- Step 3: Override destructive/external commands with safe stubs ---
# These MUST come AFTER sourcing the extracted functions so our stubs
# replace the real implementations of commands that have side effects.

reload_minigraph() {
    echo "ACTION: reload_minigraph" >> "${ACTION_LOG}"
    echo "Reloading minigraph..."
}

reload_configdb() {
    echo "ACTION: reload_configdb $1" >> "${ACTION_LOG}"
    echo "Reloading existing config db..."
}

generate_config() {
    echo "ACTION: generate_config $1 $2" >> "${ACTION_LOG}"
    if [ "$1" = "factory" ]; then
        echo '{}' > "$2"
    elif [ "$1" = "ztp" ]; then
        echo '{}' > "$2"
    fi
}

apply_tacacs() { :; }

config() {
    echo "ACTION: config $*" >> "${ACTION_LOG}"
}

do_db_migration() {
    echo "ACTION: do_db_migration" >> "${ACTION_LOG}"
}

ztp() {
    if [ "$1" = "status" ] && [ "$2" = "-c" ]; then
        if [ "$FAKE_ZTP_ENABLED" = "true" ]; then
            echo "3:IN-PROGRESS"
        else
            echo "0:DISABLED"
        fi
    elif [ "$1" = "erase" ]; then
        echo "ACTION: ztp erase" >> "${ACTION_LOG}"
    fi
}

sonic-db-cli() {
    if [ "$1" = "STATE_DB" ] && [ "$2" = "hget" ]; then
        if [ "$3" = "WARM_RESTART_ENABLE_TABLE|system" ] && \
           [ "$4" = "enable" ]; then
            echo "$FAKE_WARM_BOOT"
            return 0
        fi
    elif [ "$1" = "CONFIG_DB" ] && [ "$2" = "SET" ]; then
        echo "ACTION: sonic-db-cli CONFIG_DB SET $3 $4" >> "${ACTION_LOG}"
    elif [ "$1" = "CONFIG_DB" ] && [ "$2" = "HGET" ]; then
        echo ""
    fi
    return 0
}

# Override /proc/cmdline reads for warm boot detection.
# With DB-first logic, this is only consulted when DB is unavailable
# (early boot). The harness stub returns rc=0 so DB is always used,
# but we keep this override for completeness.
cat() {
    if [ "$1" = "/proc/cmdline" ]; then
        if [ "$FAKE_WARM_BOOT" = "true" ]; then
            echo "BOOT_IMAGE=/image SONIC_BOOT_TYPE=warm"
        else
            echo "BOOT_IMAGE=/image"
        fi
    else
        command cat "$@"
    fi
}

ztp_is_enabled() {
    if [ "$FAKE_ZTP_ENABLED" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Stub helpers that depend on real filesystem or services
run_hookdir() { :; }
copy_config_files_and_directories() { :; }
copy_post_migration_hooks() { :; }
get_config_db_file_list() { echo "config_db.json"; }
check_all_config_db_present() {
    [ -r "${CONFIG_DB_JSON}" ]
}

# --- Step 4: Re-source the functions under test ---
# The functions under test (do_config_initialization, boot_config, etc.)
# were sourced in Step 1 from the DUT. However, they reference variables
# and call functions that we just overrode in Steps 2-3. Since bash
# functions capture code, not variable values, the DUT's functions will
# use our fake paths and stub commands at call time.
#
# check_system_warm_boot() uses DB-first logic: it calls sonic-db-cli
# (our stub returns rc=0) so STATE_DB is always used. The /proc/cmdline
# fallback only activates when DB is unavailable AND CMD="boot".
#
# The key functions under test come directly from the DUT's config-setup.
# We do NOT redefine them here — that's the whole point.

# --- Step 5: Run the requested function ---
echo "=== TEST: $TEST_FUNC ==="
echo "  config_db=$FAKE_CONFIG_DB_EXISTS minigraph=$FAKE_MINIGRAPH_EXISTS"
echo "  ztp=$FAKE_ZTP_ENABLED warm=$FAKE_WARM_BOOT migration=$FAKE_PENDING_MIGRATION"
echo "=== OUTPUT ==="

# Some DUT functions use "exit 0" instead of "return 0" (e.g.,
# do_config_migration warm boot path). Run in a subshell so exit
# does not kill the harness, then always print actions and state.
set +e
(
    $TEST_FUNC
)
FUNC_RC=$?
set -e

echo "=== ACTIONS ==="
command cat "${ACTION_LOG}" 2>/dev/null || echo "(none)"

# Report state
echo "=== STATE ==="
if [ -e "${FAKE_ROOT}/tmp/pending_ztp_restart" ]; then
    echo "pending_ztp_restart=true"
else
    echo "pending_ztp_restart=false"
fi
if [ -e "${CONFIG_DB_JSON}" ]; then
    echo "config_db_exists=true"
else
    echo "config_db_exists=false"
fi
exit $FUNC_RC
