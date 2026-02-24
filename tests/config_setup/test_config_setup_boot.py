"""
Tests for config-setup boot flow (non-destructive).

Validates that the config-setup script correctly handles boot scenarios
when config_db.json is absent, including minigraph.xml fallback, ZTP
behavior, and warm boot guards.

These tests address the bug reported in ADO 36697420:
    "[202511.08] Config Reload is Run during warm-boot up"

The fix is in sonic-buildimage PR #25463 which updates
files/image_config/config-setup/config-setup to:
1. Prefer minigraph.xml over ZTP/factory-default when config_db.json is missing
2. Use STATE_DB for warm boot detection (with /proc/cmdline fallback during early boot only)
3. Skip config initialization and ZTP entirely during warm boot

Config priority order (consistent across all code paths):
    config_db.json > minigraph.xml > ZTP > factory default

Test modes (--config_setup_test_mode):
    harness: Non-destructive test harness that stubs destructive commands
        and runs config-setup decision logic in isolation. Safe for physical
        DUTs — no config changes, no service restarts, no console needed.
    real: End-to-end test that deletes config_db.json and runs actual
        config-setup boot. Only safe on VS/KVM where mgmt IP loss is
        recoverable. Backs up and restores config_db.json via fixture.
    auto (default): Always uses 'harness'. Real mode requires explicit
        --config_setup_test_mode=real since it is destructive (deletes
        config_db.json, may lose management connectivity on KVM).

    Harness tests validate decision logic paths (7 test classes, 12 tests).
    Real tests validate end-to-end behavior (1 test class, 2 tests).
    Real tests only run with explicit --config_setup_test_mode=real.

Topology: any
"""

import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

CONFIG_SETUP_SCRIPT = "/usr/bin/config-setup"
CONFIG_DB_JSON = "/etc/sonic/config_db.json"
CONFIG_DB_BAK = "/etc/sonic/config_db.json.test_bak"
MINIGRAPH_FILE = "/etc/sonic/minigraph.xml"
HARNESS_DIR = "/tmp/config_setup_test"
HARNESS_SCRIPT = "{}/test_harness.sh".format(HARNESS_DIR)

# The test harness script that sources config-setup functions but overrides
# all destructive commands with logging stubs. It then calls the function
# under test and reports which code path was taken via echo statements.
#
# Arguments:
#   $1 - function to test: "do_config_initialization" or "boot_config"
#   $2 - whether config_db.json "exists": "true" or "false"
#   $3 - whether minigraph.xml "exists": "true" or "false"
#   $4 - whether ZTP is "enabled": "true" or "false"
#   $5 - whether warm boot is active: "true" or "false"
#   $6 - whether pending_config_migration exists: "true" or "false"
HARNESS_CONTENT = r'''#!/bin/bash
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

# Create fake files based on test parameters
if [ "$FAKE_CONFIG_DB_EXISTS" = "true" ]; then
    echo '{}' > "${FAKE_ROOT}/etc/sonic/config_db.json"
fi
if [ "$FAKE_MINIGRAPH_EXISTS" = "true" ]; then
    echo '<fake/>' > "${FAKE_ROOT}/etc/sonic/minigraph.xml"
fi
if [ "$FAKE_PENDING_MIGRATION" = "true" ]; then
    touch "${FAKE_ROOT}/tmp/pending_config_migration"
fi

# --- Step 1: Extract functions from the DUT's actual config-setup script ---
# We cannot source config-setup directly because it has an execution block
# at the bottom. Instead, extract everything up to "### Execution starts
# here ###" (or the first non-function line after all function defs).
EXTRACTED="${HARNESS_DIR}/config_setup_functions.sh"
sed -n '1,/^### Execution starts here ###/p' \
    /usr/bin/config-setup | head -n -1 > "${EXTRACTED}"

# Rewrite hardcoded paths in the extracted script to use our fake root.
# The DUT script uses /tmp/pending_* paths directly; redirect to fake root.
sed -i "s|/tmp/pending_config_migration|${FAKE_ROOT}/tmp/pending_config_migration|g" \
    "${EXTRACTED}"
sed -i "s|/tmp/pending_config_initialization|${FAKE_ROOT}/tmp/pending_config_initialization|g" \
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
'''


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def ztp_image(request):
    """Return True if the DUT image has ZTP enabled."""
    return request.config.getoption("--ztp_image", default=False)


@pytest.fixture(scope="module")
def test_mode(request, duthosts, rand_one_dut_hostname):
    """Determine whether to use 'harness' (mock) or 'real' (actual config-setup).

    'auto' (default) always selects 'harness'. Use --config_setup_test_mode=real
    to run destructive end-to-end tests (VS/KVM only).
    """
    mode = request.config.getoption("--config_setup_test_mode", default="auto")
    duthost = duthosts[rand_one_dut_hostname]
    is_vs = duthost.facts.get("asic_type", "") == "vs"

    if mode == "auto":
        resolved = "harness"
    else:
        resolved = mode

    logger.info("config-setup test mode: %s (requested=%s, is_vs=%s)", resolved, mode, is_vs)
    return resolved


@pytest.fixture(scope="module")
def harness(duthosts, rand_one_dut_hostname):
    """Deploy the test harness script to the DUT."""
    duthost = duthosts[rand_one_dut_hostname]

    duthost.shell("mkdir -p {}".format(HARNESS_DIR))
    duthost.copy(content=HARNESS_CONTENT, dest=HARNESS_SCRIPT)
    duthost.shell("chmod +x {}".format(HARNESS_SCRIPT))

    yield duthost

    # Cleanup
    duthost.shell("rm -rf {}".format(HARNESS_DIR), module_ignore_errors=True)


CONFIG_DB_BAK = "/etc/sonic/config_db.json.config_setup_test_bak"


@pytest.fixture(scope="function")
def real_dut(duthosts, rand_one_dut_hostname):
    """Provide the DUT with config_db.json backup/restore for real-mode tests.

    Backs up config_db.json before the test and restores it afterwards,
    including a config reload to recover the DUT to its original state.
    """
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Backing up %s to %s", CONFIG_DB_JSON, CONFIG_DB_BAK)
    duthost.shell("cp {} {}".format(CONFIG_DB_JSON, CONFIG_DB_BAK))

    yield duthost

    # Restore config_db.json and reload to recover
    logger.info("Restoring %s from %s", CONFIG_DB_JSON, CONFIG_DB_BAK)
    duthost.shell("cp {} {}".format(CONFIG_DB_BAK, CONFIG_DB_JSON),
                  module_ignore_errors=True)
    duthost.shell("rm -f {}".format(CONFIG_DB_BAK), module_ignore_errors=True)
    duthost.shell("config reload -y -f", module_ignore_errors=True)
    pytest_assert(
        wait_until(300, 20, 0, duthost.critical_services_fully_started),
        "Critical services did not start after config restore"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_harness(duthost, func, config_db="false", minigraph="false",
                ztp="false", warm="false", migration="false"):
    """Run the test harness with given parameters and return parsed results.

    Returns dict with keys: stdout, actions (list), pending_ztp_restart (bool),
    config_db_exists (bool).
    """
    cmd = 'bash {} {} {} {} {} {} {}'.format(
        HARNESS_SCRIPT, func, config_db, minigraph, ztp, warm, migration)
    result = duthost.shell(cmd, module_ignore_errors=True)

    stdout = result['stdout']
    logger.info("Harness output:\n%s", stdout)

    # Parse actions
    actions = []
    in_actions = False
    in_state = False
    state = {}
    for line in stdout.splitlines():
        if line.strip() == "=== ACTIONS ===":
            in_actions = True
            in_state = False
            continue
        if line.strip() == "=== STATE ===":
            in_actions = False
            in_state = True
            continue
        if line.startswith("=== "):
            in_actions = False
            in_state = False
            continue
        if in_actions and line.startswith("ACTION: "):
            actions.append(line.strip()[len("ACTION: "):])
        if in_state and "=" in line:
            k, v = line.strip().split("=", 1)
            state[k] = v

    return {
        'stdout': stdout,
        'rc': result['rc'],
        'actions': actions,
        'pending_ztp_restart': state.get('pending_ztp_restart', 'false') == 'true',
        'config_db_exists': state.get('config_db_exists', 'false') == 'true',
    }


def run_real_config_setup(duthost):
    """Run actual config-setup boot on the DUT and return output."""
    result = duthost.shell("sudo /usr/bin/config-setup boot",
                           module_ignore_errors=True)
    logger.info("config-setup boot stdout:\n%s", result['stdout'])
    if result['stderr']:
        logger.info("config-setup boot stderr:\n%s", result['stderr'])
    return result


def get_mgmt_ip(duthost):
    """Get the current management IP."""
    result = duthost.shell("ip -4 addr show eth0 | grep inet | awk '{print $2}'",
                           module_ignore_errors=True)
    return result['stdout'].strip()


def has_minigraph(duthost):
    """Check if minigraph.xml exists on the DUT."""
    result = duthost.shell("test -f {}".format(MINIGRAPH_FILE),
                           module_ignore_errors=True)
    return result['rc'] == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConfigInitMinigraphFallback:
    """Test do_config_initialization() prefers minigraph.xml over ZTP/factory default.

    This is the primary fix: when config_db.json is absent but minigraph.xml
    is present, do_config_initialization() should use reload_minigraph.
    """

    def test_minigraph_used_when_config_db_absent(self, harness):
        """Scenario A: no config_db, minigraph present → use minigraph."""
        result = run_harness(harness, "do_config_initialization",
                             config_db="false", minigraph="true", ztp="false")

        pytest_assert(result['rc'] == 0, "Harness failed: rc={}".format(result['rc']))
        pytest_assert(
            "reload_minigraph" in result['actions'],
            "Expected reload_minigraph but got actions: {}".format(result['actions'])
        )
        pytest_assert(
            not any("generate_config factory" in a for a in result['actions']),
            "Factory default should not be generated when minigraph is available"
        )

    def test_minigraph_used_over_ztp(self, harness):
        """Scenario A+ZTP: no config_db, minigraph present, ZTP enabled → use minigraph."""
        result = run_harness(harness, "do_config_initialization",
                             config_db="false", minigraph="true", ztp="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            "reload_minigraph" in result['actions'],
            "Expected reload_minigraph but got: {}".format(result['actions'])
        )
        pytest_assert(
            not any("generate_config ztp" in a for a in result['actions']),
            "ZTP should not be triggered when minigraph is available"
        )

    def test_config_db_initialized_set_after_minigraph(self, harness):
        """CONFIG_DB_INITIALIZED should be set after minigraph init."""
        result = run_harness(harness, "do_config_initialization",
                             config_db="false", minigraph="true", ztp="false")

        pytest_assert(
            any("CONFIG_DB_INITIALIZED" in a for a in result['actions']),
            "CONFIG_DB_INITIALIZED should be set after initialization"
        )


class TestConfigInitZTPRegression:
    """Test do_config_initialization() ZTP path still works when no minigraph."""

    def test_ztp_triggers_without_minigraph(self, harness):
        """Scenario B: no config_db, no minigraph, ZTP enabled → ZTP triggers."""
        result = run_harness(harness, "do_config_initialization",
                             config_db="false", minigraph="false", ztp="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            any("generate_config ztp" in a for a in result['actions']),
            "Expected ZTP config generation but got: {}".format(result['actions'])
        )
        pytest_assert(
            "reload_minigraph" not in result['actions'],
            "reload_minigraph should not be called when no minigraph exists"
        )


class TestConfigInitFactoryDefaultRegression:
    """Test do_config_initialization() factory default path still works."""

    def test_factory_default_without_minigraph_or_ztp(self, harness):
        """Scenario C: no config_db, no minigraph, ZTP disabled → factory default."""
        result = run_harness(harness, "do_config_initialization",
                             config_db="false", minigraph="false", ztp="false")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            any("generate_config factory" in a for a in result['actions']),
            "Expected factory default but got: {}".format(result['actions'])
        )


class TestConfigInitSkippedWhenConfigExists:
    """Test do_config_initialization() is not reached when config_db.json exists."""

    def test_boot_config_skips_init_when_config_exists(self, harness):
        """config_db.json present → no initialization at all."""
        result = run_harness(harness, "boot_config",
                             config_db="true", minigraph="true", ztp="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            "reload_minigraph" not in result['actions'],
            "reload_minigraph should not be called when config_db exists"
        )
        pytest_assert(
            not any("generate_config" in a for a in result['actions']),
            "No config generation when config_db exists"
        )


class TestBootConfigWarmBootGuard:
    """Test boot_config() skips initialization during warm boot."""

    def test_warm_boot_skips_initialization(self, harness):
        """Scenario D: warm boot, no config_db → skip everything."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="true",
                             ztp="true", warm="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        stdout_lower = result['stdout'].lower()
        pytest_assert(
            "warm boot detected" in stdout_lower,
            "Expected warm boot detection message, got: {}".format(result['stdout'])
        )
        pytest_assert(
            "reload_minigraph" not in result['actions'],
            "No config actions should happen during warm boot"
        )
        pytest_assert(
            not any("generate_config" in a for a in result['actions']),
            "No config generation during warm boot"
        )
        pytest_assert(
            any("CONFIG_DB_INITIALIZED" in a for a in result['actions']),
            "CONFIG_DB_INITIALIZED should be set even during warm boot"
        )

    def test_warm_boot_skips_ztp(self, harness):
        """Warm boot with ZTP enabled → ZTP not triggered."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="false",
                             ztp="true", warm="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            not any("generate_config ztp" in a for a in result['actions']),
            "ZTP should not trigger during warm boot"
        )
        pytest_assert(
            not result['pending_ztp_restart'],
            "pending_ztp_restart should not be set during warm boot"
        )


class TestBootConfigZTPRestartGuard:
    """Test that ZTP erase/restart is skipped when minigraph was used."""

    def test_ztp_not_restarted_after_minigraph(self, harness):
        """Scenario E: minigraph used for init → ZTP restart skipped."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="true", ztp="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            "reload_minigraph" in result['actions'],
            "Expected minigraph to be used"
        )
        pytest_assert(
            not result['pending_ztp_restart'],
            "pending_ztp_restart should not be set when minigraph was used"
        )
        pytest_assert(
            not any("ztp erase" in a for a in result['actions']),
            "ZTP should not be erased when minigraph was used"
        )

    def test_ztp_restart_when_no_minigraph(self, harness):
        """No minigraph, ZTP enabled → ZTP restart logic runs."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="false", ztp="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            any("generate_config ztp" in a for a in result['actions']),
            "ZTP should trigger when no minigraph"
        )
        # ZTP status is "3:IN-PROGRESS", so pending_ztp_restart should be set
        pytest_assert(
            result['pending_ztp_restart'],
            "pending_ztp_restart should be set when ZTP was used and is in progress"
        )


class TestBootConfigMigrationPath:
    """Test boot_config() migration path handles minigraph correctly."""

    def test_migration_uses_minigraph_when_no_config_db(self, harness):
        """Migration path: no config_db, minigraph present → use minigraph."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="true",
                             ztp="false", migration="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        pytest_assert(
            "reload_minigraph" in result['actions'],
            "Migration should use minigraph when config_db is missing: {}".format(
                result['actions'])
        )

    def test_migration_warm_boot_exits_early(self, harness):
        """Migration path during warm boot → db_migration only."""
        result = run_harness(harness, "boot_config",
                             config_db="false", minigraph="true",
                             ztp="false", warm="true", migration="true")

        pytest_assert(result['rc'] == 0, "Harness failed")
        stdout_lower = result['stdout'].lower()
        pytest_assert(
            "warm reboot detected" in stdout_lower,
            "Expected warm reboot detection in migration path"
        )
        pytest_assert(
            "do_db_migration" in result['actions'],
            "db_migration should run during warm boot migration"
        )


# ---------------------------------------------------------------------------
# Real-mode tests (run actual config-setup on KVM/VS DUTs)
# ---------------------------------------------------------------------------

class TestRealConfigSetupMinigraphFallback:
    """End-to-end test: config-setup boot uses minigraph when config_db.json is absent.

    Only runs with explicit --config_setup_test_mode=real. This test actually deletes
    config_db.json and runs config-setup boot, then verifies the management
    IP is preserved. The fixture restores config_db.json afterwards.

    Skipped by default since it is destructive and may hang on KVM.
    """

    def test_real_minigraph_fallback(self, test_mode, real_dut):
        """Delete config_db.json, run config-setup boot, verify minigraph used."""
        if test_mode != "real":
            pytest.skip("Skipping real-mode test (mode={})".format(test_mode))

        duthost = real_dut

        if not has_minigraph(duthost):
            pytest.skip("No minigraph.xml on this device")

        # Capture mgmt IP before
        mgmt_ip_before = get_mgmt_ip(duthost)
        logger.info("Management IP before test: %s", mgmt_ip_before)

        # Remove config_db.json
        logger.info("Removing %s to trigger config initialization", CONFIG_DB_JSON)
        duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
        duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                      module_ignore_errors=True)

        # Run actual config-setup boot
        result = run_real_config_setup(duthost)

        # Verify minigraph was used
        stdout_lower = result['stdout'].lower()
        pytest_assert(
            "minigraph" in stdout_lower,
            "Expected config-setup to use minigraph, got: {}".format(result['stdout'])
        )
        pytest_assert(
            "zero touch" not in stdout_lower,
            "ZTP should not trigger when minigraph is available"
        )
        pytest_assert(
            "factory default" not in stdout_lower,
            "Factory default should not be generated when minigraph is available"
        )

        # Wait for services and verify mgmt IP survived
        pytest_assert(
            wait_until(120, 10, 0, duthost.critical_services_fully_started),
            "Critical services did not start after config-setup boot"
        )

        mgmt_ip_after = get_mgmt_ip(duthost)
        logger.info("Management IP after test: %s", mgmt_ip_after)
        pytest_assert(
            mgmt_ip_after == mgmt_ip_before,
            "Management IP changed from {} to {} — minigraph fallback may have failed".format(
                mgmt_ip_before, mgmt_ip_after)
        )

    def test_real_warm_boot_skips_init(self, test_mode, real_dut):
        """Simulate warm boot, delete config_db.json, verify init skipped."""
        if test_mode != "real":
            pytest.skip("Skipping real-mode test (mode={})".format(test_mode))

        duthost = real_dut
        mgmt_ip_before = get_mgmt_ip(duthost)

        # Set warm boot flag in STATE_DB
        duthost.shell(
            'sonic-db-cli STATE_DB HSET "WARM_RESTART_ENABLE_TABLE|system" enable true',
            module_ignore_errors=True
        )

        try:
            # Remove config_db.json
            duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
            duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                          module_ignore_errors=True)

            # Run actual config-setup boot
            result = run_real_config_setup(duthost)

            stdout_lower = result['stdout'].lower()
            pytest_assert(
                "warm boot detected" in stdout_lower,
                "Expected warm boot detection, got: {}".format(result['stdout'])
            )
            pytest_assert(
                "zero touch" not in stdout_lower and "factory default" not in stdout_lower,
                "No config initialization should happen during warm boot"
            )

            # Mgmt IP must be unchanged
            mgmt_ip_after = get_mgmt_ip(duthost)
            pytest_assert(
                mgmt_ip_after == mgmt_ip_before,
                "Management IP changed during warm boot"
            )

        finally:
            duthost.shell(
                'sonic-db-cli STATE_DB HSET "WARM_RESTART_ENABLE_TABLE|system" enable false',
                module_ignore_errors=True
            )
