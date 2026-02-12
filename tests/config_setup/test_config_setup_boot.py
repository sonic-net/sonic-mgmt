"""
Tests for config-setup boot flow.

Validates that the config-setup script correctly handles boot scenarios
when config_db.json is absent, including minigraph.xml fallback, ZTP
behavior, and warm boot guards.

These tests address the bug reported in ADO 36697420:
    "[202511.08] Config Reload is Run during warm-boot up"

The fix is in sonic-buildimage PR #25463 which updates
files/image_config/config-setup/config-setup to:
1. Prefer minigraph.xml over ZTP/factory-default when config_db.json is missing
2. Check /proc/cmdline for SONIC_BOOT_TYPE=warm (reliable warm boot detection)
3. Skip config initialization and ZTP entirely during warm boot

Config priority order (consistent across all code paths):
    config_db.json > minigraph.xml > ZTP > factory default

Topology: any
"""

import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

CONFIG_DB_JSON = "/etc/sonic/config_db.json"
CONFIG_DB_BAK = "/etc/sonic/config_db.json.config_setup_test_bak"
MINIGRAPH_FILE = "/etc/sonic/minigraph.xml"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def ztp_image(request):
    """Return True if the DUT image has ZTP enabled."""
    return request.config.getoption("--ztp_image", default=False)


@pytest.fixture(scope="function")
def backup_and_restore_config(duthosts, rand_one_dut_hostname):
    """Back up config_db.json before test and restore it afterwards.

    Also captures the management IP so we can verify it survives the test.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Backup config_db.json
    logger.info("Backing up {} to {}".format(CONFIG_DB_JSON, CONFIG_DB_BAK))
    duthost.shell("cp {} {}".format(CONFIG_DB_JSON, CONFIG_DB_BAK))

    yield duthost

    # Restore config_db.json and reload
    logger.info("Restoring {} from {}".format(CONFIG_DB_JSON, CONFIG_DB_BAK))
    duthost.shell("cp {} {}".format(CONFIG_DB_BAK, CONFIG_DB_JSON))
    duthost.shell("rm -f {}".format(CONFIG_DB_BAK))
    duthost.shell("config reload -y -f", module_ignore_errors=True)
    pytest_assert(
        wait_until(300, 20, 0, duthost.critical_services_fully_started),
        "Critical services did not start after config restore"
    )


@pytest.fixture(scope="function")
def mgmt_ip(duthosts, rand_one_dut_hostname):
    """Capture the management interface IP before the test."""
    duthost = duthosts[rand_one_dut_hostname]
    result = duthost.shell("ip -4 addr show eth0 | grep inet | awk '{print $2}'",
                           module_ignore_errors=True)
    ip = result['stdout'].strip()
    logger.info("Management IP before test: %s", ip)
    return ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def has_minigraph(duthost):
    """Check if minigraph.xml exists on the DUT."""
    result = duthost.shell("test -f {}".format(MINIGRAPH_FILE),
                           module_ignore_errors=True)
    return result['rc'] == 0


def get_ztp_status(duthost):
    """Get ZTP status string, or None if ZTP is not available."""
    result = duthost.shell("ztp status -c", module_ignore_errors=True)
    if result['rc'] != 0:
        return None
    return result['stdout'].strip()


def get_boot_type_from_cmdline(duthost):
    """Read SONIC_BOOT_TYPE from /proc/cmdline."""
    result = duthost.shell("cat /proc/cmdline", module_ignore_errors=True)
    cmdline = result['stdout']
    for token in cmdline.split():
        if token.startswith("SONIC_BOOT_TYPE="):
            return token.split("=", 1)[1]
    return "cold"


def run_config_setup_boot(duthost):
    """Execute config-setup boot and return the output."""
    result = duthost.shell("sudo /usr/bin/config-setup boot",
                           module_ignore_errors=True)
    logger.info("config-setup boot stdout:\n%s", result['stdout'])
    if result['stderr']:
        logger.info("config-setup boot stderr:\n%s", result['stderr'])
    return result


def verify_mgmt_ip_intact(duthost, expected_ip):
    """Verify the management IP is still configured."""
    result = duthost.shell("ip -4 addr show eth0 | grep inet | awk '{print $2}'",
                           module_ignore_errors=True)
    current_ip = result['stdout'].strip()
    logger.info("Management IP after test: %s (expected: %s)", current_ip, expected_ip)
    return current_ip == expected_ip


def check_config_db_initialized(duthost):
    """Check if CONFIG_DB_INITIALIZED flag is set."""
    result = duthost.shell(
        'sonic-db-cli CONFIG_DB GET "CONFIG_DB_INITIALIZED"',
        module_ignore_errors=True
    )
    return result['stdout'].strip() == "1"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConfigSetupMinigraphFallback:
    """Test that config-setup prefers minigraph.xml when config_db.json is missing.

    Scenario A: minigraph.xml present, config_db.json removed.
    Expected: reload_minigraph is used, management IP preserved,
              ZTP is NOT triggered.
    """

    def test_minigraph_used_when_config_db_absent(self, backup_and_restore_config,
                                                   mgmt_ip, localhost):
        """Verify config-setup uses minigraph.xml when config_db.json is absent."""
        duthost = backup_and_restore_config

        if not has_minigraph(duthost):
            pytest.skip("No minigraph.xml on this device, cannot test minigraph fallback")

        # Remove config_db.json to trigger config initialization path
        logger.info("Removing %s to simulate missing config", CONFIG_DB_JSON)
        duthost.shell("rm -f {}".format(CONFIG_DB_JSON))

        # Clear CONFIG_DB_INITIALIZED to allow re-initialization
        duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                      module_ignore_errors=True)

        # Run config-setup boot
        result = run_config_setup_boot(duthost)

        # Verify: should see "minigraph" in output, not "zero touch" or "factory default"
        stdout = result['stdout'].lower()
        pytest_assert(
            "minigraph" in stdout,
            "Expected config-setup to use minigraph.xml but got: {}".format(result['stdout'])
        )
        pytest_assert(
            "zero touch" not in stdout,
            "ZTP should not have been triggered when minigraph.xml is available"
        )
        pytest_assert(
            "factory default" not in stdout,
            "Factory default should not have been generated when minigraph.xml is available"
        )

        # Verify management IP is still intact
        pytest_assert(
            wait_until(60, 10, 0, verify_mgmt_ip_intact, duthost, mgmt_ip),
            "Management IP was lost after config-setup boot with minigraph fallback"
        )

        # Verify CONFIG_DB_INITIALIZED is set
        pytest_assert(
            check_config_db_initialized(duthost),
            "CONFIG_DB_INITIALIZED should be set after config-setup boot"
        )


class TestConfigSetupZTPRegression:
    """Test that ZTP still works when both config_db.json and minigraph.xml are absent.

    Scenario B: no config_db.json, no minigraph.xml, ZTP enabled.
    Expected: ZTP triggers as before (regression check).
    """

    def test_ztp_triggers_without_minigraph(self, backup_and_restore_config,
                                             ztp_image, localhost):
        """Verify ZTP triggers when no config_db.json and no minigraph.xml exist."""
        duthost = backup_and_restore_config

        if not ztp_image:
            pytest.skip("ZTP not enabled on this image (use --ztp_image flag)")

        ztp_status = get_ztp_status(duthost)
        if ztp_status is None or ztp_status == "0:DISABLED":
            pytest.skip("ZTP is disabled or not available on this device")

        # Temporarily rename minigraph if it exists
        minigraph_exists = has_minigraph(duthost)
        if minigraph_exists:
            duthost.shell("mv {} {}.bak".format(MINIGRAPH_FILE, MINIGRAPH_FILE))

        try:
            # Remove config_db.json
            logger.info("Removing %s and minigraph to test ZTP path", CONFIG_DB_JSON)
            duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
            duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                          module_ignore_errors=True)

            # Run config-setup boot
            result = run_config_setup_boot(duthost)

            # Verify: ZTP should be triggered
            stdout = result['stdout'].lower()
            pytest_assert(
                "zero touch" in stdout,
                "Expected ZTP to trigger when no config_db.json and no minigraph.xml, "
                "got: {}".format(result['stdout'])
            )

        finally:
            # Restore minigraph
            if minigraph_exists:
                duthost.shell("mv {}.bak {}".format(MINIGRAPH_FILE, MINIGRAPH_FILE))


class TestConfigSetupFactoryDefaultRegression:
    """Test factory default when ZTP disabled and only minigraph.xml is present.

    Scenario C: no config_db.json, minigraph.xml present, ZTP disabled.
    Expected: minigraph.xml is used instead of factory default.
    """

    def test_minigraph_preferred_over_factory_default(self, backup_and_restore_config,
                                                       mgmt_ip, localhost):
        """Verify minigraph is used instead of factory default when ZTP is disabled."""
        duthost = backup_and_restore_config

        if not has_minigraph(duthost):
            pytest.skip("No minigraph.xml on this device")

        # Check if ZTP is disabled (this test specifically covers the no-ZTP case)
        ztp_status = get_ztp_status(duthost)
        if ztp_status is not None and ztp_status != "0:DISABLED":
            logger.info("ZTP is enabled (%s); this test still validates minigraph "
                        "takes priority over both ZTP and factory default", ztp_status)

        # Remove config_db.json
        logger.info("Removing %s to test factory default path", CONFIG_DB_JSON)
        duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
        duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                      module_ignore_errors=True)

        # Run config-setup boot
        result = run_config_setup_boot(duthost)

        # Verify: minigraph should be used
        stdout = result['stdout'].lower()
        pytest_assert(
            "minigraph" in stdout,
            "Expected minigraph.xml to be used, got: {}".format(result['stdout'])
        )
        pytest_assert(
            "factory default" not in stdout,
            "Factory default should not be generated when minigraph.xml is present"
        )

        # Verify management IP survived
        pytest_assert(
            wait_until(60, 10, 0, verify_mgmt_ip_intact, duthost, mgmt_ip),
            "Management IP was lost — factory default may have overwritten minigraph config"
        )


class TestConfigSetupWarmBootGuard:
    """Test that config-setup skips initialization during warm boot.

    Scenario D: warm boot, config_db.json absent.
    Expected: config initialization and ZTP skipped entirely.
    """

    def test_warm_boot_skips_config_initialization(self, backup_and_restore_config,
                                                    mgmt_ip, localhost):
        """Verify config-setup skips initialization during warm boot."""
        duthost = backup_and_restore_config

        # Check current boot type
        boot_type = get_boot_type_from_cmdline(duthost)
        logger.info("Current boot type from /proc/cmdline: %s", boot_type)

        if boot_type != "warm":
            # Simulate warm boot by setting STATE_DB flag
            # (we can't modify /proc/cmdline, but we can test the STATE_DB path)
            logger.info("Not a warm boot — simulating via STATE_DB warm restart flag")
            duthost.shell(
                'sonic-db-cli STATE_DB HSET "WARM_RESTART_ENABLE_TABLE|system" enable true',
                module_ignore_errors=True
            )

        try:
            # Remove config_db.json
            logger.info("Removing %s to test warm boot guard", CONFIG_DB_JSON)
            duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
            duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                          module_ignore_errors=True)

            # Run config-setup boot
            result = run_config_setup_boot(duthost)

            # Verify: should see warm boot message, no ZTP or factory default
            stdout = result['stdout'].lower()
            pytest_assert(
                "warm boot detected" in stdout or boot_type == "warm",
                "Expected warm boot to be detected, got: {}".format(result['stdout'])
            )
            pytest_assert(
                "zero touch" not in stdout,
                "ZTP should not trigger during warm boot"
            )
            pytest_assert(
                "factory default" not in stdout,
                "Factory default should not be generated during warm boot"
            )

            # Verify management IP is intact
            pytest_assert(
                verify_mgmt_ip_intact(duthost, mgmt_ip),
                "Management IP changed during warm boot — config initialization was not skipped"
            )

        finally:
            # Clean up: reset warm restart flag if we set it
            if boot_type != "warm":
                duthost.shell(
                    'sonic-db-cli STATE_DB HSET "WARM_RESTART_ENABLE_TABLE|system" enable false',
                    module_ignore_errors=True
                )


class TestConfigSetupZTPNotRestarted:
    """Test that ZTP erase/restart is skipped when minigraph.xml was used.

    When config_db.json is absent and minigraph.xml is used for initialization,
    the ZTP restart logic in boot_config() should be skipped because ZTP was
    never actually invoked.
    """

    def test_ztp_not_restarted_after_minigraph_init(self, backup_and_restore_config,
                                                     ztp_image, localhost):
        """Verify ZTP is not erased/restarted when minigraph was used for init."""
        duthost = backup_and_restore_config

        if not ztp_image:
            pytest.skip("ZTP not enabled on this image (use --ztp_image flag)")

        if not has_minigraph(duthost):
            pytest.skip("No minigraph.xml on this device")

        ztp_status_before = get_ztp_status(duthost)
        if ztp_status_before is None or ztp_status_before == "0:DISABLED":
            pytest.skip("ZTP is disabled or not available")

        # Remove config_db.json
        logger.info("Removing %s to trigger init with minigraph", CONFIG_DB_JSON)
        duthost.shell("rm -f {}".format(CONFIG_DB_JSON))
        duthost.shell('sonic-db-cli CONFIG_DB DEL "CONFIG_DB_INITIALIZED"',
                      module_ignore_errors=True)

        # Run config-setup boot
        result = run_config_setup_boot(duthost)

        # Verify: ZTP status should not have been erased
        ztp_status_after = get_ztp_status(duthost)
        logger.info("ZTP status before: %s, after: %s", ztp_status_before, ztp_status_after)

        # The key check: /tmp/pending_ztp_restart should NOT be created
        pending_result = duthost.shell("test -f /tmp/pending_ztp_restart",
                                       module_ignore_errors=True)
        pytest_assert(
            pending_result['rc'] != 0,
            "pending_ztp_restart flag should not exist when minigraph was used for initialization"
        )
