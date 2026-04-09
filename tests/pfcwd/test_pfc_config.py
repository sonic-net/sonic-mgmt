import json
import os
import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.config_reload import config_reload
from tests.common.utilities import update_pfcwd_default_state
from tests.common.helpers.pfcwd_helper import is_pfcwd_hw_recovery_enabled, get_pfcwd_hw_timer_limits

logger = logging.getLogger(__name__)

DUT_RUN_DIR = "/home/admin/pfc_wd_tests"
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
TMP_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "testrun")
CONFIG_TEST_EXPECT_INVALID_ACTION_RE = ".* Invalid PFC Watchdog action .*"
CONFIG_TEST_EXPECT_INVALID_DETECT_TIME_RE = ".* Failed to parse PFC Watchdog .* detection_time .*"
CONFIG_TEST_EXPECT_INVALID_RESTORE_TIME_RE = ".* Failed to parse PFC Watchdog .* restoration_time .*"

pytestmark = [
    pytest.mark.disable_loganalyzer,    # disable automatic fixture and invoke within each test
    pytest.mark.topology('any')
]





def create_run_dir():
    """
    Creates a temp run dir 'testrun' within the pfcwd folder
    """
    try:
        os.mkdir(TMP_DIR)
    except OSError as err:
        pytest.fail("Failed to create a temp run dir: {}".format(str(err)))


def generate_cfg_templates(test_port, hw_limits=None):
    """
    Build all the config templates that will be used for the config validation test

    Args:
        test_port (string): a random port selected from the test port list
        hw_limits (dict): hardware timer limits from STATE_DB (optional)

    Returns:
        cfg_params (dict): all config templates
    """
    create_run_dir()
    with open(os.path.join(TEMPLATES_DIR, "pfc_config_params.json"), "r") as read_file:
        cfg_params = json.load(read_file)

    # If hardware limits are provided, adjust test values
    if hw_limits:
        logger.info("Adjusting test parameters for hardware mode with limits: {}".format(hw_limits))

        # Adjust forward action timer values to be within hardware limits
        # This ensures the test focuses on forward action support, not timer validation
        if 'pfc_wd_forward_action' in cfg_params:
            detect_time = cfg_params['pfc_wd_forward_action']['pfc_wd_detection_time']
            restore_time = cfg_params['pfc_wd_forward_action']['pfc_wd_restoration_time']

            # Clamp detection time to hardware range
            if detect_time < hw_limits['detection_min']:
                cfg_params['pfc_wd_forward_action']['pfc_wd_detection_time'] = hw_limits['detection_min']
                logger.info(f"Adjusted forward action detection time to hw_min: {hw_limits['detection_min']}")
            elif detect_time > hw_limits['detection_max']:
                cfg_params['pfc_wd_forward_action']['pfc_wd_detection_time'] = hw_limits['detection_max']
                logger.info(f"Adjusted forward action detection time to hw_max: {hw_limits['detection_max']}")

            # Clamp restoration time to hardware range
            if restore_time < hw_limits['restoration_min']:
                cfg_params['pfc_wd_forward_action']['pfc_wd_restoration_time'] = hw_limits['restoration_min']
                logger.info(f"Adjusted forward action restoration time to hw_min: {hw_limits['restoration_min']}")
            elif restore_time > hw_limits['restoration_max']:
                cfg_params['pfc_wd_forward_action']['pfc_wd_restoration_time'] = hw_limits['restoration_max']
                logger.info(f"Adjusted forward action restoration time to hw_max: {hw_limits['restoration_max']}")

        # Adjust boundary test values to be OUTSIDE hardware limits for testing rejection/auto-adjustment
        # Adjust low detection time to be below hardware minimum
        if 'pfc_wd_low_detect_time' in cfg_params:
            cfg_params['pfc_wd_low_detect_time']['pfc_wd_detection_time'] = max(1, hw_limits['detection_min'] - 100)

        # Adjust high detection time to be above hardware maximum
        if 'pfc_wd_high_detect_time' in cfg_params:
            cfg_params['pfc_wd_high_detect_time']['pfc_wd_detection_time'] = hw_limits['detection_max'] + 100000

        # Adjust low restoration time to be below hardware minimum
        if 'pfc_wd_low_restore_time' in cfg_params:
            cfg_params['pfc_wd_low_restore_time']['pfc_wd_restoration_time'] = (
                max(1, hw_limits['restoration_min'] - 100)
            )

        # Adjust high restoration time to be above hardware maximum
        if 'pfc_wd_high_restore_time' in cfg_params:
            cfg_params['pfc_wd_high_restore_time']['pfc_wd_restoration_time'] = hw_limits['restoration_max'] + 100000

    for key in cfg_params:
        write_file = key
        write_params = dict()
        write_params["PFC_WD"] = {test_port: {"action": cfg_params[key]["pfc_wd_action"],
                                              "detection_time": cfg_params[key]["pfc_wd_detection_time"],
                                              "restoration_time": cfg_params[key]["pfc_wd_restoration_time"]
                                              }
                                  }
        # create individual template files for each test
        with open(os.path.join(TMP_DIR, "{}.json".format(write_file)), "w") as wfile:
            json.dump(write_params, wfile)

    return cfg_params


def copy_templates_to_dut(duthost, cfg_params):
    """
    Copy all the templates created to the DUT

    Args:
        duthost (AnsibleHost): instance
        cfg_params (dict): all config templates

    Returns:
        None
    """
    duthost.shell("mkdir -p {}".format(DUT_RUN_DIR))
    for key in cfg_params:
        src_file = os.path.join(TMP_DIR, "{}.json".format(key))
        duthost.copy(src=src_file, dest="{}/{}.json".format(DUT_RUN_DIR, key))


def cfg_teardown(duthost):
    """
    Cleans up the DUT temp dir and temp dir on the host after the module run

    Args:
        duthost (AnsibleHost): instance

    Returns:
        None
    """
    if os.path.exists(TMP_DIR):
        os.system("rm -rf {}".format(TMP_DIR))
    duthost.shell("rm -rf {}".format(DUT_RUN_DIR))


@pytest.fixture(scope='class')
def cfg_setup(setup_pfc_test, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Class level automatic fixture. Prior to the test run, create all the templates
    needed for each individual test and copy them on the DUT.
    After the all the test cases are done, clean up temp dir on DUT and host

    Args:
        setup_pfc_test: module fixture defined in module conftest.py
        duthost: instance of AnsibleHost class
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    setup_info = setup_pfc_test
    pfc_wd_test_port = list(setup_info['test_ports'].keys())[0]

    # Check if hardware mode is enabled and get limits
    hw_limits = None
    if is_pfcwd_hw_recovery_enabled(duthost):
        hw_limits = get_pfcwd_hw_timer_limits(duthost)
        if hw_limits:
            logger.info("Hardware mode detected with limits: {}".format(hw_limits))

    logger.info("Creating json templates for all config tests")
    cfg_params = generate_cfg_templates(pfc_wd_test_port, hw_limits)
    logger.info("Copying templates over to the DUT")
    copy_templates_to_dut(duthost, cfg_params)

    yield
    logger.info("--- Start running config tests ---")

    logger.info("--- Clean up config dir from DUT ---")
    cfg_teardown(duthost)


@pytest.fixture(scope='class')
def mg_cfg_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Class level automatic fixture. Prior to the test run, enable default pfcwd configuration
    before load_minigraph.
    After the test case is done, recover the configuration

    Args:
        duthost: instance of AnsibleHost class
        enum_rand_one_per_hwsku_frontend_hostname(string) : randomly pick a dut in multi DUT setup
    Returns:
        None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logger.info("Enable pfcwd in configuration file")
    original_pfcwd_value = update_pfcwd_default_state(duthost, "/etc/sonic/init_cfg.json", "enable")

    yield

    logger.info("--- Recover configuration ---")
    if original_pfcwd_value == 'disable':
        update_pfcwd_default_state(duthost, '/etc/sonic/init_cfg.json', 'disable')
        config_reload(duthost, config_source='minigraph')


@pytest.fixture(scope='function', autouse=True)
def stop_pfcwd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost: instance of AnsibleHost class

    Returns:
        None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

    yield

    logger.info("--- Start Pfcwd--")
    duthost.command("pfcwd start_default")


@pytest.mark.usefixtures('cfg_setup')
class TestPfcConfig(object):
    """
    Test case definition and helper function class
    """
    def execute_test(self, duthost, syslog_marker, ignore_regex=None, expect_regex=None, expect_errors=False):
        """
        Helper function that loads each template on the DUT and verifies the expected behavior

        Args:
            duthost (AnsibleHost): instance
            syslog_marker (string): marker prefix name to be inserted in the syslog
            ignore_regex (string): file containing regexs to be ignored by loganalyzer
            expect_regex (string): regex pattern that is expected to be present in the syslog
            expect_erros (bool): if the test expects an error msg in the syslog or not. Default: False

        Returns:
            None
        """
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=syslog_marker)

        if ignore_regex:
            ignore_file = os.path.join(TEMPLATES_DIR, ignore_regex)
            reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
            loganalyzer.ignore_regex.extend(reg_exp)

        if expect_regex:
            loganalyzer.expect_regex = []
            loganalyzer.expect_regex.extend(expect_regex)

        loganalyzer.match_regex = []
        with loganalyzer(fail=not expect_errors):
            cmd = "sonic-cfggen -j {}/{}.json --write-to-db".format(DUT_RUN_DIR, syslog_marker)
            out = duthost.command(cmd)
            pytest_assert(out["rc"] == 0, "Failed to execute cmd {}: Error: {}".format(cmd, out["stderr"]))

    def test_forward_action_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests if the config gets loaded properly for a valid cfg template

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        # Check if hardware mode is enabled
        is_hw_mode = is_pfcwd_hw_recovery_enabled(duthost)

        if is_hw_mode:
            # Check platform - Cisco 8000 doesn't support forward action in hardware mode
            platform = duthost.facts.get('platform', '')
            if 'cisco-8000' in platform.lower():
                pytest.skip("Forward action not supported on Cisco 8000 in hardware mode")

        # Apply the forward-action configuration and validate that it is accepted
        # cleanly and does not produce unexpected syslog errors. We intentionally
        # keep this test focused on the configuration + syslog behavior; detailed
        # hardware/state validation is covered in dedicated hardware PFCWD tests.
        # Note: In hardware mode, timer values were adjusted to be within HW limits
        # during cfg_setup to ensure deterministic behavior.
        self.execute_test(duthost, "pfc_wd_fwd_action", "config_test_ignore_messages")

    def test_invalid_action_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests for syslog error when invalid action is configured

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_invalid_action", None, [CONFIG_TEST_EXPECT_INVALID_ACTION_RE], True)

    def test_invalid_detect_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests for syslog error when invalid detect time is configured

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_invalid_detect_time", None,
                          [CONFIG_TEST_EXPECT_INVALID_DETECT_TIME_RE], True)

    def test_low_detect_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests boundary validation when detect time < lower bound is configured

        Both hardware and software modes reject out-of-range values with error message.
        In hardware mode, config template values are adjusted to be below HW min limits.

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_low_detect_time", None, [CONFIG_TEST_EXPECT_INVALID_DETECT_TIME_RE], True)

    def test_high_detect_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests boundary validation when detect time > higher bound is configured

        Both hardware and software modes reject out-of-range values with error message.
        In hardware mode, config template values are adjusted to be above HW max limits.

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_high_detect_time", None, [CONFIG_TEST_EXPECT_INVALID_DETECT_TIME_RE], True)

    def test_invalid_restore_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests for syslog error when invalid restore time is configured

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_invalid_restore_time", None,
                          [CONFIG_TEST_EXPECT_INVALID_RESTORE_TIME_RE], True)

    def test_low_restore_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests boundary validation when restore time < lower bound is configured

        Both hardware and software modes reject out-of-range values with error message.
        In hardware mode, config template values are adjusted to be below HW min limits.

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_low_restore_time", None, [CONFIG_TEST_EXPECT_INVALID_RESTORE_TIME_RE], True)

    def test_high_restore_time_cfg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests boundary validation when restore time > higher bound is configured

        Both hardware and software modes reject out-of-range values with error message.
        In hardware mode, config template values are adjusted to be above HW max limits.

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.execute_test(duthost, "pfc_wd_high_restore_time", None, [CONFIG_TEST_EXPECT_INVALID_RESTORE_TIME_RE], True)


@pytest.mark.usefixtures('mg_cfg_setup')
class TestDefaultPfcConfig(object):
    def test_default_cfg_after_load_mg(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests for checking if pfcwd gets started after load_minigraph
        For hardware mode, also verifies STATE_DB entries

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        config_reload(duthost, config_source='minigraph', safe_reload=True)
        # sleep 20 seconds to make sure configuration is loaded
        time.sleep(20)
        res = duthost.command('pfcwd show config')
        for port_config in res['stdout_lines']:
            if "ethernet" in port_config.lower():
                # Verify hardware mode STATE_DB entries if applicable
                if is_pfcwd_hw_recovery_enabled(duthost):
                    logger.info("Hardware mode detected, verifying STATE_DB entries")

                    # Verify RECOVERY_MECHANISM
                    cmd = 'sonic-db-cli STATE_DB HGET "PFC_WD_STATE_TABLE|PFC_WD" "RECOVERY_MECHANISM"'
                    result = duthost.shell(cmd, module_ignore_errors=True)
                    if result['rc'] == 0:
                        recovery_mechanism = result['stdout'].strip().strip('"')
                        pytest_assert(
                            recovery_mechanism.upper() == 'HARDWARE',
                            "Expected RECOVERY_MECHANISM=HARDWARE, got: {}".format(recovery_mechanism)
                        )
                        logger.info("Hardware mode RECOVERY_MECHANISM verified")

                    # Verify hardware timer limits are published
                    hw_limits = get_pfcwd_hw_timer_limits(duthost)
                    if hw_limits:
                        logger.info("Hardware timer limits verified: {}".format(hw_limits))
                        pytest_assert(hw_limits['detection_min'] > 0, "Detection time min should be > 0")
                        pytest_assert(
                            hw_limits['detection_max'] > hw_limits['detection_min'],
                            "Detection time max should be > min"
                        )
                        pytest_assert(hw_limits['restoration_min'] > 0, "Restoration time min should be > 0")
                        pytest_assert(
                            hw_limits['restoration_max'] > hw_limits['restoration_min'],
                            "Restoration time max should be > min"
                        )
                    else:
                        logger.warning("Could not retrieve hardware timer limits from STATE_DB")

                return
        # If no ethernet port existing in stdout, failed this case.
        pytest.fail("Failed to start pfcwd after load_minigraph")
