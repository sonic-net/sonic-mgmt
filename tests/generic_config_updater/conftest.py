import pytest
import logging

from tests.common.utilities import skip_release
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json.before_gcu_test"

logger = logging.getLogger(__name__)


# Module Fixture
@pytest.fixture(scope="module", autouse=True)
def bypass_duplicate_lanes_platform(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts['platform'] == 'x86_64-arista_7050cx3_32s' or \
            duthost.facts['platform'] == 'x86_64-dellemc_s5232f_c3538-r0':
        pytest.skip("Temporary skip platform with duplicate lanes...")


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    """
    Config facts for selected DUT
    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthosts, rand_one_dut_hostname):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


@pytest.fixture(scope="module", autouse=True)
def reset_and_restore_test_environment(duthosts, rand_one_dut_hostname):
    """Reset and restore test env if initial Config cannot pass Yang

    Back up the existing config_db.json file and restore it once the test ends.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    logger.info("Backup {} to {} on {}".format(
        CONFIG_DB, CONFIG_DB_BACKUP, duthost.hostname))
    duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BACKUP))

    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        logger.info("Running config failed SONiC Yang validation. Reload minigraph. config: {}"
                    .format(output['stdout']))
        config_reload(duthost, config_source="minigraph", safe_reload=True)

    yield

    logger.info("Restore {} with {} on {}".format(
        CONFIG_DB, CONFIG_DB_BACKUP, duthost.hostname))
    duthost.shell("mv {} {}".format(CONFIG_DB_BACKUP, CONFIG_DB))

    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        logger.info("Restore Config after GCU test.")
        config_reload(duthost)


@pytest.fixture(scope="module", autouse=True)
def verify_configdb_with_empty_input(duthosts, rand_one_dut_hostname):
    """Fail immediately if empty input test failure

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            pytest.fail(
                "SETUP FAILURE: ConfigDB fail to validate Yang. rc:{} msg:{}"
                .format(output['rc'], output['stdout'])
            )

    finally:
        delete_tmpfile(duthost, tmpfile)


# Function Fixture
@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
       Ignore expected yang validation failure during test execution

       GCU will try several sortings of JsonPatch until the sorting passes yang validation

       Args:
            duthosts: list of DUTs.
            rand_one_dut_hostname: Hostname of a random chosen dut
           loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR sonic_yang.*",
            ".*ERR.*Failed to start dhcp_relay container.*",  # Valid test_dhcp_relay
            ".*ERR GenericConfigUpdater: Service Validator: Service has been reset.*",  # Valid test_dhcp_relay test_syslog
            ".*ERR teamd[0-9].*get_dump: Can't get dump for LAG.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#intfmgrd: :- setIntfVrf:.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#orchagent.*removeLag.*",  # Valid test_portchannel_interface
            ".*ERR kernel.*Reset adapter.*",  # Valid test_portchannel_interface replace mtu
            ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*",  # Valid test_portchannel_interface replace mtu

            # sonic-swss/orchagent/crmorch.cpp
            ".*ERR swss[0-9]*#orchagent.*getResAvailableCounters.*",  # test_monitor_config
            ".*ERR swss[0-9]*#orchagent.*objectTypeGetAvailability.*",  # test_monitor_config
            ".*ERR dhcp_relay[0-9]*#dhcrelay.*",  # test_dhcp_relay

            # sonic-sairedis/vslib/HostInterfaceInfo.cpp: Need investigation
            ".*ERR syncd[0-9]*#syncd.*tap2veth_fun: failed to write to socket.*", # test_portchannel_interface tc2
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)
