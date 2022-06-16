import pytest

from tests.common.utilities import skip_release
from tests.generic_config_updater.gu_utils import apply_patch
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
       Ignore expected yang validation failure during test execution

       GCU will try several sortings of JsonPatch until the sorting passes yang validation

       Args:
           loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    if loganalyzer:
         ignoreRegex = [
             ".*ERR sonic_yang.*",
             ".*ERR.*Failed to start dhcp_relay container.*", # Valid test_dhcp_relay
             ".*ERR GenericConfigUpdater: Service Validator: Service has been reset.*", # Valid test_dhcp_relay test_syslog
             ".*ERR teamd[0-9].*get_dump: Can't get dump for LAG.*", # Valid test_portchannel_interface
             ".*ERR swss[0-9]*#intfmgrd: :- setIntfVrf:.*", # Valid test_portchannel_interface
             ".*ERR swss[0-9]*#orchagent.*removeLag.*", # Valid test_portchannel_interface
             ".*ERR kernel.*Reset adapter.*", # Valid test_portchannel_interface replace mtu
             ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*", # Valid test_portchannel_interface replace mtu

             # sonic-swss/orchagent/crmorch.cpp
             ".*ERR swss[0-9]*#orchagent.*getResAvailableCounters.*", # test_monitor_config
             ".*ERR swss[0-9]*#orchagent.*objectTypeGetAvailability.*", # test_monitor_config
             ".*ERR dhcp_relay[0-9]*#dhcrelay.*", # test_dhcp_relay
         ]
         loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112

    Args:
        duthost: DUT host object.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    """
    Config facts for selected DUT
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module", autouse=True)
def verify_configdb_with_empty_input(duthost):
    """Fail immediately if empty input test failure

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
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
