import pytest

from tests.common.utilities import skip_release

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
             ".*ERR bgp#bgpcfgd.*Can't update the peer. Only 'admin_status' attribute is supported.*", # test_bgpl
             ".*ERR bgp#bgpcfgd: BGPAllowListMgr::Received BGP ALLOWED 'SET' message with no prefixes specified: {'NULL': 'NULL'}.*", # test_bgp_prefix
             ".*ERR.*Failed to start dhcp_relay container.*", # test_dhcp_relay
             ".*ERR GenericConfigUpdater: Service Validator: Service has been reset.*", # test_dhcp_relay test_syslog
             ".*Same listen range is attached to peer-group.*", # test_bgp_speaker -> real issue
             ".*ERR swss[0-9]*#orchagent.*removeLag.*", # autorestart/test_container_autorestart.py test_portchannel_interface
             ".*ERR swss[0-9]*#intfmgrd: :- setIntfVrf:.*", # test_portchannel_interface
             ".*ERR teamd.*get_dump: Can't get dump for LAG.*", # test_portchannel_interface
             ".*ERR kernel.*Reset adapter.*", # test_portchannel_interface replace mtu
             ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*", # test_portchannel_interface replace mtu
             ".*ERR.*Failed to apply Json change.*", # validator need updater submodule
             ".*ERR GenericConfigUpdater: Change Applier: service invoked.*", # validator need updater submodule
         ]
         loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202112

    Args:
        duthost: Hostname of DUT.

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
