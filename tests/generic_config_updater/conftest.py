import pytest
import logging

from tests.common.utilities import skip_release

CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json.before_gcu_test"

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def selected_dut_hostname(request, rand_one_dut_hostname):
    """Fixture that returns either `rand_one_dut_hostname` or `rand_one_dut_front_end_hostname`
    depending on availability."""
    if "rand_one_dut_front_end_hostname" in request.fixturenames:
        logger.info("Running on front end duthost")
        return request.getfixturevalue("rand_one_dut_front_end_hostname")
    else:
        logger.info("Running on any type of duthost")
        return rand_one_dut_hostname


# Module Fixture
@pytest.fixture(scope="module")
def cfg_facts(duthosts, selected_dut_hostname, selected_asic_index):
    """
    Config facts for selected DUT
    Args:
        duthosts: list of DUTs.
        selected_dut_hostname: Hostname of a random chosen dut
        selected_asic_index: Random selected asic id
    """
    duthost = duthosts[selected_dut_hostname]
    asic_id = selected_asic_index
    asic_namespace = duthost.get_namespace_from_asic_id(asic_id)
    return duthost.config_facts(host=duthost.hostname, source="persistent", namespace=asic_namespace)['ansible_facts']


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthosts, selected_dut_hostname):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthosts: list of DUTs.
        selected_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[selected_dut_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


@pytest.fixture(scope='function')
def skip_when_buffer_is_dynamic_model(duthost):
    buffer_model = duthost.shell(
        'redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
    if buffer_model == 'dynamic':
        pytest.skip("Skip the test, because dynamic buffer config cannot be updated")


# Function Fixture
@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(request, duthosts, loganalyzer):
    """
       Ignore expected yang validation failure during test execution

       GCU will try several sortings of JsonPatch until the sorting passes yang validation

       Args:
            request: Pytest request object to detect which DUT fixture is being used
            duthosts: list of DUTs.
           loganalyzer: Loganalyzer utility fixture
    """
    # Determine which DUT hostname fixture is being used
    if "enum_rand_one_per_hwsku_frontend_hostname" in request.fixturenames:
        dut_hostname = request.getfixturevalue("enum_rand_one_per_hwsku_frontend_hostname")
    elif "selected_dut_hostname" in request.fixturenames:
        dut_hostname = request.getfixturevalue("selected_dut_hostname")
    elif "rand_one_dut_front_end_hostname" in request.fixturenames:
        dut_hostname = request.getfixturevalue("rand_one_dut_front_end_hostname")
    elif "rand_one_dut_hostname" in request.fixturenames:
        dut_hostname = request.getfixturevalue("rand_one_dut_hostname")
    else:
        # Fallback - try to get any available DUT
        return

    duthost = duthosts[dut_hostname]
    # When loganalyzer is disabled, the object could be None
    if loganalyzer:
        ignoreRegex = [
            ".*ERR sonic_yang.*",

            # Valid test_dhcp_relay for Bookworm and newer
            ".*ERR.*Failed to start dhcp_relay.service - dhcp_relay container.*",
            ".*ERR GenericConfigUpdater:.*Command failed: 'nsenter --target 1"
            ".*systemctl restart dhcp_relay', returncode: 1",
            ".*ERR GenericConfigUpdater:.*stderr: Job for dhcp_relay.service "
            "failed because start of the service was attempted too often.",

            ".*ERR.*Failed to start dhcp_relay container.*",  # Valid test_dhcp_relay
            # Valid test_dhcp_relay test_syslog
            ".*ERR GenericConfigUpdater: Service Validator: Service has been reset.*",
            ".*ERR teamd[0-9].*get_dump: Can't get dump for LAG.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#intfmgrd: :- setIntfVrf:.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#orchagent.*removeLag.*",  # Valid test_portchannel_interface
            ".*ERR kernel.*Reset adapter.*",  # Valid test_portchannel_interface replace mtu
            ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*",  # Valid test_portchannel_interface replace mtu
            ".*ERR systemd.*Failed to start Host core file uploader daemon.*",  # Valid test_syslog
            r".*ERR monit\[\d+\]: 'routeCheck' status failed \(255\) -- Failure results:.*",

            # sonic-swss/orchagent/crmorch.cpp
            ".*ERR swss[0-9]*#orchagent.*getResAvailableCounters.*",  # test_monitor_config
            ".*ERR swss[0-9]*#orchagent.*objectTypeGetAvailability.*",  # test_monitor_config
            ".*ERR dhcp_relay[0-9]*#dhcrelay.*",  # test_dhcp_relay

            # sonic-sairedis/vslib/HostInterfaceInfo.cpp: Need investigation
            ".*ERR syncd[0-9]*#syncd.*tap2veth_fun: failed to write to socket.*",   # test_portchannel_interface tc2
            ".*ERR.*'apply-patch' executed failed.*",  # negative cases that are expected to fail

            # Ignore errors from k8s config test
            ".*ERR ctrmgrd.py: Refer file.*",
            ".*ERR ctrmgrd.py: Join failed.*"
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


@pytest.fixture(scope="session")
def skip_if_packet_trimming_not_supported(duthost):
    """
    Check if the current device supports packet trimming feature.
    """
    platform = duthost.facts["platform"]
    logger.info(f"Checking packet trimming support for platform: {platform}")

    # Check if the SWITCH_TRIMMING_CAPABLE capability is true
    trimming_capable = duthost.command('redis-cli -n 6 HGET "SWITCH_CAPABILITY|switch" "SWITCH_TRIMMING_CAPABLE"')[
        'stdout'].strip()
    if trimming_capable.lower() != 'true':
        pytest.skip("Packet trimming is not supported")
