import logging
import pytest
import time
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1"),
]


@pytest.fixture
def enable_container_autorestart(duthosts, rand_one_dut_hostname):
    # Enable autorestart for all features
    duthost = duthosts[rand_one_dut_hostname]
    feature_list, _ = duthost.get_feature_status()
    container_autorestart_states = duthost.get_container_autorestart_states()
    for feature, status in list(feature_list.items()):
        # Enable container autorestart only if the feature is enabled and container autorestart is disabled.
        if status == 'enabled' and container_autorestart_states[feature] == 'disabled':
            duthost.shell("sudo config feature autorestart {} enabled".format(feature))

    yield
    for feature, status in list(feature_list.items()):
        # Disable container autorestart back if it was initially disabled.
        if status == 'enabled' and container_autorestart_states[feature] == 'disabled':
            duthost.shell("sudo config feature autorestart {} disabled".format(feature))


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, nbrhosts, fanouthosts):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    bgp_neighbor = list(bgp_neighbors.keys())[0]

    logger.debug("setup config_facts {}".format(config_facts))
    logger.debug("setup nbrhosts {}".format(nbrhosts))
    logger.debug("setup bgp_neighbors {}".format(bgp_neighbors))
    logger.debug("setup dev_nbrs {}".format(dev_nbrs))
    logger.debug("setup portchannels {}".format(portchannels))
    logger.debug("setup test_neighbor {}".format(bgp_neighbor))

    # verify sessions are established
    pytest_assert(wait_until(30, 5, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                  "Not all BGP sessions are established on DUT")

    ip_intfs = duthost.show_and_parse('show ip interface')
    logger.debug("setup ip_intfs {}".format(ip_intfs))

    # Create a mapping of neighbor IP to interfaces and their details
    neighbor_ip_to_interfaces = {}

    # Loop through the ip_intfs list to populate the mapping
    for ip_intf in ip_intfs:
        neighbor_ip = ip_intf['neighbor ip']
        interface_name = ip_intf['interface']
        if neighbor_ip not in neighbor_ip_to_interfaces:
            neighbor_ip_to_interfaces[neighbor_ip] = {}

        # Check if the interface is in portchannels and get the relevant devices
        if interface_name in portchannels:
            for dev_name in portchannels[interface_name]:
                if dev_name in dev_nbrs and dev_nbrs[dev_name]['name'] == ip_intf['bgp neighbor']:
                    neighbor_ip_to_interfaces[neighbor_ip][dev_name] = dev_nbrs[dev_name]
        # If not in portchannels, check directly in dev_nbrs
        elif interface_name in dev_nbrs and dev_nbrs[interface_name]['name'] == ip_intf['bgp neighbor']:
            neighbor_ip_to_interfaces[neighbor_ip][interface_name] = dev_nbrs[interface_name]

    # Update bgp_neighbors with the new 'interface' key
    for ip, details in bgp_neighbors.items():
        if ip in neighbor_ip_to_interfaces:
            details['interface'] = neighbor_ip_to_interfaces[ip]

    setup_info = {
        'neighhosts': bgp_neighbors,
        "test_neighbor": bgp_neighbor
    }

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # verify sessions are established after test
    if not duthost.check_bgp_session_state(bgp_neighbors):
        local_interfaces = list(bgp_neighbors[bgp_neighbor]['interface'].keys())
        for port in local_interfaces:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("no shutdown fanout interface, fanout {} port {}".format(fanout, fanout_port))
                fanout.no_shutdown(fanout_port)
            neighbor_port = bgp_neighbors[bgp_neighbor]['interface'][port]['port']
            neighbor_name = bgp_neighbors[bgp_neighbor]['name']
            logger.info("no shutdown neighbor interface, neighbor {} port {}".format(neighbor_name, neighbor_port))
            nbrhosts[neighbor_name]['host'].no_shutdown(neighbor_port)
            time.sleep(1)

        pytest_assert(wait_until(60, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT")


def verify_bgp_session_down(duthost, bgp_neighbor):
    """Verify the bgp session to the DUT is established."""
    bgp_facts = duthost.bgp_facts()["ansible_facts"]
    return (
        bgp_neighbor in bgp_facts["bgp_neighbors"]
        and bgp_facts["bgp_neighbors"][bgp_neighbor]["state"] != "established"
    )


@pytest.mark.parametrize("test_type", ["bgp_docker", "swss_docker", "reboot"])
@pytest.mark.parametrize("failure_type", ["interface", "neighbor"])
@pytest.mark.disable_loganalyzer
def test_bgp_session_interface_down(duthosts, rand_one_dut_hostname, fanouthosts, localhost,
                                    enable_container_autorestart,
                                    nbrhosts, setup, test_type, failure_type, tbinfo):
    '''
    1: check all bgp sessions are up
    2: inject failure, shutdown fanout physical interface or neighbor port or neighbor session
    4: do the test, reset bgp or swss or do the reboot
    5: Verify all bgp sessions are up
    '''
    # Skip the test on dualtor with reboot test type
    pytest_require(
        ("dualtor" not in tbinfo["topo"]["name"] or test_type != "reboot"),
        "warm reboot is not supported on dualtor"
    )

    duthost = duthosts[rand_one_dut_hostname]

    # Skip the test on Virtual Switch due to fanout switch dependency and warm reboot
    asic_type = duthost.facts['asic_type']
    if asic_type == "vs" and (failure_type == "interface" or test_type == "reboot"):
        pytest.skip("BGP session test is not supported on Virtual Switch")

    # Skip the test if BGP or SWSS autorestart is disabled
    autorestart_states = duthost.get_container_autorestart_states()
    bgp_autorestart = autorestart_states['bgp']
    swss_autorestart = autorestart_states['swss']
    if bgp_autorestart != "enabled" or swss_autorestart != "enabled":
        logger.info("auto restart config bgp {} swss {}".format(bgp_autorestart, swss_autorestart))
        pytest.skip("BGP or SWSS autorestart is disabled")

    neighbor = setup['test_neighbor']
    neighbor_name = setup['neighhosts'][neighbor]['name']
    local_interfaces = list(setup['neighhosts'][neighbor]['interface'].keys())

    logger.debug("duthost {} neighbor {} interface {} test type {} inject failure type {}".format(
        duthost, neighbor_name, local_interfaces, test_type, failure_type))

    if failure_type == "interface":
        for port in local_interfaces:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("shutdown interface fanout {} port {}".format(fanout, fanout_port))
                fanout.shutdown(fanout_port)
                time.sleep(1)

    elif failure_type == "neighbor":
        for port in local_interfaces:
            neighbor_port = setup['neighhosts'][neighbor]['interface'][port]['port']
            logger.info("shutdown interface neighbor {} port {}".format(neighbor_name, neighbor_port))
            nbrhosts[neighbor_name]['host'].shutdown(neighbor_port)
            time.sleep(1)

    duthost.shell('show ip bgp summary', module_ignore_errors=True)
    pytest_assert(
        wait_until(90, 5, 0, verify_bgp_session_down, duthost, neighbor),
        "neighbor {} state is still established".format(neighbor)
    )

    if test_type == "bgp_docker":
        duthost.shell("docker restart bgp")
    elif test_type == "swss_docker":
        duthost.shell("docker restart swss")
    elif test_type == "reboot":
        reboot(duthost, localhost, reboot_type="warm", wait_warmboot_finalizer=True, warmboot_finalizer_timeout=360)

    pytest_assert(wait_until(360, 10, 120, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    if failure_type == "interface":
        for port in local_interfaces:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("no shutdown interface fanout {} port {}".format(fanout, fanout_port))
                fanout.no_shutdown(fanout_port)
                time.sleep(1)

    elif failure_type == "neighbor":
        for port in local_interfaces:
            neighbor_port = setup['neighhosts'][neighbor]['interface'][port]['port']
            logger.info("no shutdown interface neighbor {} port {}".format(neighbor_name, neighbor_port))
            nbrhosts[neighbor_name]['host'].no_shutdown(neighbor_port)
            time.sleep(1)

    pytest_assert(wait_until(120, 10, 30, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")
    pytest_assert(wait_until(60, 10, 0, duthost.check_bgp_session_state, list(setup['neighhosts'].keys())),
                  "Not all BGP sessions are established on DUT")
