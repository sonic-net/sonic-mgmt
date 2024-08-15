import logging
import pytest
import time
import traceback
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import InterruptableThread

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0', 't1')
]

stop_threads = False


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

    interface_list = dev_nbrs.keys()
    logger.debug('interface_list: {}'.format(interface_list))

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
        "eth_nbrs": dev_nbrs
    }

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # verify sessions are established after test
    if not duthost.check_bgp_session_state(bgp_neighbors):
        for port in interface_list:
            logger.info("no shutdown dut interface {} port {}".format(duthost, port))
            duthost.no_shutdown(port)

            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("no shutdown fanout interface, fanout {} port {}".format(fanout, fanout_port))
                fanout.no_shutdown(fanout_port)

            neighbor = dev_nbrs[port]["name"]
            neighbor_port = dev_nbrs[port]["port"]

            logger.info("no shutdown neighbor interface, neighbor {} port {}".format(neighbor, neighbor_port))
            nbrhosts[neighbor]['host'].no_shutdown(neighbor_port)

            time.sleep(1)

    pytest_assert(wait_until(600, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                  "Not all BGP sessions are established on DUT")


def flap_dut_interface(duthost, port):
    logger.info("flap dut {} interface {}".format(duthost, port))
    dut_flap_count = 0
    while (True):
        duthost.shutdown(port)
        time.sleep(0.1)
        duthost.no_shutdown(port)
        time.sleep(0.1)
        if stop_threads:
            logger.info("stop_threads now true, breaking flap dut {} interface {} flap count  {}".format(
                duthost, port, dut_flap_count))
            break
        dut_flap_count += 1


def flap_fanout_interface(fanouthosts, duthost, port):
    fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
    fanout_flap_count = 0
    if fanout and fanout_port:
        logger.info("flap interface fanout {} port {}".format(fanout, fanout_port))
        while (True):
            fanout.shutdown(fanout_port)
            time.sleep(0.1)
            fanout.no_shutdown(fanout_port)
            time.sleep(0.1)
            if stop_threads:
                logger.info("stop_threads now true, breaking flap fanout {} interface {} flap count  {}".format(
                    fanout, fanout_port, fanout_flap_count))
                break
            fanout_flap_count += 1
    else:
        logger.warning("fanout not found for {} port {}".format(duthost.hostname, port))


def flap_neighbor_interface(neighbor, neighbor_port):
    logger.info("flap neighbor {} interface {}".format(neighbor, neighbor_port))
    neighbor_flap_count = 0
    while (True):
        neighbor.shutdown(neighbor_port)
        time.sleep(0.1)
        neighbor.no_shutdown(neighbor_port)
        time.sleep(0.1)
        if stop_threads:
            logger.info("stop_threads now true, breaking flap neighbor {} interface {} flap count {}".format(
                neighbor, neighbor_port, neighbor_flap_count))
            break
        neighbor_flap_count += 1


@pytest.mark.parametrize("interface", ["dut", "fanout", "neighbor", "all"])
def test_bgp_stress_link_flap(duthosts, rand_one_dut_hostname, setup, fanouthosts, interface):
    global stop_threads

    duthost = duthosts[rand_one_dut_hostname]

    # Skip the test on Virtual Switch due to fanout switch dependency and warm reboot
    asic_type = duthost.facts['asic_type']
    if asic_type == "vs" and (interface == "fanout" or interface == "all"):
        pytest.skip("Stress link flap test is not supported on Virtual Switch")

    eth_nbrs = setup.get('eth_nbrs', {})
    interface_list = eth_nbrs.keys()
    logger.debug('interface_list: {}'.format(interface_list))

    stop_threads = False
    flap_threads = []

    if interface == "dut":
        for interface in interface_list:
            thread = InterruptableThread(
                target=flap_dut_interface,
                args=(duthost, interface)
            )
            thread.daemon = True
            thread.start()
            flap_threads.append(thread)
    elif interface == "fanout":
        for interface in interface_list:
            thread = InterruptableThread(
                target=flap_fanout_interface,
                args=(fanouthosts, duthost, interface)
            )
            thread.daemon = True
            thread.start()
            flap_threads.append(thread)
    elif interface == "neighbor":
        for interface in interface_list:
            neighbor = eth_nbrs[interface]["name"]
            neighbor_port = eth_nbrs[interface]["port"]
            logger.info("shutdown interface neighbor {} port {}".format(neighbor, neighbor_port))
            thread = InterruptableThread(
                target=flap_neighbor_interface,
                args=(neighbor, neighbor_port)
            )
            thread.daemon = True
            thread.start()
            flap_threads.append(thread)
    elif interface == "all":
        for interface in interface_list:
            logger.info("shutdown all interface {} ".format(interface))
            thread_dut = InterruptableThread(
                target=flap_dut_interface,
                args=(duthost, interface)
            )
            thread_dut.daemon = True
            thread_dut.start()
            flap_threads.append(thread_dut)

            thread_fanout = InterruptableThread(
                target=flap_fanout_interface,
                args=(fanouthosts, duthost, interface)
            )
            thread_fanout.daemon = True
            thread_fanout.start()
            flap_threads.append(thread_fanout)

            neighbor = eth_nbrs[interface]["name"]
            neighbor_port = eth_nbrs[interface]["port"]
            thread_neighbor = InterruptableThread(
                target=flap_neighbor_interface,
                args=(neighbor, neighbor_port)
            )
            thread_neighbor.daemon = True
            thread_neighbor.start()
            flap_threads.append(thread_neighbor)

    logger.info("flap_threads {} ".format(flap_threads))
    time.sleep(600)
    stop_threads = True
    time.sleep(60)

    for thread in flap_threads:
        try:
            thread.join(timeout=30)
            logger.info("thread {} joined".format(thread))
        except Exception as e:
            logger.debug("Exception occurred in thread %r:", thread)
            logger.debug("".join(traceback.format_exception(None, e, e.__traceback__)))

    # Clean up the thread list after joining all threads
    flap_threads.clear()

    return
