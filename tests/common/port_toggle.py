"""
Tool used for shutdown/startup port on the DUT.
"""

import time
import logging
import pprint

from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.link_flap.link_flap_utils import watch_system_status


logger = logging.getLogger(__name__)


def port_toggle(duthost, ports=None, wait=60, wait_after_ports_up=60, watch=False):
    """
    Toggle ports on DUT.

    Args:
        duthost: DUT host object
        ports: Specify list of ports, None if toggle all ports
        wait: Time to wait for interface to become up
        wait_after_ports_up: Time to wait after interfaces become up
        watch: Logging system state
    """

    if ports is None:
        logger.debug('ports is None, toggling all minigraph ports')
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        ports = mg_facts['minigraph_ports'].keys()

    logger.info('toggling ports:\n%s', pprint.pformat(ports))

    for port in ports:
        duthost.command('config interface shutdown {}'.format(port))
        if watch:
            time.sleep(1)
            watch_system_status(duthost)

    # verify all interfaces are down
    ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
    pytest_assert(len(ports_down) == len(ports), "dut ports {} didn't go down as expected".format(list(set(ports).difference(set(ports_down)))))

    for port in ports:
        duthost.command('config interface startup {}'.format(port))

    logger.info('waiting for ports to become up')

    start = time.time()
    ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
    while ports_down and time.time() - start < wait:
        ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
        logger.info('retry, down ports:\n%s', pprint.pformat(ports_down))
        if not ports_down:
            break

    pytest_assert(not ports_down, "dut ports {} didn't go up as expected".format(ports_down))

    logger.info('wait %d seconds for system to startup', wait_after_ports_up)
    time.sleep(wait_after_ports_up)
