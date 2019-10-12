import time
import logging
import pprint

logger = logging.getLogger(__name__)


def port_toggle(duthost, ports=None, wait=60, wait_after_ports_up=60):
    """
    Toggle ports on DUT
    :param duthost: DUT host object
    :param ports: specify list of ports, None if toggle all ports
    :param wait: time to wait for interface to become up
    :param wait_after_ports_up: time to wait after interfaces become up
    :return:
    """

    if ports is None:
        logger.debug('ports is None, toggling all minigraph ports')
        mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
        ports = mg_facts['minigraph_ports'].keys()

    logger.info('toggling ports:\n{}'.format(pprint.pformat(ports)))

    for port in ports:
        duthost.command('config interface shutdown {}'.format(port))

    # verify all interfaces are up
    ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
    assert len(ports_down) == len(ports)

    for port in ports:
        duthost.command('config interface startup {}'.format(port))

    logger.info('waiting for ports to become up')

    start = time.time()
    ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
    while time.time() - start < wait:
        ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
        logger.info('retry, down ports:\n{}'.format(pprint.pformat(ports_down)))
        if len(ports_down) == 0:
            break

    assert len(ports_down) == 0

    logger.info('wait {} seconds for system to startup'.format(wait_after_ports_up))
    time.sleep(wait_after_ports_up)
