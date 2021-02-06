import logging
import pytest
import time

from .args.wr_arp_args import add_wr_arp_args
from .arp_utils import collect_info, get_po
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

# WR-ARP pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_wr_arp_args(parser)


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    intf_facts = duthost.interface_facts()['ansible_facts']

    ports = list(sorted(mg_facts['minigraph_ports'].keys(), key=lambda item: int(item.replace('Ethernet', ''))))
    # Select port index 0 & 1 two interfaces for testing
    intf1 = ports[0]
    intf2 = ports[1]
    logger.info("Selected ints are {0} and {1}".format(intf1, intf2))

    intf1_index = mg_facts['minigraph_ptf_indices'][intf1]
    intf2_index = mg_facts['minigraph_ptf_indices'][intf2]

    return intf1, intf1_index, intf2, intf2_index, intf_facts, mg_facts, duthost


@pytest.fixture(scope="module")
def common_setup_teardown(ptfhost, intfs_for_test):
    intf1, intf1_indice, intf2, intf2_index, intf_facts, mg_facts, duthost = intfs_for_test

    po1 = get_po(mg_facts, intf1)
    po2 = get_po(mg_facts, intf2)

    try:
        # Make sure selected interfaces are not in portchannel
        if po1 is not None:
            duthost.shell('config portchannel member del {0} {1}'.format(po1, intf1))
            collect_info(duthost)
            duthost.shell('config interface startup {0}'.format(intf1))
            collect_info(duthost)

        if po2 is not None:
            duthost.shell('config portchannel member del {0} {1}'.format(po2, intf2))
            collect_info(duthost)
            duthost.shell('config interface startup {0}'.format(intf2))
            collect_info(duthost)

        # Change SONiC DUT interface IP to test IP address
        duthost.shell('config interface ip add {0} 10.10.1.2/28'.format(intf1))
        collect_info(duthost)
        duthost.shell('config interface ip add {0} 10.10.1.20/28'.format(intf2))
        collect_info(duthost)

        if (po1 is not None) or (po2 is not None):
            time.sleep(40)

        yield duthost, ptfhost, intf_facts, intf1, intf2, intf1_indice, intf2_index
    finally:
        # Recover DUT interface IP address
        config_reload(duthost, config_source='config_db', wait=120)
