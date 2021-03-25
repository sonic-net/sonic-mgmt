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
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in mg_facts['minigraph_ports'].keys() if 'BP' not in p]
    ports = list(sorted(external_ports, key=lambda item: int(item.replace('Ethernet', ''))))
    # Select port index 0 & 1 two interfaces for testing
    intf1 = ports[0]
    intf2 = ports[1]
    logger.info("Selected ints are {0} and {1}".format(intf1, intf2))

    intf1_indice = mg_facts['minigraph_ptf_indices'][intf1]
    intf2_indice = mg_facts['minigraph_ptf_indices'][intf2]

    po1 = get_po(mg_facts, intf1)
    po2 = get_po(mg_facts, intf2)

    if po1 is not None:
        asic.config_portchannel_member(po1, intf1, "del")
        collect_info(duthost)
        asic.startup_interface(intf1)
        collect_info(duthost)
    
    if po2 is not None:
        asic.config_portchannel_member(po2, intf2, "del")
        collect_info(duthost)
        asic.startup_interface(intf2)
        collect_info(duthost)

    asic.config_ip_intf(intf1, "10.10.1.2/28", "add")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "add")

    if (po1 is not None) or (po2 is not None):
        time.sleep(40)
    
    yield intf1, intf2, intf1_indice, intf2_indice

    asic.config_ip_intf(intf1, "10.10.1.2/28", "remove")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "remove")



@pytest.fixture(scope="module")
def common_setup_teardown(duthosts, ptfhost, enum_rand_one_per_hwsku_frontend_hostname):
    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
        # Copy test files
        ptfhost.copy(src="ptftests", dest="/root")
        logging.info("router_mac {}".format(router_mac))
        yield duthost, ptfhost, router_mac
    finally:
        #Recover DUT interface IP address
        config_reload(duthost, config_source='config_db', wait=120)


