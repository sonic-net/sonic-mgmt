import logging
import pytest

from .args.wr_arp_args import add_wr_arp_args
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
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo, config_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in mg_facts['minigraph_ports'].keys() if 'BP' not in p]
    ports = list(sorted(external_ports, key=lambda item: int(item.replace('Ethernet', ''))))

    if 'PORTCHANNEL_MEMBER' in config_facts:
        portchannel_members = []
        for _, v in config_facts['PORTCHANNEL_MEMBER'].items():
            portchannel_members += v.keys()
        ports_for_test = [x for x in ports if x not in portchannel_members]
    else:
        ports_for_test = ports

    # Select two interfaces for testing which are not in portchannel
    intf1 = ports_for_test[0]
    intf2 = ports_for_test[1]
    logger.info("Selected ints are {0} and {1}".format(intf1, intf2))

    intf1_indice = mg_facts['minigraph_ptf_indices'][intf1]
    intf2_indice = mg_facts['minigraph_ptf_indices'][intf2]

    asic.config_ip_intf(intf1, "10.10.1.2/28", "add")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "add")

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


