
import pytest
import logging
import ipaddress

from tests.common import config_reload

from test_voq_init import check_voq_interfaces

from tests.common.helpers.sonic_db import VoqDbCli, SonicDbKeyNotFound
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from test_voq_disrupts import check_bgp_neighbors
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

ADDR = ipaddress.IPv4Interface(u"50.1.1.1/24")


def test_cycle_voq_intf(duthosts, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Delete and recreate VOQ interface through config save/load.  Verify interface
    is removed after configdb reload and then recreated after loading initial minigraph.

    Args:
        duthosts: The duthosts fixture
        all_cfg_facts: all_cfg_facts fixture from voq conftest
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture from voq conftest

    """

    duthost = duthosts.frontend_nodes[0]
    for asic in duthost.asics:
        cfg_facts = all_cfg_facts[duthost.hostname][asic.asic_index]['ansible_facts']
        check_voq_interfaces(duthosts, duthost, asic, cfg_facts)

    intf_asic = duthost.asics[0]
    intf_config_facts = duthost.config_facts(source='persistent',
                                             asic_index=intf_asic.asic_index)['ansible_facts']
    portchannel = intf_config_facts['PORTCHANNEL'].keys()[0]
    portchannel_members = intf_config_facts['PORTCHANNEL'][portchannel].get('members')
    portchannel_ips = [x.split("/")[0].lower() for x in intf_config_facts['PORTCHANNEL_INTERFACE'][portchannel].keys()]
    bgp_nbrs_to_portchannel = []
    for a_bgp_neighbor in intf_config_facts['BGP_NEIGHBOR']:
        if intf_config_facts['BGP_NEIGHBOR'][a_bgp_neighbor]['local_addr'] in portchannel_ips:
            bgp_nbrs_to_portchannel.append(a_bgp_neighbor.lower())

    try:
        logger.info("remove ethernet from a portchannel to use for interface create")
        intf = portchannel_members[0]
        logging.info('Deleting lag members {} from lag {} on dut {}'
                     .format(portchannel_members, portchannel, duthost.hostname))
        for member in portchannel_members:
            duthost.shell("config portchannel {} member del {} {}"
                          .format(intf_asic.cli_ns_option, portchannel, member))

        logger.info("add an IP interface to a former member")
        cmd = "config interface {} ip add {} {}".format(intf_asic.cli_ns_option, intf, str(ADDR))
        logger.info("Execute: %s", cmd)
        duthost.shell(cmd)

        logger.info("Save and reload config")

        duthost.shell_cmds(cmds=["config save -y"])
        config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)
        pytest_assert(wait_until(300, 10, 0, check_bgp_neighbors, duthosts, bgp_nbrs_to_portchannel),
                      "All BGP's are not established after ports removed from LAG and IP added to one of them")
        logger.info("Check interfaces after add.")
        for asic in duthost.asics:
            new_cfgfacts = duthost.config_facts(source='persistent', asic_index='all')[asic.asic_index]['ansible_facts']
            check_voq_interfaces(duthosts, duthost, asic, new_cfgfacts)

        logger.info("Check interface on supervisor - should be present from chassis db.")
        if duthost.is_multi_asic and len(duthosts.supervisor_nodes) == 0:
            sup = duthost
        else:
            sup = duthosts.supervisor_nodes[0]
        voqdb = VoqDbCli(sup)

        key = "SYSTEM_INTERFACE|{}|{}|{}".format(intf_config_facts['DEVICE_METADATA']['localhost']['hostname'],
                                                 intf_config_facts['DEVICE_METADATA']['localhost']['asic_name'],
                                                 intf)

        voqdb.get_keys(key)

        logger.info("Remove an IP interface to a former member.")
        cmd = "config interface {} ip remove {} {}".format(intf_asic.cli_ns_option, intf, str(ADDR))
        logger.info("Execute: %s", cmd)
        duthost.shell(cmd)

        logger.info("Save and reload config")

        duthost.shell_cmds(cmds=["config save -y"])
        config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)
        pytest_assert(wait_until(300, 10, 0, check_bgp_neighbors, duthosts, bgp_nbrs_to_portchannel),
                      "All BGP's are not established after added IP removed from a LAG member")
        logger.info("check interface is gone after config reload")

        for asic in duthost.asics:
            new_cfgfacts = duthost.config_facts(source='persistent', asic_index='all')[asic.asic_index]['ansible_facts']
            check_voq_interfaces(duthosts, duthost, asic, new_cfgfacts)

        with pytest.raises(SonicDbKeyNotFound):
            voqdb.get_keys(key)
        logger.info("-- Interface {} deleted from chassisdb on supervisor card".format(key))

    finally:
        # restore interface from minigraph
        logger.info("Restore config from minigraph.")
        config_reload(duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True)
        pytest_assert(wait_until(300, 10, 0, check_bgp_neighbors, duthosts),
                      "All BGP's are not established after config reload from original minigraph")
        duthost.shell_cmds(cmds=["config save -y"])

        for asic in duthost.asics:
            new_cfgfacts = duthost.config_facts(source='persistent', asic_index='all')[asic.asic_index]['ansible_facts']
            check_voq_interfaces(duthosts, duthost, asic, new_cfgfacts)
