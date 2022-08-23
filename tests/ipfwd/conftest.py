import pytest
from ipaddress import ip_address
import logging
import json
import time
from tests.common import constants

logger = logging.getLogger(__name__)


'''
In case of multi-dut we need src_host_ip, src_router_ip, dst_host_ip, src_ptf_port_list, dst_ptf_port_list for the dut under test, 
to take care of that made changes in the testcase 
'''

def get_lag_facts(dut, lag_facts, switch_arptable, mg_facts, ignore_lags, enum_rand_one_frontend_asic_index, key='src'):
    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")

    # minigraph facts
    selected_lag_facts = {}
    up_lag = None
    for a_lag_name, a_lag_data in lag_facts['lags'].items():
        if a_lag_data['po_intf_stat'] == 'Up' and a_lag_name not in ignore_lags:
            if enum_rand_one_frontend_asic_index is not None and \
                    int(lag_facts['lags'][a_lag_name]['po_namespace_id']) != enum_rand_one_frontend_asic_index:
                    continue
            # We found a portchannel that is up.
            up_lag = a_lag_name
            selected_lag_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][intf] for intf in a_lag_data['po_config']['ports']]
            selected_lag_facts[key + '_router_mac'] =  dut.asic_instance(enum_rand_one_frontend_asic_index).get_router_mac()
            for intf in mg_facts['minigraph_portchannel_interfaces']:
                if dut.is_backend_portchannel(intf['attachto'], mg_facts):
                    continue 
                if intf['attachto'] == up_lag:
                    addr = ip_address(unicode(intf['addr']))
                    selected_lag_facts[key + '_router_intf_name'] = intf['attachto']
                    if addr.version == 4:
                        selected_lag_facts[key + '_router_ipv4'] = intf['addr']
                        selected_lag_facts[key + '_host_ipv4'] = intf['peer_addr']
                        selected_lag_facts[key + '_host_mac'] = switch_arptable['arptable']['v4'][intf['peer_addr']]['macaddress']
                    elif addr.version == 6:
                        selected_lag_facts[key + '_router_ipv6'] = intf['addr']
                        selected_lag_facts[key + '_host_ipv6'] = intf['peer_addr']
            logger.info("{} lag is {}".format(key, up_lag))
            break

    return up_lag, selected_lag_facts


def get_port_facts(dut, mg_facts, port_status, switch_arptable, ignore_intfs, enum_rand_one_frontend_asic_index, key='src'):
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
    if is_backend_topology:
        interfaces = mg_facts['minigraph_vlan_sub_interfaces']
    else:
        interfaces = mg_facts['minigraph_interfaces']

    if not interfaces:
        pytest.fail("interfaces is not defined.")

    selected_port_facts = {}
    up_port = None
    for a_intf_name, a_intf_data in port_status['int_status'].items():
        if dut.is_backend_port(a_intf_name, mg_facts):
            continue
        if a_intf_data['oper_state'] == 'up' and a_intf_name not in ignore_intfs:
            # Got a port that is up and not already used.
            for intf in interfaces:
                attachto_match = False
                if is_backend_topology:
                    # e.g. a_inft_name: 'Ethernet8' attachto:'Ethernet8.10'
                    attachto_match = (a_intf_name + constants.VLAN_SUB_INTERFACE_SEPARATOR) in intf['attachto']
                else:
                    attachto_match = intf['attachto'] == a_intf_name

                if attachto_match:
                    up_port = a_intf_name
                    selected_port_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][a_intf_name]]
                    selected_port_facts[key + '_router_mac'] = dut.asic_instance(enum_rand_one_frontend_asic_index).get_router_mac()
                    addr = ip_address(unicode(intf['addr']))
                    selected_port_facts[key + '_router_intf_name'] = intf['attachto']
                    if addr.version == 4:
                        selected_port_facts[key + '_router_ipv4'] = intf['addr']
                        selected_port_facts[key + '_host_ipv4'] = intf['peer_addr']
                        selected_port_facts[key + '_host_mac'] = switch_arptable['arptable']['v4'][intf['peer_addr']]['macaddress']
                    elif addr.version == 6:
                        selected_port_facts[key + '_router_ipv6'] = intf['addr']
                        selected_port_facts[key + '_host_ipv6'] = intf['peer_addr']
            if up_port:
                logger.info("{} port is {}".format(key, up_port))
                break
    return up_port, selected_port_facts

def arptable_on_switch(dut, asic_host, mg_facts):
    """
    The arp table will be cleared in sanity_check for dualtor testbed, and it needs
    60 seconds (BGP keepalive timer) in maximum for neigh to be rebuilt.
    """
    TIMEOUT = 70
    while TIMEOUT >= 0:
        all_rebuilt = True
        switch_arptable = asic_host.switch_arptable()['ansible_facts']
        for intf in mg_facts['minigraph_portchannel_interfaces']:
            if dut.is_backend_portchannel(intf['attachto'], mg_facts):
	        continue 
            peer_addr = intf['peer_addr']
            if ip_address(peer_addr).version == 4 and peer_addr not in switch_arptable['arptable']['v4']:
                all_rebuilt = False
                break
            if ip_address(peer_addr).version == 6 and peer_addr not in switch_arptable['arptable']['v6']:
                all_rebuilt = False
                break
        if all_rebuilt:
            return switch_arptable
        time.sleep(5)
        TIMEOUT -= 5
    return None
    

@pytest.fixture(scope='function')
def gather_facts(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    facts = {}

    logger.info("Gathering facts on DUT ...")
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    # Use the arp table to get the mac address of the host (VM's) instead of lldp_facts as that is was is used
    # by the DUT to forward traffic - regardless of lag or port.

    switch_arptable = arptable_on_switch(duthost, asichost, mg_facts)
    if not switch_arptable:
        pytest.fail("ARP table is not rebuilt in given time")

    used_intfs = set()
    src = None  # Name of lag or interface that is is up
    dst = None  # Name of lag or interface that is is up

    # if minigraph_portchannel_interfaces is not empty - topology with lag - check if we have 2 lags that are 'Up'
    if mg_facts['minigraph_portchannel_interfaces']:
        # Get lag facts from the DUT to check which ag is up
        lag_facts = duthost.lag_facts(host=duthost.hostname)[
            'ansible_facts']['lag_facts']
        src, src_lag_facts = get_lag_facts(
            duthost, lag_facts, switch_arptable, mg_facts, used_intfs, enum_rand_one_frontend_asic_index, key='src')
        used_intfs.add(src)
        if src:
            facts.update(src_lag_facts)
            # We found a src lag, let see if we can find a dst lag
            dst, dst_lag_facts = get_lag_facts(
                duthost, lag_facts, switch_arptable, mg_facts, used_intfs, enum_rand_one_frontend_asic_index, key='dst')
            used_intfs.add(dst)
            facts.update(dst_lag_facts)

    if src is None or dst is None:
        # We didn't find 2 lags, lets check up interfaces
        port_status = asichost.show_interface(command='status')['ansible_facts']
        if src is None:
            src, src_port_facts = get_port_facts(duthost, mg_facts, port_status, switch_arptable, used_intfs, enum_rand_one_frontend_asic_index, key='src')
            used_intfs.add(src)
            facts.update(src_port_facts)

        if dst is None:
            dst, dst_port_facts = get_port_facts(duthost, mg_facts, port_status, switch_arptable, used_intfs, enum_rand_one_frontend_asic_index, key='dst')
            facts.update(dst_port_facts)

    if src is None or dst is None:
        pytest.fail("Did not find 2 lag or interfaces that are up on host {}".format(duthost.hostname))
    logger.info("gathered_new_facts={}".format(json.dumps(facts, indent=2)))

    yield facts
