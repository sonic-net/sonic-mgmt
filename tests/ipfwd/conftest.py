import pytest
from ipaddress import ip_address
import logging
import json


logger = logging.getLogger(__name__)


'''
In case of multi-dut we need src_host_ip, src_router_ip, dst_host_ip, src_ptf_port_list, dst_ptf_port_list for the dut under test, 
to take care of that made changes in the testcase 
'''

def get_lag_facts(dut, lag_facts, switch_arptable, mg_facts, ignore_lags, test_facts, key='src'):
    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")

    # minigraph facts
    up_lag = None
    for a_lag_name, a_lag_data in lag_facts['lags'].items():
        if a_lag_data['po_intf_stat'] == 'Up' and a_lag_name not in ignore_lags:
            # We found a portchannel that is up.
            up_lag = a_lag_name
            test_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][intf] for intf in a_lag_data['po_config']['ports']]
            test_facts[key + '_router_mac'] = dut.facts['router_mac']
            for intf in mg_facts['minigraph_portchannel_interfaces']:
                if intf['attachto'] == up_lag:
                    addr = ip_address(unicode(intf['addr']))
                    if addr.version == 4:
                        test_facts[key + '_router_ipv4'] = intf['addr']
                        test_facts[key + '_host_ipv4'] = intf['peer_addr']
                        test_facts[key + '_host_mac'] = switch_arptable['arptable']['v4'][intf['peer_addr']]['macaddress']
                    elif addr.version == 6:
                        test_facts[key + '_router_ipv6'] = intf['addr']
                        test_facts[key + '_host_ipv6'] = intf['peer_addr']
            logger.info("{} lag is {}".format(key, up_lag))
            break

    return up_lag


def get_port_facts(dut, mg_facts, port_status, switch_arptable, ignore_intfs, test_facts, key='src'):
    if not mg_facts['minigraph_interfaces']:
        pytest.fail("minigraph_interfaces is not defined.")

    up_port = None
    for a_intf_name, a_intf_data in port_status['int_status'].items():
        if a_intf_data['oper_state'] == 'up' and a_intf_name not in ignore_intfs:
            # Got a port that is up and not already used.
            for intf in mg_facts['minigraph_interfaces']:
                if intf['attachto'] == a_intf_name:
                    up_port = a_intf_name
                    test_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][a_intf_name]]
                    test_facts[key + '_router_mac'] = dut.facts['router_mac']
                    addr = ip_address(unicode(intf['addr']))
                    if addr.version == 4:
                        test_facts[key + '_router_ipv4'] = intf['addr']
                        test_facts[key + '_host_ipv4'] = intf['peer_addr']
                        test_facts[key + '_host_mac'] = switch_arptable['arptable']['v4'][intf['peer_addr']]['macaddress']
                    elif addr.version == 6:
                        test_facts[key + '_router_ipv6'] = intf['addr']
                        test_facts[key + '_host_ipv6'] = intf['peer_addr']
            if up_port:
                logger.info("{} port is {}".format(key, up_port))
                break
    return up_port

@pytest.fixture(scope='function')
def gather_facts(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    facts = {}

    logger.info("Gathering facts on DUT ...")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Use the arp table to get the mac address of the host (VM's) instead of lldp_facts as that is was is used
    # by the DUT to forward traffic - regardless of lag or port.
    switch_arptable = duthost.switch_arptable()['ansible_facts']
    used_intfs = set()
    src = None  # Name of lag or interface that is is up
    dst = None  # Name of lag or interface that is is up

    # if minigraph_portchannel_interfaces is not empty - topology with lag - check if we have 2 lags that are 'Up'
    if mg_facts['minigraph_portchannel_interfaces']:
        # Get lag facts from the DUT to check which ag is up
        new_lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
        src = get_lag_facts(duthost, new_lag_facts, switch_arptable, mg_facts, used_intfs, facts, key='src')
        used_intfs.add(src)
        if src:
            # We found a src lag, let see if we can find a dst lag
            dst = get_lag_facts(duthost, new_lag_facts, switch_arptable, mg_facts, used_intfs, facts, key='dst')
            used_intfs.add(dst)

    if src is None or dst is None:
        # We didn't find 2 lags, lets check up interfaces
        port_status = duthost.show_interface(command='status')['ansible_facts']
        if src is None:
            src = get_port_facts(duthost, mg_facts, port_status, switch_arptable, used_intfs, facts, key='src')
            used_intfs.add(src)
        if dst is None:
            dst = get_port_facts(duthost, mg_facts, port_status, switch_arptable, used_intfs, facts, key='dst')

    if src is None or dst is None:
        pytest.fail("Did not find 2 lag or interfaces that are up on host {}".duthost.hostname)
    logger.info("gathered_new_facts={}".format(json.dumps(facts, indent=2)))

    yield facts
