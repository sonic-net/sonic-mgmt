import pytest
import time
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from datetime import datetime
from ipaddress import ip_address
import json
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

'''
In case of multi-dut we need src_host_ip, src_router_ip, dst_host_ip, src_ptf_port_list, dst_ptf_port_list for the dut under test, 
to take care of that made changes in the testcase 
'''
def get_lag_facts(dut, lag_facts, mg_facts, ignore_lags, test_facts, key='src'):
    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")

    # minigraph facts
    up_lag = None
    for a_lag_name, a_lag_data in lag_facts['lags'].items():
        if a_lag_data['po_intf_stat'] == 'Up' and a_lag_name not in ignore_lags:
            # We found a portchannel that is up.
            up_lag = a_lag_name
            test_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][intf] for intf in a_lag_data['po_config']['ports']]
            for intf in mg_facts['minigraph_portchannel_interfaces']:
                if intf['attachto'] == up_lag:
                    addr = ip_address(unicode(intf['addr']))
                    if addr.version == 4:
                        test_facts[key + '_router_ip'] = intf['addr']
                        test_facts[key + '_host_ip'] = intf['peer_addr']
                        break
            logger.info("{} lag is {}".format(key, up_lag))
            break

    return up_lag


def get_port_facts(dut, mg_facts, port_status, ignore_intfs, test_facts, key='src'):
    if not mg_facts['minigraph_interfaces']:
        pytest.fail("minigraph_interfaces is not defined.")

    up_port = None
    for a_intf_name, a_intf_data in port_status['int_status'].items():
        if a_intf_data['oper_state'] == 'up' and a_intf_name not in ignore_intfs:
            # Got a port that is up and not already used.
            for intf in mg_facts['minigraph_interfaces']:
                if intf['attachto'] == a_intf_name:
                    up_port = a_intf_name
                    addr = ip_address(unicode(intf['addr']))
                    if addr.version == 4:
                        test_facts[key + '_router_ip'] = intf['addr']
                        test_facts[key + '_host_ip'] = intf['peer_addr']
                        test_facts[key + '_port_ids'] = [mg_facts['minigraph_ptf_indices'][a_intf_name]]
                        break
            if up_port:
                logger.info("{} port is {}".format(key, up_port))
                break
    return up_port

@pytest.fixture(scope='function')
def gather_facts(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    facts = {}

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t0', 't1', 't2'):
        pytest.skip("Unsupported topology")

    logger.info("Gathering facts on DUT ...")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    facts = {}
    used_intfs = set()
    src = None      # Name of lag or interface that is is up
    dst = None      # Name of lag or interface that is is up

    # if minigraph_portchannel_interfaces is not empty - topology with lag - check if we have 2 lags that are 'Up'
    if mg_facts['minigraph_portchannel_interfaces']:
        # Get lag facts from the DUT to check which ag is up
        lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
        src = get_lag_facts(duthost, lag_facts, mg_facts, used_intfs, facts, key='src')
        used_intfs.add(src)
        if src:
            # We found a src lag, let see if we can find a dst lag
            dst = get_lag_facts(duthost, lag_facts, mg_facts, used_intfs, facts, key='dst')
            used_intfs.add(dst)

    if src is None or dst is None:
        # We didn't find 2 lags, lets check up interfaces
        port_status = duthost.show_interface(command='status')['ansible_facts']
        if src is None:
            src = get_port_facts(duthost, mg_facts, port_status, used_intfs, facts, key='src')
            used_intfs.add(src)
        if dst is None:
            dst = get_port_facts(duthost, mg_facts, port_status, used_intfs, facts, key='dst')

    if src is None or dst is None:
        pytest.fail("Did not find 2 lag or interfaces that are up on host {}".duthost.hostname)

    logger.info("gathered_facts={}".format(json.dumps(facts, indent=2)))

    yield facts

@pytest.mark.parametrize("mtu", [1514,9114])
def test_mtu(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, mtu, gather_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu,
                       "src_host_ip": gather_facts['src_host_ip'],
                       "src_router_ip": gather_facts['src_router_ip'],
                       "dst_host_ip": gather_facts['dst_host_ip'],
                       "src_ptf_port_list": gather_facts['src_port_ids'],
                       "dst_ptf_port_list": gather_facts['dst_port_ids']
                       },
               log_file=log_file,
               socket_recv_size=16384)
