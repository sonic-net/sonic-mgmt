import pytest
import time
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from datetime import datetime

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

'''
In case of multi-dut we need src_host_ip, src_router_ip, dst_host_ip, src_ptf_port_list, dst_ptf_port_list for the dut under test, 
to take care of that made changes in the testcase 
'''

def lag_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_portchannels']:
        pytest.fail("minigraph_portchannels is not defined")

    # minigraph facts
    src_lag = mg_facts['minigraph_portchannel_interfaces'][0]['attachto']
    dst_lag = mg_facts['minigraph_portchannel_interfaces'][2]['attachto']
    logger.info("src_lag is {}, dst_lag is {}".format(src_lag, dst_lag))

    for intf in mg_facts['minigraph_portchannel_interfaces']:
        if intf['attachto'] == dst_lag:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['dst_router_ip'] = intf['addr']
                facts['dst_host_ip'] = intf['peer_addr']
        if intf['attachto'] == src_lag:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['src_router_ip'] = intf['addr']
                facts['src_host_ip'] = intf['peer_addr']

    facts['dst_port_ids'] = []
    for intf in mg_facts['minigraph_portchannels'][dst_lag]['members']:
        facts['dst_port_ids'].append(mg_facts['minigraph_ptf_indices'][intf])

    facts['src_port_ids'] = []
    for intf in mg_facts['minigraph_portchannels'][src_lag]['members']:
        facts['src_port_ids'].append(mg_facts['minigraph_ptf_indices'][intf])

    return facts


def port_facts(dut, mg_facts):
    facts = {}

    if not mg_facts['minigraph_interfaces']:
        pytest.fail("minigraph_interfaces is not defined.")

    # minigraph facts
    src_port = mg_facts['minigraph_interfaces'][0]['attachto']
    dst_port = mg_facts['minigraph_interfaces'][2]['attachto']
    logger.info("src_port is {}, dst_port is {}".format(src_port, dst_port))


    for intf in mg_facts['minigraph_interfaces']:
        if intf['attachto'] == dst_port:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['dst_router_ip'] = intf['addr']
                facts['dst_host_ip'] = intf['peer_addr']
        if intf['attachto'] == src_port:
            addr = ip_address(unicode(intf['addr']))
            if addr.version == 4:
                facts['src_router_ip'] = intf['addr']
                facts['src_host_ip'] = intf['peer_addr']

    facts['dst_port_ids'] = [mg_facts['minigraph_ptf_indices'][dst_port]]
    facts['src_port_ids'] = [mg_facts['minigraph_ptf_indices'][src_port]]

    return facts


@pytest.fixture(scope='function')
def gather_facts(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    facts = {}

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t0', 't1', 't2'):
        pytest.skip("Unsupported topology")

    logger.info("Gathering facts on DUT ...")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # if minigraph_portchannel_interfaces is not empty - topology with lag
    if mg_facts['minigraph_portchannel_interfaces']:
        facts = lag_facts(duthost, mg_facts)
    else:
        facts = port_facts(duthost, mg_facts)

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
