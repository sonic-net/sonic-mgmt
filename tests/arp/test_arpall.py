import logging
import pytest
import time
from datetime import datetime

from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common import config_reload

pytestmark = [
    pytest.mark.topology('t1')
]

@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    int_facts = duthost.interface_facts()['ansible_facts']

    ports = list(sorted(mg_facts['minigraph_ports'].keys(), key=lambda item: int(item.replace('Ethernet', ''))))

    # Select port index 0 & 1 two interfaces for testing
    intf1 = ports[0]
    intf2 = ports[1]
    logging.info("Selected ints are {0} and {1}".format(intf1, intf2))

    intf1_indice = mg_facts['minigraph_port_indices'][intf1]
    intf2_indice = mg_facts['minigraph_port_indices'][intf2]

    po1 = get_po(mg_facts, intf1)
    po2 = get_po(mg_facts, intf2)

    try:
        # Make sure selected interfaces are not in portchannel
        if po1 is not None:
            duthost.shell('config portchannel member del {0} {1}'.format(po1, intf1))
            duthost.shell('config interface startup {0}'.format(intf1))

        if po2 is not None:
            duthost.shell('config portchannel member del {0} {1}'.format(po2, intf2))
            duthost.shell('config interface startup {0}'.format(intf2))

        # Change SONiC DUT interface IP to test IP address
        duthost.shell('config interface ip add {0} 10.10.1.2/28'.format(intf1))
        duthost.shell('config interface ip add {0} 10.10.1.20/28'.format(intf2))

        if (po1 is not None) or (po2 is not None):
            time.sleep(40)

        # Copy test files
        ptfhost.copy(src="ptftests", dest="/root")

        yield duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice
    finally:
        # Recover DUT interface IP address
        config_reload(duthost, config_source='config_db', wait=120)

def test_arp_unicast_reply(common_setup_teardown):
    duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice = common_setup_teardown

    # Start PTF runner and send correct unicast arp packets
    clear_dut_arp_cache(duthost)
    params = {
        'acs_mac': int_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }
    log_file = "/tmp/arptest.VerifyUnicastARPReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.VerifyUnicastARPReply", '/root/ptftests', params=params, log_file=log_file)

    # Get DUT arp table
    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:00')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)

def test_arp_expect_reply(common_setup_teardown):
    duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice = common_setup_teardown
    params = {
        'acs_mac': int_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }

    # Start PTF runner and send correct arp packets
    clear_dut_arp_cache(duthost)
    log_file = "/tmp/arptest.ExpectReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.ExpectReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)

def test_arp_no_reply_other_intf(common_setup_teardown):
    duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice = common_setup_teardown

    # Check DUT won't reply ARP and install ARP entry when ARP request coming from other interfaces
    clear_dut_arp_cache(duthost)
    intf2_params = {
        'acs_mac': int_facts['ansible_interface_facts'][intf2]['macaddress'],
        'port': intf2_indice
    }
    log_file = "/tmp/arptest.SrcOutRangeNoReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.SrcOutRangeNoReply", '/root/ptftests', params=intf2_params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.4')

def test_arp_no_reply_src_out_range(common_setup_teardown):
    duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice = common_setup_teardown
    params = {
        'acs_mac': int_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }

    # Check DUT won't reply ARP and install ARP entry when src address is not in interface subnet range
    clear_dut_arp_cache(duthost)
    log_file = "/tmp/arptest.SrcOutRangeNoReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.SrcOutRangeNoReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.22')

def test_arp_garp_no_update(common_setup_teardown):
    duthost, ptfhost, int_facts, intf1, intf2, intf1_indice, intf2_indice = common_setup_teardown
    params = {
        'acs_mac': int_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }

    # Test Gratuitous ARP behavior, no Gratuitous ARP installed when arp was not resolved before
    clear_dut_arp_cache(duthost)
    log_file = "/tmp/arptest.GarpNoUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpNoUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.7')

    # Test Gratuitous ARP upate case, when received garp, no arp reply, update arp table if it was solved before
    log_file = "/tmp/arptest.ExpectReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.ExpectReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)

    time.sleep(2)

    log_file = "/tmp/arptest.GarpUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:00:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)

def clear_dut_arp_cache(duthost):
    duthost.shell('ip -stats neigh flush all')

def get_po(mg_facts, intf):
    for k, v in mg_facts['minigraph_portchannels'].iteritems():
        if intf in v['members']:
            return k
    return None

