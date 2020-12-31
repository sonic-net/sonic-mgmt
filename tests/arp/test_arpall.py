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

logger = logging.getLogger(__name__)


def collect_info(duthost):
    if duthost.facts['asic_type'] == "mellanox":
        logger.info('************* Collect information for debug *************')
        duthost.shell('ip link')
        duthost.shell('ip addr')
        duthost.shell('grep . /sys/class/net/Ethernet*/address', module_ignore_errors=True)
        duthost.shell('grep . /sys/class/net/PortChannel*/address', module_ignore_errors=True)



@pytest.fixture(scope="module")
def common_setup_teardown(duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")
    # Copy test files
    ptfhost.copy(src="ptftests", dest="/root")
    logging.info("router_mac {}".format(router_mac))
    yield duthost, ptfhost, router_mac

    logging.info("tearing down")
    config_reload(duthost, config_source='config_db', wait=180)


@pytest.fixture(scope='function')
def get_test_interfaces(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    asic = duthost.get_asic(enum_frontend_asic_index)
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


def test_arp_unicast_reply(common_setup_teardown, get_test_interfaces, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = get_test_interfaces
    
    asichost = duthost.get_asic(enum_frontend_asic_index)
    # Start PTF runner and send correct unicast arp packets
    clear_dut_arp_cache(duthost, asichost.cli_ns_option)
    params = {
        'acs_mac': router_mac,
        'port': intf1_indice
    }
    log_file = "/tmp/arptest.VerifyUnicastARPReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.VerifyUnicastARPReply", '/root/ptftests', params=params, log_file=log_file)

    # Get DUT arp table
    switch_arptable = asichost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:00')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)


def test_arp_expect_reply(common_setup_teardown, get_test_interfaces, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = get_test_interfaces
    
    asichost = duthost.get_asic(enum_frontend_asic_index)
    params = {
        'acs_mac': router_mac,
        'port': intf1_indice
    }

    # Start PTF runner and send correct arp packets
    clear_dut_arp_cache(duthost, asichost.cli_ns_option)
    log_file = "/tmp/arptest.ExpectReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.ExpectReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)


def test_arp_no_reply_other_intf(common_setup_teardown, get_test_interfaces, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = get_test_interfaces
    
    asichost = duthost.get_asic(enum_frontend_asic_index)

    # Check DUT won't reply ARP and install ARP entry when ARP request coming from other interfaces
    clear_dut_arp_cache(duthost, asichost.cli_ns_option)
    intf2_params = {
        'acs_mac': router_mac,
        'port': intf2_indice
    }
    log_file = "/tmp/arptest.SrcOutRangeNoReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.SrcOutRangeNoReply", '/root/ptftests', params=intf2_params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.4')


def test_arp_no_reply_src_out_range(common_setup_teardown, get_test_interfaces, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = get_test_interfaces
    
    asichost = duthost.get_asic(enum_frontend_asic_index)
    params = {
        'acs_mac': router_mac,
        'port': intf1_indice
    }

    # Check DUT won't reply ARP and install ARP entry when src address is not in interface subnet range
    clear_dut_arp_cache(duthost, asichost.cli_ns_option)
    log_file = "/tmp/arptest.SrcOutRangeNoReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.SrcOutRangeNoReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.22')


def test_arp_garp_no_update(common_setup_teardown, get_test_interfaces, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = get_test_interfaces
    
    asichost = duthost.get_asic(enum_frontend_asic_index)
    params = {
        'acs_mac': router_mac,
        'port': intf1_indice
    }

    # Test Gratuitous ARP behavior, no Gratuitous ARP installed when arp was not resolved before
    clear_dut_arp_cache(duthost, asichost.cli_ns_option)
    log_file = "/tmp/arptest.GarpNoUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpNoUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    for ip in switch_arptable['arptable']['v4'].keys():
        pytest_assert(ip != '10.10.1.7')

    # Test Gratuitous ARP update case, when received garp, no arp reply, update arp table if it was solved before
    log_file = "/tmp/arptest.ExpectReply.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.ExpectReply", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:06:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)

    time.sleep(2)

    log_file = "/tmp/arptest.GarpUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = asichost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:00:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] == intf1)


def clear_dut_arp_cache(duthost, ns_option):
    duthost.shell('ip -stats {} neigh flush all'.format(ns_option))


def get_po(mg_facts, intf):
    for k, v in mg_facts['minigraph_portchannels'].iteritems():
        if intf in v['members']:
            return k
    return None

