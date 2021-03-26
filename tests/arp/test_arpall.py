import logging
import pytest
import time
from datetime import datetime

from tests.arp.arp_utils import clear_dut_arp_cache
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)

def test_arp_unicast_reply(common_setup_teardown, intfs_for_test, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = intfs_for_test
    
    asichost = duthost.asic_instance(enum_frontend_asic_index)
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


def test_arp_expect_reply(common_setup_teardown, intfs_for_test, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = intfs_for_test
    
    asichost = duthost.asic_instance(enum_frontend_asic_index)
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


def test_arp_no_reply_other_intf(common_setup_teardown, intfs_for_test, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = intfs_for_test
    
    asichost = duthost.asic_instance(enum_frontend_asic_index)

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


def test_arp_no_reply_src_out_range(common_setup_teardown, intfs_for_test, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = intfs_for_test
    
    asichost = duthost.asic_instance(enum_frontend_asic_index)
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


def test_arp_garp_no_update(common_setup_teardown, intfs_for_test, enum_frontend_asic_index):
    duthost, ptfhost, router_mac = common_setup_teardown
    intf1, intf2, intf1_indice, intf2_indice = intfs_for_test
    
    asichost = duthost.asic_instance(enum_frontend_asic_index)
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

