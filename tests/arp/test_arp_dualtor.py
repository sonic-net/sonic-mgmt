import pytest

from datetime import datetime
from tests.arp.arp_utils import clear_dut_arp_cache
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]


@pytest.mark.topology(('t0', 'dualtor'))
def test_arp_garp_enabled(intfs_for_test, ptfhost):
    intf1, intf1_indice, intf2, intf2_indice, intf_facts, mg_facts, duthost = intfs_for_test
    params = {
        'acs_mac': intf_facts['ansible_interface_facts'][intf1]['macaddress'],
        'port': intf1_indice
    }
    clear_dut_arp_cache(duthost)

    vlan_intfs = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']['VLAN_INTERFACE'].keys()
    garp_enable_cmd = 'redis-cli -n 4 HSET "VLAN_INTERFACE|{}" grat_arp enabled'
    for vlan in vlan_intfs:
        res = duthost.shell(garp_enable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to enable GARP for {}".format(vlan))

        res = duthost.shell("cat /proc/sys/net/ipv4/conf/Vlan1000/arp_accept")

        print(res['stdout'])

    log_file = "/tmp/arptest.GarpEnabledUpdate.{0}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(ptfhost, 'ptftests', "arptest.GarpEnabledUpdate", '/root/ptftests', params=params, log_file=log_file)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['macaddress'] == '00:00:07:08:09:0a')
    pytest_assert(switch_arptable['arptable']['v4']['10.10.1.3']['interface'] in vlan_intfs)
