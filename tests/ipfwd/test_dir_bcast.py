import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from datetime import datetime

pytestmark = [
    pytest.mark.topology('t0')
]

def test_dir_bcast(duthost, ptfhost, testbed, fib):
    support_testbed_types = frozenset(['t0', 't0-16', 't0-56', 't0-64', 't0-64-32', 't0-116'])
    testbed_type = testbed['topo']['name']
    if testbed_type not in support_testbed_types:
        pytest.skip("Not support given test bed type %s" % testbed_type)

    # Copy VLAN information file to PTF-docker
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    extra_vars = {
        'minigraph_vlan_interfaces': mg_facts['minigraph_vlan_interfaces'],
        'minigraph_vlans':           mg_facts['minigraph_vlans'],
        'minigraph_port_indices':    mg_facts['minigraph_port_indices']
    }
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="../ansible/roles/test/templates/fdb.j2", dest="/root/vlan_info.txt")

    # Start PTF runner
    host_facts = duthost.setup()['ansible_facts']
    params = {
        'testbed_type': testbed_type,
        'router_mac': host_facts['ansible_Ethernet0']['macaddress'],
        'vlan_info': '/root/vlan_info.txt'
    }
    log_file = "/tmp/dir_bcast.BcastTest.{}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(
        ptfhost,
        'ptftests',
        'dir_bcast_test.BcastTest',
        '/root/ptftests',
        params=params,
        log_file=log_file)
