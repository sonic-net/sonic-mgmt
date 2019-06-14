import pytest
from ansible_host import ansible_host
from ptf import ptf_runner

def test_fdb(localhost, ansible_adhoc, testbed):
    """
    1. verify fdb forwarding in T0 topology.
    2. verify show mac command on DUT for learned mac.
    """

    if testbed['topo'] not in ['t0', 't0-64', 't0-116']:
        pytest.skip("unsupported testbed type")
    
    hostname = testbed['dut']
    ptf_hostname = testbed['ptf']

    duthost = ansible_host(ansible_adhoc, hostname)
    ptfhost = ansible_host(ansible_adhoc, ptf_hostname)

    host_facts  = duthost.setup()['ansible_facts']
    mg_facts = duthost.minigraph_facts(host=hostname)['ansible_facts']

    # remove existing IPs from PTF host 
    ptfhost.script("fdb/remove_ip.sh")

    # Set unique MACs to PTF interfaces
    res = ptfhost.script("fdb/change_mac.sh")

    root_dir   = "/root"

    ptfhost.copy(src="scripts/arp_responder.py", dest="/opt")
    extra_vars = { 'arp_responder_args': None }
    ptfhost.host.options['variable_manager'].extra_vars = extra_vars
    ptfhost.template(src="scripts/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    extra_vars = { 'mg_facts': mg_facts }
    ptfhost.host.options['variable_manager'].extra_vars = extra_vars
    ptfhost.template(src="fdb/fdb.j2", dest="{}/fdb_info.txt".format(root_dir))

    ptfhost.copy(src="ptftests", dest=root_dir)

    dummy_mac_prefix = "02:11:22:33"
    dummy_mac_number = 10
    vlan_member_count = sum([len(v['members']) for k, v in mg_facts['minigraph_vlans'].items()])

    duthost.command("sonic-clear fdb all")

    # run ptf test
    ptf_runner(ptfhost, \
               "ptftests",
               "fdb_test.FdbTest",
               platform_dir="ptftests",
               params={"testbed_type": "t0",
                      "router_mac": host_facts['ansible_Ethernet0']['macaddress'],
                      "fdb_info": "/root/fdb_info.txt",
                      "vlan_ip": mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                      "dummy_mac_prefix": dummy_mac_prefix,
                      "dummy_mac_number": dummy_mac_number },
               log_file="/tmp/fdb_test.FdbTest.log")

    res = duthost.command("show mac")
    
    dummy_mac_count = 0
    total_mac_count = 0
    for l in res['stdout_lines']:
        if dummy_mac_prefix in l.lower():
            dummy_mac_count += 1
        if "dynamic" in l.lower():
            total_mac_count += 1

    # Verify that the number of dummy MAC entries is expected
    assert dummy_mac_count == dummy_mac_number * vlan_member_count

    # Verify that total number of MAC entries is expected
    assert total_mac_count == dummy_mac_number * vlan_member_count + vlan_member_count

    duthost.command("sonic-clear fdb all")
