from ansible_host import AnsibleHost
import logging
import pytest

@pytest.fixture(scope="module", autouse=True)
def setup_check_topo(testbed):
    if testbed['topo']['type'] == 'ptf':
        pytest.skip('Unsupported topology')

logger = logging.getLogger(__name__)

def test_lldp(localhost, ansible_adhoc, testbed):
    """ verify the LLDP message on DUT """

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)

    mg_facts  = ans_host.minigraph_facts(host=hostname)['ansible_facts']
    lldp_facts = ans_host.lldp()['ansible_facts']

    minigraph_lldp_nei = {}
    for k, v in mg_facts['minigraph_neighbors'].items():
        if 'server' not in v['name'].lower():
            minigraph_lldp_nei[k] = v

    # Verify LLDP information is available on most interfaces
    assert len(lldp_facts['lldp']) > len(minigraph_lldp_nei) * 0.8

    for k, v in lldp_facts['lldp'].items():
        if k == 'eth0':
            continue
        # Compare the LLDP neighbor name with minigraph neigbhor name (exclude the management port)
        assert v['chassis']['name'] == minigraph_lldp_nei[k]['name']
        # Compare the LLDP neighbor interface with minigraph neigbhor interface (exclude the management port)
        assert v['port']['ifname'] == mg_facts['minigraph_neighbors'][k]['port']


def test_lldp_neighbor(localhost, ansible_adhoc, testbed, eos):
    """ verify LLDP information on neighbors """

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    mg_facts  = ans_host.minigraph_facts(host=hostname)['ansible_facts']
    res = ans_host.shell("docker exec -i lldp lldpcli show chassis | grep \"SysDescr:\" | sed -e 's/^\\s*SysDescr:\\s*//g'")
    dut_system_description = res['stdout']
    lldp_facts = ans_host.lldp()['ansible_facts']
    host_facts  = ans_host.setup()['ansible_facts']
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)

    config_facts  = ans_host.config_facts(host=hostname, source="running")['ansible_facts']
    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})

    for k, v in lldp_facts['lldp'].items():
        if k == 'eth0':
            # skip test on management interface
            continue

        try:
            hostip = v['chassis']['mgmt-ip']
        except:
            logger.info("Neighbor device {} does not sent management IP via lldp".format(v['chassis']['name']))
            hostip = nei_meta[v['chassis']['name']]['mgmt_addr']

        nei_lldp_facts = lhost.lldp_facts(host=hostip, version='v2c', community=eos['snmp_rocommunity'])['ansible_facts']
        print nei_lldp_facts
        neighbor_interface = v['port']['ifname']
        # Verify the published DUT system name field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name'] == hostname
        # Verify the published DUT chassis id field is not empty
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == \
                "0x%s" % (host_facts['ansible_eth0']['macaddress'].replace(':', ''))
        # Verify the published DUT system description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_desc'] == dut_system_description
        # Verify the published DUT port id field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_id'] == mg_facts['minigraph_ports'][k]['alias']
        # Verify the published DUT port description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_desc'] == \
                "%s:%s" % (mg_facts['minigraph_neighbors'][k]['name'], mg_facts['minigraph_neighbors'][k]['port'])
