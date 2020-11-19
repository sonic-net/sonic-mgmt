import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, rand_one_dut_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


def test_lldp(duthosts, rand_one_dut_hostname, localhost, collect_techsupport, tbinfo):
    """ verify the LLDP message on DUT """
    duthost = duthosts[rand_one_dut_hostname]

    mg_facts  = duthost.get_extended_minigraph_facts(tbinfo)
    lldp_facts = duthost.lldp()['ansible_facts']

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


def test_lldp_neighbor(duthosts, rand_one_dut_hostname, localhost, eos,
                       collect_techsupport, loganalyzer, tbinfo):
    """ verify LLDP information on neighbors """
    duthost = duthosts[rand_one_dut_hostname]

    if loganalyzer:
        loganalyzer.ignore_regex.extend([
            ".*ERR syncd#syncd: :- check_fdb_event_notification_data.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb \
                notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was \
                not sent since it contain invalid OIDs, bug.*",
        ])

    mg_facts  = duthost.get_extended_minigraph_facts(tbinfo)
    res = duthost.shell("docker exec -i lldp lldpcli show chassis | grep \"SysDescr:\" | sed -e 's/^\\s*SysDescr:\\s*//g'")
    dut_system_description = res['stdout']
    lldp_facts = duthost.lldp()['ansible_facts']
    host_facts  = duthost.setup()['ansible_facts']

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
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

        nei_lldp_facts = localhost.lldp_facts(host=hostip, version='v2c', community=eos['snmp_rocommunity'])['ansible_facts']
        print nei_lldp_facts
        neighbor_interface = v['port']['ifname']
        # Verify the published DUT system name field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name'] == duthost.hostname
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
