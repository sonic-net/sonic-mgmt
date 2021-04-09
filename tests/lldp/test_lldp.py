import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


def test_lldp(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, collect_techsupport_all_duts, enum_frontend_asic_index):
    """ verify the LLDP message on DUT """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
    lldpctl_facts = duthost.lldpctl_facts(asic_instance_id=enum_frontend_asic_index, skip_interface_pattern_list=["eth0", "Ethernet-BP"])['ansible_facts']
    for k, v in lldpctl_facts['lldpctl'].items():
        # Compare the LLDP neighbor name with minigraph neigbhor name (exclude the management port)
        assert v['chassis']['name'] == config_facts['DEVICE_NEIGHBOR'][k]['name']
        # Compare the LLDP neighbor interface with minigraph neigbhor interface (exclude the management port)
        assert v['port']['ifname'] == config_facts['DEVICE_NEIGHBOR'][k]['port']


def test_lldp_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, eos,
                       collect_techsupport_all_duts, loganalyzer, enum_frontend_asic_index):
    """ verify LLDP information on neighbors """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if loganalyzer:
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend([
            ".*ERR syncd#syncd: :- check_fdb_event_notification_data.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb \
                notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was \
                not sent since it contain invalid OIDs, bug.*",
        ])

    res = duthost.shell("docker exec -i lldp lldpcli show chassis | grep \"SysDescr:\" | sed -e 's/^\\s*SysDescr:\\s*//g'")
    dut_system_description = res['stdout']
    lldpctl_facts = duthost.lldpctl_facts(asic_instance_id=enum_frontend_asic_index, skip_interface_pattern_list=["eth0", "Ethernet-BP"])['ansible_facts']
    host_facts  = duthost.setup()['ansible_facts']
    config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
 
    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})

    for k, v in lldpctl_facts['lldpctl'].items():
        try:
            hostip = v['chassis']['mgmt-ip']
        except:
            logger.info("Neighbor device {} does not sent management IP via lldp".format(v['chassis']['name']))
            hostip = nei_meta[v['chassis']['name']]['mgmt_addr']

        nei_lldp_facts = localhost.lldp_facts(host=hostip, version='v2c', community=eos['snmp_rocommunity'])['ansible_facts']
        neighbor_interface = v['port']['ifname']
        # Verify the published DUT system name field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name'] == duthost.hostname
        # Verify the published DUT chassis id field is not empty
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == \
                "0x%s" % (host_facts['ansible_eth0']['macaddress'].replace(':', ''))
        # Verify the published DUT system description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_desc'] == dut_system_description
        # Verify the published DUT port id field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_id'] == config_facts['PORT'][k]['alias']
        # Verify the published DUT port description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_desc'] == config_facts['PORT'][k]['description']
