import pytest
import re

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, enum_rand_one_per_hwsku_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("LLDP not supported on supervisor node")
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


@pytest.mark.bsl
def test_snmp_lldp(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, tbinfo):
    """
    Test checks for ieee802_1ab MIBs:
     - lldpLocalSystemData  1.0.8802.1.1.2.1.3
     - lldpLocPortTable     1.0.8802.1.1.2.1.3.7
     - lldpLocManAddrTable     1.0.8802.1.1.2.1.3.8

     - lldpRemTable  1.0.8802.1.1.2.1.4.1
     - lldpRemManAddrTable  1.0.8802.1.1.2.1.4.2

    For local data check if every OID has value
    For remote values check for availability for at least 80% of minigraph neighbors
    (similar to lldp test)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("LLDP not supported on supervisor node")
    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    snmp_facts = localhost.snmp_facts(host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"])['ansible_facts']
    for asic in duthost.asics:
        lldp_nei = []
        cfg_facts = asic.config_facts(host=duthost.hostname,
                                      source="persistent", verbose=False)['ansible_facts']
        if "PORT" in cfg_facts:
            for port, port_info_dict in cfg_facts["PORT"].items():
                if re.search('ARISTA', port_info_dict['description']):
                    lldp_nei.append(port)

    print snmp_facts['snmp_lldp']
    for k in ['lldpLocChassisIdSubtype', 'lldpLocChassisId', 'lldpLocSysName', 'lldpLocSysDesc']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    # Check if lldpLocPortTable is present for all ports
    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['name'] or "eth" in v['name']:
            for oid in ['lldpLocPortIdSubtype', 'lldpLocPortId', 'lldpLocPortDesc']:
                assert v.has_key(oid)
                assert "No Such Object currently exists" not in v[oid]

    # Check if lldpLocManAddrTable is present
    for k in ['lldpLocManAddrLen', \
               'lldpLocManAddrIfSubtype', \
               'lldpLocManAddrIfId', \
               'lldpLocManAddrOID']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    # Check if lldpRemTable is present
    active_intf = []
    for k, v in snmp_facts['snmp_interfaces'].items():
        if v.has_key("lldpRemChassisIdSubtype") and \
           v.has_key("lldpRemChassisId") and \
           v.has_key("lldpRemPortIdSubtype") and \
           v.has_key("lldpRemPortId") and \
           v.has_key("lldpRemPortDesc") and \
           v.has_key("lldpRemSysName") and \
           v.has_key("lldpRemSysDesc") and \
           v.has_key("lldpRemSysCapSupported") and \
           v.has_key("lldpRemSysCapEnabled"):
            active_intf.append(k)
    print "lldpRemTable: ", active_intf

    assert len(active_intf) >= len(lldp_nei) * 0.8

    # skip neighbors that do not send chassis information via lldp
    lldp_facts= {}
    for asic_id in duthost.get_asic_ids(): 
       lldp_facts_ns = duthost.lldpctl_facts(asic_instance_id=asic_id)['ansible_facts']['lldpctl']
       if lldp_facts_ns is not None:
           lldp_facts.update(lldp_facts_ns)
    pattern = re.compile(r'^eth0|^Ethernet-IB')
    nei = [k for k, v in lldp_facts.items() if not re.match(pattern, k) and v['chassis'].has_key('mgmt-ip') ]
    print "neighbors {} send chassis management IP information".format(nei)

    # Check if lldpRemManAddrTable is present
    active_intf = []
    for k, v in snmp_facts['snmp_interfaces'].items():
        if v.has_key("lldpRemManAddrIfSubtype") and \
           v.has_key("lldpRemManAddrIfId") and \
           v.has_key("lldpRemManAddrOID") and \
           v['name'] != 'eth0' and 'Etherent-IB' not in v['name']:
            active_intf.append(k)
    print "lldpRemManAddrTable: ", active_intf

    assert len(active_intf) == len(nei)
