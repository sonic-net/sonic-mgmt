from ansible_host import AnsibleHost

def test_snmp_interfaces(ansible_adhoc, testbed, creds):
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

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']

    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"])['ansible_facts']
    mg_facts   = ans_host.minigraph_facts(host=hostname)['ansible_facts']

    print snmp_facts['snmp_lldp']
    for k in ['lldpLocChassisIdSubtype', 'lldpLocChassisId', 'lldpLocSysName', 'lldpLocSysDesc']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    # Check if lldpLocPortTable is present for all ports
    for k, v in snmp_facts['snmp_interfaces'].items():
        if "Ethernet" in v['name'] or "eth" in v['name']: 
            for oid in ['lldpLocPortNum', 'lldpLocPortIdSubtype', 'lldpLocPortId', 'lldpLocPortDesc']:
                assert v.has_key(oid)
                assert "No Such Object currently exists" not in v[oid]

    # Check if lldpLocManAddrTable is present
    for k in ['lldpLocManAddrSubtype', \
               'lldpLocManAddr', \
               'lldpLocManAddrLen', \
               'lldpLocManAddrIfSubtype', \
               'lldpLocManAddrIfId', \
               'lldpLocManAddrOID']:
        assert snmp_facts['snmp_lldp'][k]
        assert "No Such Object currently exists" not in snmp_facts['snmp_lldp'][k]

    minigraph_lldp_nei = []
    for k, v in mg_facts['minigraph_neighbors'].items():
        if "server" not in v['name'].lower():
            minigraph_lldp_nei.append(k)
    print minigraph_lldp_nei
 
    # Check if lldpRemTable is present
    active_intf = []
    for k, v in snmp_facts['snmp_interfaces'].items():
        if v.has_key("lldpRemTimeMark") and \
           v.has_key("lldpRemLocalPortNum") and \
           v.has_key("lldpRemIndex") and \
           v.has_key("lldpRemChassisIdSubtype") and \
           v.has_key("lldpRemChassisId") and \
           v.has_key("lldpRemPortIdSubtype") and \
           v.has_key("lldpRemPortId") and \
           v.has_key("lldpRemPortDesc") and \
           v.has_key("lldpRemSysName") and \
           v.has_key("lldpRemSysDesc") and \
           v.has_key("lldpRemSysCapSupported") and \
           v.has_key("lldpRemSysCapEnabled"):
            active_intf.append(k)
    print active_intf

    assert len(active_intf) >= len(minigraph_lldp_nei) * 0.8 

    # Check if lldpRemManAddrTable is present
    active_intf = []
    for k, v in snmp_facts['snmp_interfaces'].items():
        if v.has_key("lldpRemManAddrSubtype") and \
           v.has_key("lldpRemManAddr") and \
           v.has_key("lldpRemManAddrIfSubtype") and \
           v.has_key("lldpRemManAddrIfId") and \
           v.has_key("lldpRemManAddrOID"):
            active_intf.append(k)
    print active_intf

    assert len(active_intf) >= len(minigraph_lldp_nei) * 0.8 
