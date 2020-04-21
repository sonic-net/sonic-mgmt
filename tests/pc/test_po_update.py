import time
import pytest
import logging

def test_po_update(duthost):
    """
    test port channel add/deletion as well ip address configuration
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    int_facts = duthost.interface_facts()['ansible_facts']

    # Initialize portchannel
    if len(mg_facts['minigraph_portchannels'].keys()) == 0:
        pytest.skip("Skip test due to there is no portchannel exists in current topology.")

    portchannel = mg_facts['minigraph_portchannels'].keys()[0]
    tmp_portchannel = "PortChannel999"
    # Initialize portchannel_ip and portchannel_members
    portchannel_ip = int_facts['ansible_interface_facts'][portchannel]['ipv4']['address']
    portchannel_members = mg_facts['minigraph_portchannels'][portchannel]['members']
    # Initialize flags
    remove_portchannel_members = False
    remove_portchannel_ip = False
    create_tmp_portchannel = False
    add_tmp_portchannel_members = False
    add_tmp_portchannel_ip = False

    logging.info("portchannel=%s" % portchannel)
    logging.info("portchannel_ip=%s" % portchannel_ip)
    logging.info("portchannel_members=%s" % portchannel_members)

    try:
        if len(portchannel_members) == 0:
            pytest.skip("Skip test due to there is no portchannel member exists in current topology.")

        # Step 1: Remove portchannel members from portchannel
        for member in portchannel_members:
            duthost.shell("config portchannel member del %s %s" % (portchannel, member))
        remove_portchannel_members = True

        # Step 2: Remove portchannel ip from portchannel
        duthost.shell("config interface ip remove %s %s/31" % (portchannel, portchannel_ip))
        remove_portchannel_ip = True

        time.sleep(30)
        int_facts = duthost.interface_facts()['ansible_facts']
        assert not int_facts['ansible_interface_facts'][portchannel]['link']
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        assert bgp_facts['bgp_statistics']['ipv4_idle'] == 1

        # Step 3: Create tmp portchannel
        duthost.shell("config portchannel add %s" % tmp_portchannel)
        create_tmp_portchannel = True

        # Step 4: Add portchannel member to tmp portchannel
        for member in portchannel_members:
            duthost.shell("config portchannel member add %s %s" % (tmp_portchannel, member))
        add_tmp_portchannel_members = True

        # Step 5: Add portchannel ip to tmp portchannel
        duthost.shell("config interface ip add %s %s/31" % (tmp_portchannel, portchannel_ip))
        int_facts = duthost.interface_facts()['ansible_facts']
        assert int_facts['ansible_interface_facts'][tmp_portchannel]['ipv4']['address'] == portchannel_ip
        add_tmp_portchannel_ip = True

        time.sleep(30)
        int_facts = duthost.interface_facts()['ansible_facts']
        assert int_facts['ansible_interface_facts'][tmp_portchannel]['link']
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        assert bgp_facts['bgp_statistics']['ipv4_idle'] == 0
    finally:
        # Recover all states
        if add_tmp_portchannel_ip:
            duthost.shell("config interface ip remove %s %s/31" % (tmp_portchannel, portchannel_ip))

        time.sleep(5)
        if add_tmp_portchannel_members:
            for member in portchannel_members:
                duthost.shell("config portchannel member del %s %s" % (tmp_portchannel, member))

        time.sleep(5)
        if create_tmp_portchannel:
            duthost.shell("config portchannel del %s" % tmp_portchannel)
        if remove_portchannel_ip:
            duthost.shell("config interface ip add %s %s/31" % (portchannel, portchannel_ip))
        if remove_portchannel_members:
            for member in portchannel_members:
                duthost.shell("config portchannel member add %s %s" % (portchannel, member))

        time.sleep(30)
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        assert bgp_facts['bgp_statistics']['ipv4_idle'] == 0
