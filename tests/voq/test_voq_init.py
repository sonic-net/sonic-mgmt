"""Test initialization of VoQ objects, switch, system ports, router interfaces, neighbors, inband port."""
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

from tests.common.helpers.redis import AsicDbCli, RedisKeyNotFound
from tests.common.errors import RunAnsibleModuleFail
from voq_helpers import check_local_neighbor, check_voq_remote_neighbor, get_sonic_mac, get_neighbor_mac
from voq_helpers import check_local_neighbor_asicdb, get_device_system_ports, get_inband_info, get_port_by_ip
from voq_helpers import check_rif_on_sup, check_voq_neighbor_on_sup, find_system_port

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def chassis_facts(duthosts):
    """
    Fixture to add some items to host facts from inventory file.
    """
    for a_host in duthosts.nodes:

        if len(duthosts.supervisor_nodes) > 0:
            out = a_host.command("cat /etc/sonic/card_details.json")
            card_details = json.loads(out['stdout'])
            if 'slot_num' in card_details:
                a_host.facts['slot_num'] = card_details['slot_num']


@pytest.fixture(scope="module")
def nbrhosts_facts(nbrhosts):
    nbrhosts_facts = {}
    for a_vm in nbrhosts:
        try:
            vm_facts = nbrhosts[a_vm]['host'].eos_facts()
        except RunAnsibleModuleFail:
            logger.error("VM: %s is down, skipping config fetching.", a_vm)
            continue
        logger.debug("vm facts: {}".format(json.dumps(vm_facts, indent=4)))
        nbrhosts_facts[a_vm] = vm_facts
    return nbrhosts_facts


def test_voq_switch_create(duthosts):
    """Compare the config facts with the asic db for switch:
    * Verify ASIC_DB get all system ports referenced in configDB created on all hosts and ASICs.
    * Verify object creation and values of port attributes.
    """

    switch_id_list = []
    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_facts = cfg_facts['DEVICE_METADATA']['localhost']
            asicdb = AsicDbCli(asic)

            switchkey = asicdb.get_switch_key()
            logger.info("Checking switch %s", switchkey)
            check_list = {
                "max_cores": "SAI_SWITCH_ATTR_MAX_SYSTEM_CORES",
                "switch_id": "SAI_SWITCH_ATTR_SWITCH_ID"}
            for k in check_list:
                asicdb.get_and_check_key_value(switchkey, dev_facts[k], field=check_list[k])

            pytest_assert(dev_facts["switch_id"] not in switch_id_list,
                          "Switch ID: %s has been used more than once" % dev_facts["switch_id"])
            switch_id_list.append(dev_facts["switch_id"])

            asicdb.get_and_check_key_value(switchkey, "SAI_SWITCH_TYPE_VOQ", field="SAI_SWITCH_ATTR_TYPE")


def test_voq_system_port_create(duthosts):
    """Compare the config facts with the asic db for system ports

    * Verify ASIC_DB get all system ports referenced in configDB created on all hosts and ASICs.
    * Verify object creation and values of port attributes.

    """

    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            logger.info("Checking system ports on host: %s, asic: %s", per_host.hostname, asic.asic_index)
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_ports = get_device_system_ports(cfg_facts)
            asicdb = AsicDbCli(asic)
            keylist = asicdb.get_system_port_key_list()
            pytest_assert(len(keylist) == len(dev_ports.keys()),
                          "Found %d system port keys, %d entries in cfg_facts, not matching" % (
                              len(keylist), len(dev_ports.keys())))
            logger.info("Found %d system port keys, %d entries in cfg_facts, checking each.",
                        len(keylist), len(dev_ports.keys()))
            for portkey in keylist:
                try:
                    port_output = asicdb.hget_key_value(portkey, field="SAI_SYSTEM_PORT_ATTR_CONFIG_INFO")
                except RedisKeyNotFound:
                    # TODO: Need to check on behavior here.
                    logger.warning("System port: %s had no SAI_SYSTEM_PORT_ATTR_CONFIG_INFO", portkey)
                    continue
                port_data = json.loads(port_output)
                for cfg_port in dev_ports:
                    if dev_ports[cfg_port]['system_port_id'] == port_data['port_id']:
                        #             "switch_id": "0",
                        #             "core_index": "1",
                        #             "core_port_index": "6",
                        #             "speed": "400000"
                        pytest_assert(dev_ports[cfg_port]['switch_id'] == port_data[
                            'attached_switch_id'], "switch IDs do not match for port: %s" % portkey)
                        pytest_assert(dev_ports[cfg_port]['core_index'] == port_data[
                            'attached_core_index'], "switch IDs do not match for port: %s" % portkey)
                        pytest_assert(dev_ports[cfg_port]['core_port_index'] == port_data[
                            'attached_core_port_index'], "switch IDs do not match for port: %s" % portkey)
                        pytest_assert(dev_ports[cfg_port]['speed'] == port_data[
                            'speed'], "switch IDs do not match for port: %s" % portkey)
                        break
                else:
                    logger.error("Could not find config entry for portkey: %s" % portkey)

            logger.info("Host: %s, Asic: %s all ports match all parameters", per_host.hostname, asic.asic_index)


def test_voq_local_port_create(duthosts):
    """Compare the config facts with the asic db for local ports

    * Verify ASIC_DB has host interface information for all local ports on all cards and ASICs.
    * Verify host interfaces exist on host CLI (ifconfig).
    * Verify interfaces exist in show interfaces on the linecard.
    """

    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_ports = cfg_facts['PORT']

            asicdb = AsicDbCli(asic)

            keylist = asicdb.get_hostif_list()
            pytest_assert(len(keylist) == len(dev_ports.keys()),
                          "Found %d hostif keys, %d entries in cfg_facts" % (len(keylist), len(dev_ports.keys())))
            logger.info("Found %s ports to check on host:%s, asic: %s.", len(dev_ports.keys()), per_host.hostname,
                        asic.asic_index)

            show_intf = asic.show_interface(command="status")['ansible_facts']
            for portkey in keylist:
                port_name = asicdb.hget_key_value(portkey, "SAI_HOSTIF_ATTR_NAME")
                port_state = asicdb.hget_key_value(portkey, "SAI_HOSTIF_ATTR_OPER_STATUS")
                port_type = asicdb.hget_key_value(portkey, "SAI_HOSTIF_ATTR_TYPE")
                logger.info("Checking port: %s, state: %s", port_name, port_state)
                # "SAI_HOSTIF_ATTR_NAME": "Ethernet0",
                # "SAI_HOSTIF_ATTR_OBJ_ID": "oid:0x1000000000002",
                # "SAI_HOSTIF_ATTR_OPER_STATUS": "false",
                # "SAI_HOSTIF_ATTR_TYPE": "SAI_HOSTIF_TYPE_NETDEV"
                pytest_assert(port_type == "SAI_HOSTIF_TYPE_NETDEV", "Port %s is not type netdev" % portkey)
                if port_state == "true":
                    pytest_assert(show_intf['int_status'][port_name]['oper_state'] == "up",
                                  "Show interface state is down when it should be up")
                if port_state == "false":
                    pytest_assert(show_intf['int_status'][port_name]['oper_state'] == "down",
                                  "Show interface state is up when it should be down")

                if asic.namespace is None:
                    cmd = "sudo ifconfig %s" % port_name
                else:
                    cmd = "sudo ip netns exec %s ifconfig %s" % (asic.namespace, port_name)
                ifout = per_host.command(cmd)
                assert "not found" not in ifout['stdout_lines'][0], "Interface %s not found" % port_name
                if port_state == "true" and "RUNNING" in ifout['stdout_lines'][0]:
                    logger.debug("Interface state is up and matches")
                elif port_state == "false" and "RUNNING" not in ifout['stdout_lines'][0]:
                    logger.debug("Interface state is down and matches")
                else:
                    raise AssertionError("Interface state does not match: %s %s", port_state, ifout['stdout_lines'][0])


def test_voq_interface_create(duthosts):
    """
    Verify router interfaces are created on all line cards and present in Chassis App Db.

    * Verify router interface creation on local ports in ASIC DB.
    * PORT_ID should match system port table and traced back to config_db.json, mac and MTU should match as well.
    * Verify SYSTEM_INTERFACE table in Chassis AppDb (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
    * Verify creation interfaces with different MTUs in configdb.json.
    * Verify creation of different subnet masks in configdb.json.
    * Repeat with IPv4, IPv6, dual-stack.

    """
    for per_host in duthosts.frontend_nodes:
        logger.info("Check router interfaces on node: %s", per_host.hostname)

        for asic in per_host.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_intfs = cfg_facts['INTERFACE']
            dev_sysports = get_device_system_ports(cfg_facts)

            slot = per_host.facts['slot_num']
            rif_ports_in_asicdb = []

            # intf_list = get_router_interface_list(dev_intfs)
            asicdb = AsicDbCli(asic)

            asicdb_intf_key_list = asicdb.get_router_if_list()
            # Check each rif in the asicdb, if it is local port, check VOQ DB for correct RIF.
            # If it is on system port, verify slot/asic/port and OID match a RIF in VoQDB
            for rif in asicdb_intf_key_list:
                rif_type = asicdb.hget_key_value(rif, "SAI_ROUTER_INTERFACE_ATTR_TYPE")
                if rif_type != "SAI_ROUTER_INTERFACE_TYPE_PORT":
                    logger.info("Skip this rif: %s, it is not on a port: %s", rif, rif_type)
                    continue
                else:
                    portid = asicdb.hget_key_value(rif, "SAI_ROUTER_INTERFACE_ATTR_PORT_ID")
                    logger.info("Process RIF %s, Find port with ID: %s", rif, portid)

                porttype = asicdb.get_rif_porttype(portid)
                logger.info("RIF: %s is of type: %s", rif, porttype)
                if porttype == 'hostif':
                    # find the hostif entry to get the physical port the router interface is on.
                    hostifkey = asicdb.find_hostif_by_portid(portid)
                    hostif = asicdb.hget_key_value(hostifkey, 'SAI_HOSTIF_ATTR_NAME')
                    logger.info("RIF: %s is on local port: %s", rif, hostif)
                    rif_ports_in_asicdb.append(hostif)
                    if hostif not in dev_intfs:
                        pytest.fail("Port: %s has a router interface, but it isn't in configdb." % portid)

                    # check MTU and ethernet address
                    asicdb.get_and_check_key_value(rif, cfg_facts['PORT'][hostif]['mtu'],
                                                   field="SAI_ROUTER_INTERFACE_ATTR_MTU")
                    intf_mac = get_sonic_mac(per_host, asic.asic_index, hostif)
                    asicdb.get_and_check_key_value(rif, intf_mac, field="SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS")

                    sup_rif = asicdb.hget_key_value("VIDTORID", "oid:" + rif.split(":")[3])
                    sysport_info = find_system_port(dev_sysports, slot, asic.asic_index, hostif)
                    for sup in duthosts.supervisor_nodes:
                        check_rif_on_sup(sup, sup_rif, sysport_info['slot'], sysport_info['asic'], hostif)

                elif porttype == 'sysport':
                    try:
                        port_output = asicdb.hget_key_value("ASIC_STATE:SAI_OBJECT_TYPE_SYSTEM_PORT:" + portid,
                                                            field="SAI_SYSTEM_PORT_ATTR_CONFIG_INFO")
                    except RedisKeyNotFound:
                        # not a hostif or system port, log error and continue
                        logger.error("Did not find OID %s in local or system tables" % portid)
                        continue
                    port_data = json.loads(port_output)
                    for cfg_port in dev_sysports:
                        if dev_sysports[cfg_port]['system_port_id'] == port_data['port_id']:
                            logger.info("RIF: %s is on remote port: %s", rif, cfg_port)
                            break
                    else:
                        raise AssertionError("Did not find OID %s in local or system tables" % portid)

                    sys_slot, sys_asic, sys_port = cfg_port.split("|")
                    sup_rif = asicdb.hget_key_value("VIDTORID", "oid:" + rif.split(":")[3])
                    for sup in duthosts.supervisor_nodes:
                        check_rif_on_sup(sup, sup_rif, sys_slot, sys_asic, sys_port)

                elif porttype == 'port':
                    # this is the RIF on the inband port.
                    inband = get_inband_info(cfg_facts)
                    logger.info("RIF: %s is on local port: %s", rif, inband['port'])

                    # check MTU and ethernet address
                    asicdb.get_and_check_key_value(rif, cfg_facts['PORT'][inband['port']]['mtu'],
                                                   field="SAI_ROUTER_INTERFACE_ATTR_MTU")
                    intf_mac = get_sonic_mac(per_host, asic.asic_index, inband['port'])
                    asicdb.get_and_check_key_value(rif, intf_mac, field="SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS")

                    sup_rif = asicdb.hget_key_value("VIDTORID", "oid:" + rif.split(":")[3])
                    sysport_info = find_system_port(dev_sysports, slot, asic.asic_index, inband['port'])
                    for sup in duthosts.supervisor_nodes:
                        check_rif_on_sup(sup, sup_rif, sysport_info['slot'], sysport_info['asic'], inband['port'])

            # Verify each RIF in config had a corresponding local port RIF in the asicDB.
            for rif in dev_intfs:
                pytest_assert(rif in rif_ports_in_asicdb, "Interface %s is in configdb.json but not in asicdb" % rif)
            logger.info("Interfaces %s are present in configdb.json and asicdb" % str(dev_intfs.keys()))


def test_voq_neighbor_create(duthosts, nbrhosts, nbrhosts_facts):
    """
    Verify neighbor entries are created on linecards for local and remote VMS.

    For local neighbors:
    * ARP/NDP should be resolved when BGP to adjacent VMs is established.
    * On local linecard, verify ASIC DB entries.
        * MAC address matches MAC of neighbor VM.
        * Router interface OID matches back to the correct interface and port the neighbor was learned on.
    * On local linecard, verify show arp/ndp, ip neigh commands.
        * MAC address matches MAC of neighbor VM.
    * On local linecard. verify neighbor table in appDB.
        * MAC address matches MAC of neighbor VM.
    * On supervisor card, verify SYSTEM_NEIGH table in Chassis AppDB (redis-dump -h <ip> -p 6380 -d 12 on supervisor).
        * Verify encap index and MAC address match between ASICDB the Chassis AppDB
    * Repeat with IPv4, IPv6, dual-stack.

    For remote neighbors:
    * When local neighbors are established as in the Local Neighbor testcase, corresponding entries will be established
      on all other line cards.  On each remote card, verify:
    * Verify ASIC DB entries on remote linecards.
        * Verify impose index=True in ASIC DB.
        * Verify MAC address in ASIC DB is the remote neighbor mac.
        * Verify encap index for ASIC DB entry matches Chassis App DB.
        * Verify router interface OID matches the interface the neighbor was learned on.
    * Verify on linecard CLI, show arp/ndp, ip neigh commands.
        * For inband port, MAC should be inband port mac in kernel table and LC appDb.
        * For inband vlan mode, MAC will be remote ASIC mac in kernel table and LC appdb.
    * Verify neighbor table in linecard appdb.
    * Verify static route is installed in kernel routing table with /32 (or /128 for IPv6) for neighbor entry.
    * Repeat with IPv4, IPv6, dual-stack.

    """

    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            logger.info("Checking local neighbors on host: %s, asic: %s", per_host.hostname, asic.asic_index)
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_sysports = get_device_system_ports(cfg_facts)
            neighs = cfg_facts['BGP_NEIGHBOR']
            inband_info = get_inband_info(cfg_facts)

            # Check each neighbor in table
            for neighbor in neighs:
                local_ip = neighs[neighbor]['local_addr']
                if local_ip == inband_info['ipv4_addr'] or local_ip == inband_info['ipv6_addr']:
                    # skip inband neighbors
                    continue

                # Check neighbor on local linecard
                local_port = get_port_by_ip(cfg_facts, local_ip)
                show_intf = asic.show_interface(command="status")['ansible_facts']
                if local_port is None:
                    logger.error("Did not find port for this neighbor %s, must skip", local_ip)
                    continue
                elif "portchannel" in local_port.lower():
                    # TODO: LAG support
                    logger.info("Port channel is not supported yet by this test, skip port: %s", local_port)
                    continue
                if show_intf['int_status'][local_port]['oper_state'] == "down":
                    logger.error("Port is down, must skip interface: %s, IP: %s", local_port, local_ip)
                    continue

                neigh_mac = get_neighbor_mac(neighbor, nbrhosts, nbrhosts_facts)
                if neigh_mac is None:
                    logger.error("Could not find neighbor MAC, must skip.  IP: %s, port: %s", local_ip, local_port)

                local_dict = check_local_neighbor(per_host, asic, neighbor, neigh_mac, local_port)
                logger.info("Local_dict: %s", local_dict)

                # Check the same neighbor entry on the supervisor nodes
                sysport_info = find_system_port(dev_sysports, per_host.facts['slot_num'], asic.asic_index, local_port)
                for sup in duthosts.supervisor_nodes:
                    check_voq_neighbor_on_sup(sup, sysport_info['slot'], sysport_info['asic'], local_port,
                                              neighbor, local_dict['encap_index'], neigh_mac)

                # Check the neighbor entry on each remote linecard
                for rem_host in duthosts.frontend_nodes:

                    for rem_asic in rem_host.asics:
                        if rem_host == per_host and rem_asic == asic:
                            # skip remote check on local host
                            continue
                        rem_cfg_facts = rem_asic.config_facts(source="persistent")['ansible_facts']
                        remote_inband_info = get_inband_info(rem_cfg_facts)
                        remote_inband_mac = get_sonic_mac(rem_host, rem_asic.asic_index, remote_inband_info['port'])
                        check_voq_remote_neighbor(rem_host, rem_asic, neighbor, neigh_mac, remote_inband_info['port'],
                                                  local_dict['encap_index'], remote_inband_mac)


def test_voq_inband_port_create(duthosts):
    """
    Test inband port creation.

    These steps are covered by previous test cases:
        * On each linecard, verify inband ports are present in ASICDB.
        * On each linecard, verify inband router interfaces are present in ASICDB
        * On supervisor card, verify inband router interfaces are present in Chassis App DB

    This test function will cover:
        * On each linecard, verify permanent neighbors for all inband ports.
        * On each linecard, verify kernel routes for all inband ports.
        * Repeat with IPv4, IPv6, dual-stack.


    """
    for per_host in duthosts.frontend_nodes:

        for asic in per_host.asics:
            cfg_facts = asic.config_facts(source="persistent")['ansible_facts']
            dev_sysports = get_device_system_ports(cfg_facts)
            inband_info = get_inband_info(cfg_facts)
            inband_mac = get_sonic_mac(per_host, asic.asic_index, inband_info['port'])

            inband_ips = []
            if 'ipv6_addr' in inband_info:
                inband_ips.append(inband_info['ipv6_addr'])
            if 'ipv4_addr' in inband_info:
                inband_ips.append(inband_info['ipv4_addr'])

            for neighbor_ip in inband_ips:

                host = per_host
                neighbor_mac = inband_mac
                interface = inband_info['port']

                logger.info("Check local neighbor on host %s, asic %s for %s/%s via port: %s", host.hostname,
                            str(asic.asic_index),
                            neighbor_ip, neighbor_mac, interface)

                asic_dict = check_local_neighbor_asicdb(asic, neighbor_ip, neighbor_mac)
                encap_idx = asic_dict['encap_index']

                # Check the inband neighbor entry on the supervisor nodes
                sysport_info = find_system_port(dev_sysports, per_host.facts['slot_num'], asic.asic_index, interface)
                for sup in duthosts.supervisor_nodes:
                    check_voq_neighbor_on_sup(sup, sysport_info['slot'], sysport_info['asic'], interface, neighbor_ip,
                                              encap_idx, inband_mac)

                # Check the neighbor entry on each remote linecard
                for rem_host in duthosts.frontend_nodes:

                    for rem_asic in rem_host.asics:
                        if rem_host == per_host and rem_asic == asic:
                            # skip remote check on local host
                            continue
                        rem_cfg_facts = rem_asic.config_facts(source="persistent")['ansible_facts']
                        remote_inband_info = get_inband_info(rem_cfg_facts)
                        remote_inband_mac = get_sonic_mac(rem_host, rem_asic.asic_index, remote_inband_info['port'])
                        check_voq_remote_neighbor(rem_host, rem_asic, neighbor_ip, inband_mac,
                                                  remote_inband_info['port'],
                                                  encap_idx, remote_inband_mac)
