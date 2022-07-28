import json
import logging
import re
import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli, AppDbCli, VoqDbCli, SonicDbKeyNotFound

logger = logging.getLogger(__name__)

def check_host_arp_table_deleted(host, asic, neighs):
    """
    Verifies the ARP entry is deleted.

    Args:
        host: instance of SonicHost to run the arp show.
        neighbor_ip: IP address of the neighbor to verify.
        arptable: Optional arptable output, if not provided it will be fetched from host.

    """
    if host.is_multi_asic:
        arptable = host.switch_arptable(namespace=asic.namespace)['ansible_facts']
    else:
        arptable = host.switch_arptable()['ansible_facts']

    neighs_present = []
    for neighbor_ip in neighs:
        if ':' in neighbor_ip:
            table = arptable['arptable']['v6']
        else:
            table = arptable['arptable']['v4']
        if neighbor_ip in table:
            neighs_present.append(neighbor_ip)
    logger.debug("On host {} asic {}, found neighbors {} that were supposed to be deleted".format(host, asic.asic_index, neighs_present))
    return len(neighs_present) == 0


def poll_neighbor_table_delete(duthosts, neighs, delay=2, poll_time=180):
    """
    Poller for clear tests to determine when to proceed with test after issuing
    clear commands.

    Args:
        duthosts: The duthosts fixture.
        neighs: List of neighbor IPs which should be cleared.
        delay: How long to delay between checks.
        poll_time: How long to poll for.

    """
    for node in duthosts.frontend_nodes:
        for asic in node.asics:
            logger.info("Poll for ARP clear of %s on host: %s/%s", neighs, node.hostname, asic.asic_index)
            pytest_assert(wait_until(poll_time, delay, 0, check_host_arp_table_deleted, node, asic, neighs),
                          "Not all neighbors {} deleted on host {}/{}".format(neighs, node.hostname, asic.asic_index))


def check_host_arp_table(host, asic, neighbor_ip, neighbor_mac, interface, state, arptable=None):
    """
    Validates the ARP table of a host by running ip neigh for a single neighbor.

    Args:
        host: instance of SonicHost to use.
        asic: instance of SonicAsic to run the arp show.
        neighbor_ip: IP address of the neighbor to verify.
        neighbor_mac: MAC address expected in the show command output.
        interface: Port expected in the show command output.
        state: ARP entry state expected in the show command output.
        arptable: Optional arptable output to run validation on without rerunning CLI.

    """

    if arptable is None:
        arptable = asic.switch_arptable()['ansible_facts']

    if ':' in neighbor_ip:
        table = arptable['arptable']['v6']
    else:
        table = arptable['arptable']['v4']
    for entry in table:
        logger.debug("%s ARP: %s => %s", host.hostname, entry, table[entry])
    pytest_assert(neighbor_ip in table, "IP %s not in arp list: %s" % (neighbor_ip, table.keys()))
    pytest_assert(table[neighbor_ip]['macaddress'] == neighbor_mac,
                  "table MAC %s does not match neighbor mac: %s" % (table[neighbor_ip]['macaddress'], neighbor_mac))
    pytest_assert(table[neighbor_ip]['interface'] == interface,
                  "table interface %s does not match interface: %s" % (table[neighbor_ip]['interface'], interface))
    if state:
        pytest_assert(table[neighbor_ip]['state'].lower() == state.lower(),
                      "table state %s is not %s" % (table[neighbor_ip]['state'].lower(), state.lower()))


def check_local_neighbor_asicdb(asic, neighbor_ip, neighbor_mac):
    """
    Verifies the neighbor information of a sonic host in the asicdb for a locally attached neighbor.

    Args:
        asic: The SonicAsic instance to be checked.
        neighbor_ip: The IP address of the neighbor.
        neighbor_mac: The MAC address of the neighbor.

    Returns:
        A dictionary with the encap ID from the ASIC neighbor table.

    Raises:
        Pytest Failed exception when assertions fail.

    """
    asicdb = AsicDbCli(asic)
    neighbor_key = asicdb.get_neighbor_key_by_ip(neighbor_ip)
    pytest_assert(neighbor_key is not None, "Did not find neighbor in asictable for IP: %s" % neighbor_ip)
    asic_mac = asicdb.get_neighbor_value(neighbor_key, 'SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS')
    pytest_assert(asic_mac.lower() == neighbor_mac.lower(),
                  "MAC does not match in asicDB, asic %s, device %s" % (asic_mac.lower(), neighbor_mac.lower()))
    encap_idx = asicdb.get_neighbor_value(neighbor_key, 'SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX')
    return {"encap_index": encap_idx}


def check_local_neighbor(host, asic, neighbor_ip, neighbor_mac, interface):
    """
    Verifies the neighbor information of a sonic host for a locally attached neighbor.

    The ASIC DB, APP DB, and host ARP table are checked.

    Args:
        host: Instance of SonicHost to check.
        asic: Instance of SonicAsic to check.
        neighbor_ip: IP address if the neighbor to check.
        neighbor_mac: Expected ethernet MAC address of the neighbor.
        interface: Expected interface the neighbor was learned on.

    Returns:
        A dictionary with the key into the LC APP DB neighbor table and the encap ID from the ASIC DB neighbor table.
        {'encap_index': u'1074790408',
         'neighbor_key': u'NEIGH_TABLE:Ethernet10:2064:103::1'}

    Raises:
        Pytest Failed exception when assertions fail.

    """
    logger.info("Check local neighbor on host %s, asic %s for %s/%s via port: %s", host.hostname, str(asic.asic_index),
                neighbor_ip, neighbor_mac, interface)

    # verify asic db
    asic_dict = check_local_neighbor_asicdb(asic, neighbor_ip, neighbor_mac)

    # verify LC appdb
    appdb = AppDbCli(asic)
    neighbor_key = appdb.get_neighbor_key_by_ip(neighbor_ip)
    appdb.get_and_check_key_value(neighbor_key, neighbor_mac, field="neigh")
    pytest_assert(":{}:".format(interface) in neighbor_key, "Port for %s does not match" % neighbor_key)

    # verify linux arp table
    check_host_arp_table(host, asic, neighbor_ip, neighbor_mac, interface, 'REACHABLE')

    return {'neighbor_key': neighbor_key, 'encap_index': asic_dict['encap_index']}


def check_bgp_kernel_route(host, asicnum, prefix, ipver, interface, present=True, parsed=None):
    """
    Checks the kernel route is installed from the bgp container.

    Args:
        host: sonic duthost instance to check.
        asicnum: asic index to check.
        prefix: IP address plus mask to check in routing table.
        ipver: ip or ipv6.
        interface: Attached interface for the neighbor route.
        present: Optional; Check whether route is installed or removed.
        parsed: Optional; Output from BGP docker to run validation against without rerunning CLI.

    Raises:
        Pytest Failed exception when assertions fail.

    """
    docker = "bgp"
    if host.facts["num_asic"] > 1:
        docker = "bgp" + str(asicnum)

    if parsed is None:
        output = host.command("docker exec " + docker + " vtysh -c \"show {} route {} json\"".format(ipver, prefix))
        parsed = json.loads(output["stdout"])
    if present is True:
        pytest_assert(prefix in parsed.keys(), "Prefix: %s not in route list: %s" % (prefix, parsed.keys()))
        found = False
        for route in parsed[prefix]:
            if route['distance'] != 0:
                continue
            found = True
            pytest_assert(route['protocol'] == "kernel", "Prefix: %s not kernel route" % prefix)
            pytest_assert(route['nexthops'][0]['directlyConnected'] is True,
                          "Prefix: %s not directly connected" % prefix)
            pytest_assert(route['nexthops'][0]['active'] is True, "Prefix: %s not active" % prefix)
            pytest_assert(route['nexthops'][0]['interfaceName'] == interface,
                          "Prefix: %s out interface is not correct" % prefix)
            break
        pytest_assert(found, "Kernel route is not present in bgp output: %s" % parsed[prefix])
        logger.debug("Route %s is present in remote neighbor: %s/%s", prefix, host.hostname, str(asicnum))
    if present is False:
        #logger.info("outout: %s", parsed)
        pytest_assert(prefix not in parsed, "Prefix: %s still in route list: %s" % (prefix, parsed.keys()))
        logger.info("Route %s is removed from remote neighbor: %s/%s", prefix, host.hostname, str(asicnum))


def check_no_routes_from_nexthop(asic, nexthop):
    if ':' in nexthop:
        ver = '-6'
    else:
        ver = '-4'
    special_nexthop = nexthop.replace('.', '\\\.')
    cmd = "ip {} route show | grep -w {} | wc -l".format(ver, special_nexthop)
    if asic.namespace is not None:
        fullcmd = "sudo ip netns exec {} {}".format(asic.namespace, cmd)
        output = asic.sonichost.shell(fullcmd)
    else:
        output = asic.sonichost.shell(cmd)
    output = int(output['stdout'].split()[0])
    return output == 0


def verify_no_routes_from_nexthop(duthosts, nexthop):
    for dut in duthosts.frontend_nodes:
        for asic in dut.asics:
            pytest_assert(wait_until(45, 2, 0, check_no_routes_from_nexthop, asic, nexthop),
                          "Not all routes flushed from nexthop {} on asic {} on {}".format(nexthop, asic.asic_index, dut.hostname))


def check_host_kernel_route(host, asicnum, ipaddr, ipver, interface, present=True):

    """
    Checks the kernel route on the host OS.

    Args:
        host: sonic duthost instance to check.
        asicnum: asic index to check.
        ipaddr: IP address to check in routing table.
        ipver: ip or ipv6.
        interface: Attached interface for the neighbor route.
        present: Optional; Check whether route is installed or removed.

    Raises:
        Pytest Failed exception when assertions fail.

    """
    ver = "-4" if ipver == "ip" else "-6"
    if host.facts["num_asic"] == 1:
        cmd = "ip {} route show exact {}".format(ver, ipaddr)
    else:
        cmd = "ip netns exec asic{} ip {} route show exact {}".format(asicnum, ver, ipaddr)
    logger.debug("Kernel rt cmd: %s", cmd)
    output = host.command(cmd)['stdout']
    logger.info("host ip route output: %s", output)
    if present is True:
        logger.info("host ip route output: %s", output)
        pytest_assert(output.startswith(ipaddr), "Address: %s not in netstat output list: %s" % (ipaddr, output))
        pytest_assert("dev %s" % interface in output, "Interface is not %s: %s" % (interface, output))
    if present is False:
        pytest_assert(output == "", "Address: %s still in netstat output list: %s" % (ipaddr, output))


def check_neighbor_kernel_route(host, asicnum, ipaddr, interface, present=True):
    """
    Verifies if a neighbor kernel route is installed or not.

    Checks BGP docker and linux kernel route tables.

    Args:
        host: sonic duthost instance to check.
        asicnum: asic index to check.
        ipaddr: IP address to check in routing table.  Mask will be applied by this function.
        interface: Attached interface for the neighbor route.
        present: Optional; Check whether route is installed or removed.
    """
    if ":" in ipaddr:
        ipver = "ipv6"
        prefix = ipaddr + "/128"
    else:
        ipver = "ip"
        prefix = ipaddr + "/32"

    check_bgp_kernel_route(host, asicnum, prefix, ipver, interface, present)
    check_host_kernel_route(host, asicnum, ipaddr, ipver, interface, present)


def check_voq_remote_neighbor(host, asic, neighbor_ip, neighbor_mac, interface, encap_idx, inband_mac):
    """
    Verifies the neighbor information of a neighbor learned on a different host.

    The ASIC DB, APP DB, and host ARP table are checked. The host kernal route is verified.  The encap ID from the
    local neighbor is provided as a parameter and verified that it is imposed.

    Args:
        host: Instance of SonicHost to check.
        asic: Instance of SonicAsic to check.
        neighbor_ip: IP address if the neighbor to check.
        neighbor_mac: Expected ethernet MAC address of the neighbor.
        interface: Expected interface the neighbor was learned on.
        encap_idx: The encap index from the SONIC host the neighbor is directly attached to.
        inband_mac: The MAC of the inband port of the remote host.

    Raises:
        Pytest Failed exception when assertions fail.
    """
    logger.info("Check remote neighbor on host %s, asic: %s for %s/%s via port: %s", host.hostname,
                str(asic.asic_index), neighbor_ip, neighbor_mac, interface)

    # asic db
    asicdb = AsicDbCli(asic)
    neighbor_key = asicdb.get_neighbor_key_by_ip(neighbor_ip)
    pytest_assert(neighbor_key is not None, "Did not find neighbor in asic table for IP: %s" % neighbor_ip)
    pytest_assert(asicdb.get_neighbor_value(neighbor_key,
                                            'SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS').lower() == neighbor_mac.lower(),
                  "MAC does not match in asicDB")
    pytest_assert(asicdb.get_neighbor_value(neighbor_key,
                                            'SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX') == encap_idx,
                  "Encap index does not match in asicDB")
    pytest_assert(asicdb.get_neighbor_value(neighbor_key,
                                            'SAI_NEIGHBOR_ENTRY_ATTR_IS_LOCAL') == "false",
                  "is local is not false in asicDB")

    # LC app db
    appdb = AppDbCli(asic)
    neighbor_key = appdb.get_neighbor_key_by_ip(neighbor_ip)
    pytest_assert(":{}:".format(interface) in neighbor_key, "Port for %s does not match" % neighbor_key)
    if host.get_facts()['asic_type'] == "vs":
        appdb.get_and_check_key_value(neighbor_key, neighbor_mac, field="neigh")
        # verify linux arp table
        check_host_arp_table(host, asic, neighbor_ip, neighbor_mac, interface, 'PERMANENT')
    else:
        appdb.get_and_check_key_value(neighbor_key, inband_mac, field="neigh")
        # verify linux arp table
        check_host_arp_table(host, asic, neighbor_ip, inband_mac, interface, 'PERMANENT')

    # verify linux route entry
    check_neighbor_kernel_route(host, asic.asic_index, neighbor_ip, interface)


def check_rif_on_sup(systemintftable, slot, asic, port):
    """
    Checks the router interface entry on the supervisor card.

    Args:
        sup: duthost for the supervisor card
        slot: The slot number the router interface is on.
        asic: The asic number the asic is on, or 0 if a single asic card.
        port: the name of the port (Ethernet1)

    """
    slot = str(slot)
    if slot.isdigit():
        slot_str = "Linecard" + slot
    else:
        slot_str = slot

    asic = str(asic)
    if asic.isdigit():
        asic_str = "Asic" + asic
    else:
        asic_str = asic

    key = "SYSTEM_INTERFACE|{}|{}|{}".format(slot_str, asic_str, port)
    if key in systemintftable:
        logger.info("Found key {} on chassisdb on supervisor card".format(key))
    else:
        raise SonicDbKeyNotFound("No keys for %s found in chassisdb SYSTEM_INTERFACE table" % key)


def check_voq_neighbor_on_sup(sup, slot, asic, port, neighbor, encap_index, mac):
    """
     Checks the neighbor entry on the supervisor card.

     Args:
         sup: duthost for the supervisor card
         slot: The slot the router interface is on, as in system port table (Slot2).
         asic: The asic the router interface is on, as in the system port table (Asic0) .
         port: the name of the port (Ethernet1)
         neighbor: The IP of the neighbor
         encap_index: The encap ID of the neighbor from the local asic db
         mac: The MAC address of the neighbor

    Raises:
        Pytest Failed exception when assertions fail.

    """
    voqdb = VoqDbCli(sup)
    neigh_key = voqdb.get_neighbor_key_by_ip(neighbor)
    logger.info("Neigh key: %s, slotnum: %s", neigh_key, slot)
    pytest_assert("|%s|" % slot in neigh_key,
                  "Slot for %s does not match %s" % (neigh_key, slot))
    pytest_assert("|%s:" % port in neigh_key or "|%s|" % port in neigh_key,
                  "Port for %s does not match %s" % (neigh_key, port))
    pytest_assert("|%s|" % asic in neigh_key,
                  "Asic for %s does not match %s" % (neigh_key, asic))

    voqdb.get_and_check_key_value(neigh_key, mac, field="neigh")
    voqdb.get_and_check_key_value(neigh_key, encap_index, field="encap_index")


def get_eos_mac(nbr, nbr_intf):
    """
    Gets the MAC address of and interface from an EOS host.

    Args:
        nbr: The element for the neighbor from nbrhosts fixture.
        nbr_intf: The interface name on the neighbor to retrieve the MAC

    Returns:
        A dictionary with the mac address and shell interface name.
    """
    if "port-channel" in nbr_intf.lower():
        # convert Port-Channel1 to po1
        shell_intf = "po" + nbr_intf[-1]
    else:
        # convert Ethernet1 to eth1
        shell_intf = "eth" + nbr_intf[-1]

    output = nbr['host'].command("ip addr show dev %s" % shell_intf)
    # 8: Ethernet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9100 ...
    #     link/ether a6:69:05:fd:da:5f brd ff:ff:ff:ff:ff:ff

    mac = output['stdout_lines'][1].split()[1]
    return {'mac': mac, "shell_intf": shell_intf}


def get_neighbor_info(neigh_ip, nbrhosts):
    """
    Gets the neighbor VM info of a neighbor VM on an EOS host.

    We need to get the MAC of the VM out of the linux shell, not from the EOS CLI.  The MAC used for punt/inject
    on the EOS seems to be the linux one.  Find the interface name on the VM that is associated with the IP address,
    then look on the linux OS shell for the MAC address of that interface.

    Args:
        neigh_ip: The IP address of the neighbor.
        nbrhosts: dictionary provided by the nbrhosts fixture.

    Returns:
        A dictionary with mac, vmname, port and shell port name.
    """

    vm_info = get_vm_with_ip(neigh_ip, nbrhosts)
    nbr_vm = vm_info['vm']
    nbr_intf = vm_info['port']

    macs = get_eos_mac(nbrhosts[nbr_vm], nbr_intf)

    return {'mac': macs['mac'], "port": nbr_intf, "shell_intf": macs['shell_intf'], "vm": nbr_vm}


def get_sonic_mac(host, asicnum, port):
    """Gets the MAC address of an SONIC port.

    Args:
        host: a duthost instance
        asicnum: The asic number to run on, or empty string.
        port: The name of the port to get the MAC

    Returns:
        A string with the MAC address.
    """
    if host.facts["num_asic"] == 1:
        cmd = "sudo ip link show {}".format(port)
    else:
        ns = "asic" + str(asicnum)
        cmd = "sudo ip netns exec {} ip link show {}".format(ns, port)
    output = host.command(cmd)
    mac = output['stdout_lines'][1].split()[1]
    logger.info("host: %s, asic: %d, port: %s, mac: %s", host.hostname, asicnum, port, mac)
    return mac


def get_device_system_ports(cfg_facts):
    """Returns the system ports from the config facts as a single dictionary, instead of a nested dictionary.

    The ansible module for config facts automatically makes a 2 level nested dictionary when the keys are in the form
    of part1|part2|part3 or part1|part2.  The first dictionary is keyed as "part1" and the nested dictionary is the
    remainder of the key with the value.  This function returns a flat dictionary with the keys restored to their values
    from the files.

   Args:
        cfg_facts: The "ansible_facts" output from the duthost "config_facts" module.

    Returns:
        The system port config facts in a single layer dictionary.

    """

    sys_port_slot_dict = cfg_facts['SYSTEM_PORT']
    merge_dict = {}
    for slot in sys_port_slot_dict:
        for port in sys_port_slot_dict[slot]:
            merge_dict[slot + "|" + port] = sys_port_slot_dict[slot][port]
    return merge_dict


def get_inband_info(cfg_facts):
    """
    Returns the inband port and IP addresses present in the configdb.json.

   Args:
        cfg_facts: The "ansible_facts" output from the duthost "config_facts" module.

    Returns:
        A dictionary with the inband port and IP addresses.
    """
    ret = {}

    if 'VOQ_INBAND_INTERFACE' in cfg_facts:
        intf = cfg_facts['VOQ_INBAND_INTERFACE']
        for a_intf in intf:
            for addrs in intf[a_intf]:
                if "/" not in addrs:
                    continue
                ret['port'] = a_intf

                # Skip fields that are not inband address
                if '/' not in addrs:
                    continue

                intf_ip = addrs.split('/')
                if ':' in intf_ip[0]:
                    ret['ipv6_addr'] = intf_ip[0]
                    ret['ipv6_mask'] = intf_ip[1]
                else:
                    ret['ipv4_addr'] = intf_ip[0]
                    ret['ipv4_mask'] = intf_ip[1]
    return ret


def get_vm_with_ip(neigh_ip, nbrhosts):
    """
    Finds the EOS VM and port with a specific IP Address.

    Args:
        neigh_ip: IP address to find.
        nbrhosts: nbrhosts fixture.

    Returns:
        A dictionary with the vm index for nbrhosts, and port name.
    """
    for a_vm in nbrhosts:
        for port, a_intf in nbrhosts[a_vm]['conf']['interfaces'].iteritems():
            if 'ipv4' in a_intf and a_intf['ipv4'].split("/")[0] == neigh_ip:
                return {"vm": a_vm, "port": port}
            if 'ipv6' in a_intf and a_intf['ipv6'].split("/")[0].lower() == neigh_ip.lower():
                return {"vm": a_vm, "port": port}
    logger.error("Could not find vm connected to neighbor IP: %s", neigh_ip)
    logger.info("nbrhosts: {}".format(json.dumps(nbrhosts, indent=4)))
    return None


def get_port_by_ip(cfg_facts, ipaddr):
    """
    Returns the port which has a given IP address from the dut config.

    Args:
        cfg_facts: The "ansible_facts" output from the duthost "config_facts" module.
        ipaddr: The IP address to search for.

    Returns:
        A string with the port name or None if not found.  ("Ethernet12")

    """
    if ':' in ipaddr:
        iptype = "ipv6"
    else:
        iptype = "ipv4"

    intf = {}
    intf.update(cfg_facts.get('INTERFACE', {}))
    if "PORTCHANNEL_INTERFACE" in cfg_facts:
        intf.update(cfg_facts['PORTCHANNEL_INTERFACE'])
    for a_intf in intf:
        for addrs in intf[a_intf]:
            intf_ip = addrs.split('/')
            if iptype == 'ipv6' and ':' in intf_ip[0] and intf_ip[0].lower() == ipaddr.lower():
                return a_intf
            elif iptype == 'ipv4' and ':' not in intf_ip[0] and intf_ip[0] == ipaddr:
                return a_intf

    raise Exception("Dod not find port for IP %s" % ipaddr)


def check_one_neighbor_present(duthosts, per_host, asic, neighbor, nbrhosts, all_cfg_facts):
    """
    Verifies a single neighbor entry is present in a voq system on local and remote sonic instances.

    For local neighbor, verifies ASIC DB, APP DB, and ARP table entry.  Collects encap ID.
    On supervisor, verifies neighbor in Chassis DB and verifies encap ID.
    On remote sonics, verifies ASIC DB, APP DB, kernel route and ARP entries, and encap ID.

    Args:
        duthosts: The duthost fixture.
        per_host: The MultiAsicSonicHost instance for the local neighbor.
        asic: The SonicAsic instance for the local neighbor.
        neighbor: The IP address of the neighbor to check as a string.
        nbrhosts: The nbrhosts fixture.
        all_cfg_facts: The config facts fixture from voq/conftest.py

    """
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']

    neighs = cfg_facts['BGP_NEIGHBOR']
    inband_info = get_inband_info(cfg_facts)
    local_ip = neighs[neighbor]['local_addr']

    if local_ip == inband_info['ipv4_addr'] or local_ip == inband_info['ipv6_addr']:
        # skip inband neighbors
        return

    # Check neighbor on local linecard
    local_port = get_port_by_ip(cfg_facts, local_ip)
    if local_port is None:
        logger.error("Did not find port for this neighbor %s, must skip", local_ip)
        return

    neigh_mac = get_neighbor_info(neighbor, nbrhosts)['mac']
    if neigh_mac is None:
        logger.error("Could not find neighbor MAC, must skip.  IP: %s, port: %s", local_ip, local_port)

    local_dict = check_local_neighbor(per_host, asic, neighbor, neigh_mac, local_port)
    logger.info("Local_dict: %s", local_dict)

    # Check the same neighbor entry on the supervisor nodes
    slotname = cfg_facts['DEVICE_METADATA']['localhost']['hostname']
    asicname = cfg_facts['DEVICE_METADATA']['localhost']['asic_name']

    if per_host.is_multi_asic and len(duthosts.supervisor_nodes) == 0:
        check_voq_neighbor_on_sup(per_host, slotname, asicname, local_port,
                                  neighbor, local_dict['encap_index'], neigh_mac)
    else:
        for sup in duthosts.supervisor_nodes:
            check_voq_neighbor_on_sup(sup, slotname, asicname, local_port,
                                      neighbor, local_dict['encap_index'], neigh_mac)

    # Check the neighbor entry on each remote linecard
    for rem_host in duthosts.frontend_nodes:

        for rem_asic in rem_host.asics:
            if rem_host == per_host and rem_asic == asic:
                # skip remote check on local host
                continue
            rem_cfg_facts = all_cfg_facts[rem_host.hostname][rem_asic.asic_index]['ansible_facts']
            remote_inband_info = get_inband_info(rem_cfg_facts)
            if remote_inband_info == {}:
                logger.info("No inband configuration on this asic: %s/%s, will be skipped.", rem_host.hostname,
                            rem_asic.asic_index)
                continue
            remote_inband_mac = get_sonic_mac(rem_host, rem_asic.asic_index, remote_inband_info['port'])
            check_voq_remote_neighbor(rem_host, rem_asic, neighbor, neigh_mac, remote_inband_info['port'],
                                      local_dict['encap_index'], remote_inband_mac)


def check_all_neighbors_present(duthosts, nbrhosts, all_cfg_facts, nbr_macs, check_nbr_state=True):
    """
    Verifies all neighbors for all sonic hosts in a voq system.

    Args:
        duthosts: The duthost fixture.
        nbrhosts: The nbrhosts fixture.
        all_cfg_facts: The config facts fixture from voq/conftest.py
        nbr_macs: The nbr_macs fixture from voq/conftest.py

    """
    for per_host in duthosts.frontend_nodes:
        for asic in per_host.asics:
            logger.info("Checking local neighbors on host: %s, asic: %s", per_host.hostname, asic.asic_index)
            cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
            if 'BGP_NEIGHBOR' in cfg_facts:
                neighs = cfg_facts['BGP_NEIGHBOR']
            else:
                logger.info("No local neighbors for host: %s/%s, skipping", per_host.hostname, asic.asic_index)
                continue

            dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, neighs.keys(),
                                              nbrhosts, all_cfg_facts, nbr_macs, check_nbr_state=check_nbr_state)


def check_all_neighbors_present_local(duthosts, per_host, asic, neighbors, all_cfg_facts, nbrhosts, nbr_macs, check_nbr_state=True):
    """
    Dumps out data from redis and CLI and validates all local neighbors at once.

    Args:
        duthosts: The duthosts fixture
        per_host: Instance of MultiAsicSonicHost to check.
        asic: Instance of SonicAsic to test.
        neighbors: Neighbors to check, list if IP addresses.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture from voq/conftest.py

    Returns:
        Dictionary with encap IDs and total of any non-fatal failures.
    """
    cfg_facts = all_cfg_facts[per_host.hostname][asic.asic_index]['ansible_facts']
    neighs = cfg_facts['BGP_NEIGHBOR']

    fail_cnt = 0

    # Grab dumps of the asicdb, appdb, voqdb, and arp table
    asicdb = AsicDbCli(asic)
    asic_dump = asicdb.dump_neighbor_table()

    appdb = AppDbCli(asic)
    app_dump = appdb.dump_neighbor_table()

    encaps = {}

    if per_host.is_multi_asic:
        arptable = per_host.switch_arptable(namespace=asic.namespace)['ansible_facts']
    else:
        arptable = per_host.switch_arptable()['ansible_facts']

    if len(duthosts.supervisor_nodes) == 1:
        voqdb = VoqDbCli(duthosts.supervisor_nodes[0])
        voq_dump = voqdb.dump_neighbor_table()
    elif per_host.is_multi_asic:
        # look on linecard for pizzabox multiasic
        voqdb = VoqDbCli(per_host)
        voq_dump = voqdb.dump_neighbor_table()
    else:
        voq_dump = {}

    for neighbor in neighbors:
        nbr_vm = get_vm_with_ip(neighbor, nbrhosts)
        neigh_mac = nbr_macs[nbr_vm['vm']][nbr_vm['port']]
        local_ip = neighs[neighbor]['local_addr']
        local_port = get_port_by_ip(cfg_facts, local_ip)

        sysport_info = {'slot': cfg_facts['DEVICE_METADATA']['localhost']['hostname'],
                        'asic': cfg_facts['DEVICE_METADATA']['localhost']['asic_name']}

        # Validate the asic db entries
        for entry in asic_dump:
            matchstr = '"%s",' % neighbor
            if matchstr in entry:

                if neigh_mac.lower() != asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower():
                    logger.error("Asic neighbor macs for %s do not match: %s != %s", neighbor, neigh_mac.lower(),
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower())
                    fail_cnt += 1
                else:
                    logger.debug("Asic neighbor macs for %s match: %s == %s", neighbor, neigh_mac.lower(),
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower())
                encaps[neighbor] = asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX']
                break
        else:
            logger.error("Did not find neighbor in asictable for IP: %s" % neighbor)
            fail_cnt += 1

        # Validate the APP db entries
        for entry in app_dump:
            matchstr = ':%s' % neighbor
            if entry.endswith(matchstr):
                if neigh_mac.lower() != app_dump[entry]['value']['neigh'].lower():
                    logger.error("App neighbor macs for %s do not match: %s != %s", neighbor, neigh_mac.lower(),
                                 app_dump[entry]['value']['neigh'].lower())
                    fail_cnt += 1
                else:
                    logger.debug("App neighbor macs for %s match: %s == %s", neighbor, neigh_mac.lower(),
                                 app_dump[entry]['value']['neigh'].lower())

                pytest_assert(":{}:".format(local_port) in entry, "Port for %s does not match" % entry)
                break
        else:
            logger.error("Did not find neighbor in app for IP: %s" % neighbor)
            fail_cnt += 1

        # Validate the arp table entries
        if check_nbr_state:
            check_host_arp_table(per_host, asic, neighbor, neigh_mac, local_port, 'REACHABLE', arptable=arptable)
        else:
            check_host_arp_table(per_host, asic, neighbor, neigh_mac, local_port, None, arptable=arptable)

        # supervisor checks
        for entry in voq_dump:
            if entry.endswith('|%s' % neighbor) or entry.endswith(':%s' % neighbor):

                if "portchannel" in local_port.lower():
                    slotname = cfg_facts['DEVICE_METADATA']['localhost']['hostname']
                    asicname = cfg_facts['DEVICE_METADATA']['localhost']['asic_name']
                else:
                    slotname = sysport_info['slot']
                    asicname = sysport_info['asic']

                logger.debug("Neigh key: %s, slotnum: %s", entry, slotname)
                pytest_assert("|%s|" % slotname in entry,
                              "Slot for %s does not match %s" % (entry, slotname))
                pytest_assert("|%s:" % local_port in entry or "|%s|" % local_port in entry,
                              "Port for %s does not match %s" % (entry, local_port))
                pytest_assert("|%s|" % asicname in entry,
                              "Asic for %s does not match %s" % (entry, asicname))

                pytest_assert(voq_dump[entry]['value']['neigh'].lower() == neigh_mac.lower(),
                              "Voq: neighbor: %s mac does not match: %s" % (neighbor,
                                                                            voq_dump[entry]['value']['neigh'].lower()))
                pytest_assert(voq_dump[entry]['value']['encap_index'].lower() == encaps[neighbor],
                              "Voq: encap: %s mac does not match: %s" % (neighbor,
                                                                         voq_dump[entry]['value']['encap_index'].lower()))
                break
        else:
            logger.error("Neighbor: %s on slot: %s, asic: %s not present in voq", neighbor, sysport_info['slot'], sysport_info['asic'])
            fail_cnt += 1

        logger.info("Local %s/%s and chassisdb neighbor validation of %s is successful (mac: %s, idx: %s)",
                    per_host.hostname, asic.asic_index, neighbor, neigh_mac, encaps[neighbor])

    return {'encaps': encaps, 'fail_cnt': fail_cnt}


def check_all_neighbors_present_remote(local_host, rem_host, rem_asic, neighs, encaps, all_cfg_facts, nbrhosts, nbr_macs):
    """
    Dumps and verifies all neighbors on a remote host.

    Args:
        local_host: MultiAsicSonicHost instance where the neighs are ingressing (eBGP into)
        rem_host: MultiAsicSonicHost instance to check.
        rem_asic: SonicAsic instance to check.
        neighs: List of neighbors to verify.  (IP address strings)
        encaps: Encap ID dictionary from check_all_neighbors_present_local.  Dict of encap IDs indexed by neighbor.
        all_cfg_facts: all_cfg_facts fixture from voq/conftest.py
        nbrhosts: nbrhosts fixture
        nbr_macs: nbr_macs fixture from voq/conftest.py

    Returns:
        Dictionary with total of any non-fatal failures.

    """

    rem_cfg_facts = all_cfg_facts[rem_host.hostname][rem_asic.asic_index]['ansible_facts']
    remote_inband_info = get_inband_info(rem_cfg_facts)
    if remote_inband_info == {}:
        logger.info("No inband configuration on this asic: %s/%s, will be skipped.", rem_host.hostname, rem_asic.asic_index)
        return {'fail_cnt': 0}
    remote_inband_mac = get_sonic_mac(rem_host, rem_asic.asic_index, remote_inband_info['port'])
    fail_cnt = 0

    # Grab dumps of the asicdb, appdb, routing table, and arp table

    # bgp routes
    docker = "bgp"
    if rem_host.facts["num_asic"] > 1:
        docker = "bgp" + str(rem_asic.asic_index)

    v4_output = rem_host.command("docker exec " + docker + " vtysh -c \"show ip route kernel json\"")
    v6_output = rem_host.command("docker exec " + docker + " vtysh -c \"show ipv6 route kernel json\"")
    v4_parsed = json.loads(v4_output["stdout"])
    v6_parsed = json.loads(v6_output["stdout"])

    # kernel routes
    if rem_host.is_multi_asic:
        v4cmd = "ip netns exec {} ip -4 route show scope link".format(rem_asic.namespace)
        v6cmd = "ip netns exec {} ip -6 route show".format(rem_asic.namespace)
    else:
        v4cmd = "ip -4 route show scope link"
        v6cmd = "ip -6 route show"

    v4_kern = rem_host.command(v4cmd)['stdout_lines']
    v6_kern = rem_host.command(v6cmd)['stdout_lines']

    # databases and ARP table
    asicdb = AsicDbCli(rem_asic)
    asic_dump = asicdb.dump_neighbor_table()

    appdb = AppDbCli(rem_asic)
    app_dump = appdb.dump_neighbor_table()

    if rem_host.is_multi_asic:
        arptable = rem_host.switch_arptable(namespace=rem_asic.namespace)['ansible_facts']
    else:
        arptable = rem_host.switch_arptable()['ansible_facts']

    for neighbor in neighs:
        neighbor_mac_on_dut = remote_inband_mac
        if rem_host.get_facts()['asic_type'] == 'vs':
            # For vs platform, the mac programmed will be remote asic's mac as required for datapath to work.
            neighbor_mac_on_dut = local_host.get_facts()['router_mac']
        logger.info("Check remote host: %s, asic: %s, for neighbor %s", rem_host.hostname, rem_asic.asic_index,
                    neighbor)
        nbr_vm = get_vm_with_ip(neighbor, nbrhosts)
        neigh_mac = nbr_macs[nbr_vm['vm']][nbr_vm['port']]
        encap_id = encaps[neighbor]

        # Verify ASIC DB entries
        for entry in asic_dump:
            matchstr = '"%s",' % neighbor
            if matchstr in entry:

                if neigh_mac.lower() != asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower():
                    logger.error("Asic neighbor macs for %s do not match: %s != %s", neighbor, neigh_mac.lower(),
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower())
                    fail_cnt += 1
                else:
                    logger.debug("Asic neighbor macs for %s match: %s == %s", neighbor, neigh_mac.lower(),
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS'].lower())

                if encap_id != asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX']:
                    logger.error("Asic neighbor encap for %s do not match: %s != %s", neighbor, encap_id,
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX'])
                    fail_cnt += 1
                else:
                    logger.debug("Asic neighbor encap for %s match: %s == %s", neighbor, encap_id,
                                 asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_INDEX'])

                pytest_assert(asic_dump[entry]['value']['SAI_NEIGHBOR_ENTRY_ATTR_IS_LOCAL'] == "false",
                              "is local is not false in asicDB")

                break
        else:
            logger.error("Did not find neighbor in asictable for IP: %s on remote %s", neighbor, rem_host.hostname)
            fail_cnt += 1

        # Verify APP DB entries
        for entry in app_dump:
            matchstr = ':%s' % neighbor
            if entry.endswith(matchstr):
                if neighbor_mac_on_dut.lower() != app_dump[entry]['value']['neigh'].lower():
                    logger.error("App neighbor macs for %s do not match: %s != %s", neighbor, remote_inband_mac.lower(),
                                 app_dump[entry]['value']['neigh'].lower())
                    fail_cnt += 1
                else:
                    logger.debug("App neighbor macs for %s match: %s == %s", neighbor, remote_inband_mac.lower(),
                                 app_dump[entry]['value']['neigh'].lower())

                pytest_assert(":{}:".format(remote_inband_info['port']) in entry, "Port for %s does not match" % entry)
                break
        else:
            logger.error("Did not find neighbor in appdb for IP: %s on remote %s", neighbor, rem_host.hostname)
            fail_cnt += 1

        # Verify ARP table

        check_host_arp_table(rem_host, rem_asic, neighbor, neighbor_mac_on_dut, remote_inband_info['port'], 'PERMANENT',
                             arptable=arptable)

        # Verify routing tables
        if ":" in neighbor:
            ipver = "ipv6"
            prefix = neighbor + "/128"
            bgp_parse = v6_parsed
            kern_route = v6_kern
        else:
            ipver = "ip"
            prefix = neighbor + "/32"
            bgp_parse = v4_parsed
            kern_route = v4_kern

        # bgp routing table
        check_bgp_kernel_route(rem_host, rem_asic.asic_index, prefix, ipver, remote_inband_info['port'], present=True,
                               parsed=bgp_parse)

        # kernel routing table
        for route in kern_route:
            if route.startswith("%s " % neighbor):
                pytest_assert("dev %s" % remote_inband_info['port'] in route,
                              "Neigbor: %s, Route device not inband port: %s" % (neighbor, remote_inband_info['port']))
                break
        else:
            logger.error("Neighbor: %s not in kernel table" % neighbor)
            fail_cnt += 1

        logger.info("Check remote host: %s, asic: %s, check for neighbor %s successful",
                    rem_host.hostname, rem_asic.asic_index, neighbor)
    return {'fail_cnt': fail_cnt}


def dump_and_verify_neighbors_on_asic(duthosts, per_host, asic, neighs, nbrhosts, all_cfg_facts, nbr_macs, check_nbr_state=True):
    """
    Verifies all neighbors for all sonic hosts in a voq system.

    Args:
        duthosts: The duthost fixture.
        per_host: Instance of MultiAsicSonicHost to check.
        asic: Instance of SonicAsic to check.
        neighs: List of neighbors to check, IP address strings.
        nbrhosts: The nbrhosts fixture.
        all_cfg_facts: The config facts fixture from voq/conftest.py
        nbr_macs: The nbr_macs fixture from voq/conftest.py

    """

    logger.info("Checking local neighbors on host: %s, asic: %s", per_host.hostname, asic.asic_index)
    ret = check_all_neighbors_present_local(duthosts, per_host, asic, neighs, all_cfg_facts, nbrhosts, nbr_macs, check_nbr_state=check_nbr_state)
    encaps = ret['encaps']
    fail_cnt = ret['fail_cnt']

    # Check the neighbor entry on each remote linecard
    for rem_host in duthosts.frontend_nodes:

        for rem_asic in rem_host.asics:
            if rem_host == per_host and rem_asic == asic:
                # skip remote check on local host
                continue
            ret = check_all_neighbors_present_remote(per_host, rem_host, rem_asic, neighs, encaps,
                                                     all_cfg_facts, nbrhosts, nbr_macs)

            fail_cnt += ret['fail_cnt']

    if fail_cnt > 1:
        pytest.fail("Test failed because of previous errors.")
    else:
        logger.info("Verification of all neighbors succeeded.")


def asic_cmd(asic, cmd, module_ignore_errors=False):
    """
    Runs a command in the appropriate namespace for an ASIC.
    Args:
        asic: Instance of SonicAsic to run a command.
        cmd: Command string to execute.
        module_ignore_errors: Flag to pass along to ansible to ignore any execution errors.

    Returns:
        The output of the SonicHost.command() execution.

    """
    if asic.namespace is not None:
        fullcmd = "sudo ip netns exec {} {}".format(asic.namespace, cmd)
        return asic.sonichost.command(fullcmd, module_ignore_errors=module_ignore_errors)
    else:
        return asic.sonichost.command(cmd, module_ignore_errors=module_ignore_errors)


def sonic_ping(asic, ipaddr, count=1, timeout=3, interface=None, size=None, ttl=None, verbose=False):
    """
    Sends a ping from a sonic asic instance.

    Args:
        asic: Instance of SonicAsic to send ping command in.
        ipaddr: String with the target IP.
        count: Integer for ping count.
        timeout: Integer of timeout.
        interface: String of IP address to egress packet.
        size: size of ICMP data.
        ttl: TTL of sent packet
        verbose: True to print send and rx output.

    Returns:
        The output of the SonicHost.command() execution.

    """
    cmd = "ping -c{c} {ip} -W {to}".format(c=count, ip=ipaddr, to=timeout)
    if interface is not None:
        cmd += " -I {}".format(interface)
    if size is not None:
        cmd += " -s {}".format(size)
    if ttl is not None:
        cmd += " -t {}".format(ttl)

    output = asic_cmd(asic, cmd, module_ignore_errors=True)

    if verbose:
        logger.info("Ping  : %s, %s : %s" % (asic.sonichost.hostname, asic.asic_index, cmd))
        logger.info("Result: %s", output['stdout_lines'][-2:])

    output['parsed'] = parse_ping(output['stdout_lines'])

    if "0% packet loss" not in output['stdout_lines'][-2]:
        raise AssertionError(output['parsed'])

    return output


def check_neighbors_are_gone(duthosts, all_cfg_facts, per_host, asic, neighbors):
    """
    Verifies a neighbor has been deleted from local and remote sonic instances, and the supervisor.

    Args:
        duthosts: Instance of the duthosts fixture.
        all_cfg_facts: Instance of fixture from voq/conftest.py
        per_host: Instance of MultiAsicSonicHost where neighbor is attached.
        asic: Instance of SonicAsic where neighbor is attached.
        neighbors: List of IPs of the neighbors to check.

    """
    asicdb = AsicDbCli(asic)
    appdb = AppDbCli(asic)

    # Check that the arp entry is deleted for all the neighbors on all the asics.
    poll_neighbor_table_delete(duthosts, neighbors, poll_time=30)

    asicdb_neigh_table = asicdb.dump_neighbor_table()
    app_neigh_table = appdb.dump_neighbor_table()
    voqdb = VoqDbCli(duthosts.supervisor_nodes[0])
    voq_dump = voqdb.dump_neighbor_table()

    for neighbor in neighbors:
        logger.info("Checking neighbor entry for %s is deleted from host: %s, asic: %s", neighbor, per_host.hostname,
                    asic.asic_index)

        for entry in asicdb_neigh_table.keys():
            search = '"ip":"%s"' % neighbor
            if search in entry:
                raise AssertionError("Found neighbor %s in asicdb: %s", search, entry)

        for entry in app_neigh_table.keys():
            if entry.endswith(":" + neighbor):
                raise AssertionError("Found neighbor %s in app: %s", neighbor, entry)

        # check supervisor
        for entry in voq_dump.keys():
            if entry.endswith(":" + neighbor):
                raise AssertionError("Found neighbor %s in voq: %s", neighbor, entry)

    # check remote hosts
    for rem_host in duthosts.frontend_nodes:
        for rem_asic in rem_host.asics:
            if rem_host == per_host and rem_asic == asic:
                # skip remote check on local host
                continue
            for neighbor in neighbors:
                logger.info("Remote host checks of ARP/NDP for %s are deleted from host: %s, asic: %s", neighbor,
                            rem_host.hostname,
                            rem_asic.asic_index)
                rem_cfg_facts = all_cfg_facts[rem_host.hostname][rem_asic.asic_index]['ansible_facts']
                remote_inband_info = get_inband_info(rem_cfg_facts)
                if remote_inband_info == {}:
                    logger.info("No inband configuration on this ASIC: %s/%s, skipping", rem_host.hostname,
                                rem_asic.asic_index)
                    continue
                asicdb = AsicDbCli(rem_asic)
                appdb = AppDbCli(rem_asic)
                asicdb_neigh_table = asicdb.dump_neighbor_table()
                app_neigh_table = appdb.dump_neighbor_table()

                for entry in asicdb_neigh_table.keys():
                    search = '"ip":"%s"' % neighbor
                    if search in entry:
                        raise AssertionError("Found neighbor %s in asicdb: %s", search, entry)

                for entry in app_neigh_table.keys():
                    if entry.endswith(":" + neighbor):
                        raise AssertionError("Found neighbor %s in app: %s", neighbor, entry)

                check_neighbor_kernel_route(rem_host, rem_asic.asic_index, neighbor, remote_inband_info['port'],
                                            present=False)


def parse_ping(stdout):
    """
    Parses the result of the ping command for eos and sonic.

    Args:
        stdout: The stdout_lines output of the eos_ping or sonic_ping.

    Returns:
        A list of dictionaries, one per packet. The dictionary has the following keys:
            -icmp_seq: the sequence number of the packet
            -bytes: the received packet size
            -ttl: the received ttl
            -time: the received round trip time.
            -ttl_exceeded: flag for whether a ttl exceeded error was recieved.

    """
    parsed_lines = []
    for line in stdout:
        # 64 bytes from 100.0.0.1: icmp_seq=1 ttl=63 time=1.32 ms
        parsed = {}
        match = re.search(r"icmp_seq=(\d+)", line)
        if match:
            parsed['icmp_seq'] = match.group(1)
        else:
            continue

        match = re.search(r"(\d+) bytes", line)
        if match:
            parsed['bytes'] = match.group(1)

        match = re.search(r"ttl=(\d+)", line)
        if match:
            parsed['ttl'] = match.group(1)

        match = re.search(r"time=([\.\d]+)", line)
        if match:
            parsed['time'] = match.group(1)

        match = re.search(r"Time[\w\s]+exceeded", line)
        if match:
            parsed['ttl_exceed'] = True
        else:
            parsed['ttl_exceed'] = False

        if parsed != {}:
            parsed_lines.append(parsed)

    return parsed_lines


def eos_ping(eos, ipaddr, count=2, timeout=3, interface=None, size=None, ttl=None, verbose=False):
    """
    Sends a ping from a sonic asic instance.

    Args:
        eos: Instance of EosHost to send ping command in.
        ipaddr: String with the target IP.
        count: Integer for ping count.
        timeout: Integer of timeout.
        interface: String of IP address to egress packet.
        size: size of ICMP data.
        ttl: TTL of sent packet
        verbose: True to print send and rx output.

    Returns:
        The output of the EosHost.eos_command() execution.

    Raises:
        AssertionError if there an error code returned from the command.

    """

    cmd = "sudo ping -c{c} {ip} -W {to}".format(c=count, ip=ipaddr, to=timeout)
    if interface is not None:
        cmd += " -I {}".format(interface)
    if size is not None:
        cmd += " -s {}".format(size)
    if ttl is not None:
        cmd += " -t {}".format(ttl)

    output = eos.command(cmd, module_ignore_errors=True)
    if verbose:
        logger.info("Ping  : %s" % cmd)
        logger.info("Result: %s", output['stdout_lines'][-2:])

    output['parsed'] = parse_ping(output['stdout_lines'])

    if "Network is unreachable" in output['stderr']:
        raise AssertionError('Network is unreachable')

    if "error code" in output['stdout_lines'][-1]:
        raise AssertionError(output['parsed'])

    if "0% packet loss" not in output['stdout_lines'][-2]:
        logger.warning("Did not find 0 percent packet loss: %s" % output['stdout_lines'][-2:])
        raise AssertionError("Ping failed: %s" % output['parsed'])

    return output


def get_ptf_port(duthosts, cfg_facts, tbinfo, dut, dut_port):
    """
    Gets the port or ports of the PTF connected to a specific dut port.

    Args:
        duthosts: The duthosts fixture.
        cfg_facts: The config facts for the requested dut.
        tbinfo: The tbinfo fixture.
        dut: The duthost (frontend node) the port is on.
        dut_port: The port of the dut the needed PTF is connected to.

    Returns:
        A list of ports connected to a dut port.  Single element list if dutport
        is ethernet, multiple elements if dutport is portchannel.  The port numbers
        are ints.

    """

    # get the index of the frontend node to index into the tbinfo dictionary.
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)

    if "portchannel" in dut_port.lower():
        pc_cfg = cfg_facts['PORTCHANNEL_MEMBER']
        pc_members = pc_cfg[dut_port]
        logger.info("Portchannel members %s: %s", dut_port, pc_members.keys())
        port_list = pc_members.keys()
    else:
        port_list = [dut_port]

    ret = []
    for port in port_list:
        ret.append(mg_facts['minigraph_ptf_indices'][port])

    return ret
