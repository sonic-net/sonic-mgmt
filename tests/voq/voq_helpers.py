import json
import logging
import re
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.redis import AsicDbCli, AppDbCli, VoqDbCli

logger = logging.getLogger(__name__)


def check_host_arp_table(host, neighbor_ip, neighbor_mac, interface, state):
    """
    Validates the ARP table of a host by running ip neigh for a single neighbor.

    Args:
        host: instance of SonicHost to run the arp show.
        neighbor_ip: IP address of the neighbor to verify.
        neighbor_mac: MAC address expected in the show command output.
        interface: Port expected in the show command output.
        state: ARP entry state expected in the show command output.

    """
    arptable = host.switch_arptable()['ansible_facts']
    logger.debug("ARP: %s", arptable)
    if ':' in neighbor_ip:
        table = arptable['arptable']['v6']
    else:
        table = arptable['arptable']['v4']
    pytest_assert(neighbor_ip in table, "IP %s not in arp list: %s" % (neighbor_ip, table.keys()))
    pytest_assert(table[neighbor_ip]['macaddress'] == neighbor_mac,
                  "table MAC %s does not match neighbor mac: %s" % (table[neighbor_ip]['macaddress'], neighbor_mac))
    pytest_assert(table[neighbor_ip]['interface'] == interface,
                  "table interface %s does not match interface: %s" % (table[neighbor_ip]['interface'], interface))
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
    check_host_arp_table(host, neighbor_ip, neighbor_mac, interface, 'REACHABLE')

    return {'neighbor_key': neighbor_key, 'encap_index': asic_dict['encap_index']}


def check_bgp_kernel_route(host, asicnum, prefix, ipver, interface, present=True):
    """
    Checks the kernel route is installed from the bgp container.

    Args:
        host: sonic duthost instance to check.
        asicnum: asic index to check.
        prefix: IP address plus mask to check in routing table.
        ipver: ip or ipv6.
        interface: Attached interface for the neighbor route.
        present: Optional; Check whether route is installed or removed.

    Raises:
        Pytest Failed exception when assertions fail.

    """
    docker = "bgp"
    if host.facts["num_asic"] > 1:
        docker = "bgp" + str(asicnum)

    output = host.command("docker exec " + docker + " vtysh -c \"show {} route {} json\"".format(ipver, prefix))
    parsed = json.loads(output["stdout"])
    if present is True:
        pytest_assert(prefix in parsed.keys(), "Prefix: %s not in route list: %s" % (prefix, parsed.keys()))
        for route in parsed[prefix]:
            if route['distance'] != 0:
                found = False
                continue
            pytest_assert(route['protocol'] == "kernel", "Prefix: %s not kernel route" % prefix)
            pytest_assert(route['nexthops'][0]['directlyConnected'] is True,
                          "Prefix: %s not directly connected" % prefix)
            pytest_assert(route['nexthops'][0]['active'] is True, "Prefix: %s not active" % prefix)
            pytest_assert(route['nexthops'][0]['interfaceName'] == interface,
                          "Prefix: %s out interface is not correct" % prefix)

            found = True
            break
        pytest_assert(found, "Kernel route is not present in bgp output: %s" % parsed[prefix])
        logger.info("Route %s is present in remote neighbor: %s/%s", prefix, host.hostname, str(asicnum))


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
    if present is True:
        logger.info("host ip route output: %s", output)
        pytest_assert(output.startswith(ipaddr), "Address: %s not in netstat output list: %s" % (ipaddr, output))
        pytest_assert("dev %s" % interface in output, "Interface is not %s: %s" % (interface, output))


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
                                            'SAI_NEIGHBOR_ENTRY_ATTR_ENCAP_IMPOSE_INDEX') == "true",
                  "Encap impose is not true in asicDB")
    pytest_assert(asicdb.get_neighbor_value(neighbor_key,
                                            'SAI_NEIGHBOR_ENTRY_ATTR_IS_LOCAL') == "false",
                  "is local is not false in asicDB")

    # LC app db
    appdb = AppDbCli(asic)
    neighbor_key = appdb.get_neighbor_key_by_ip(neighbor_ip)
    pytest_assert(":{}:".format(interface) in neighbor_key, "Port for %s does not match" % neighbor_key)
    appdb.get_and_check_key_value(neighbor_key, inband_mac, field="neigh")

    # verify linux arp table
    check_host_arp_table(host, neighbor_ip, inband_mac, interface, 'PERMANENT')

    # verify linux route entry
    check_neighbor_kernel_route(host, asic.asic_index, neighbor_ip, interface)


def check_rif_on_sup(sup, rif, slot, asic, port):
    """
    Checks the router interface entry on the supervisor card.

    Args:
        sup: duthost for the supervisor card
        rif: OID of the router interface to check for.
        slot: The slot number the router interface is on.
        asic: The asic number the asic is on, or 0 if a single asic card.
        port: the name of the port (Ethernet1)

    """
    voqdb = VoqDbCli(sup)

    rif_oid = voqdb.get_router_interface_id(slot, asic, port)

    if rif_oid == rif:
        logger.info("RIF on sup: %s = %s", rif_oid, rif)
    elif rif_oid[-10:-1] == rif[-10:-1]:
        logger.warning("RIF on sup is a partial match: %s != %s", rif_oid, rif)
    else:
        logger.error("RIF on sup does not match: %s != %s" % (rif_oid, rif))


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
    pytest_assert("|%s:" % port in neigh_key,
                  "Port for %s does not match %s" % (neigh_key, port))
    pytest_assert("|%s|" % asic in neigh_key,
                  "Asic for %s does not match %s" % (neigh_key, asic))

    voqdb.get_and_check_key_value(neigh_key, mac, field="neigh")
    voqdb.get_and_check_key_value(neigh_key, encap_index, field="encap_index")


def get_neighbor_mac(neigh_ip, nbrhosts, nbrhosts_facts):
    """
    Gets the MAC address of a neighbor IP on an EOS host.

    We need to get the MAC of the VM out of the linux shell, not from the EOS CLI.  The MAC used for punt/inject
    on the EOS seems to be the linux one.  Find the interface name on the VM that is associated with the IP address,
    then look on the linux OS shell for the MAC address of that interface.

    Args:
        neigh_ip: The IP address of the neighbor.
        nbrhosts: dictionary provided by the nbrhosts fixture.

    Returns:
        A string with the MAC address.
    """
    nbr_vm = ""
    nbr_intf = ""

    for a_vm in nbrhosts_facts:

        intfs = nbrhosts_facts[a_vm]['ansible_facts']['ansible_net_interfaces']
        for intf in intfs:
            if intfs[intf]['ipv4'] != {} and intfs[intf]['ipv4']['address'] == neigh_ip:
                nbr_vm = a_vm
                nbr_intf = intf
                break
            if 'ipv6' in intfs[intf] and intfs[intf]['ipv6']['address'].lower() == neigh_ip.lower():
                nbr_vm = a_vm
                nbr_intf = intf
                break
        if nbr_vm != "":
            break
    else:
        logger.error("Could not find port for neighbor IP: %s", neigh_ip)
        logger.info("vm facts: {}".format(json.dumps(nbrhosts_facts, indent=4)))
        return None
    # convert Ethernet1 to eth1
    shell_intf = "eth" + nbr_intf[-1]
    nbrhosts[nbr_vm]['host'].eos_command(commands=["enable"])
    output = nbrhosts[nbr_vm]['host'].eos_command(commands=["bash ip addr show dev %s" % shell_intf])
    # 8: Ethernet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9100 ...
    #     link/ether a6:69:05:fd:da:5f brd ff:ff:ff:ff:ff:ff
    mac = output['stdout_lines'][0][1].split()[1]
    logger.info("mac: %s", mac)
    return mac


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

    intf = cfg_facts['VOQ_INBAND_INTERFACE']
    ret = {}
    for a_intf in intf:
        for addrs in intf[a_intf]:
            ret['port'] = a_intf
            intf_ip = addrs.split('/')
            if ':' in intf_ip[0]:
                ret['ipv6_addr'] = intf_ip[0]
                ret['ipv6_mask'] = intf_ip[1]
            elif ':' not in intf_ip[0]:
                ret['ipv4_addr'] = intf_ip[0]
                ret['ipv4_mask'] = intf_ip[1]
    return ret


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
    intf.update(cfg_facts['INTERFACE'])
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


def find_system_port(dev_sysports, slot, asic_index, hostif):
    """
    System key string can be arbitrary text with slot, asic, and port, so try to find the match
    and return the correct string.  ex.  "Slot1|asic3|Ethernet12" or "Linecard4|Asic1|Portchannel23"

    Args:
        dev_sysports: dictionary from config_facts with all of the system ports on the system.
        slot: The slot number of the system port to find.
        asic_index: The asic number of ths system port to find.
        hostif: The interface of the system port to find.

    Returns:
        A dictionary with the system port text strings.

    Raises:
        KeyError if the system port can't be found in the dictionary.

    """

    sys_re = re.compile(r'([a-zA-Z]+{})\|([a-zA-Z]+{})\|{}'.format(slot, asic_index, hostif))
    sys_info = {}

    for sysport in dev_sysports:
        match = sys_re.match(sysport)
        if match:
            sys_info['slot'] = match.group(1)
            sys_info['asic'] = match.group(2)
            sys_info['key'] = sysport
            return sys_info

    raise KeyError("Could not find system port for {}/{}/{}".format(slot, asic_index, hostif))
