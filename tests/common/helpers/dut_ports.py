import logging
import netaddr

logger = logging.getLogger(__name__)


def encode_dut_port_name(dutname, portname):
    return dutname + '|' + portname


def decode_dut_port_name(dut_portname):
    tokens = dut_portname.split('|')
    if len(tokens) >= 2:
        dutname = tokens[0]
        portname = tokens[1]
    elif len(tokens) == 1:
        dutname = None
        portname = dut_portname
    else:
        dutname = None
        portname = None
    return dutname, portname


def get_duthost_with_name(duthosts, dut_name):
    for duthost in duthosts:
        if dut_name in ['unknown', duthost.hostname]:
            return duthost
    logger.error("Can't find duthost with name {}.".format(dut_name))
    return


def get_vlan_interfaces_dict(duthost, tbinfo):
    """
    Helper function to organize VLAN interface information from minigraph and config facts
    into a structured dictionary separating IPv4 and IPv6 addresses per VLAN.

    Args:
        mg_facts (dict): Minigraph facts containing VLAN interface information
        config_facts (dict): Config facts containing VLAN interface configuration

    Returns:
        dict: Structured dictionary with VLAN interfaces organized by IPv4/IPv6 addresses
        {
            "Vlan1000": {
                "ipv4": [
                {
                    'addr': '192.168.0.1',
                    'subnet': '192.168.0.0/25',
                    'prefixlen': 25,
                    'mask': '255.255.255.128',
                    'peer_addr': '192.168.0.2'
                },
                {
                    'addr': '192.169.0.1',
                    'subnet': '192.169.0.0/22',
                    'attachto': 'Vlan1000',
                    'prefixlen': 22,
                    'mask': '255.255.252.0',
                    'peer_addr': '192.169.0.2',
                    'secondary': True
                }
                ],
                "ipv6": [
                {
                    'addr': 'fc02:1000::1',
                    'subnet': 'fc02:1000::/64',
                    'attachto': 'Vlan1000',
                    'prefixlen': 64,
                    'mask': '64',
                    'peer_addr': 'fc02:1000::2'
                }
                ]
            }
        }
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    result = {}

    # Group interfaces by VLAN
    for interface in mg_facts['minigraph_vlan_interfaces']:
        vlan = interface['attachto']
        if vlan not in result:
            result[vlan] = {'ipv4': [], 'ipv6': []}

        # Create interface info dict
        interface_info = {
            'addr': interface['addr'],
            'subnet': interface['subnet'],
            'prefixlen': interface['prefixlen'],
            'mask': interface['mask'],
            'peer_addr': interface['peer_addr'],
            'attachto': interface['attachto']
        }

        # Check if this is a secondary address from config facts
        if vlan in config_facts['VLAN_INTERFACE']:
            ip_with_prefix = f"{interface['addr']}/{interface['prefixlen']}"
            if ip_with_prefix in config_facts['VLAN_INTERFACE'][vlan]:
                config = config_facts['VLAN_INTERFACE'][vlan][ip_with_prefix]
                if isinstance(config, dict) and config.get('secondary') == 'true':
                    interface_info['secondary'] = True

        # Add to appropriate IP version list
        ip_version = netaddr.IPAddress(str(interface['addr'])).version
        if ip_version == 6:  # IPv6
            result[vlan]['ipv6'].append(interface_info)
        else:  # IPv4
            result[vlan]['ipv4'].append(interface_info)
    return result


def get_vlan_interface_list(duthost):
    """
    Helper function to get list of VLANs configured on the device.

    Args:
        mg_facts (dict): Minigraph facts containing VLAN interface information

    Returns:
        list: List of VLAN names (e.g. ["Vlan1000"] or ["Vlan1000", "Vlan2000"])
    """
    vlans = set()
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    for vlan_interface in config_facts['VLAN_INTERFACE']:
        vlans.add(vlan_interface)
    return sorted(list(vlans))


def get_vlan_interface_info(duthost, tbinfo, vlan_name, ip_version="ipv4"):
    """
    Helper function to get non-secondary IP interface information for a specific VLAN and IP version.

    Args:
        vlan_interfaces_dict (dict): Dict containing VLAN interface information from get_vlan_interfaces_dict()
        vlan_name (str): Name of VLAN interface (e.g. "Vlan1000")
        ip_version (int): IP version to filter by (4 or 6)

    Returns:
        list: List of dicts containing interface info (addr, subnet, etc) for non-secondary IPs
        {
            'addr': '192.168.0.1',
            'subnet': '192.168.0.0/25',
            'prefixlen': 25,
            'mask': '255.255.255.128',
            'peer_addr': '192.168.0.2'
        }
    """
    vlan_interfaces_dict = get_vlan_interfaces_dict(duthost, tbinfo)
    if vlan_name not in vlan_interfaces_dict:
        return {}

    result = {}

    for interface in vlan_interfaces_dict[vlan_name][ip_version]:
        # Skip secondary addresses
        if isinstance(interface, dict) and interface.get('secondary'):
            continue

        result = interface
        break

    return result


def get_secondary_subnet(duthost, tbinfo):
    """
    Check if any VLAN interface has a secondary subnet configured.

    Args:
        tbinfo: Testbed information dictionary

    Returns:
        tuple: (has_secondary, vlan_name, ip_version, interface_info)
        - has_secondary: True if a secondary subnet exists
        - vlan_name: VLAN interface name with secondary subnet
        - ip_version: IP version ("ipv4" or "ipv6") of the secondary subnet
        - interface_info: Configuration dict for the secondary subnet
    """
    vlan_interfaces_dict = get_vlan_interfaces_dict(duthost, tbinfo)

    # Initialize return values
    for vlan_name, ip_versions in vlan_interfaces_dict.items():
        for ip_version, interfaces in ip_versions.items():
            for interface in interfaces:
                if interface.get('secondary'):
                    return True, vlan_name, ip_version, interface

    # No secondary subnet found
    return False, None, None, None
