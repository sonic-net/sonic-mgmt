import sys
import ipaddress
from ipaddress import ip_address, IPv4Address, IPv6Address

# NOTE: Ensure the ports are mapped correctly to the respective duts in ansible/files/*links.csv
# NOTE: The MULTIDUT_TESTBED must match with the conf-name defined in testbed.yml/testbed.csv file
MULTIDUT_TESTBED = 'vms-snappi-sonic-multidut'
MULTIDUT_PORT_INFO = {MULTIDUT_TESTBED: (
    ({
        'multi-dut-single-asic': {
            'rx_ports': [
                {'port_name': 'Ethernet72', 'hostname': "sonic-s6100-dut1"},
                {'port_name': 'Ethernet76', 'hostname': "sonic-s6100-dut1"}
            ],
            'tx_ports': [
                {'port_name': 'Ethernet64', 'hostname': "sonic-s6100-dut2"},
                {'port_name': 'Ethernet68', 'hostname': "sonic-s6100-dut2"}
            ]
        }
    }),
    ({
        'single-dut-single-asic': {
            'rx_ports': [
                {'port_name': 'Ethernet72', 'hostname': "sonic-s6100-dut1"},
                {'port_name': 'Ethernet76', 'hostname': "sonic-s6100-dut1"}
            ],
            'tx_ports': [
                {'port_name': 'Ethernet64', 'hostname': "sonic-s6100-dut1"},
                {'port_name': 'Ethernet68', 'hostname': "sonic-s6100-dut1"}
            ]
        }
    })
)}
# rx port is 400Gbps port receiving traffic in mixed-speed mode.
# tx port is 100Gbps port sending traffic to IXIA.
MIXED_SPEED_PORT_INFO = {MULTIDUT_TESTBED: (
    ({
        'multiple-dut-any-asic': {
            'rx_ports': [
                {'port_name': 'Ethernet0', 'hostname': "sonic-s6100-dut1"}
            ],
            'tx_ports': [
                {'port_name': 'Ethernet0', 'hostname': "sonic-s6100-dut2"}
            ]
        }
    })
)}
'''
In this file user can modify the line_card_choice and it chooses the corresponding hostname
and asic values from the config_set hostnames can be modified according to the dut hostname mentioned
in the snappi_sonic_devices.csv and asic values based on if its a chassis based dut
    chassis_single_line_card_single_asic : this option selects the ports form the
                                           hostname and its respective asic value
    chassis_single_line_card_multi_asic : this option selects the ports from the hostname
                                          and minimum of 1 port from each of the asic values
    chassis_multi_line_card_single_asic : this option selects min 1 port from each of
                                          the hostnames and its asic value
    chassis_multi_line_card_multi_asic : this option selects min of 1 port from hostname1
                                         and asic1 and 1 port from hostname2 and asic2
    non_chassis_multi_line_card : this option selects min of 1 port from hostname1
                                  and 1 port from hostname2
    non_chassis_single_line_card : this option selects all the ports from the hostname
'''
line_card_choice = 'chassis_multi_line_card_multi_asic'
config_set = {
                "chassis_single_line_card_single_asic": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': ["asic0"]
                },
                "chassis_single_line_card_multi_asic": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': ["asic0", "asic1"]
                },
                "chassis_multi_line_card_single_asic": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': ["asic1"]
                },
                "chassis_multi_line_card_multi_asic": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': ["asic0", "asic1"]
                },
                "non_chassis_multi_line_card": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': [None]
                },
                "non_chassis_single_line_card": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': [None]
                }
            }


def create_ip_list(value, count, mask=32, incr=0):
    '''
        Create a list of ips based on the count provided
        Parameters:
            value: start value of the list
            count: number of ips required
            mask: subnet mask for the ips to be created
            incr: increment value of the ip
    '''
    if sys.version_info.major == 2:
        value = unicode(value)          # noqa: F821

    ip_list = [value]
    for i in range(1, count):
        if ip_address(value).version == 4:
            incr1 = pow(2, (32 - int(mask))) + incr
            value = (IPv4Address(value) + incr1).compressed
        elif ip_address(value).version == 6:
            if mask == 32:
                mask = 64
            incr1 = pow(2, (128 - int(mask))) + incr
            value = (IPv6Address(value) + incr1).compressed
        ip_list.append(value)

    return ip_list


def get_host_addresses(subnet, count):
    try:
        # Create an IPv4Network object
        network = ipaddress.ip_network(subnet, strict=False)

        # Generate all possible host addresses
        all_hosts = list(network.hosts())

        # Check if the requested count is within the available host range
        if count > len(all_hosts):
            raise ValueError("Requested count exceeds the number of available hosts in the subnet.")

        # Return the list of host addresses up to the specified count
        return all_hosts[:count]

    except ValueError as e:
        return str(e)


# =============================================================================
# BGP OUTBOUND ROUTE CONVERGENCE TEST CONFIGURATIONS
# =============================================================================
#
# This file contains configuration variables for BGP outbound route convergence tests.
# It supports two topology types:
#   - T2_CHASSIS: Multi-DUT chassis topology (Uplink LC, Downlink LC, Supervisor)
#   - T2_PIZZABOX: Single-DUT pizzabox topology (multi-asic)
#
# PRE-REQUISITE:
#   DUT Configs:
#     For T2 Chassis: Use topo_tgen_t2_2lc_masic_route_conv.yml (multi-asic)
#                     or topo_tgen_t2_2lc_route_conv.yml (single-asic)
#     For T2 Pizzabox: Use topo_t2_tgen_route_conv.yml (multi-asic)
#     For Lower Tier DUT: Configure using initial_setup() fixture in conftest.py
#     For Fanout: Configure using initial_setup() fixture in conftest.py
#
# =============================================================================

# =============================================================================
# TOPOLOGY TYPE CONSTANTS
# =============================================================================
TOPOLOGY_T2_CHASSIS = 'T2_CHASSIS'
TOPOLOGY_T2_PIZZABOX = 'T2_PIZZABOX'

# =============================================================================
# COMMON CONSTANTS (shared by both topologies)
# =============================================================================
# AS Numbers:
#   T2_DUT_AS_NUM (65100): The T2 DUT under test
#   UPPER_TIER_SNAPPI_AS_NUM (65400): T3/Spine devices emulated via Snappi on uplink side
#   BACKUP_T2_SNAPPI_AS_NUM (65300): Backup T2 DUTs emulated via Snappi on downlink side
#   LOWER_TIER_DUT_AS_NUM (65200): Lower tier DUT AS number
T2_DUT_AS_NUM = 65100
UPPER_TIER_SNAPPI_AS_NUM = 65400
BACKUP_T2_SNAPPI_AS_NUM = 65300
LOWER_TIER_DUT_AS_NUM = 65200

# BGP Configuration
BGP_TYPE = 'ebgp'
SNAPPI_TRIGGER = 60      # timeout value for snappi operation
DUT_TRIGGER = 180        # longer timeout value for dut operation
DUT_TRIGGER_SHORT = 60   # shorter timeout value for dut operation

# IP Subnets
IPV4_SUBNET = '20.0.1.1/31'
IPV6_SUBNET = '2000:1:1:1::1/126'
V4_PREFIX_LENGTH = int(IPV4_SUBNET.split('/')[1])
V6_PREFIX_LENGTH = int(IPV6_SUBNET.split('/')[1])

# BGP Communities
COMMUNITY_LOWER_TIER_LEAK = ["8075:54000"]
COMMUNITY_LOWER_TIER_DROP = ["8075:54001"]
COMMUNITY_UPPER_TIER = ["8075:316", "8075:10400"]

# Other constants
AS_PATHS = [65002]
NUM_REGIONAL_HUBS = 2
FANOUT_PRESENCE = True

# =============================================================================
# TOPOLOGY-SPECIFIC CONFIGURATIONS
# Organized by: TOPOLOGY -> VENDOR -> DATA
# =============================================================================
# Note: Increase the MaxSessions in /etc/ssh/sshd_config if the number of fanout ports used is more than 10

TOPOLOGY_CONFIG = {
    # =========================================================================
    # T2 CHASSIS TOPOLOGY (Multi-DUT: Uplink LC, Downlink LC, Supervisor)
    # =========================================================================
    TOPOLOGY_T2_CHASSIS: {
        'Vendor1': {
            # Device hostnames: [lower_tier, uplink_dut, downlink_dut, supervisor]
            'device_hostnames': ["str2-7260cx3-d10-u42", "str2-7250-lc1-2", "str2-7250-lc2-2", "str2-7250-sup-2"],

            'lower_tier_info': {
                'dut_ip': '10.64.246.10',
                'ports': ['Ethernet24', 'Ethernet28'],
                'interconnect_port': 'Ethernet0',
            },

            'lower_tier_snappi_ports': [
                {
                    "ip": "10.3.145.74",
                    "port_id": "11.3",
                    "peer_port": "Ethernet24",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.3.145.74/11.3",
                    "api_server_ip": "10.64.246.188",
                },
                {
                    "ip": "10.3.145.74",
                    "port_id": "11.4",
                    "peer_port": "Ethernet28",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.3.145.74/11.4",
                    "api_server_ip": "10.64.246.188",
                },
            ],

            'uplink_fanout': {
                'fanout_ip': '10.3.146.9',
                'port_mapping': [
                    {'fanout_port': 'Ethernet64', 'uplink_port': 'Ethernet0'},
                    {'fanout_port': 'Ethernet68', 'uplink_port': 'Ethernet8'},
                    {'fanout_port': 'Ethernet72', 'uplink_port': 'Ethernet16'},
                    {'fanout_port': 'Ethernet76', 'uplink_port': 'Ethernet24'},
                    {'fanout_port': 'Ethernet80', 'uplink_port': 'Ethernet40'},
                    {'fanout_port': 'Ethernet84', 'uplink_port': 'Ethernet48'},
                    {'fanout_port': 'Ethernet88', 'uplink_port': 'Ethernet56'},
                    {'fanout_port': 'Ethernet92', 'uplink_port': 'Ethernet64'},
                    {'fanout_port': 'Ethernet96', 'uplink_port': 'Ethernet144'},
                    {'fanout_port': 'Ethernet100', 'uplink_port': 'Ethernet152'},
                    {'fanout_port': 'Ethernet104', 'uplink_port': 'Ethernet160'},
                    {'fanout_port': 'Ethernet108', 'uplink_port': 'Ethernet168'},
                    {'fanout_port': 'Ethernet112', 'uplink_port': 'Ethernet176'},
                    {'fanout_port': 'Ethernet116', 'uplink_port': 'Ethernet184'},
                    {'fanout_port': 'Ethernet120', 'uplink_port': 'Ethernet192'},
                    {'fanout_port': 'Ethernet124', 'uplink_port': 'Ethernet200'}
                ]
            },

            'uplink_portchannel_members': {
                'asic0': {
                    'PortChannel0': ['Ethernet0', 'Ethernet8'],
                    'PortChannel1': ['Ethernet16'],
                    'PortChannel2': ['Ethernet24'],
                    'PortChannel3': ['Ethernet40'],
                    'PortChannel4': ['Ethernet48'],
                    'PortChannel5': ['Ethernet56'],
                    'PortChannel6': ['Ethernet64']
                },
                'asic1': {
                    'PortChannel7': ['Ethernet144'],
                    'PortChannel8': ['Ethernet152'],
                    'PortChannel9': ['Ethernet160'],
                    'PortChannel10': ['Ethernet168'],
                    'PortChannel11': ['Ethernet176'],
                    'PortChannel12': ['Ethernet184'],
                    'PortChannel13': ['Ethernet192'],
                    'PortChannel14': ['Ethernet200']
                }
            },

            'dut_interconnect_port': {'port_name': 'Ethernet0', 'asic_value': 'asic0'},
        },

        'Vendor2': {
            # Device hostnames: [lower_tier, uplink_dut, downlink_dut, supervisor]
            'device_hostnames': ["str2-7260cx3-d10-u42", "str3-7800-lc6-2", "str3-7800-lc5-2", "str3-7808-sup-2"],

            'lower_tier_info': {
                'dut_ip': '10.64.246.10',
                'ports': ['Ethernet24', 'Ethernet28'],
                'interconnect_port': 'Ethernet32',
            },

            'lower_tier_snappi_ports': [
                {
                    "ip": "10.3.145.74",
                    "port_id": "11.3",
                    "peer_port": "Ethernet24",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.3.145.74/11.3",
                    "api_server_ip": "10.64.246.188",
                },
                {
                    "ip": "10.3.145.74",
                    "port_id": "11.4",
                    "peer_port": "Ethernet28",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.3.145.74/11.4",
                    "api_server_ip": "10.64.246.188",
                },
            ],

            'uplink_fanout': {
                'fanout_ip': '10.3.146.9',
                'port_mapping': [
                    {'fanout_port': 'Ethernet128', 'uplink_port': 'Ethernet0'},
                    {'fanout_port': 'Ethernet132', 'uplink_port': 'Ethernet4'},
                    {'fanout_port': 'Ethernet136', 'uplink_port': 'Ethernet8'},
                    {'fanout_port': 'Ethernet140', 'uplink_port': 'Ethernet12'},
                    {'fanout_port': 'Ethernet144', 'uplink_port': 'Ethernet16'},
                    {'fanout_port': 'Ethernet148', 'uplink_port': 'Ethernet20'},
                    {'fanout_port': 'Ethernet152', 'uplink_port': 'Ethernet24'},
                    {'fanout_port': 'Ethernet156', 'uplink_port': 'Ethernet28'},
                    {'fanout_port': 'Ethernet160', 'uplink_port': 'Ethernet32'},
                    {'fanout_port': 'Ethernet164', 'uplink_port': 'Ethernet36'},
                    {'fanout_port': 'Ethernet168', 'uplink_port': 'Ethernet40'},
                    {'fanout_port': 'Ethernet172', 'uplink_port': 'Ethernet44'},
                    {'fanout_port': 'Ethernet176', 'uplink_port': 'Ethernet48'},
                    {'fanout_port': 'Ethernet180', 'uplink_port': 'Ethernet52'},
                    {'fanout_port': 'Ethernet184', 'uplink_port': 'Ethernet56'},
                    {'fanout_port': 'Ethernet188', 'uplink_port': 'Ethernet60'}
                ]
            },

            'uplink_portchannel_members': {
                None: {
                    'PortChannel0': ['Ethernet0', 'Ethernet4'],
                    'PortChannel1': ['Ethernet8'],
                    'PortChannel2': ['Ethernet12'],
                    'PortChannel3': ['Ethernet16'],
                    'PortChannel4': ['Ethernet20'],
                    'PortChannel5': ['Ethernet24'],
                    'PortChannel6': ['Ethernet28'],
                    'PortChannel7': ['Ethernet32'],
                    'PortChannel8': ['Ethernet36'],
                    'PortChannel9': ['Ethernet40'],
                    'PortChannel10': ['Ethernet44'],
                    'PortChannel11': ['Ethernet48'],
                    'PortChannel12': ['Ethernet52'],
                    'PortChannel13': ['Ethernet56'],
                    'PortChannel14': ['Ethernet60']
                }
            },

            'dut_interconnect_port': {'port_name': 'Ethernet0', 'asic_value': None},
        },
    },

    # =========================================================================
    # T2 PIZZABOX TOPOLOGY (Single-DUT: multi-asic pizzabox)
    # =========================================================================
    TOPOLOGY_T2_PIZZABOX: {
        'Vendor1': {
            # Device hostnames: [lower_tier, dut]
            'device_hostnames': ["str2-7260cx3-d10-u42", "str-7280dr3-1"],

            'lower_tier_info': {
                'dut_ip': '10.64.246.10',
                'ports': ['Ethernet24', 'Ethernet28'],
                'interconnect_port': 'Ethernet112',
            },

            'lower_tier_snappi_ports': [
                {
                    "ip": "10.64.247.89",
                    "port_id": "9.3",
                    "peer_port": "Ethernet24",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.64.247.89/9.3",
                    "api_server_ip": "10.64.247.89",
                },
                {
                    "ip": "10.64.247.89",
                    "port_id": "9.4",
                    "peer_port": "Ethernet28",
                    "peer_device": "str2-7260cx3-d10-u42",
                    "speed": "speed_100_gbps",
                    "location": "10.64.247.89/9.4",
                    "api_server_ip": "10.64.247.89",
                },
            ],

            'uplink_fanout': {
                'fanout_ip': '10.64.247.77',
                'port_mapping': [
                    {'fanout_port': 'Ethernet128', 'uplink_port': 'Ethernet0'},
                    {'fanout_port': 'Ethernet132', 'uplink_port': 'Ethernet8'},
                    {'fanout_port': 'Ethernet136', 'uplink_port': 'Ethernet16'},
                    {'fanout_port': 'Ethernet140', 'uplink_port': 'Ethernet24'},
                    {'fanout_port': 'Ethernet144', 'uplink_port': 'Ethernet32'},
                    {'fanout_port': 'Ethernet148', 'uplink_port': 'Ethernet40'},
                    {'fanout_port': 'Ethernet152', 'uplink_port': 'Ethernet48'},
                    {'fanout_port': 'Ethernet156', 'uplink_port': 'Ethernet56'},
                    {'fanout_port': 'Ethernet160', 'uplink_port': 'Ethernet64'},
                    {'fanout_port': 'Ethernet164', 'uplink_port': 'Ethernet72'},
                    {'fanout_port': 'Ethernet168', 'uplink_port': 'Ethernet80'},
                    {'fanout_port': 'Ethernet172', 'uplink_port': 'Ethernet88'},
                    {'fanout_port': 'Ethernet176', 'uplink_port': 'Ethernet96'},
                    {'fanout_port': 'Ethernet180', 'uplink_port': 'Ethernet104'},
                    {'fanout_port': 'Ethernet184', 'uplink_port': 'Ethernet112'},
                    {'fanout_port': 'Ethernet188', 'uplink_port': 'Ethernet120'}
                ]
            },

            'uplink_portchannel_members': {
                'asic0': {
                    'PortChannel0': ['Ethernet0', 'Ethernet8'],
                    'PortChannel1': ['Ethernet16'],
                    'PortChannel2': ['Ethernet24'],
                    'PortChannel3': ['Ethernet32'],
                    'PortChannel4': ['Ethernet40'],
                    'PortChannel5': ['Ethernet48'],
                    'PortChannel6': ['Ethernet56'],
                    'PortChannel7': ['Ethernet64'],
                    'PortChannel8': ['Ethernet72'],
                    'PortChannel9': ['Ethernet80'],
                    'PortChannel10': ['Ethernet88'],
                    'PortChannel11': ['Ethernet96'],
                    'PortChannel12': ['Ethernet104'],
                    'PortChannel13': ['Ethernet112'],
                    'PortChannel14': ['Ethernet120']
                }
            },

            'dut_interconnect_port': {'port_name': 'Ethernet256', 'asic_value': 'asic1'},
        },
    },
}


# =============================================================================
# ACCESSOR FUNCTIONS
# =============================================================================

def get_topology_config(topology_type, vendor, key=None, default=None):
    """
    Get configuration value for a topology/vendor combination.

    Args:
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: VendorName
        key: Optional key to retrieve specific value. If None, returns entire vendor config.
        default: Default value if key not found

    Returns:
        Configuration value or default
    """
    vendor_config = TOPOLOGY_CONFIG.get(topology_type, {}).get(vendor, {})
    if key is None:
        return vendor_config
    return vendor_config.get(key, default)


def get_device_hostnames(topology_type, vendor):
    """Get device hostnames for a topology/vendor combination."""
    return get_topology_config(topology_type, vendor, 'device_hostnames', [])


def detect_topology_and_vendor(hostnames):
    """
    Detect topology type and vendor from DUT hostnames.

    Args:
        hostnames: List of DUT hostnames

    Returns:
        tuple: (topology_type, vendor) or (None, None) if not found
    """
    for topology_type in TOPOLOGY_CONFIG:
        for vendor in TOPOLOGY_CONFIG[topology_type]:
            device_hostnames = get_device_hostnames(topology_type, vendor)
            if any(host in device_hostnames for host in hostnames):
                return topology_type, vendor
    return None, None


def get_lower_tier_info(topology_type, vendor):
    """Get lower tier device info (IP, ports, interconnect port)."""
    return get_topology_config(topology_type, vendor, 'lower_tier_info', {})


def get_lower_tier_snappi_ports(topology_type, vendor):
    """Get Snappi ports connected to lower tier device."""
    return get_topology_config(topology_type, vendor, 'lower_tier_snappi_ports', [])


def get_uplink_fanout_info(topology_type, vendor):
    """Get fanout info for uplink ports."""
    return get_topology_config(topology_type, vendor, 'uplink_fanout', {})


def get_uplink_portchannel_members(topology_type, vendor):
    """Get portchannel members for uplink ports."""
    return get_topology_config(topology_type, vendor, 'uplink_portchannel_members', {})


def get_dut_interconnect_port(topology_type, vendor):
    """Get DUT-side interconnect port info."""
    return get_topology_config(topology_type, vendor, 'dut_interconnect_port', {})


def get_as_numbers():
    """
    Get AS numbers used in BGP configuration.

    Returns:
        dict: Dictionary with AS number mappings
    """
    return {
        'dut_as': T2_DUT_AS_NUM,
        'upper_tier_snappi_as': UPPER_TIER_SNAPPI_AS_NUM,
        'backup_t2_snappi_as': BACKUP_T2_SNAPPI_AS_NUM,
        'lower_tier_dut_as': LOWER_TIER_DUT_AS_NUM,
    }


def get_routed_port_count(topology_type, vendor):
    """Calculate routed port count for a topology/vendor."""
    lower_tier_info = get_lower_tier_info(topology_type, vendor)
    # 1 for interconnect port + number of lower tier ports
    return 1 + len(lower_tier_info.get('ports', []))


def get_portchannel_count(topology_type, vendor):
    """Calculate portchannel count for a topology/vendor."""
    portchannel_members = get_uplink_portchannel_members(topology_type, vendor)
    count = 0
    for asic_key, portchannels in portchannel_members.items():
        count += len(portchannels)
    return count


def generate_ips_for_bgp(ipv4_subnet, ipv6_subnet, total_count):
    """
    Generate IP addresses for BGP case.
    Reusable function for both T2 chassis and T2 pizzabox topologies.

    Args:
        ipv4_subnet: IPv4 subnet string (e.g., '20.0.1.1/31')
        ipv6_subnet: IPv6 subnet string (e.g., '2000:1:1:1::1/126')
        total_count: Total number of IP pairs to generate (routed_port_count + portchannel_count)

    Returns:
        tuple: (ip_list, peer_ip_list, ipv6_list, peer_ipv6_list, router_id_list)
    """
    v4_start_ips = create_ip_list(ipv4_subnet.split('/')[0], total_count, mask=16)
    v6_start_ips = create_ip_list(ipv6_subnet.split('/')[0], total_count, mask=64)
    count = 2  # Note: count is always 2

    ip_list = []
    peer_ip_list = []
    ipv6_list = []
    peer_ipv6_list = []

    for index in range(0, total_count):
        v4_host_addresses = get_host_addresses(str(v4_start_ips[index]) + '/' + str(ipv4_subnet.split('/')[1]), count)
        v6_host_addresses = get_host_addresses(str(v6_start_ips[index]) + '/' + str(ipv6_subnet.split('/')[1]), count)
        ip_list.append(str(v4_host_addresses[0]))
        peer_ip_list.append(str(v4_host_addresses[1]))
        ipv6_list.append(str(v6_host_addresses[0]))
        peer_ipv6_list.append(str(v6_host_addresses[1]))

    router_id_list = create_ip_list('100.0.0.1', total_count, mask=32)
    return ip_list, peer_ip_list, ipv6_list, peer_ipv6_list, router_id_list


def get_bgp_ips_for_topology(topology_type, vendor):
    """
    Generate and return BGP IP addresses for a specific topology/vendor.

    Args:
        topology_type: TOPOLOGY_T2_CHASSIS or TOPOLOGY_T2_PIZZABOX
        vendor: 'NOKIA', 'ARISTA', or 'CISCO'

    Returns:
        dict: Dictionary containing all IP lists for BGP configuration
    """
    routed_port_count = get_routed_port_count(topology_type, vendor)
    portchannel_count = get_portchannel_count(topology_type, vendor)
    total_count = routed_port_count + portchannel_count

    ip, peer_ip, ipv6, peer_ipv6, router_ids = generate_ips_for_bgp(
        IPV4_SUBNET, IPV6_SUBNET, total_count)

    return {
        'dut_ipv4_list': ip[:routed_port_count],
        'snappi_ipv4_list': peer_ip[:routed_port_count],
        'dut_portchannel_ipv4_list': ip[routed_port_count:],
        'snappi_portchannel_ipv4_list': peer_ip[routed_port_count:],
        'dut_ipv6_list': ipv6[:routed_port_count],
        'snappi_ipv6_list': peer_ipv6[:routed_port_count],
        'dut_portchannel_ipv6_list': ipv6[routed_port_count:],
        'snappi_portchannel_ipv6_list': peer_ipv6[routed_port_count:],
        'router_ids': router_ids,
        'routed_port_count': routed_port_count,
        'portchannel_count': portchannel_count,
    }


# =============================================================================
# END OF BGP OUTBOUND ROUTE CONVERGENCE CONFIGURATIONS
# =============================================================================
