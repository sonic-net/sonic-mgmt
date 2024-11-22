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


ip = []
peer_ip = []
ipv6 = []
peer_ipv6 = []
# START ---------------------   T2 BGP Case -------------------
'''
    PRE-REQUISITE : The DUT ports must be Administratively Up and configured as Routed ports before starting the test
'''
# *********** Common variables for Performance and Outbound ****************
T2_SNAPPI_AS_NUM = 65400
T2_DUT_AS_NUM = 65100
BGP_TYPE = 'ebgp'
t1_t2_device_hostnames = ["sonic-t1", "sonic-t2-uplink", "sonic-t2-downlink"]
SNAPPI_TRIGGER = 60  # timeout value for snappi operation
DUT_TRIGGER = 180    # timeout value for dut operation

ipv4_subnet = '20.0.1.1/31'
ipv6_subnet = '2000:1:1:1::1/126'
v4_prefix_length = int(ipv4_subnet.split('/')[1])
v6_prefix_length = int(ipv6_subnet.split('/')[1])

# *********** Performance case variables ****************
# asic_value is None if it's non-chassis based or single line card
PERFORMANCE_PORTS = {
                        'Traffic_Tx_Ports': [
                            {'port_name': 'Ethernet0', 'hostname': t1_t2_device_hostnames[1], 'asic_value': 'asic0'},
                            {'port_name': 'Ethernet88', 'hostname': t1_t2_device_hostnames[1], 'asic_value': 'asic0'},
                        ],
                        'Uplink BGP Session': [
                            {'port_name': 'Ethernet192', 'hostname': t1_t2_device_hostnames[1], 'asic_value': 'asic1'},
                            {'port_name': 'Ethernet144', 'hostname': t1_t2_device_hostnames[1], 'asic_value': 'asic1'},
                        ]
                    }
# *********** Outbound case variables ****************
# Expect the T1 and T2 ports to be routed ports and not part of any portchannel.
T1_SNAPPI_AS_NUM = 65300
T1_DUT_AS_NUM = 65200
AS_PATHS = [65002]

snappi_community_for_t1 = ["8075:54000"]
snappi_community_for_t2 = ["8075:316", "8075:10400"]
fanout_presence = True
# Note: Increase the MaxSessions in /etc/ssh/sshd_config if the number of fanout ports used is more than 10
t2_uplink_fanout_info = [
                            {
                                 'fanout_ip': '152.148.150.143',
                                 'port_mapping': [{'fanout_port': 'Ethernet0', 'uplink_port': 'Ethernet0'},
                                                  {'fanout_port': 'Ethernet88', 'uplink_port': 'Ethernet88'},
                                                  {'fanout_port': 'Ethernet192', 'uplink_port': 'Ethernet192'},
                                                  {'fanout_port': 'Ethernet144', 'uplink_port': 'Ethernet144'}]
                            },
                            {
                                'fanout_ip': '152.148.150.142',
                                'port_mapping': [{'fanout_port': 'Ethernet2', 'uplink_port': 'Ethernet2'},
                                                 {'fanout_port': 'Ethernet3', 'uplink_port': 'Ethernet3'},
                                                 {'fanout_port': 'Ethernet4', 'uplink_port': 'Ethernet4'},
                                                 {'fanout_port': 'Ethernet5', 'uplink_port': 'Ethernet5'}]
                            }
                        ]
# The order of hostname is very important for the outbound test (T1, T2 Uplink, T2 Downlink and Supervisor)
t1_t2_device_hostnames = ["sonic-t1", "sonic-t2-uplink", "sonic-t2-downlink", "sonic-t2-supervisor"]
t1_ports = {
                t1_t2_device_hostnames[0]:
                [
                    'Ethernet8',
                    'Ethernet16'
                ]
            }

# asic_value is None if it's non-chassis based or single line card
t2_uplink_portchannel_members = {
                                    t1_t2_device_hostnames[1]:
                                    {
                                        'asic0':
                                            {
                                                'PortChannel0': ['Ethernet0', 'Ethernet88']
                                            },
                                        'asic1':
                                            {
                                                'PortChannel1': ['Ethernet192', 'Ethernet144']
                                            }
                                    }
                                }
# TODO: Multiple interconnected ports scenario
t1_side_interconnected_port = 'Ethernet120'
t2_side_interconnected_port = {'port_name': 'Ethernet272', 'asic_value': 'asic1'}

routed_port_count = 1+len(t1_ports[t1_t2_device_hostnames[0]])
portchannel_count = sum([len(portchannel_info) for _, portchannel_info in
                        t2_uplink_portchannel_members[t1_t2_device_hostnames[1]].items()])


def generate_ips_for_bgp_case(ipv4_subnet, ipv6_subnet):
    v4_start_ips = create_ip_list(ipv4_subnet.split('/')[0], routed_port_count+portchannel_count, mask=16)
    v6_start_ips = create_ip_list(ipv6_subnet.split('/')[0], routed_port_count+portchannel_count, mask=64)
    count = 2  # Note: count is always 2

    for index in range(0, routed_port_count+portchannel_count):
        v4_host_addresses = get_host_addresses(str(v4_start_ips[index])+'/'+str(ipv4_subnet.split('/')[1]), count)
        v6_host_addresses = get_host_addresses(str(v6_start_ips[index])+'/'+str(ipv6_subnet.split('/')[1]), count)
        ip.append(str(v4_host_addresses[0]))
        peer_ip.append(str(v4_host_addresses[1]))
        ipv6.append(str(v6_host_addresses[0]))
        peer_ipv6.append(str(v6_host_addresses[1]))


generate_ips_for_bgp_case(ipv4_subnet, ipv6_subnet)
router_ids = create_ip_list('100.0.0.1', routed_port_count+portchannel_count, mask=32)
t1_t2_dut_ipv4_list = ip[:routed_port_count]
t1_t2_snappi_ipv4_list = peer_ip[:routed_port_count]

t2_dut_portchannel_ipv4_list = ip[routed_port_count:]
snappi_portchannel_ipv4_list = peer_ip[routed_port_count:]

t1_t2_dut_ipv6_list = ipv6[:routed_port_count]
t1_t2_snappi_ipv6_list = peer_ipv6[:routed_port_count]

t2_dut_portchannel_ipv6_list = ipv6[routed_port_count:]
snappi_portchannel_ipv6_list = peer_ipv6[routed_port_count:]

t2_dut_ipv4_list = ip[:len(PERFORMANCE_PORTS['Traffic_Tx_Ports'] + PERFORMANCE_PORTS['Uplink BGP Session'])]
t2_dut_ipv6_list = ipv6[:len(PERFORMANCE_PORTS['Traffic_Tx_Ports'] + PERFORMANCE_PORTS['Uplink BGP Session'])]
t2_snappi_ipv4_list = peer_ip[:len(PERFORMANCE_PORTS['Traffic_Tx_Ports'] + PERFORMANCE_PORTS['Uplink BGP Session'])]
t2_snappi_ipv6_list = peer_ipv6[:len(PERFORMANCE_PORTS['Traffic_Tx_Ports'] + PERFORMANCE_PORTS['Uplink BGP Session'])]

# END ---------------------   T2 BGP Case -------------------
