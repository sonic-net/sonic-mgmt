import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
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
line_card_choice = 'non_chassis_single_line_card'
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

dut_ip_start = '20.0.1.1'
snappi_ip_start = '20.0.1.2'
prefix_length = 24


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


# START ---------------------   T2 BGP Case -------------------
# Pre-requisites
# Expect the T1 and T2 orts to be routed ports and not part of any portchannel. The ports must not have ips configured
T1_SNAPPI_AS_NUM = 65300
T2_SNAPPI_AS_NUM = 65400
T1_DUT_AS_NUM = 65200
T2_DUT_AS_NUM = 65100
AS_PATHS = [65002]
BGP_TYPE = 'ebgp'
route_count = 10000
v4_prefix_length = 24
v6_prefix_length = 64
TIMEOUT = 20

# The order of the hostnames are important [ t1 hostname, t2 uplink hostname, t2 downlink hostname]
t1_t2_device_hostnames = ["sonic-t1", "sonic-t2-uplink", "sonic-t2-downlink"]
t2_asic_port_map = {
        "asic0": ['Ethernet%d' % i for i in range(0, 144, 4)],
        "asic1": ['Ethernet%d' % i for i in range(144, 276, 4)],
    }

t1_ports = {
                t1_t2_device_hostnames[0]:
                [
                    'Ethernet8',
                    'Ethernet16'
                ]
            }

t2_uplink_portchannel_members = {
                                    t1_t2_device_hostnames[1]:
                                    {
                                        'asic0': {
                                            'PortChannel0': ('Ethernet0', 'Ethernet88')
                                        },
                                        'asic1': {
                                            'PortChannel1': ('Ethernet192', 'Ethernet144')
                                        }
                                    }
                                }

t1_side_interconnected_port = 'Ethernet120'
t2_side_interconnected_port = {'port_name': 'Ethernet272', 'asic_value': 'asic1'}

routed_port_count = 1+len(t1_ports[t1_t2_device_hostnames[0]])
portchannel_count = sum([len(portchannel_info) for asic, portchannel_info in
                        t2_uplink_portchannel_members[t1_t2_device_hostnames[1]].items()])


t1_t2_dut_ipv4_list = create_ip_list('20.0.1.1', routed_port_count, mask=v4_prefix_length)
t1_t2_dut_ipv6_list = create_ip_list('2000:1::1', routed_port_count, mask=v6_prefix_length)

t1_t2_snappi_ipv4_list = create_ip_list('20.0.1.2', routed_port_count, mask=v4_prefix_length)
t1_t2_snappi_ipv6_list = create_ip_list('2000:1::2', routed_port_count, mask=v6_prefix_length)


t2_dut_portchannel_ipv4_list = create_ip_list('30.0.1.1', portchannel_count, mask=v4_prefix_length)
t2_dut_portchannel_ipv6_list = create_ip_list('3000:1::1', portchannel_count, mask=v6_prefix_length)

snappi_portchannel_ipv4_list = create_ip_list('30.0.1.2', portchannel_count, mask=v4_prefix_length)
snappi_portchannel_ipv6_list = create_ip_list('3000:1::2', portchannel_count, mask=v6_prefix_length)

# END ---------------------   T2 BGP Case -------------------
