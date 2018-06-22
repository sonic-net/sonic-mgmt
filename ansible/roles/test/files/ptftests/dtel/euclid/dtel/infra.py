import socket
import sys

REPORT_UDP_PORT = 32766
REPORT_TRUNCATE_SIZE = 256


def check_ip_address(input_ip_address, return_version=False, allow_none=False):
    if isinstance(input_ip_address, list):
        ip_address_list = input_ip_address
    else:
        ip_address_list = [input_ip_address]
    version_list = []
    for ip_address in ip_address_list:
        if allow_none and ip_address is None:
            version_list.append(None)
        else:
            try:
                # Check if IPv4
                socket.inet_pton(socket.AF_INET, ip_address)
                version_list.append('ipv4')
            except socket.error:
                try:
                    # Check if IPv6
                    socket.inet_pton(socket.AF_INET6, ip_address)
                    version_list.append('ipv6')
                except socket.error:
                    print "%s is not a valid IP address" % ip_address
                    sys.exit()
    if return_version:
        if isinstance(input_ip_address, list):
            return version_list
        else:
            return version_list[0]
    else:
        if isinstance(input_ip_address, list):
            return ip_address_list
        else:
            return ip_address_list[0]


def fpport_to_swport(input_port_list):
    if not isinstance(input_port_list, list):
        port_list = [input_port_list]
    else:
        port_list = input_port_list
    output_port_list = []
    for port in port_list:
        if not isinstance(port, str):
            raise TypeError('%s: front panel port has to be a string' % str(port))
        port_fields = port.split('/')
        if len(port_fields) != 2:
            raise TypeError('%s: The format of the port should be A/B' % port)
        if int(port_fields[0]) < 0 or int(port_fields[0]) > 65:
            raise ValueError('%s: incorrect front panel port' % port)
        if port_fields[1] == '-':
            port_fields[1] = 0
        if int(port_fields[1]) < 0 or int(port_fields[1]) > 3:
            raise ValueError('%s: incorrect front panel port' % port)
        swport = (int(port_fields[0]) - 1) * 4 + int(port_fields[1])
        output_port_list.append(swport)
    if not isinstance(input_port_list, list):
        output_port_list = output_port_list[0]
    return output_port_list


def swport_to_fpport(input_port_list):
    if not isinstance(input_port_list, list):
        port_list = [input_port_list]
    else:
        port_list = input_port_list
    output_port_list = []
    for port in port_list:
        if not isinstance(port, int):
            raise TypeError('%s: swport should be an int' % str(port))
        if port < 0 or port > 257:
            raise ValueError('%s: invalid swport number' % port)
        port_field_a = port / 4 + 1
        port_field_b = port % 4
        output_port_list.append(str(port_field_a) + '/' + str(port_field_b))
    if not isinstance(input_port_list, list):
        output_port_list = output_port_list[0]
    return output_port_list


class FrozenClass(object):
    __isfrozen = False

    def __setattr__(self, key, value):
        if self.__isfrozen and not hasattr(self, key):
            raise TypeError('Class %s does not have attribute %s' % (type(self).__name__, key))
        object.__setattr__(self, key, value)

    def _freeze(self):
        self.__isfrozen = True
