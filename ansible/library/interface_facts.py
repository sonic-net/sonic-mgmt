#!/usr/bin/python
import os
import sys
import stat
import array
import errno
import fcntl
import fnmatch
import glob
import platform
import re
import signal
import socket
import struct
import datetime
import getpass
import pwd
import ConfigParser
import StringIO

from ansible.module_utils.basic import *
from collections import defaultdict

DOCUMENTATION = '''
---
module: interfaces_facts
version_added: "1.1"
author: Ying Xie (yinxi@microsoft.com)
short_description: Retrive interface facts from device
description:
    - Retrieve interface facts for a device, the facts will be
      inserted to the ansible_facts key.
options:
    up_ports:
        description:
            - all ports that expected to be at link up status
            - this parameter doens't limit how many ports can
              be present on the device, interface_facts returns
              facts of all existing ports.
        required: false
'''

EXAMPLES = '''
# Gather minigraph facts
- name: Gathering minigraph facts about the device
  interface_facts:

# Gather minigraph facts and check a set of ports should be up
- name: Gathering minigraph facts about the device
  interface_facts: up_ports={{minigraph_ports}}

# Gather minigraph facts and check a set of ports should be up except one
- name: Gathering minigraph facts about the device
  interface_facts: up_ports={{minigraph_ports | difference('Some port, e.g. Ethernet0'}}

'''

def get_default_interfaces(ip_path, module):
    # Use the commands:
    #     ip -4 route get 8.8.8.8                     -> Google public DNS
    #     ip -6 route get 2404:6800:400a:800::1012    -> ipv6.google.com
    # to find out the default outgoing interface, address, and gateway
    command = dict(
        v4 = [ip_path, '-4', 'route', 'get', '8.8.8.8'],
        v6 = [ip_path, '-6', 'route', 'get', '2404:6800:400a:800::1012']
    )
    interface = dict(v4 = {}, v6 = {})
    for key in command.keys():
        """
        if key == 'v6' and self.facts['os_family'] == 'RedHat' \
            and self.facts['distribution_version'].startswith('4.'):
            continue
        """
        if key == 'v6' and not socket.has_ipv6:
            continue
        rc, out, err = module.run_command(command[key])
        if not out:
            # v6 routing may result in
            #   RTNETLINK answers: Invalid argument
            continue
        words = out.split('\n')[0].split()
        # A valid output starts with the queried address on the first line
        if len(words) > 0 and words[0] == command[key][-1]:
            for i in range(len(words) - 1):
                if words[i] == 'dev':
                    interface[key]['interface'] = words[i+1]
                elif words[i] == 'src':
                    interface[key]['address'] = words[i+1]
                elif words[i] == 'via' and words[i+1] != command[key][-1]:
                    interface[key]['gateway'] = words[i+1]
    return interface['v4'], interface['v6']

def get_file_content(path, default=None, strip=True):
    data = default
    if os.path.exists(path) and os.access(path, os.R_OK):
        try:
            datafile = open(path)
            data = datafile.read()
            if strip:
                data = data.strip()
            if len(data) == 0:
                data = default
        finally:
            datafile.close()
    return data

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ip_path=dict(required=False, default="/sbin/ip"),
            up_ports=dict(default={}),
        ),
        supports_check_mode=False)

    """
    f = Network(module)
    #facts = linux_network.populate()
    results = Tree()

    # results['ansible_interfaces_facts'] = facts
    module.exit_json(ansible_facts=results)

    """
    m_args = module.params
    ip_path = m_args['ip_path']
    up_ports = m_args['up_ports']
    default_ipv4, default_ipv6 = get_default_interfaces(ip_path, module)
    interfaces = dict()
    ips = dict(
        all_ipv4_addresses = [],
        all_ipv6_addresses = [],
    )

    #paths = ['/sys/class/net/Ethernet4', '/sys/class/net/lo', '/sys/class/net/eth0']
    for path in glob.glob('/sys/class/net/*'):
    #for path in paths:
        if not os.path.isdir(path):
            continue
        device = os.path.basename(path)
        interfaces[device] = { 'device': device }
        if os.path.exists(os.path.join(path, 'address')):
            macaddress = get_file_content(os.path.join(path, 'address'), default='')
            if macaddress and macaddress != '00:00:00:00:00:00':
                interfaces[device]['macaddress'] = macaddress
        if os.path.exists(os.path.join(path, 'mtu')):
            val = get_file_content(os.path.join(path, 'mtu'))
            if val != None and True == val.isdigit():
                interfaces[device]['mtu'] = int(val)
        if os.path.exists(os.path.join(path, 'operstate')):
            interfaces[device]['active'] = get_file_content(os.path.join(path, 'operstate')) != 'down'

        if os.path.exists(os.path.join(path, 'carrier')):
            try:
                interfaces[device]['link'] = ( get_file_content(os.path.join(path, 'carrier')) == '1')
            except:
                pass
        if os.path.exists(os.path.join(path, 'device','driver', 'module')):
            interfaces[device]['module'] = os.path.basename(os.path.realpath(os.path.join(path, 'device', 'driver', 'module')))
        if os.path.exists(os.path.join(path, 'type')):
            protocol_type = get_file_content(os.path.join(path, 'type'))
            if protocol_type == '1':
                interfaces[device]['type'] = 'ether'
            elif protocol_type == '512':
                interfaces[device]['type'] = 'ppp'
            elif protocol_type == '772':
                interfaces[device]['type'] = 'loopback'
        if os.path.exists(os.path.join(path, 'bridge')):
            interfaces[device]['type'] = 'bridge'
            interfaces[device]['interfaces'] = [ os.path.basename(b) for b in glob.glob(os.path.join(path, 'brif', '*')) ]
            if os.path.exists(os.path.join(path, 'bridge', 'bridge_id')):
                interfaces[device]['id'] = get_file_content(os.path.join(path, 'bridge', 'bridge_id'), default='')
            if os.path.exists(os.path.join(path, 'bridge', 'stp_state')):
                interfaces[device]['stp'] = get_file_content(os.path.join(path, 'bridge', 'stp_state')) == '1'
        if os.path.exists(os.path.join(path, 'bonding')):
            interfaces[device]['type'] = 'bonding'
            interfaces[device]['slaves'] = get_file_content(os.path.join(path, 'bonding', 'slaves'), default='').split()
            interfaces[device]['mode'] = get_file_content(os.path.join(path, 'bonding', 'mode'), default='').split()[0]
            interfaces[device]['miimon'] = get_file_content(os.path.join(path, 'bonding', 'miimon'), default='').split()[0]
            interfaces[device]['lacp_rate'] = get_file_content(os.path.join(path, 'bonding', 'lacp_rate'), default='').split()[0]
            primary = get_file_content(os.path.join(path, 'bonding', 'primary'))
            if primary:
                interfaces[device]['primary'] = primary
                path = os.path.join(path, 'bonding', 'all_slaves_active')
                if os.path.exists(path):
                    interfaces[device]['all_slaves_active'] = get_file_content(path) == '1'
        if os.path.exists(os.path.join(path,'device')):
            interfaces[device]['pciid'] = os.path.basename(os.readlink(os.path.join(path,'device')))

        # Check whether an interface is in promiscuous mode
        if os.path.exists(os.path.join(path,'flags')):
            promisc_mode = False
            # The second byte indicates whether the interface is in promiscuous mode.
            # 1 = promisc
            # 0 = no promisc
            data = int(get_file_content(os.path.join(path, 'flags')),16)
            promisc_mode = (data & 0x0100 > 0)
            interfaces[device]['promisc'] = promisc_mode

        def parse_ip_output(module, output, secondary=False):
            for line in output.split('\n'):
                if not line:
                    continue
                words = line.split()
                broadcast = ''
                if words[0] == 'inet':
                    if len(words) < 2:
                        continue
                    if '/' in words[1]:
                        address, netmask_length = words[1].split('/')
                        if len(words) > 3:
                            broadcast = words[3]
                    else:
                        # pointopoint interfaces do not have a prefix
                        address = words[1]
                        netmask_length = "32"
                    address_bin = struct.unpack('!L', socket.inet_aton(address))[0]
                    netmask_bin = (1<<32) - (1<<32>>int(netmask_length))
                    netmask = socket.inet_ntoa(struct.pack('!L', netmask_bin))
                    network = socket.inet_ntoa(struct.pack('!L', address_bin & netmask_bin))
                    iface = words[-1]
                    if iface != device:
                        interfaces[iface] = {}
                    if False == secondary:
                        if "ipv4" not in interfaces[iface]:
                            interfaces[iface]['ipv4'] = {'address': address,
                                                         'broadcast': broadcast,
                                                         'netmask': netmask,
                                                         'network': network}
                    else:
                        if "ipv4_secondaries" not in interfaces[iface]:
                            interfaces[iface]["ipv4_secondaries"] = []

                        interfaces[iface]["ipv4_secondaries"].append({
                            'address': address,
                            'broadcast': broadcast,
                            'netmask': netmask,
                            'network': network,
                        })

                    # add this secondary IP to the main device
                    if secondary:
                        if "ipv4_secondaries" not in interfaces[device]:
                            interfaces[device]["ipv4_secondaries"] = []
                        interfaces[device]["ipv4_secondaries"].append({
                            'address': address,
                            'broadcast': broadcast,
                            'netmask': netmask,
                            'network': network,
                        })

                    # If this is the default address, update default_ipv4
                    if 'address' in default_ipv4 and default_ipv4['address'] == address:
                        default_ipv4['broadcast'] = broadcast
                        default_ipv4['netmask'] = netmask
                        default_ipv4['network'] = network
                        default_ipv4['macaddress'] = macaddress
                        default_ipv4['mtu'] = interfaces[device]['mtu']
                        default_ipv4['type'] = interfaces[device].get("type", "unknown")
                        default_ipv4['alias'] = words[-1]
                    if not address.startswith('127.'):
                        ips['all_ipv4_addresses'].append(address)
                elif words[0] == 'inet6':
                    address, prefix = words[1].split('/')
                    scope = words[3]
                    if 'ipv6' not in interfaces[device]:
                        interfaces[device]['ipv6'] = []
                    interfaces[device]['ipv6'].append({
                        'address' : address,
                        'prefix'  : prefix,
                        'scope'   : scope
                    })
                    # If this is the default address, update default_ipv6
                    if 'address' in default_ipv6 and default_ipv6['address'] == address:
                        default_ipv6['prefix']     = prefix
                        default_ipv6['scope']      = scope
                        default_ipv6['macaddress'] = macaddress
                        default_ipv6['mtu']        = interfaces[device]['mtu']
                        default_ipv6['type']       = interfaces[device].get("type", "unknown")
                    if not address == '::1':
                        ips['all_ipv6_addresses'].append(address)

        ip_path = module.get_bin_path("ip")

        args = [ip_path, 'addr', 'show', 'primary', device]
        rc, stdout, stderr = module.run_command(args)
        primary_data = stdout

        args = [ip_path, 'addr', 'show', 'secondary', device]
        rc, stdout, stderr = module.run_command(args)
        secondary_data = stdout

        parse_ip_output(module, primary_data)
        parse_ip_output(module, secondary_data, secondary=True)

    results = {}

    down_ports = []
    for name in up_ports:
        try:
            if not interfaces[name]['link']:
                down_ports += [name]
        except:
            down_ports += [name]
            pass 

    results['ansible_interface_facts'] = interfaces
    results['ansible_interface_ips'] = ips
    results['ansible_interface_link_down_ports'] = down_ports
    module.exit_json(ansible_facts=results)

main()

