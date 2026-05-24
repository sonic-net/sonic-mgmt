#!/usr/bin/python

import re
from ansible.module_utils.basic import AnsibleModule
import traceback
from ipaddress import ip_network
import logging
from collections import defaultdict
try:
    from natsort import natsorted
except ImportError:
    import re as _re

    def natsorted(seq, key=None):
        def _key(s):
            s = key(s) if key else s
            return [int(c) if c.isdigit() else c.lower() for c in _re.split(r'(\d+)', str(s))]
        return sorted(seq, key=_key)

try:
    from ansible.module_utils.debug_utils import config_module_logging
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.debug_utils import config_module_logging


config_module_logging('nut_allocate_ip')


DOCUMENTATION = '''
module: nut_allocate_ip.py
version_added:  1.0.0.0
short_description: Allocate IPs for devices in network under test (NUT) testbed
notes:
    - Device templates can optionally define p2p_v4_subnet_len and p2p_v6_subnet_len to override the
      default child subnet lengths used for P2P allocation.
    - p2p_v4_subnet_len must be within [parent_prefix_len + 1, 31].
    - p2p_v6_subnet_len must be within [parent_prefix_len + 1, 127].
options:
    - testbed_facts:
      Description: Testbed info returned from nut_test_facts module
      Default: None
      required: True
    - device_info:
      Description: Device info returned from conn_graph_facts module
      Default: None
      required: True
    - device_port_links:
      Description: Connection graph info returned from conn_graph_facts module
      Default: None
      required: True
'''

EXAMPLES = '''
    Input testbed fact:

        {
            "name": "testbed-nut-1",
            "test_tags": [ "snappi-capacity" ],
            "topo": {
                "name": "nut-2tiers",
                "type": "nut",
                "properties": {
                    "dut_templates": [{
                        "name": ".*-t0-.*"
                        "type": "ToRRouter"
                        "loopback_v4": "100.1.0.0/24"
                        "loopback_v6": "2064:100:0:0::/64"
                        "asn_base": 64001
                        "p2p_v4": "10.0.0.0/16"
                        "p2p_v4_subnet_len": 31,
                        "p2p_v6": "fc0a::/64",
                        "p2p_v6_subnet_len": 127
                    }, ...],
                    "tg_template": {
                        "type": "Server",
                        "asn_base": 60001,
                        "p2p_v4": "10.0.0.0/16",
                        "p2p_v4_subnet_len": 31,
                        "p2p_v6": "fc0a::/64",
                        "p2p_v6_subnet_len": 127
                    }
                }
            },
            "duts": [ "switch-t0-1", "switch-t1-1" ],
            "tgs": [ "tg-1" ],
            ...
        }

    Input connection facts:

        {
            "device_info": {
                "ManagementIp": "10.251.0.76/24",
                "HwSku": "Arista-7260QX-64",
                "Type": "FanoutLeaf"
            },
            "device_conn": {
                "switch-t0-1": {
                    "Ethernet0": {
                        "peerdevice": "switch-t1-1",
                        "peerport": "Ethernet4",
                        "speed": "100000"
                    },
                }
            },
            "device_vlan_range": {
                "VlanRange": "201-980,1041-1100"
            },
            "device_vlan_port": {
                ...
                "Ethernet44": {
                  "vlanids": "801-860",
                  "mode": "Trunk"
                },
                "Ethernet42": {
                  "vlanids": "861-920",
                  "mode": "Trunk"
                },
                ......
            }
        }

    To use it:
    - name: Create device config info
      nut_allocate_ip: testbed_facts="{{ testbed_facts }}" device_info="{{ device_info }}"
        device_port_links="{{ device_conn }}"

    The optional p2p_v4_subnet_len and p2p_v6_subnet_len fields can be used to allocate /31 and /127
    point-to-point subnets from a larger parent CIDR.
'''

RETURN = '''
    Ansible_facts:
        "device_meta": {
            "switch-t0-1": {
                "loopback_v4": "100.1.0.1/32",
                "loopback_v6": "2064:100::1/128",
                "bgp_asn": 64001,
                "bgp_router_id": "100.1.0.1",
            }
        },
        "device_bgp_neighbor_devices": {
            "switch-t0-1": {
                "switch-t1-1": {
                    "type": "LeafRouter",
                    "hwsku": "SomeHwSku",
                    "loopback_v4": "10.0.0.1/32",
                    "loopback_v6": "fc0a::1/128",
                    "mgmt_v4": "10.1.0.1/24",
                    "mgmt_v6": "fc0a::1/64"
                },
                ...
            }
        },
        "device_bgp_neighbor_ports": {
            "tg-1": {
                "Port1.1": {
                    "p2p_v4_subnet": "10.0.0.1",
                    "p2p_v6_subnet": "fc0a::1",
                    "peer_device": "switch-t0-1",
                    "peer_port": "Ethernet0"
                },
                ...
            },
        }
'''


class IPAllocator():
    """IP address allocator for generating loopback and P2P IP addresses."""

    def __init__(self, ipcidr: str, child_subnet_prefix_len: int, start_offset: int = 0):
        self.network = ip_network(ipcidr)
        self.subnets = self.network.subnets(new_prefix=child_subnet_prefix_len)

        for _ in range(start_offset):
            try:
                next(self.subnets)
            except StopIteration:
                raise ValueError("Start offset exceeds available subnets in the network")

    def allocate(self):
        """Allocate an IP address based on the current offset and child subnet size."""
        try:
            allocated_subnet = next(self.subnets)
        except StopIteration:
            raise ValueError("Offset exceeds available subnets in the network")

        return allocated_subnet


class GenerateDeviceConfig():
    """Generate device config for devices in network under test (NUT) testbed."""

    @staticmethod
    def _build_allocator_key(ipcidr, child_subnet_prefix_len):
        return ipcidr, child_subnet_prefix_len

    @staticmethod
    def _validate_p2p_subnet_len(ipcidr, child_subnet_prefix_len, max_prefix_len):
        parent_prefix_len = ip_network(ipcidr).prefixlen
        min_prefix_len = parent_prefix_len + 1
        if child_subnet_prefix_len < min_prefix_len or child_subnet_prefix_len > max_prefix_len:
            raise ValueError(
                f"Invalid child subnet prefix length {child_subnet_prefix_len} for {ipcidr}; "
                f"expected range [{min_prefix_len}, {max_prefix_len}]"
            )

    def __init__(self, testbed_facts, device_info, device_port_links, device_port_vrfs):
        self.testbed_facts = testbed_facts
        self.device_info = device_info
        self.device_port_links = device_port_links
        self.device_port_vrfs = device_port_vrfs

        self.device_templates = defaultdict(dict)
        self.device_ipv4_allocators = defaultdict(dict)
        self.device_ipv6_allocators = defaultdict(dict)

        self.device_meta = defaultdict(dict)
        self.device_interfaces = defaultdict(dict)
        self.device_bgp_neighbor_devices = defaultdict(dict)
        self.device_bgp_neighbor_ports = defaultdict(dict)

    def run(self):
        self._prepare()
        logging.debug("")

        for index, dut in enumerate(self.testbed_facts['duts']):
            logging.debug("=================================================================")
            logging.debug(f"Start allocating device metadata and IP for {dut} (index={index})")
            self._set_dut_device_meta(dut)
            self._allocate_dut_loopback_ip(index, dut)
            self._allocate_dut_bgp_asn(index, dut)
        logging.debug("")

        for index, tg in enumerate(self.testbed_facts['tgs']):
            logging.debug("=================================================================")
            logging.debug(f"Start allocating device metadata and IP for traffic generator {tg} (index={index})")
            self._set_tg_device_meta(tg)
            self._allocate_tg_bgp_asn(index, tg)
        logging.debug("")

        self._allocate_p2p_ip()

    def _prepare(self):
        logging.debug("=================================================================")
        logging.debug(f"Preparing device config generation for testbed: {self.testbed_facts['name']}")

        # Build device template map
        for dut in self.testbed_facts['duts']:
            for device_template in self.testbed_facts['topo']['properties']['dut_templates']:
                if re.match(device_template['name'], dut):
                    self.device_templates[dut] = device_template
                    logging.debug(f"Found template for DUT {dut}: {device_template}")
                    break
            else:
                raise ValueError(f"No template found for DUT {dut}")

        # Build device IP allocator for P2P links
        p2p_v4_allocator_map = {}
        p2p_v6_allocator_map = {}
        for dut in self.testbed_facts['duts']:
            device_template = self.device_templates[dut]
            if 'p2p_v4' in device_template:
                p2p_v4_cidr = device_template['p2p_v4']
                p2p_v4_subnet_len = device_template.get('p2p_v4_subnet_len', 30)
                self._validate_p2p_subnet_len(p2p_v4_cidr, p2p_v4_subnet_len, 31)
                allocator_key = self._build_allocator_key(p2p_v4_cidr, p2p_v4_subnet_len)
                if allocator_key not in p2p_v4_allocator_map:
                    p2p_v4_allocator_map[allocator_key] = IPAllocator(p2p_v4_cidr, p2p_v4_subnet_len)

                self.device_ipv4_allocators[dut] = p2p_v4_allocator_map[allocator_key]
                logging.debug(
                    f"Found P2P v4 allocator for {dut} with CIDR {p2p_v4_cidr}/{p2p_v4_subnet_len}"
                )

            if 'p2p_v6' in device_template:
                p2p_v6_cidr = device_template['p2p_v6']
                p2p_v6_subnet_len = device_template.get('p2p_v6_subnet_len', 126)
                self._validate_p2p_subnet_len(p2p_v6_cidr, p2p_v6_subnet_len, 127)
                allocator_key = self._build_allocator_key(p2p_v6_cidr, p2p_v6_subnet_len)
                if allocator_key not in p2p_v6_allocator_map:
                    p2p_v6_allocator_map[allocator_key] = IPAllocator(p2p_v6_cidr, p2p_v6_subnet_len)

                self.device_ipv6_allocators[dut] = p2p_v6_allocator_map[allocator_key]
                logging.debug(
                    f"Found P2P v6 allocator for {dut} with CIDR {p2p_v6_cidr}/{p2p_v6_subnet_len}"
                )

        tg_template = self.testbed_facts['topo']['properties']['tg_template']
        for tg in self.testbed_facts['tgs']:
            # TGs intentionally share one template, so they also share the same configured subnet lengths here.
            if 'p2p_v4' in tg_template:
                p2p_v4_cidr = tg_template['p2p_v4']
                p2p_v4_subnet_len = tg_template.get('p2p_v4_subnet_len', 30)
                self._validate_p2p_subnet_len(p2p_v4_cidr, p2p_v4_subnet_len, 31)
                allocator_key = self._build_allocator_key(p2p_v4_cidr, p2p_v4_subnet_len)
                if allocator_key not in p2p_v4_allocator_map:
                    p2p_v4_allocator_map[allocator_key] = IPAllocator(p2p_v4_cidr, p2p_v4_subnet_len)

                self.device_ipv4_allocators[tg] = p2p_v4_allocator_map[allocator_key]
                logging.debug(
                    f"Found P2P v4 allocator for {tg} with CIDR {p2p_v4_cidr}/{p2p_v4_subnet_len}"
                )

            if 'p2p_v6' in tg_template:
                p2p_v6_cidr = tg_template['p2p_v6']
                p2p_v6_subnet_len = tg_template.get('p2p_v6_subnet_len', 126)
                self._validate_p2p_subnet_len(p2p_v6_cidr, p2p_v6_subnet_len, 127)
                allocator_key = self._build_allocator_key(p2p_v6_cidr, p2p_v6_subnet_len)
                if allocator_key not in p2p_v6_allocator_map:
                    p2p_v6_allocator_map[allocator_key] = IPAllocator(p2p_v6_cidr, p2p_v6_subnet_len)

                self.device_ipv6_allocators[tg] = p2p_v6_allocator_map[allocator_key]
                logging.debug(
                    f"Found P2P v6 allocator for {tg} with CIDR {p2p_v6_cidr}/{p2p_v6_subnet_len}"
                )

    def _set_dut_device_meta(self, dut):
        """
        Set device metadata such as loopback IPs, BGP ASN, and router ID based on the device template.
        """
        self.device_meta[dut]['type'] = self.device_templates[dut]['type']
        logging.debug(f"Setting device type for {dut}: {self.device_meta[dut]['type']}")

        self.device_meta[dut]['extra_meta'] = self.device_templates[dut].get('extra_meta', {})
        logging.debug(f"Setting device extra meta for {dut}: {self.device_meta[dut]['extra_meta']}")

    def _allocate_dut_loopback_ip(self, index, dut):
        """
        Allocate loopback IPs and BGP router ID for the device based on the index of the device in the testbed.
        """
        device_template = self.device_templates[dut]

        if 'loopback_v4' not in device_template and 'loopback_v6' not in device_template:
            raise ValueError(f"loopback_v4 or loopback_v6 not found in device template for {dut}")

        loopback_v4_ipcidr = None
        if 'loopback_v4' in device_template:
            loopback_v4_allocator = IPAllocator(device_template['loopback_v4'], 32, start_offset=index + 1)
            loopback_v4_ipcidr = loopback_v4_allocator.allocate()
            self.device_meta[dut]['loopback_v4'] = str(loopback_v4_ipcidr)
            logging.debug(f"Allocated loopback v4 IP for {dut}: {self.device_meta[dut]['loopback_v4']}")

        # If explicit router id pool is provided, use it. Otherwise, use loopback_v4 IP as router id
        if 'router_id' in device_template:
            router_id_allocator = IPAllocator(device_template['router_id'], 32, start_offset=index + 1)
            self.device_meta[dut]['bgp_router_id'] = str(router_id_allocator.allocate()[0])
            logging.debug(f"Allocated router ID explicitly for {dut}: {self.device_meta[dut]['bgp_router_id']}")
        elif 'loopback_v4' in device_template:
            self.device_meta[dut]['bgp_router_id'] = str(loopback_v4_ipcidr[0])
            logging.debug(f"Using loopback v4 IP as router ID for {dut}: {self.device_meta[dut]['bgp_router_id']}")
        else:
            raise ValueError(f"loopback_v4 or router_id not found in device template for {dut}")

        if 'loopback_v6' in device_template:
            loopback_v6_allocator = IPAllocator(device_template['loopback_v6'], 128, start_offset=index + 1)
            self.device_meta[dut]['loopback_v6'] = str(loopback_v6_allocator.allocate())
            logging.debug(f"Allocated loopback v6 IP for {dut}: {self.device_meta[dut]['loopback_v6']}")

    def _allocate_dut_bgp_asn(self, index, dut):
        """
        Allocate BGP ASN for the device based on the index of the device in the testbed.
        """
        device_template = self.device_templates[dut]
        if 'asn_base' not in device_template:
            raise ValueError(f"asn_base not found in device template for {dut}")

        # ASN is allocated based on the index of the device in the testbed
        self.device_meta[dut]['bgp_asn'] = device_template['asn_base'] + index * device_template.get('asn_step', 1)
        logging.debug(f"Allocated BGP ASN for {dut}: {self.device_meta[dut]['bgp_asn']}")

    def _set_tg_device_meta(self, tg):
        tg_template = self.testbed_facts['topo']['properties']['tg_template']
        logging.debug(f"Setting device type for {tg}: {tg_template['type']}")
        self.device_meta[tg]['type'] = tg_template['type']

    def _allocate_tg_bgp_asn(self, index, tg):
        """
        Allocate BGP ASN for the traffic generator based on the index of the traffic generator in the testbed.
        """
        if 'tg_template' not in self.testbed_facts['topo']['properties']:
            raise ValueError("tg_template not found in testbed facts")

        tg_template = self.testbed_facts['topo']['properties']['tg_template']
        if 'asn_base' not in tg_template:
            raise ValueError("asn_base not found in testbed facts tg_template")

        # ASN is allocated based on the index of the traffic generator in the testbed
        asn_base = tg_template['asn_base']
        self.device_meta[tg]['bgp_asn'] = asn_base + index * tg_template.get('asn_step', 1)
        logging.debug(f"Allocated BGP ASN for traffic generator {tg}: {self.device_meta[tg]['bgp_asn']}")

    def _allocate_p2p_ip(self):
        """
        Allocate P2P IP addresses for each port. To make sure all P2P links has its own subnet,
        we use BFS to traverse the links and allocate subnet for each link.
        """
        logging.debug("=================================================================")
        logging.debug("Start allocating P2P IPs for all devices in the testbed")

        pending_devices = []
        visit_devices = set()

        # Start from traffic generator ports
        for tg in self.testbed_facts['tgs']:
            pending_devices.append(tg)

        # Run BFS to allocate P2P IPs
        while len(pending_devices) > 0:
            local_device = pending_devices.pop(0)
            visit_devices.add(local_device)

            logging.debug(f"Start working on device: {local_device}")

            for local_port, link in self.device_port_links[local_device].items():
                if (link['peerdevice'] not in self.testbed_facts['duts'] and
                        link['peerdevice'] not in self.testbed_facts['tgs']):
                    continue

                # Check if the port has been visited
                if (local_device in self.device_bgp_neighbor_ports and
                        local_port in self.device_bgp_neighbor_ports[local_device]):
                    continue

                # Craft peer device and port information
                logging.debug(
                    f"New link found: {local_device}:{local_port} <-> "
                    f"{link['peerdevice']}:{link['peerport']}"
                )

                peer_device = link['peerdevice']
                peer_port = link['peerport']
                if (peer_device in self.device_bgp_neighbor_ports and
                        peer_port in self.device_bgp_neighbor_ports[peer_device]):
                    raise ValueError(
                        f"Duplicate P2P link found: {local_device}:{local_port} <-> "
                        f"{peer_device}:{peer_port}"
                    )

                self.device_interfaces[local_device].setdefault(local_port, {
                    'vrf_name': self.device_port_vrfs[local_device].get(local_port, {}).get('name', ''),
                    'mac_addr': self.device_port_links[local_device].get(local_port, {}).get('mac', ''),
                })

                self.device_interfaces[peer_device].setdefault(peer_port, {
                    'vrf_name': self.device_port_vrfs[peer_device].get(peer_port, {}).get('name', ''),
                    'mac_addr': self.device_port_links[peer_device].get(peer_port, {}).get('mac', ''),
                })

                local_device_config = {
                    'peer_device': peer_device,
                    'peer_port': peer_port,
                }

                peer_device_config = {
                    'peer_device': local_device,
                    'peer_port': local_port,
                }

                p2p_v4_allocator = self.device_ipv4_allocators.get(local_device, None)
                if p2p_v4_allocator:
                    p2p_v4_subnet = p2p_v4_allocator.allocate()

                    local_device_ip = str(p2p_v4_subnet[0] if p2p_v4_subnet.prefixlen == 31 else p2p_v4_subnet[1])
                    peer_device_ip = str(p2p_v4_subnet[1] if p2p_v4_subnet.prefixlen == 31 else p2p_v4_subnet[2])
                    p2p_ip_prefix_len = str(p2p_v4_subnet.prefixlen)

                    self.device_interfaces[local_device][local_port]['ip_v4'] = local_device_ip
                    self.device_interfaces[local_device][local_port]['ip_v4_subnet_size'] = p2p_ip_prefix_len
                    self.device_interfaces[peer_device][peer_port]['ip_v4'] = peer_device_ip
                    self.device_interfaces[peer_device][peer_port]['ip_v4_subnet_size'] = p2p_ip_prefix_len

                    logging.debug(
                        f"P2P v4 allocated: {local_device}:{local_port} "
                        f"({local_device_ip}/{p2p_ip_prefix_len}) <-> "
                        f"{peer_device}:{peer_port} "
                        f"({peer_device_ip}/{p2p_ip_prefix_len})"
                    )

                    local_device_config['local_ip_v4'] = local_device_ip
                    local_device_config['peer_ip_v4'] = peer_device_ip
                    local_device_config['peer_asn'] = self.device_meta[peer_device]['bgp_asn']
                    local_device_config['p2p_v4_subnet_size'] = p2p_ip_prefix_len

                    peer_device_config['local_ip_v4'] = peer_device_ip
                    peer_device_config['peer_ip_v4'] = local_device_ip
                    peer_device_config['peer_asn'] = self.device_meta[local_device]['bgp_asn']
                    peer_device_config['p2p_v4_subnet_size'] = p2p_ip_prefix_len

                p2p_v6_allocator = self.device_ipv6_allocators.get(local_device, None)
                if p2p_v6_allocator:
                    p2p_v6_subnet = p2p_v6_allocator.allocate()

                    # /127 (RFC 6164) has two usable addresses, so both endpoints use the subnet members directly.
                    local_device_ip = str(p2p_v6_subnet[0] if p2p_v6_subnet.prefixlen == 127 else p2p_v6_subnet[1])
                    peer_device_ip = str(p2p_v6_subnet[1] if p2p_v6_subnet.prefixlen == 127 else p2p_v6_subnet[2])
                    p2p_ip_prefix_len = str(p2p_v6_subnet.prefixlen)

                    self.device_interfaces[local_device][local_port]['ip_v6'] = local_device_ip
                    self.device_interfaces[local_device][local_port]['ip_v6_subnet_size'] = p2p_ip_prefix_len
                    self.device_interfaces[peer_device][peer_port]['ip_v6'] = peer_device_ip
                    self.device_interfaces[peer_device][peer_port]['ip_v6_subnet_size'] = p2p_ip_prefix_len

                    logging.debug(
                        f"P2P v6 allocated: {local_device}:{local_port} "
                        f"({local_device_ip}/{p2p_ip_prefix_len}) <-> "
                        f"{peer_device}:{peer_port} "
                        f"({peer_device_ip}/{p2p_ip_prefix_len})"
                    )

                    local_device_config['local_ip_v6'] = local_device_ip
                    local_device_config['peer_ip_v6'] = peer_device_ip
                    local_device_config['peer_asn'] = self.device_meta[peer_device]['bgp_asn']
                    local_device_config['p2p_v6_subnet_size'] = p2p_ip_prefix_len

                    peer_device_config['local_ip_v6'] = peer_device_ip
                    peer_device_config['peer_ip_v6'] = local_device_ip
                    peer_device_config['peer_asn'] = self.device_meta[local_device]['bgp_asn']
                    peer_device_config['p2p_v6_subnet_size'] = p2p_ip_prefix_len

                # Skip if peer device is the same as local device.
                # This is used as snake setup and we should never create loopback BGP sessions
                if link['peerdevice'] == local_device:
                    continue

                if p2p_v4_allocator or p2p_v6_allocator:
                    self.device_bgp_neighbor_ports[local_device][local_port] = local_device_config
                    self.device_bgp_neighbor_ports[peer_device][peer_port] = peer_device_config

                    if self.device_bgp_neighbor_devices[local_device].get(peer_device) is None:
                        self.device_bgp_neighbor_devices[local_device][peer_device] = {
                            "type": self.device_meta[peer_device]['type'],
                            "hwsku": self.device_info[peer_device]['HwSku'],
                            "loopback_v4": self.device_meta[peer_device].get('loopback_v4', "0.0.0.0/0"),
                            "loopback_v6": self.device_meta[peer_device].get('loopback_v6', "::/0"),
                            "mgmt_v4": self.device_info[peer_device].get('ManagementIp', "0.0.0.0/0"),
                            "mgmt_v6": self.device_info[peer_device].get('ManagementIpV6', "::/0"),
                        }

                    if self.device_bgp_neighbor_devices[peer_device].get(local_device) is None:
                        self.device_bgp_neighbor_devices[peer_device][local_device] = {
                            "type": self.device_meta[local_device]['type'],
                            "hwsku": self.device_info[local_device]['HwSku'],
                            "loopback_v4": self.device_meta[local_device].get('loopback_v4', "0.0.0.0/0"),
                            "loopback_v6": self.device_meta[local_device].get('loopback_v6', "::/0"),
                            "mgmt_v4": self.device_info[local_device].get('ManagementIp', "0.0.0.0/0"),
                            "mgmt_v6": self.device_info[local_device].get('ManagementIpV6', "::/0"),
                        }

                # Add peer device to pending devices if not already present
                if peer_device not in visit_devices and peer_device not in pending_devices:
                    pending_devices.append(peer_device)


class L2SnakeVlanAllocator():
    """L2 snake strategy — VLAN pair allocation, no IP/BGP.

    Trace parallel snake chains across the whole DUT set using a lockstep
    algorithm, then assign VLAN IDs to each local per-DUT hop.

    A chain always starts on a TG-connected TX port, bridges traffic to the
    next available port on the same DUT, then follows the physical cable from
    that egress port to either:
      * another port on the same DUT (loopback cable),
      * a port on a different DUT (inter-DUT cable), or
      * a TG-connected RX port, which terminates the chain.

    Each VLAN pair is local to one DUT. When a chain crosses between DUTs, the
    current pair ends on the source DUT and the next pair starts on the peer
    DUT port reached by the physical link.
    """

    def __init__(self, testbed_facts, device_info, device_port_links, device_port_vrfs):
        self.testbed_facts = testbed_facts
        self.device_info = device_info
        self.device_port_links = device_port_links
        self.device_port_vrfs = device_port_vrfs

        self.device_meta = defaultdict(dict)
        self.device_interfaces = {}
        self.device_bgp_neighbor_devices = defaultdict(dict)
        self.device_bgp_neighbor_ports = defaultdict(dict)

        # L2 snake specific outputs
        self.device_vlans = {}
        self.device_port_vlans = {}
        self.device_vlan_list = {}
        self.device_vrfs = {}
        self.device_conn = {}

    def run(self):
        topo_props = self.testbed_facts['topo']['properties']
        vlan_base = topo_props.get('vlan_base')
        if vlan_base is None:
            raise ValueError("L2 snake topo YAML must specify 'vlan_base'.")

        duts = self.testbed_facts['duts']
        tgs = self.testbed_facts['tgs']
        tg_set = set(tgs)

        self._initialize_device_facts(duts)
        self._trace_chain_global(duts, tg_set, vlan_base)

        for tg in tgs:
            self.device_meta[tg]['type'] = 'Server'

    def _initialize_device_facts(self, duts):
        """Initialize per-device outputs so all DUTs return deterministic facts."""
        for dut in duts:
            self.device_meta[dut]['type'] = self.device_info[dut].get('Type', 'ToRRouter')
            self.device_interfaces[dut] = {}
            self.device_vrfs[dut] = {}
            self.device_conn[dut] = self.device_port_links[dut]
            self.device_vlans[dut] = {}
            self.device_port_vlans[dut] = {}
            self.device_vlan_list[dut] = []

    def _classify_ports(self, duts, tg_set):
        """Build global link metadata for L2 snake tracing."""
        dut_set = set(duts)
        dut_ports = {}
        global_tgen_ports = []

        for dut in duts:
            links = self.device_port_links[dut]
            sorted_ports = natsorted(links.keys())
            port_index = {port: idx for idx, port in enumerate(sorted_ports)}
            loopback_map = {}
            inter_dut_map = {}
            tgen_ports = []

            for port in sorted_ports:
                link = links[port]
                peer_device = link['peerdevice']
                peer_port = link['peerport']

                if peer_device in tg_set:
                    tgen_ports.append(port)
                    global_tgen_ports.append((dut, port))
                elif peer_device == dut:
                    loopback_map[port] = (peer_device, peer_port)
                elif peer_device in dut_set:
                    inter_dut_map[port] = (peer_device, peer_port)
                else:
                    raise ValueError(
                        f"Unsupported L2 snake link {dut}:{port} -> {peer_device}:{peer_port}. "
                        "Peer must be a TG, the same DUT, or another DUT in the testbed."
                    )

            dut_ports[dut] = {
                'all_ports': sorted_ports,
                'port_index': port_index,
                'loopback_map': loopback_map,
                'inter_dut_map': inter_dut_map,
                'tgen_ports': tgen_ports,
            }

        self._validate_tgen_port_count(global_tgen_ports)
        return dut_ports

    def _trace_chain_global(self, duts, tg_set, vlan_base):
        """Trace all L2 snake chains across the whole testbed in lockstep."""
        dut_ports = self._classify_ports(duts, tg_set)
        tx_ports, rx_ports = self._split_global_tgen_ports(duts, dut_ports)
        chains = self._build_chains(tx_ports)
        self._walk_chains(chains, dut_ports, set(rx_ports))
        self._assign_vlan_outputs(duts, chains, vlan_base)

    def _validate_tgen_port_count(self, global_tgen_ports):
        if len(global_tgen_ports) < 2:
            raise ValueError(
                f"L2 snake requires at least 2 TG-connected ports across the testbed, found {len(global_tgen_ports)}."
            )

        if len(global_tgen_ports) % 2 != 0:
            raise ValueError(
                "L2 snake requires an even number of TG-connected ports across the testbed, "
                f"but found {len(global_tgen_ports)}."
            )

    def _split_global_tgen_ports(self, duts, dut_ports):
        """Split TG-connected ports into global TX/RX lists using per-DUT halves."""
        tx_ports = []
        rx_ports = []

        for dut in duts:
            tgen_ports = dut_ports[dut]['tgen_ports']
            if not tgen_ports:
                continue

            if len(tgen_ports) % 2 != 0:
                raise ValueError(
                    f"L2 snake requires an even number of TG-connected ports on {dut}, "
                    f"but found {len(tgen_ports)}."
                )

            # Intentional design constraint: TX/RX endpoints are derived from the first/second
            # halves of each DUT's natsorted TG port list, so every participating DUT must
            # contribute an even number of TG-connected ports.
            half = len(tgen_ports) // 2
            tx_ports.extend((dut, port) for port in tgen_ports[:half])
            rx_ports.extend((dut, port) for port in tgen_ports[half:])

        return tx_ports, rx_ports

    def _build_chains(self, tx_ports):
        chains = []
        for chain_id, tx_node in enumerate(tx_ports):
            chains.append({
                'chain_id': chain_id,
                'current': tx_node,
                'pairs': [],
                'complete': False,
                'tx_node': tx_node,
                'rx_node': None,
            })
        return chains

    def _walk_chains(self, chains, dut_ports, rx_set):
        """Advance all chains in lockstep until they reach RX ports."""
        used = {chain['tx_node'] for chain in chains}
        max_steps = sum(len(meta['all_ports']) for meta in dut_ports.values())

        for _step in range(max_steps):
            for chain in chains:
                if chain['complete']:
                    continue

                current_dut, current_port = chain['current']
                partner = self._find_next_local_partner(current_dut, current_port, used, dut_ports, rx_set)
                if partner is None:
                    raise ValueError(
                        f"Chain {chain['chain_id']} dead end at {current_dut}:{current_port}: "
                        "no available port forward in natsorted order on the same DUT."
                    )

                used.add(partner)
                chain['pairs'].append({
                    'dut': current_dut,
                    'ports': [current_port, partner[1]],
                })

                next_node, complete = self._get_transition_port(chain['chain_id'], partner, used, dut_ports, rx_set)
                if complete:
                    chain['complete'] = True
                    chain['rx_node'] = partner
                    continue

                used.add(next_node)
                chain['current'] = next_node

            if all(chain['complete'] for chain in chains):
                break

        for chain in chains:
            if not chain['complete']:
                raise ValueError(f"Chain {chain['chain_id']} did not reach an RX port.")

    def _find_next_local_partner(self, dut, current_port, used, dut_ports, rx_set):
        """Find the next unused partner port on the same DUT."""
        all_ports = dut_ports[dut]['all_ports']
        current_idx = dut_ports[dut]['port_index'][current_port]
        rx_candidate = None

        for idx in range(current_idx + 1, len(all_ports)):
            candidate = (dut, all_ports[idx])
            if candidate in used:
                continue
            if candidate in rx_set:
                # Prefer a non-RX forward hop when available so chains only terminate on RX
                # after exhausting other valid local candidates.
                if rx_candidate is None:
                    rx_candidate = candidate
                continue
            return candidate

        return rx_candidate

    def _get_transition_port(self, chain_id, partner_node, used, dut_ports, rx_set):
        """Follow the physical cable attached to a local egress port."""
        dut, partner_port = partner_node
        partner_key = (dut, partner_port)

        if partner_key in rx_set:
            return None, True

        loopback_map = dut_ports[dut]['loopback_map']
        inter_dut_map = dut_ports[dut]['inter_dut_map']

        if partner_port in loopback_map:
            next_dut, next_port = loopback_map[partner_port]
        elif partner_port in inter_dut_map:
            next_dut, next_port = inter_dut_map[partner_port]
        else:
            raise ValueError(
                f"Chain {chain_id} dead end at {dut}:{partner_port}: no loopback/inter-DUT cable and not an RX port."
            )

        next_node = (next_dut, next_port)
        if next_node in used:
            raise ValueError(
                f"Chain {chain_id}: transition target {next_dut}:{next_port} from {dut}:{partner_port} is already used."
            )

        return next_node, False

    def _assign_vlan_outputs(self, duts, chains, vlan_base):
        total_vlans = sum(len(chain['pairs']) for chain in chains)
        if total_vlans == 0:
            raise ValueError("L2 snake tracing produced no VLAN pairs.")

        if vlan_base + total_vlans - 1 > 4094:
            raise ValueError(
                f"VLAN range overflow: need VLANs {vlan_base}–{vlan_base + total_vlans - 1}, but max VLAN ID is 4094."
            )

        port_vlan_assignment = {}
        chain_views = defaultdict(list)
        vlan_id = vlan_base

        for chain in chains:
            for pair in chain['pairs']:
                dut = pair['dut']
                ports = pair['ports']
                vlan_info = self._record_vlan_pair(dut, ports, vlan_id, port_vlan_assignment)
                chain_views[dut].append(vlan_info)
                vlan_id += 1

        for dut in duts:
            self.device_vlans[dut] = self._merge_chain_views(chain_views[dut])

    def _record_vlan_pair(self, dut, ports, vlan_id, port_vlan_assignment):
        for port in ports:
            port_key = (dut, port)
            if port_key in port_vlan_assignment:
                raise ValueError(
                    f"Port {dut}:{port} already assigned to VLAN {port_vlan_assignment[port_key]}, "
                    f"cannot assign to VLAN {vlan_id}."
                )
            port_vlan_assignment[port_key] = vlan_id
            self.device_port_vlans[dut][port] = {
                'vlanlist': [vlan_id],
                'mode': 'Access',
            }

        self.device_vlan_list[dut].append(vlan_id)
        return {
            'vlan_id': vlan_id,
            'ports': ports,
        }

    def _merge_chain_views(self, vlan_pairs):
        """Flatten per-DUT VLAN pairs into a compatibility/debug ``device_vlans`` view.

        This helper intentionally discards chain-level grouping and only keeps the
        per-DUT VLAN list, for example::

            {
                'vlans': [
                    {'vlan_id': 1000, 'ports': ['Ethernet0', 'Ethernet4']},
                    {'vlan_id': 1001, 'ports': ['Ethernet8', 'Ethernet12']},
                ]
            }
        """
        return {
            'vlans': vlan_pairs,
        }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            testbed_facts=dict(required=True, default=None, type='dict'),
            device_info=dict(required=True, default=None, type='dict'),
            device_port_links=dict(required=True, default=None, type='dict'),
            device_port_vrfs=dict(required=False, default=None, type='dict'),
        ),
        supports_check_mode=True
    )

    m_args = module.params
    testbed_facts = m_args['testbed_facts']
    device_info = m_args['device_info']
    device_port_links = m_args['device_port_links']
    device_port_vrfs = m_args['device_port_vrfs']

    try:
        topo_type = testbed_facts.get('topo', {}).get('properties', {}).get('type', 'nut')
        if topo_type == 'l2-snake':
            device_config_gen = L2SnakeVlanAllocator(testbed_facts, device_info, device_port_links, device_port_vrfs)
        else:
            device_config_gen = GenerateDeviceConfig(testbed_facts, device_info, device_port_links, device_port_vrfs)
        device_config_gen.run()

        facts = {
            'device_meta': device_config_gen.device_meta,
            'device_interfaces': device_config_gen.device_interfaces,
            'device_bgp_neighbor_devices': device_config_gen.device_bgp_neighbor_devices,
            'device_bgp_neighbor_ports': device_config_gen.device_bgp_neighbor_ports,
        }
        # Add L2 snake specific facts if available
        if hasattr(device_config_gen, 'device_vlans'):
            facts['device_vlans'] = device_config_gen.device_vlans
        if hasattr(device_config_gen, 'device_vlan_list'):
            facts['device_vlan_list'] = device_config_gen.device_vlan_list
        if hasattr(device_config_gen, 'device_port_vlans'):
            facts['device_port_vlans'] = device_config_gen.device_port_vlans
        if hasattr(device_config_gen, 'device_vrfs'):
            facts['device_vrfs'] = device_config_gen.device_vrfs
        if hasattr(device_config_gen, 'device_conn'):
            facts['device_conn'] = device_config_gen.device_conn
        module.exit_json(ansible_facts=facts)
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
